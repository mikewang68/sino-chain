// Service to verify accounts hashes with other known validator nodes.
//
// Each interval, publish the snapshat hash which is the full accounts state
// hash on gossip. Monitor gossip for messages from validators in the `--known-validator`s
// set and halt the node if a mismatch is detected.

use {
    rayon::ThreadPool,
    gossip::cluster_info::{ClusterInfo, MAX_SNAPSHOT_HASHES},
    measure::measure::Measure,
    runtime::{
        accounts_db::{self, AccountsDb},
        accounts_hash::HashStats,
        snapshot_config::SnapshotConfig,
        snapshot_package::{
            AccountsPackage, AccountsPackageReceiver, PendingSnapshotPackage, SnapshotPackage,
            SnapshotType,
        },
        sorted_storages::SortedStorages,
    },
    sdk::{clock::Slot, hash::Hash, pubkey::Pubkey},
    std::{
        collections::{HashMap, HashSet},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc::RecvTimeoutError,
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct AccountsHashVerifier {
    t_accounts_hash_verifier: JoinHandle<()>,
}

impl AccountsHashVerifier {
    pub fn new(
        accounts_package_receiver: AccountsPackageReceiver,
        pending_snapshot_package: Option<PendingSnapshotPackage>,
        exit: &Arc<AtomicBool>,
        cluster_info: &Arc<ClusterInfo>,
        known_validators: Option<HashSet<Pubkey>>,
        halt_on_known_validators_accounts_hash_mismatch: bool,
        fault_injection_rate_slots: u64,
        snapshot_config: Option<SnapshotConfig>,
        ledger_path: PathBuf,
    ) -> Self {
        let exit = exit.clone();
        let cluster_info = cluster_info.clone();
        let t_accounts_hash_verifier = Builder::new()
            .name("sino-hash-accounts".to_string())
            .spawn(move || {
                let mut hashes = vec![];
                let mut thread_pool = None;
                loop {
                    if exit.load(Ordering::Relaxed) {
                        break;
                    }

                    match accounts_package_receiver.recv_timeout(Duration::from_secs(1)) {
                        Ok(accounts_package) => {
                            if accounts_package.hash_for_testing.is_some() && thread_pool.is_none()
                            {
                                thread_pool = Some(accounts_db::make_min_priority_thread_pool());
                            }

                            Self::process_accounts_package(
                                accounts_package,
                                &cluster_info,
                                known_validators.as_ref(),
                                halt_on_known_validators_accounts_hash_mismatch,
                                pending_snapshot_package.as_ref(),
                                &mut hashes,
                                &exit,
                                fault_injection_rate_slots,
                                snapshot_config.as_ref(),
                                thread_pool.as_ref(),
                                &ledger_path,
                            );
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => (),
                    }
                }
            })
            .unwrap();
        Self {
            t_accounts_hash_verifier,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_accounts_package(
        accounts_package: AccountsPackage,
        cluster_info: &ClusterInfo,
        known_validators: Option<&HashSet<Pubkey>>,
        halt_on_known_validator_accounts_hash_mismatch: bool,
        pending_snapshot_package: Option<&PendingSnapshotPackage>,
        hashes: &mut Vec<(Slot, Hash)>,
        exit: &Arc<AtomicBool>,
        fault_injection_rate_slots: u64,
        snapshot_config: Option<&SnapshotConfig>,
        thread_pool: Option<&ThreadPool>,
        ledger_path: &Path,
    ) {
        Self::verify_accounts_package_hash(&accounts_package, thread_pool, ledger_path);

        Self::push_accounts_hashes_to_cluster(
            &accounts_package,
            cluster_info,
            known_validators,
            halt_on_known_validator_accounts_hash_mismatch,
            hashes,
            exit,
            fault_injection_rate_slots,
        );

        Self::submit_for_packaging(accounts_package, pending_snapshot_package, snapshot_config);
    }

    fn verify_accounts_package_hash(
        accounts_package: &AccountsPackage,
        thread_pool: Option<&ThreadPool>,
        ledger_path: &Path,
    ) {
        let mut measure_hash = Measure::start("hash");
        if let Some(expected_hash) = accounts_package.hash_for_testing {
            let sorted_storages = SortedStorages::new(&accounts_package.snapshot_storages);
            let (hash, wens) = AccountsDb::calculate_accounts_hash_without_index(
                ledger_path,
                &sorted_storages,
                thread_pool,
                HashStats::default(),
                false,
                None,
                None, // this will fail with filler accounts
                None, // this code path is only for testing, so use default # passes here
            )
            .unwrap();

            assert_eq!(accounts_package.expected_capitalization, wens);
            assert_eq!(expected_hash, hash);
        };
        measure_hash.stop();
        datapoint_info!(
            "accounts_hash_verifier",
            ("calculate_hash", measure_hash.as_us(), i64),
        );
    }

    fn push_accounts_hashes_to_cluster(
        accounts_package: &AccountsPackage,
        cluster_info: &ClusterInfo,
        known_validators: Option<&HashSet<Pubkey>>,
        halt_on_known_validator_accounts_hash_mismatch: bool,
        hashes: &mut Vec<(Slot, Hash)>,
        exit: &Arc<AtomicBool>,
        fault_injection_rate_slots: u64,
    ) {
        let hash = accounts_package.hash;
        if fault_injection_rate_slots != 0
            && accounts_package.slot % fault_injection_rate_slots == 0
        {
            // For testing, publish an invalid hash to gossip.
            use {
                rand::{thread_rng, Rng},
                sdk::hash::extend_and_hash,
            };
            warn!("inserting fault at slot: {}", accounts_package.slot);
            let rand = thread_rng().gen_range(0, 10);
            let hash = extend_and_hash(&hash, &[rand]);
            hashes.push((accounts_package.slot, hash));
        } else {
            hashes.push((accounts_package.slot, hash));
        }

        while hashes.len() > MAX_SNAPSHOT_HASHES {
            hashes.remove(0);
        }

        if halt_on_known_validator_accounts_hash_mismatch {
            let mut slot_to_hash = HashMap::new();
            for (slot, hash) in hashes.iter() {
                slot_to_hash.insert(*slot, *hash);
            }
            if Self::should_halt(cluster_info, known_validators, &mut slot_to_hash) {
                exit.store(true, Ordering::Relaxed);
            }
        }

        cluster_info.push_accounts_hashes(hashes.clone());
    }

    fn submit_for_packaging(
        accounts_package: AccountsPackage,
        pending_snapshot_package: Option<&PendingSnapshotPackage>,
        snapshot_config: Option<&SnapshotConfig>,
    ) {
        if accounts_package.snapshot_type.is_none()
            || pending_snapshot_package.is_none()
            || snapshot_config.is_none()
        {
            return;
        };

        let snapshot_package = SnapshotPackage::from(accounts_package);
        let pending_snapshot_package = pending_snapshot_package.unwrap();
        let _snapshot_config = snapshot_config.unwrap();

        // If the snapshot package is an Incremental Snapshot, do not submit it if there's already
        // a pending Full Snapshot.
        let can_submit = match snapshot_package.snapshot_type {
            SnapshotType::FullSnapshot => true,
            SnapshotType::IncrementalSnapshot(_) => pending_snapshot_package
                .lock()
                .unwrap()
                .as_ref()
                .map_or(true, |snapshot_package| {
                    snapshot_package.snapshot_type.is_incremental_snapshot()
                }),
        };

        if can_submit {
            *pending_snapshot_package.lock().unwrap() = Some(snapshot_package);
        }
    }

    fn should_halt(
        cluster_info: &ClusterInfo,
        known_validators: Option<&HashSet<Pubkey>>,
        slot_to_hash: &mut HashMap<Slot, Hash>,
    ) -> bool {
        let mut verified_count = 0;
        let mut highest_slot = 0;
        if let Some(known_validators) = known_validators {
            for known_validator in known_validators {
                let is_conflicting = cluster_info.get_accounts_hash_for_node(known_validator, |accounts_hashes|
                {
                    accounts_hashes.iter().any(|(slot, hash)| {
                        if let Some(reference_hash) = slot_to_hash.get(slot) {
                            if *hash != *reference_hash {
                                error!("Known validator {} produced conflicting hashes for slot: {} ({} != {})",
                                    known_validator,
                                    slot,
                                    hash,
                                    reference_hash,
                                );
                                true
                            } else {
                                verified_count += 1;
                                false
                            }
                        } else {
                            highest_slot = std::cmp::max(*slot, highest_slot);
                            slot_to_hash.insert(*slot, *hash);
                            false
                        }
                    })
                }).unwrap_or(false);

                if is_conflicting {
                    return true;
                }
            }
        }
        inc_new_counter_info!("accounts_hash_verifier-hashes_verified", verified_count);
        datapoint_info!(
            "accounts_hash_verifier",
            ("highest_slot_verified", highest_slot, i64),
        );
        false
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_accounts_hash_verifier.join()
    }
}

#[cfg(test)]
mod tests {
    use runtime::bank::Bank;

    use {
        super::*,
        gossip::{cluster_info::make_accounts_hashes_message, contact_info::ContactInfo},
        runtime::snapshot_utils::{ArchiveFormat, SnapshotVersion},
        sdk::{
            genesis_config::ClusterType,
            hash::hash,
            signature::{Keypair, Signer},
        },
        sino_streamer::socket::SocketAddrSpace,
    };
    use evm_state::AccountProvider;

    fn new_test_cluster_info(contact_info: ContactInfo) -> ClusterInfo {
        ClusterInfo::new(
            contact_info,
            Arc::new(Keypair::new()),
            SocketAddrSpace::Unspecified,
        )
    }

    #[test]
    fn test_should_halt() {
        let keypair = Keypair::new();

        let contact_info = ContactInfo::new_localhost(&keypair.pubkey(), 0);
        let cluster_info = new_test_cluster_info(contact_info);
        let cluster_info = Arc::new(cluster_info);

        let mut known_validators = HashSet::new();
        let mut slot_to_hash = HashMap::new();
        assert!(!AccountsHashVerifier::should_halt(
            &cluster_info,
            Some(&known_validators),
            &mut slot_to_hash,
        ));

        let validator1 = Keypair::new();
        let hash1 = hash(&[1]);
        let hash2 = hash(&[2]);
        {
            let message = make_accounts_hashes_message(&validator1, vec![(0, hash1)]).unwrap();
            cluster_info.push_message(message);
            cluster_info.flush_push_queue();
        }
        slot_to_hash.insert(0, hash2);
        known_validators.insert(validator1.pubkey());
        assert!(AccountsHashVerifier::should_halt(
            &cluster_info,
            Some(&known_validators),
            &mut slot_to_hash,
        ));
    }

    #[test]
    fn test_max_hashes() {
        sino_logger::setup();
        use {std::path::PathBuf, tempfile::TempDir};
        let keypair = Keypair::new();

        let contact_info = ContactInfo::new_localhost(&keypair.pubkey(), 0);
        let cluster_info = new_test_cluster_info(contact_info);
        let cluster_info = Arc::new(cluster_info);

        let known_validators = HashSet::new();
        let exit = Arc::new(AtomicBool::new(false));
        let mut hashes = vec![];
        let full_snapshot_archive_interval_slots = 100;
        let snapshot_config = SnapshotConfig {
            full_snapshot_archive_interval_slots,
            incremental_snapshot_archive_interval_slots: Slot::MAX,
            ..SnapshotConfig::default()
        };
        let bank = Arc::new(Bank::new_for_tests(&Default::default()));
        for i in 0..MAX_SNAPSHOT_HASHES + 1 {
            let accounts_package = AccountsPackage {
                slot: full_snapshot_archive_interval_slots + i as u64,
                block_height: full_snapshot_archive_interval_slots + i as u64,
                slot_deltas: vec![],
                snapshot_links: TempDir::new().unwrap(),
                snapshot_storages: vec![],
                hash: hash(&[i as u8]),
                archive_format: ArchiveFormat::TarBzip2,
                snapshot_version: SnapshotVersion::default(),
                snapshot_archives_dir: PathBuf::default(),
                expected_capitalization: 0,
                hash_for_testing: None,
                cluster_type: ClusterType::MainnetBeta,
                snapshot_type: None,
                evm_db: bank.evm_state.read().unwrap().kvs().clone(),
                evm_root: bank.evm_state.read().unwrap().last_root(),
                bank: bank.clone()
            };

            let ledger_path = TempDir::new().unwrap();

            AccountsHashVerifier::process_accounts_package(
                accounts_package,
                &cluster_info,
                Some(&known_validators),
                false,
                None,
                &mut hashes,
                &exit,
                0,
                Some(&snapshot_config),
                None,
                ledger_path.path(),
            );

            // sleep for 1ms to create a newer timestmap for gossip entry
            // otherwise the timestamp won't be newer.
            std::thread::sleep(Duration::from_millis(1));
        }
        cluster_info.flush_push_queue();
        let cluster_hashes = cluster_info
            .get_accounts_hash_for_node(&keypair.pubkey(), |c| c.clone())
            .unwrap();
        info!("{:?}", cluster_hashes);
        assert_eq!(hashes.len(), MAX_SNAPSHOT_HASHES);
        assert_eq!(cluster_hashes.len(), MAX_SNAPSHOT_HASHES);
        assert_eq!(
            cluster_hashes[0],
            (full_snapshot_archive_interval_slots + 1, hash(&[1]))
        );
        assert_eq!(
            cluster_hashes[MAX_SNAPSHOT_HASHES - 1],
            (
                full_snapshot_archive_interval_slots + MAX_SNAPSHOT_HASHES as u64,
                hash(&[MAX_SNAPSHOT_HASHES as u8])
            )
        );
    }
}
