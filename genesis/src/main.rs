//! A command-line executable for generating the chain's genesis config.用于生成链的genesis配置的命令行可执行文件
#![allow(clippy::integer_arithmetic)]

use ledger::blockstore::EvmStateJson;

use {
    clap::{crate_description, crate_name, value_t, value_t_or_exit, App, Arg, ArgMatches},
    evm_state::U256,
    log::{error, info},
    clap_utils::{
        input_parsers::{
            cluster_type_of, pubkey_of, pubkeys_of, unix_timestamp_from_rfc3339_datetime,
        },
        input_validators::{
            is_pubkey_or_keypair, is_rfc3339_datetime, is_slot, is_valid_percentage,
        },
    },
    sino_entry::poh::compute_hashes_per_tick,
    genesis::Base64Account,
    ledger::{blockstore::create_new_ledger,blockstore_db::AccessType},//blockstore::create_new_ledger,
    runtime::hardened_unpack::MAX_GENESIS_ARCHIVE_UNPACKED_SIZE,//定义了创世档案文件解压后的最大大小。700MB
    sdk::{
        account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
        clock,
        epoch_schedule::EpochSchedule,
        fee_calculator::FeeRateGovernor,
        genesis_config::{
            self, evm_genesis::{OpenEthereumAccountExtractor, GethAccountExtractor},
            ClusterType, GenesisConfig
        },
        inflation::Inflation,
        native_token::sol_to_lamports,
        poh_config::PohConfig,
        pubkey::Pubkey,
        rent::Rent,
        signature::{Keypair, Signer},
        stake::state::StakeState,
        system_program, timing,
    },
    stake_program::stake_state,//内容过多，暂不解析
    vote_program::vote_state::{self, VoteState},
    std::{
        collections::HashMap,
        error,
        fs::File,
        io::{self, Read},
        path::PathBuf,
        process,
        str::FromStr,
        time::Duration,
    },
};
pub enum AccountFileFormat {//账户文件
    Pubkey,
    Keypair,
}
fn pubkey_from_str(key_str: &str) -> Result<Pubkey, Box<dyn error::Error>> {
    Pubkey::from_str(key_str).or_else(|_| {
        let bytes: Vec<u8> = serde_json::from_str(key_str)?;
        let keypair = Keypair::from_bytes(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(keypair.pubkey())
    })
}
pub fn load_genesis_accounts(file: &str, genesis_config: &mut GenesisConfig) -> io::Result<u64> {
    let mut lamports = 0;
    let accounts_file = File::open(file)?;

    let genesis_accounts: HashMap<String, Base64Account> =
        serde_yaml::from_reader(accounts_file)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("{:?}", err)))?;

    for (key, account_details) in genesis_accounts {
        let pubkey = pubkey_from_str(key.as_str()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid pubkey/keypair {}: {:?}", key, err),
            )
        })?;

        let owner_program_id = Pubkey::from_str(account_details.owner.as_str()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid owner: {}: {:?}", account_details.owner, err),
            )
        })?;

        let mut account = AccountSharedData::new(account_details.balance, 0, &owner_program_id);
        if account_details.data != "~" {
            account.set_data(
                base64::decode(account_details.data.as_str()).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Invalid account data: {}: {:?}", account_details.data, err),
                    )
                })?,
            );
        }
        account.set_executable(account_details.executable);
        lamports += account.wens();
        genesis_config.add_account(pubkey, account);
    }

    Ok(lamports)
}
#[allow(clippy::cognitive_complexity)]
fn main() -> Result<(), Box<dyn error::Error>> {
    let default_faucet_pubkey = cli_config::Config::default().keypair_path;
    let fee_rate_governor = FeeRateGovernor::default();
    let (
        default_target_lamports_per_signature,
        default_target_signatures_per_slot,
        default_fee_burn_percentage,
    ) = {
        (
            &fee_rate_governor.target_lamports_per_signature.to_string(),
            &fee_rate_governor.target_signatures_per_slot.to_string(),
            &fee_rate_governor.burn_percent.to_string(),
        )
    };

    let rent = Rent::default();
    let (
        default_lamports_per_byte_year,
        default_rent_exemption_threshold,
        default_rent_burn_percentage,
    ) = {
        (
            &rent.lamports_per_byte_year.to_string(),
            &rent.exemption_threshold.to_string(),
            &rent.burn_percent.to_string(),
        )
    };

    // vote account 投票账户
    let default_bootstrap_validator_lamports = &sol_to_lamports(500.0)
        .max(VoteState::get_rent_exempt_reserve(&rent))
        .to_string();
    // stake account 质押账户
    let default_bootstrap_validator_stake_lamports = &sol_to_lamports(0.5)
        .max(StakeState::get_rent_exempt_reserve(&rent)).to_string();

    let default_target_tick_duration =
        timing::duration_as_us(&PohConfig::default().target_tick_duration);
    let default_ticks_per_slot = &clock::DEFAULT_TICKS_PER_SLOT.to_string();
    let default_cluster_type = "mainnet-beta";
    let default_genesis_archive_unpacked_size = MAX_GENESIS_ARCHIVE_UNPACKED_SIZE.to_string();
    let version = sino_version::version!();
    let app = App::new(crate_name!())
        .about(crate_description!())
        .version(version)
        .arg(
            Arg::with_name("creation_time")
                .long("creation-time")
                .value_name("RFC3339 DATE TIME")
                .validator(is_rfc3339_datetime)
                .takes_value(true)
                .help("Time when the bootstrap validator will start the cluster [default: current system time]"),
        )
        .arg(
            Arg::with_name("bootstrap_validator")// 定义第二个参数bootstrap_validator。
                .short("b")//它的短选项为"b"
                .long("bootstrap-validator")//长选项为"bootstrap-validator"。
                .value_name("IDENTITY_PUBKEY VOTE_PUBKEY STAKE_PUBKEY")//要求三个pubkey或keypair的值
                .takes_value(true)
                .validator(is_pubkey_or_keypair)//使用is_pubkey_or_keypair验证器验证。
                .number_of_values(3)//参数接受的值数量、
                .multiple(true)//是否允许多次输入
                .required(true)//是否为必填
                .help("The bootstrap validator's identity, vote and stake pubkeys"),
        )
        .arg(
            Arg::with_name("ledger_path")
                .short("l")
                .long("ledger")
                .value_name("DIR")
                .takes_value(true)//需要指定值
                .required(true)//必填
                .help("Use directory as persistent ledger location"),//使用目录作为持久化账本位置
        )
        .arg(
            Arg::with_name("faucet_lamports")
                .short("t")
                .long("faucet-lamports")
                .value_name("LAMPORTS")
                .takes_value(true)
                .help("Number of lamports to assign to the faucet"),
        )
        .arg(
            Arg::with_name("faucet_pubkey")//参数的名称为"faucet_pubkey"。
                .short("m")//短选项"-m"
                .long("faucet-pubkey")//长选项"--faucet-pubkey"。
                .value_name("PUBKEY")//值的名称为"PUBKEY",且要求一个值
                .takes_value(true)
                .validator(is_pubkey_or_keypair)//使用is_pubkey_or_keypair验证器验证输入的值。
                .requires("faucet_lamports")//参数需要同时指定"faucet_lamports"参数，使用requires方法指定这个依赖关系。//该参数依赖于faucet_lamports
                .default_value(&default_faucet_pubkey)//使用default_value方法为该参数指定一个默认值default_faucet_pubkey。
                .help("Path to file containing the faucet's pubkey"),
        )
        .arg(
            Arg::with_name("bootstrap_stake_authorized_pubkey")
                .long("bootstrap-stake-authorized-pubkey")
                .value_name("BOOTSTRAP STAKE AUTHORIZED PUBKEY")
                .takes_value(true)
                .validator(is_pubkey_or_keypair)
                .help(
                    "Path to file containing the pubkey authorized to manage the bootstrap \
                     validator's stake [default: --bootstrap-validator IDENTITY_PUBKEY]",
                ),
        )
        .arg(
            Arg::with_name("bootstrap_validator_lamports")
                .long("bootstrap-validator-lamports")
                .value_name("LAMPORTS")
                .takes_value(true)
                .default_value(default_bootstrap_validator_lamports)
                .help("Number of lamports to assign to the bootstrap validator"),
        )
        .arg(
            Arg::with_name("bootstrap_validator_stake_lamports")
                .long("bootstrap-validator-stake-lamports")
                .value_name("LAMPORTS")
                .takes_value(true)
                .default_value(default_bootstrap_validator_stake_lamports)
                .help("Number of lamports to assign to the bootstrap validator's stake account"),
        )
        .arg(
            Arg::with_name("target_lamports_per_signature")
                .long("target-lamports-per-signature")
                .value_name("LAMPORTS")
                .takes_value(true)
                .default_value(default_target_lamports_per_signature)
                .help(
                    "The cost in lamports that the cluster will charge for signature \
                     verification when the cluster is operating at target-signatures-per-slot",
                ),
        )
        .arg(
            Arg::with_name("lamports_per_byte_year")
                .long("lamports-per-byte-year")
                .value_name("LAMPORTS")
                .takes_value(true)
                .default_value(default_lamports_per_byte_year)
                .help(
                    "The cost in lamports that the cluster will charge per byte per year \
                     for accounts with data",
                ), 
        )
        .arg(
            Arg::with_name("rent_exemption_threshold")
                .long("rent-exemption-threshold")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value(default_rent_exemption_threshold)
                .help(
                    "amount of time (in years) the balance has to include rent for \
                     to qualify as rent exempted account",
                ),
        )
        .arg(
            Arg::with_name("rent_burn_percentage")
                .long("rent-burn-percentage")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value(default_rent_burn_percentage)
                .help("percentage of collected rent to burn")
                .validator(is_valid_percentage),
        )
        .arg(
            Arg::with_name("fee_burn_percentage")
                .long("fee-burn-percentage")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value(default_fee_burn_percentage)
                .help("percentage of collected fee to burn")
                .validator(is_valid_percentage),
        )
        .arg(
            Arg::with_name("vote_commission_percentage")
                .long("vote-commission-percentage")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value("100")
                .help("percentage of vote commission")
                .validator(is_valid_percentage),
        )
        .arg(
            Arg::with_name("target_signatures_per_slot")
                .long("target-signatures-per-slot")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value(default_target_signatures_per_slot)
                .help(
                    "Used to estimate the desired processing capacity of the cluster. \
                    When the latest slot processes fewer/greater signatures than this \
                    value, the lamports-per-signature fee will decrease/increase for \
                    the next slot. A value of 0 disables signature-based fee adjustments",
                ),
        )
        .arg(
            Arg::with_name("target_tick_duration")
                .long("target-tick-duration")
                .value_name("MILLIS")
                .takes_value(true)
                .help("The target tick rate of the cluster in milliseconds"),
        )
        .arg(
            Arg::with_name("hashes_per_tick")
                .long("hashes-per-tick")
                .value_name("NUM_HASHES|\"auto\"|\"sleep\"")
                .takes_value(true)
                .default_value("auto")
                .help(
                    "How many PoH hashes to roll before emitting the next tick. \
                     If \"auto\", determine based on --target-tick-duration \
                     and the hash rate of this computer. If \"sleep\", for development \
                     sleep for --target-tick-duration instead of hashing",
                ),
        )
        .arg(
            Arg::with_name("ticks_per_slot")
                .long("ticks-per-slot")
                .value_name("TICKS")
                .takes_value(true)
                .default_value(default_ticks_per_slot)
                .help("The number of ticks in a slot"),
        )
        .arg(
            Arg::with_name("slots_per_epoch")
                .long("slots-per-epoch")
                .value_name("SLOTS")
                .validator(is_slot)
                .takes_value(true)
                .help("The number of slots in an epoch"),
        ) 
        .arg(
            Arg::with_name("enable_warmup_epochs")
                .long("enable-warmup-epochs")
                .help(
                    "When enabled epochs start short and will grow. \
                     Useful for warming up stake quickly during development"
                ),
        )
        .arg(
            Arg::with_name("primordial_accounts_file")
                .long("primordial-accounts-file")
                .value_name("FILENAME")
                .takes_value(true)
                .multiple(true)
                .help("The location of pubkey for primordial accounts and balance"),
                
        )
        .arg(
            Arg::with_name("cluster_type")  
                .long("cluster-type")
                .possible_values(&ClusterType::STRINGS)
                .takes_value(true)
                .default_value(default_cluster_type)
                .help(
                    "Selects the features that will be enabled for the cluster"
                ),
        )
        .arg(
            Arg::with_name("max_genesis_archive_unpacked_size")
                .long("max-genesis-archive-unpacked-size")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value(&default_genesis_archive_unpacked_size)
                .help(
                    "maximum total uncompressed file size of created genesis archive",
                ),
        )
        .arg(
            Arg::with_name("bpf_program")
                .long("bpf-program")
                .value_name("ADDRESS BPF_PROGRAM.SO")
                .takes_value(true)
                .number_of_values(3)
                .multiple(true)
                .help("Install a BPF program at the given address"),
        )      
        .arg(
            Arg::with_name("inflation")
                .required(false)
                .long("inflation")
                .takes_value(true)
                .possible_values(&["pico", "full", "none"])
                .help("Selects inflation"),
        );
        
    let matches = if cfg!(feature = "with_evm") {
        app.arg(
            Arg::with_name("evm-root")
                .long("evm-root")
                .takes_value(true)
                .help("Root hash for evm state snapshot, Used to verify snapshot integrity."),
        ).arg(
            Arg::with_name("evm-state-file")
                .long("evm-state-file")
                .takes_value(true)
                .help("Path to EVM state json file, can be retrived from `parity export state` command."),
        ).arg(
            Arg::with_name("evm-chain-id")
                .required(false)
                .long("evm-chain-id")
                .takes_value(true)
                .help("EVM chain id"),
        )

    } else {
        app
    }
    .get_matches();

    sino_logger::setup_with("info");

    let ledger_path = PathBuf::from(matches.value_of("ledger_path").unwrap());

    let rent = Rent {
        lamports_per_byte_year: value_t_or_exit!(matches, "lamports_per_byte_year", u64),
        exemption_threshold: value_t_or_exit!(matches, "rent_exemption_threshold", f64),
        burn_percent: value_t_or_exit!(matches, "rent_burn_percentage", u8),
    };

    fn rent_exempt_check(matches: &ArgMatches<'_>, name: &str, exempt: u64) -> io::Result<u64> {
        let lamports = value_t_or_exit!(matches, name, u64);

        if lamports < exempt {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "error: insufficient {}: {} for rent exemption, requires {}",
                    name, lamports, exempt
                ),
            ))
        } else {
            Ok(lamports)
        }
    }

    let bootstrap_validator_pubkeys = pubkeys_of(&matches, "bootstrap_validator").unwrap();
    assert_eq!(bootstrap_validator_pubkeys.len() % 3, 0);

    // Ensure there are no duplicated pubkeys in the --bootstrap-validator list
    {
        let mut v = bootstrap_validator_pubkeys.clone();
        v.sort();
        v.dedup();
        if v.len() != bootstrap_validator_pubkeys.len() {
            error!("Error: --bootstrap-validator pubkeys cannot be duplicated");
            process::exit(1);
        }
    }

    let bootstrap_validator_lamports =
        value_t_or_exit!(matches, "bootstrap_validator_lamports", u64);

    let bootstrap_validator_stake_lamports =
        value_t_or_exit!(matches, "bootstrap_validator_stake_lamports", u64);
    rent_exempt_check(
        &matches,
        "bootstrap_validator_stake_lamports",
        bootstrap_validator_stake_lamports,
    )?;

    let bootstrap_stake_authorized_pubkey =
        pubkey_of(&matches, "bootstrap_stake_authorized_pubkey");
    let faucet_lamports = value_t!(matches, "faucet_lamports", u64).unwrap_or(0);
    let faucet_pubkey = pubkey_of(&matches, "faucet_pubkey");

    let ticks_per_slot = value_t_or_exit!(matches, "ticks_per_slot", u64);

    let mut fee_rate_governor = FeeRateGovernor::new(
        value_t_or_exit!(matches, "target_lamports_per_signature", u64),
        value_t_or_exit!(matches, "target_signatures_per_slot", u64),
    );
    fee_rate_governor.burn_percent = value_t_or_exit!(matches, "fee_burn_percentage", u8);

    let mut poh_config = PohConfig {
        target_tick_duration: if matches.is_present("target_tick_duration") {
            Duration::from_micros(value_t_or_exit!(matches, "target_tick_duration", u64))
        } else {
            Duration::from_micros(default_target_tick_duration)
        },
        ..PohConfig::default()
    };

    let cluster_type = cluster_type_of(&matches, "cluster_type").unwrap();

    match matches.value_of("hashes_per_tick").unwrap() {
        "auto" => match cluster_type {
            ClusterType::Development => {
                let hashes_per_tick =
                    compute_hashes_per_tick(poh_config.target_tick_duration, 1_000_000);
                poh_config.hashes_per_tick = Some(hashes_per_tick / 2); // use 50% of peak ability
            }
            ClusterType::Devnet | ClusterType::Testnet | ClusterType::MainnetBeta => {
                poh_config.hashes_per_tick = Some(clock::DEFAULT_HASHES_PER_TICK);
            }
        },
        "sleep" => {
            poh_config.hashes_per_tick = None;
        }
        _ => {
            poh_config.hashes_per_tick = Some(value_t_or_exit!(matches, "hashes_per_tick", u64));
        }
    }

    let slots_per_epoch = if matches.value_of("slots_per_epoch").is_some() {
        value_t_or_exit!(matches, "slots_per_epoch", u64)
    } else {
        match cluster_type {
            ClusterType::Development => clock::DEFAULT_DEV_SLOTS_PER_EPOCH,
            ClusterType::Devnet | ClusterType::Testnet | ClusterType::MainnetBeta => {
                clock::DEFAULT_SLOTS_PER_EPOCH
            }
        }
    };
    let epoch_schedule = EpochSchedule::custom(
        slots_per_epoch,
        slots_per_epoch,
        matches.is_present("enable_warmup_epochs"),
    );

    let evm_chain_id = if matches.value_of("evm-chain-id").is_some() {
        value_t_or_exit!(matches, "evm-chain-id", u64)
    } else {
        match cluster_type {
            ClusterType::MainnetBeta => genesis_config::EVM_MAINNET_CHAIN_ID,
            ClusterType::Testnet => genesis_config::EVM_TESTNET_CHAIN_ID,
            ClusterType::Devnet | ClusterType::Development => genesis_config::EVM_DEVELOP_CHAIN_ID,
        }
    };

    // 创建 genesis config
    let mut genesis_config = GenesisConfig {
        native_instruction_processors: vec![],
        ticks_per_slot,
        poh_config,
        fee_rate_governor,
        rent,
        epoch_schedule,
        cluster_type,
        evm_chain_id,
        ..GenesisConfig::default()
    };

    // ----------------------- evm 根 ----------------------------------
    // 将evm根hash配置到evm config中
    if cfg!(feature = "with_evm") {
        let root = value_t!(matches, "evm-root", String);
        match root {
            Ok(root) => {
                let root_hash = evm_rpc::Hex::<evm_state::H256>::from_hex(&root).unwrap(); // 取 evm 根 hash
                genesis_config.set_evm_root_hash(root_hash.0)  // 将 evm 根 hash 配置到 genesis config 中
            }
            Err(e) => {
                error!(
                    "EVM root was not found but genesis was compiled with `with_evm` feature {}",
                    e
                );
            }
        }
    }

    // ------------------genesis json----------------------------
    // 从命令参数中获取 evm-state-file 和 evm-state-format
    // 其中 evm-state-file 代表路径 evm-state-format 代表客户端类型
    // 通过 evm-state-file 和  evm-state-format 配置evm state json
    let evm_state_file = matches.value_of("evm-state-file");
    let evm_state_format = matches.value_of("evm-state-format");
    let evm_state_json = match (evm_state_file, evm_state_format) {
        (Some(path), Some(format)) if format == "geth" => {
            EvmStateJson::Geth(std::path::Path::new(path))
        },
        (Some(path), Some(format)) if format == "open-ethereum" => {
            EvmStateJson::OpenEthereum(std::path::Path::new(path))
        },
        (None, _) => {
            EvmStateJson::None
        },
        _ => {
            panic!("`evm-state-format` argument value must be `open-ethereum` or `geth`")
        }
    };

    // ------------------- 通货膨胀 ------------------------------
    if let Ok(raw_inflation) = value_t!(matches, "inflation", String) {
        let inflation = match raw_inflation.as_str() {
            "pico" => Inflation::pico(),
            "full" => Inflation::full(),
            "none" => Inflation::new_disabled(),
            _ => unreachable!(),
        };
        genesis_config.inflation = inflation;
    }

    // ------------------ commission ----------------------------
    let commission = value_t_or_exit!(matches, "vote_commission_percentage", u8);

    // ------------------- 创建账户 -------------------
    let mut bootstrap_validator_pubkeys_iter = bootstrap_validator_pubkeys.iter();
    loop {
        let identity_pubkey = match bootstrap_validator_pubkeys_iter.next() {
            None => break,
            Some(identity_pubkey) => identity_pubkey,
        };
        let vote_pubkey = bootstrap_validator_pubkeys_iter.next().unwrap();
        let stake_pubkey = bootstrap_validator_pubkeys_iter.next().unwrap();

        genesis_config.add_account(
            *identity_pubkey,
            AccountSharedData::new(bootstrap_validator_lamports, 0, &system_program::id()),
        );

        let vote_account = vote_state::create_account_with_authorized(
            identity_pubkey,
            identity_pubkey,
            identity_pubkey,
            commission,
            VoteState::get_rent_exempt_reserve(&rent).max(1),
        );

        genesis_config.add_account(
            *stake_pubkey,
            stake_state::create_account(
                bootstrap_stake_authorized_pubkey
                    .as_ref()
                    .unwrap_or(identity_pubkey),
                vote_pubkey,
                &vote_account,
                &rent,
                bootstrap_validator_stake_lamports,
            ),
        );

        genesis_config.add_account(*vote_pubkey, vote_account);
    }

    // --------------------------- 创建时间 ----------------------------
    if let Some(creation_time) = unix_timestamp_from_rfc3339_datetime(&matches, "creation_time") {
        genesis_config.creation_time = creation_time;
    }

    // --------------------------- 水龙头 ----------------------------
    if let Some(faucet_pubkey) = faucet_pubkey {
        genesis_config.add_account(
            faucet_pubkey,
            AccountSharedData::new(faucet_lamports, 0, &system_program::id()),
        );
    }

    // ------------------------- 质押合约 --------------------------
    stake_program::add_genesis_accounts(&mut genesis_config);

    // ------------------------ 集群类型 --------------------------
    // dev 激活所有功能，其他情况激活部分功能
    if matches!(
        genesis_config.cluster_type,
        ClusterType::Development | ClusterType::Devnet
    ) {
        runtime::genesis_utils::activate_all_features(&mut genesis_config);
    } else {
        runtime::genesis_utils::activate_velas_features_on_prod(&mut genesis_config);
    }

    // ----------------- 从原始账户中获取账户信息 ----------------------
    if let Some(files) = matches.values_of("primordial_accounts_file") {
        for file in files {
            load_genesis_accounts(file, &mut genesis_config)?;
        }
    }

    // ------------------- 最大创世纪档案解压大小 ---------------------
    let max_genesis_archive_unpacked_size =
        value_t_or_exit!(matches, "max_genesis_archive_unpacked_size", u64);

    // -------------------- evm 状态余额 ----------------------
    // evm两种客户端转储文件中读取的账户余额添加到evm state余额，并将Gwei转lamport
    let mut evm_state_balance = U256::zero();

    match evm_state_json {
        EvmStateJson::OpenEthereum(path) => {
            info!("Calculating evm state lamports");
            let dump_extractor = OpenEthereumAccountExtractor::open_dump(path)
                .unwrap_or_else(|_| {
                    panic!(
                        "Unable to open dump at path: `{}`",
                        path.display()
                    )
                });
    
            for pair in dump_extractor {
                evm_state_balance += pair.unwrap().account.balance;
            }
        },
        EvmStateJson::Geth(path) => {
            info!("Calculating evm state lamports");
            let dump_extractor = GethAccountExtractor::open_dump(path)
                .unwrap_or_else(|_| {
                    panic!(
                        "Unable to open dump at path: `{}`",
                        path.display()
                    )
                });
    
            for pair in dump_extractor {
                evm_state_balance += pair.unwrap().account.balance;
            }
        },
        EvmStateJson::None => {
            info!("No evm state file provided");
        },
    }

    let (mut evm_state_lamports, change) =
        evm_loader_program::scope::evm::gweis_to_wens(evm_state_balance);
    if change != U256::zero() {
        evm_state_lamports += 1;
    }

    // 将state账户添加到genesis config中
    genesis_config.add_account(
        sdk::evm_state::ID,
        evm_loader_program::create_state_account(evm_state_lamports),
    );

    let issued_lamports = genesis_config
        .accounts
        .values()
        .map(|account| account.lamports)
        .sum::<u64>();

    info!(
        "Total issued lamports = {}, for faucet/bridge = {}, for evm = {}",
        issued_lamports, faucet_lamports, evm_state_lamports
    );

    // TODO: add_genesis_accounts for evm.
    // add_genesis_accounts(&mut genesis_config, issued_lamports - faucet_lamports);
    // -------------------- bpf 合约中账户添加到genesis config中---------------------
    if let Some(values) = matches.values_of("bpf_program") {
        let values: Vec<&str> = values.collect::<Vec<_>>();
        for address_loader_program in values.chunks(3) {
            match address_loader_program {
                [address, loader, program] => {
                    let address = address.parse::<Pubkey>().unwrap_or_else(|err| {
                        eprintln!("Error: invalid address {}: {}", address, err);
                        process::exit(1);
                    });

                    let loader = loader.parse::<Pubkey>().unwrap_or_else(|err| {
                        eprintln!("Error: invalid loader {}: {}", loader, err);
                        process::exit(1);
                    });

                    let mut program_data = vec![];
                    File::open(program)
                        .and_then(|mut file| file.read_to_end(&mut program_data))
                        .unwrap_or_else(|err| {
                            eprintln!("Error: failed to read {}: {}", program, err);
                            process::exit(1);
                        });
                    genesis_config.add_account(
                        address,
                        AccountSharedData::from(Account {
                            lamports: genesis_config.rent.minimum_balance(program_data.len()),
                            data: program_data,
                            executable: true,
                            owner: loader,
                            rent_epoch: 0,
                        }),
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    create_new_ledger(
        &ledger_path,
        evm_state_json,
        &genesis_config,
        max_genesis_archive_unpacked_size,
        AccessType::PrimaryOnly,
    )?;

    println!("{}", genesis_config);
    Ok(())
}

