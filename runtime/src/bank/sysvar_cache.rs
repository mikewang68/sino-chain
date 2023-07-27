use {
    super::Bank,
    program_runtime::sysvar_cache::SysvarCache,
    sdk::{account::ReadableAccount, sysvar::Sysvar},
};

impl Bank {
    pub(crate) fn fill_missing_sysvar_cache_entries(&self) {
        let mut sysvar_cache = self.sysvar_cache.write().unwrap();
        if sysvar_cache.get_clock().is_err() {
            if let Some(clock) = self.load_sysvar_account() {
                sysvar_cache.set_clock(clock);
            }
        }
        if sysvar_cache.get_epoch_schedule().is_err() {
            if let Some(epoch_schedule) = self.load_sysvar_account() {
                sysvar_cache.set_epoch_schedule(epoch_schedule);
            }
        }
        #[allow(deprecated)]
        if sysvar_cache.get_fees().is_err() {
            if let Some(fees) = self.load_sysvar_account() {
                sysvar_cache.set_fees(fees);
            }
        }
        if sysvar_cache.get_rent().is_err() {
            if let Some(rent) = self.load_sysvar_account() {
                sysvar_cache.set_rent(rent);
            }
        }
        if sysvar_cache.get_slot_hashes().is_err() {
            if let Some(slot_hashes) = self.load_sysvar_account() {
                sysvar_cache.set_slot_hashes(slot_hashes);
            }
        }
    }

    pub(crate) fn reset_sysvar_cache(&self) {
        let mut sysvar_cache = self.sysvar_cache.write().unwrap();
        *sysvar_cache = SysvarCache::default();
    }

    fn load_sysvar_account<T: Sysvar>(&self) -> Option<T> {
        if let Some(account) = self.get_account_with_fixed_root(&T::id()) {
            bincode::deserialize(account.data()).ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        sdk::{genesis_config::create_genesis_config, pubkey::Pubkey},
        std::sync::Arc,
    };

    #[test]
    #[allow(deprecated)]
    fn test_sysvar_cache_initialization() {
        let (genesis_config, _mint_keypair) = create_genesis_config(100_000);
        let bank0 = Arc::new(Bank::new_for_tests(&genesis_config));

        let bank0_sysvar_cache = bank0.sysvar_cache.read().unwrap();
        let bank0_cached_clock = bank0_sysvar_cache.get_clock();
        let bank0_cached_epoch_schedule = bank0_sysvar_cache.get_epoch_schedule();
        let bank0_cached_fees = bank0_sysvar_cache.get_fees();
        let bank0_cached_rent = bank0_sysvar_cache.get_rent();

        assert!(bank0_cached_clock.is_ok());
        assert!(bank0_cached_epoch_schedule.is_ok());
        assert!(bank0_cached_fees.is_ok());
        assert!(bank0_cached_rent.is_ok());
        assert!(bank0
            .sysvar_cache
            .read()
            .unwrap()
            .get_slot_hashes()
            .is_err());

        let bank1 = Bank::new_from_parent(&bank0, &Pubkey::default(), bank0.slot() + 1);

        let bank1_sysvar_cache = bank1.sysvar_cache.read().unwrap();
        let bank1_cached_clock = bank1_sysvar_cache.get_clock();
        let bank1_cached_epoch_schedule = bank0_sysvar_cache.get_epoch_schedule();
        let bank1_cached_fees = bank0_sysvar_cache.get_fees();
        let bank1_cached_rent = bank0_sysvar_cache.get_rent();

        assert!(bank1_cached_clock.is_ok());
        assert!(bank1_cached_epoch_schedule.is_ok());
        assert!(bank1_cached_fees.is_ok());
        assert!(bank1_cached_rent.is_ok());
        assert!(bank1.sysvar_cache.read().unwrap().get_slot_hashes().is_ok());

        assert_ne!(bank0_cached_clock, bank1_cached_clock);
        assert_eq!(bank0_cached_epoch_schedule, bank1_cached_epoch_schedule);
        assert_eq!(bank0_cached_fees, bank1_cached_fees);
        assert_eq!(bank0_cached_rent, bank1_cached_rent);
    }

    #[test]
    #[allow(deprecated)]
    fn test_reset_and_fill_sysvar_cache() {
        let (genesis_config, _mint_keypair) = create_genesis_config(100_000);
        let bank0 = Arc::new(Bank::new_for_tests(&genesis_config));
        let bank1 = Bank::new_from_parent(&bank0, &Pubkey::default(), bank0.slot() + 1);

        let bank1_sysvar_cache = bank1.sysvar_cache.read().unwrap();
        let bank1_cached_clock = bank1_sysvar_cache.get_clock();
        let bank1_cached_epoch_schedule = bank1_sysvar_cache.get_epoch_schedule();
        let bank1_cached_fees = bank1_sysvar_cache.get_fees();
        let bank1_cached_rent = bank1_sysvar_cache.get_rent();
        let bank1_cached_slot_hashes = bank1_sysvar_cache.get_slot_hashes();

        assert!(bank1_cached_clock.is_ok());
        assert!(bank1_cached_epoch_schedule.is_ok());
        assert!(bank1_cached_fees.is_ok());
        assert!(bank1_cached_rent.is_ok());
        assert!(bank1_cached_slot_hashes.is_ok());

        drop(bank1_sysvar_cache);
        bank1.reset_sysvar_cache();

        let bank1_sysvar_cache = bank1.sysvar_cache.read().unwrap();
        assert!(bank1_sysvar_cache.get_clock().is_err());
        assert!(bank1_sysvar_cache.get_epoch_schedule().is_err());
        assert!(bank1_sysvar_cache.get_fees().is_err());
        assert!(bank1_sysvar_cache.get_rent().is_err());
        assert!(bank1_sysvar_cache.get_slot_hashes().is_err());

        drop(bank1_sysvar_cache);
        bank1.fill_missing_sysvar_cache_entries();

        let bank1_sysvar_cache = bank1.sysvar_cache.read().unwrap();
        assert_eq!(bank1_sysvar_cache.get_clock(), bank1_cached_clock);
        assert_eq!(
            bank1_sysvar_cache.get_epoch_schedule(),
            bank1_cached_epoch_schedule
        );
        assert_eq!(bank1_sysvar_cache.get_fees(), bank1_cached_fees);
        assert_eq!(bank1_sysvar_cache.get_rent(), bank1_cached_rent);
        assert_eq!(
            bank1_sysvar_cache.get_slot_hashes(),
            bank1_cached_slot_hashes
        );
    }
}
