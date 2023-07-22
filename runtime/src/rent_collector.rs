//! calculate and collect rent from Accounts
use sdk::{
    account::{AccountSharedData, ReadableAccount, WritableAccount},
    clock::Epoch,
    epoch_schedule::EpochSchedule,
    genesis_config::GenesisConfig,
    incinerator,
    pubkey::Pubkey,
    rent::{Rent, RentDue},
    sysvar,
};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, AbiExample)]
pub struct RentCollector {
    pub epoch: Epoch,
    pub epoch_schedule: EpochSchedule,
    pub slots_per_year: f64,
    pub rent: Rent,
}

impl Default for RentCollector {
    fn default() -> Self {
        Self {
            epoch: Epoch::default(),
            epoch_schedule: EpochSchedule::default(),
            // derive default value using GenesisConfig::default()
            slots_per_year: GenesisConfig::default().slots_per_year(),
            rent: Rent::default(),
        }
    }
}

impl RentCollector {
     /// Performs easy checks to see if rent collection can be skipped
     fn can_skip_rent_collection(
        &self,
        address: &Pubkey,
        account: &mut AccountSharedData,
        rent_for_sysvars: bool,
        filler_account_suffix: Option<&Pubkey>,
    ) -> bool {
        !self.should_collect_rent(address, account, rent_for_sysvars)
            || account.rent_epoch() > self.epoch
            || crate::accounts_db::AccountsDb::is_filler_account_helper(
                address,
                filler_account_suffix,
            )
    }

    /// true if it is easy to determine this account should consider having rent collected from it
    pub fn should_collect_rent(
        &self,
        address: &Pubkey,
        account: &impl ReadableAccount,
        rent_for_sysvars: bool,
    ) -> bool {
        !(account.executable() // executable accounts must be rent-exempt balance
            || (!rent_for_sysvars && sysvar::check_id(account.owner()))
            || *address == incinerator::id()
            || *address == sdk::evm_state::id())
    }

    /// given an account that 'should_collect_rent'
    /// returns (amount rent due, is_exempt_from_rent)
    pub fn get_rent_due(&self, account: &impl ReadableAccount) -> RentDue {
        let slots_elapsed: u64 = (account.rent_epoch()..=self.epoch)
            .map(|epoch| self.epoch_schedule.get_slots_in_epoch(epoch + 1))
            .sum();

        // avoid infinite rent in rust 1.45
        let years_elapsed = if self.slots_per_year != 0.0 {
            slots_elapsed as f64 / self.slots_per_year
        } else {
            0.0
        };

        self.rent
            .due(account.wens(), account.data().len(), years_elapsed)
    }

    // Updates the account's lamports and status, and returns the amount of rent collected, if any.
    // This is NOT thread safe at some level. If we try to collect from the same account in
    // parallel, we may collect twice.
    #[must_use = "add to Bank::collected_rent"]
    pub fn collect_from_existing_account(
        &self,
        address: &Pubkey,
        account: &mut AccountSharedData,
        rent_for_sysvars: bool,
        filler_account_suffix: Option<&Pubkey>,
    ) -> CollectedInfo {
        if self.can_skip_rent_collection(address, account, rent_for_sysvars, filler_account_suffix)
        {
            return CollectedInfo::default();
        }

        let rent_due = self.get_rent_due(account);
        if let RentDue::Paying(0) = rent_due {
            // maybe collect rent later, leave account alone
            return CollectedInfo::default();
        }

        let epoch_increment = match rent_due {
            // Rent isn't collected for the next epoch
            // Make sure to check exempt status again later in current epoch
            RentDue::Exempt => 0,
            // Rent is collected for next epoch
            RentDue::Paying(_) => 1,
        };
        account.set_rent_epoch(self.epoch + epoch_increment);

        let begin_lamports = account.wens();
        account.saturating_sub_lamports(rent_due.lamports());
        let end_lamports = account.wens();

        let mut account_data_len_reclaimed = 0;
        if end_lamports == 0 {
            account_data_len_reclaimed = account.data().len() as u64;
            *account = AccountSharedData::default();
        }

        CollectedInfo {
            rent_amount: begin_lamports - end_lamports,
            account_data_len_reclaimed,
        }
    }

    pub fn clone_with_epoch(&self, epoch: Epoch) -> Self {
        Self {
            epoch,
            ..self.clone()
        }
    }

    pub fn new(
        epoch: Epoch,
        epoch_schedule: &EpochSchedule,
        slots_per_year: f64,
        rent: &Rent,
    ) -> Self {
        Self {
            epoch,
            epoch_schedule: *epoch_schedule,
            slots_per_year,
            rent: *rent,
        }
    }

}

/// Information computed during rent collection
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct CollectedInfo {
    /// Amount of rent collected from account
    pub rent_amount: u64,
    /// Size of data reclaimed from account (happens when account's lamports go to zero)
    pub account_data_len_reclaimed: u64,
}

impl std::ops::Add for CollectedInfo {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self {
            rent_amount: self.rent_amount + other.rent_amount,
            account_data_len_reclaimed: self.account_data_len_reclaimed
                + other.account_data_len_reclaimed,
        }
    }
}

impl std::ops::AddAssign for CollectedInfo {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

