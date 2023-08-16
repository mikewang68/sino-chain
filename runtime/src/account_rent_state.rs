use {
    log::*,
    sdk::{
        account::{AccountSharedData, ReadableAccount},
        pubkey::Pubkey,
        rent::Rent,
        transaction::{Result, TransactionError},
    },
};

#[derive(Debug, PartialEq)]
pub(crate) enum RentState {
    /// account.wens == 0
    Uninitialized,
    /// 0 < account.wens < rent-exempt-minimum
    /// Parameter is the size of the account data
    RentPaying(usize),
    /// account.wens >= rent-exempt-minimum
    RentExempt,
}

impl RentState {
    pub(crate) fn from_account(account: &AccountSharedData, rent: &Rent) -> Self {
        if account.wens() == 0 {
            Self::Uninitialized
        } else if !rent.is_exempt(account.wens(), account.data().len()) {
            Self::RentPaying(account.data().len())
        } else {
            Self::RentExempt
        }
    }

    pub(crate) fn transition_allowed_from(
        &self,
        pre_rent_state: &RentState,
        do_support_realloc: bool,
    ) -> bool {
        if let Self::RentPaying(post_data_size) = self {
            if let Self::RentPaying(pre_data_size) = pre_rent_state {
                if do_support_realloc {
                    post_data_size == pre_data_size // Cannot be RentPaying if resized
                } else {
                    true // RentPaying can continue to be RentPaying
                }
            } else {
                false // Only RentPaying can continue to be RentPaying
            }
        } else {
            true // Post not-RentPaying always ok
        }
    }
}

pub(crate) fn submit_rent_state_metrics(pre_rent_state: &RentState, post_rent_state: &RentState) {
    match (pre_rent_state, post_rent_state) {
        (&RentState::Uninitialized, &RentState::RentPaying(_)) => {
            inc_new_counter_info!("rent_paying_err-new_account", 1);
        }
        (&RentState::RentPaying(_), &RentState::RentPaying(_)) => {
            inc_new_counter_info!("rent_paying_ok-legacy", 1);
        }
        (_, &RentState::RentPaying(_)) => {
            inc_new_counter_info!("rent_paying_err-other", 1);
        }
        _ => {}
    }
}

pub(crate) fn check_rent_state(
    pre_rent_state: Option<&RentState>,
    post_rent_state: Option<&RentState>,
    address: &Pubkey,
    account: &AccountSharedData,
    do_support_realloc: bool,
) -> Result<()> {
    if let Some((pre_rent_state, post_rent_state)) = pre_rent_state.zip(post_rent_state) {
        submit_rent_state_metrics(pre_rent_state, post_rent_state);
        if !sdk::incinerator::check_id(address)
            && !post_rent_state.transition_allowed_from(pre_rent_state, do_support_realloc)
        {
            debug!("Account {:?} not rent exempt, state {:?}", address, account);
            return Err(TransactionError::InvalidRentPayingAccount);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {super::*, sdk::pubkey::Pubkey};

    #[test]
    fn test_from_account() {
        let program_id = Pubkey::new_unique();
        let uninitialized_account = AccountSharedData::new(0, 0, &Pubkey::default());

        let account_data_size = 100;

        let rent = Rent::free();
        let rent_exempt_account = AccountSharedData::new(1, account_data_size, &program_id); // if rent is free, all accounts with non-zero wens and non-empty data are rent-exempt

        assert_eq!(
            RentState::from_account(&uninitialized_account, &rent),
            RentState::Uninitialized
        );
        assert_eq!(
            RentState::from_account(&rent_exempt_account, &rent),
            RentState::RentExempt
        );

        let rent = Rent::default();
        let rent_minimum_balance = rent.minimum_balance(account_data_size);
        let rent_paying_account = AccountSharedData::new(
            rent_minimum_balance.saturating_sub(1),
            account_data_size,
            &program_id,
        );
        let rent_exempt_account = AccountSharedData::new(
            rent.minimum_balance(account_data_size),
            account_data_size,
            &program_id,
        );

        assert_eq!(
            RentState::from_account(&uninitialized_account, &rent),
            RentState::Uninitialized
        );
        assert_eq!(
            RentState::from_account(&rent_paying_account, &rent),
            RentState::RentPaying(account_data_size)
        );
        assert_eq!(
            RentState::from_account(&rent_exempt_account, &rent),
            RentState::RentExempt
        );
    }

    #[test]
    fn test_transition_allowed_from() {
        let post_rent_state = RentState::Uninitialized;
        assert!(post_rent_state.transition_allowed_from(&RentState::Uninitialized, true));
        assert!(post_rent_state.transition_allowed_from(&RentState::RentExempt, true));
        assert!(post_rent_state.transition_allowed_from(&RentState::RentPaying(0), true));

        let post_rent_state = RentState::RentExempt;
        assert!(post_rent_state.transition_allowed_from(&RentState::Uninitialized, true));
        assert!(post_rent_state.transition_allowed_from(&RentState::RentExempt, true));
        assert!(post_rent_state.transition_allowed_from(&RentState::RentPaying(0), true));

        let post_rent_state = RentState::RentPaying(2);
        assert!(!post_rent_state.transition_allowed_from(&RentState::Uninitialized, true));
        assert!(!post_rent_state.transition_allowed_from(&RentState::RentExempt, true));
        assert!(!post_rent_state.transition_allowed_from(&RentState::RentPaying(3), true));
        assert!(!post_rent_state.transition_allowed_from(&RentState::RentPaying(1), true));
        assert!(post_rent_state.transition_allowed_from(&RentState::RentPaying(2), true));
    }
}
