//! Stakes serve as a cache of stake and vote accounts to derive
//! node stakes
use {
    crate::{
        stake_delegations::StakeDelegations,
        stake_history::StakeHistory,
        vote_account::{VoteAccount, VoteAccounts, VoteAccountsHashMap},
    },
    sdk::{
        account::{AccountSharedData, ReadableAccount},
        clock::{Epoch},
        pubkey::Pubkey,
        stake::{
            // self,
            state::{Delegation, /*StakeActivationStatus, StakeState*/},
        },
    },
    std::{
        collections::HashMap,
        sync::{Arc, RwLock, RwLockReadGuard},
    },
    stake_program::stake_state,
    vote_program::vote_state::VoteState,
};


#[derive(Default, Clone, PartialEq, Debug, Deserialize, Serialize, AbiExample)]
pub struct Stakes {
    /// vote accounts
    vote_accounts: VoteAccounts,

    /// stake_delegations
    stake_delegations: StakeDelegations,

    /// unused
    unused: u64,

    /// current epoch, used to calculate current stake
    epoch: Epoch,

    /// history of staking levels
    stake_history: StakeHistory,
}

impl Stakes {
    pub fn history(&self) -> &StakeHistory {
        &self.stake_history
    }

    pub fn update_stake_delegation(
        &mut self,
        stake_pubkey: &Pubkey,
        new_delegation: Option<(u64, Delegation)>,
        remove_delegation: bool,
    ) {
        //  old_stake is stake lamports and voter_pubkey from the pre-store() version
        let old_stake = self.stake_delegations.get(stake_pubkey).map(|delegation| {
            (
                delegation.voter_pubkey,
                delegation.stake(self.epoch, Some(&self.stake_history)),
            )
        });

        let new_stake = new_delegation.map(|(stake, delegation)| (delegation.voter_pubkey, stake));

        // check if adjustments need to be made...
        if new_stake != old_stake {
            if let Some((voter_pubkey, stake)) = old_stake {
                self.vote_accounts.sub_stake(&voter_pubkey, stake);
            }
            if let Some((voter_pubkey, stake)) = new_stake {
                self.vote_accounts.add_stake(&voter_pubkey, stake);
            }
        }

        if remove_delegation {
            // when account is removed (lamports == 0), remove it from Stakes as well
            // so that given `pubkey` can be used for any owner in the future, while not
            // affecting Stakes.
            self.stake_delegations.remove(stake_pubkey);
        } else if let Some((_stake, delegation)) = new_delegation {
            self.stake_delegations.insert(*stake_pubkey, delegation);
        }
    }

    /// Sum the stakes that point to the given voter_pubkey
    fn calculate_stake(
        &self,
        voter_pubkey: &Pubkey,
        epoch: Epoch,
        stake_history: &StakeHistory,
    ) -> u64 {
        let matches_voter_pubkey = |(_, stake_delegation): &(&_, &Delegation)| {
            &stake_delegation.voter_pubkey == voter_pubkey
        };
        let get_stake = |(_, stake_delegation): (_, &Delegation)| {
            stake_delegation.stake(epoch, Some(stake_history))
        };

        self.stake_delegations
            .iter()
            .filter(matches_voter_pubkey)
            .map(get_stake)
            .sum()
    }

    pub fn update_vote_account(
        &mut self,
        vote_pubkey: &Pubkey,
        new_vote_account: Option<VoteAccount>,
    ) {
        // unconditionally remove existing at first; there is no dependent calculated state for
        // votes, not like stakes (stake codepath maintains calculated stake value grouped by
        // delegated vote pubkey)
        let old_entry = self.vote_accounts.remove(vote_pubkey);
        if let Some(new_vote_account) = new_vote_account {
            debug_assert!(new_vote_account.is_deserialized());
            let new_stake = old_entry.as_ref().map_or_else(
                || self.calculate_stake(vote_pubkey, self.epoch, &self.stake_history),
                |(old_stake, _old_vote_account)| *old_stake,
            );

            self.vote_accounts
                .insert(*vote_pubkey, (new_stake, new_vote_account));
        }
    }

    pub fn vote_accounts(&self) -> &VoteAccounts {
        &self.vote_accounts
    }

    pub fn staked_nodes(&self) -> Arc<HashMap<Pubkey, u64>> {
        self.vote_accounts.staked_nodes()
    }
}


#[derive(Default, Debug, Deserialize, Serialize, AbiExample)]
pub struct StakesCache(RwLock<Stakes>);

impl StakesCache {
    pub fn new(stakes: Stakes) -> Self {
        Self(RwLock::new(stakes))
    }

    pub fn check_and_store(
        &self,
        pubkey: &Pubkey,
        account: &AccountSharedData,
        remove_delegation_on_inactive: bool,
    ) {
        if vote_program::check_id(account.owner()) {
            let new_vote_account = if account.wens() != 0
                && VoteState::is_correct_size_and_initialized(account.data())
            {
                let vote_account = VoteAccount::from(account.clone());
                {
                    // Called to eagerly deserialize vote state
                    let _res = vote_account.vote_state();
                }
                Some(vote_account)
            } else {
                None
            };

            self.0
                .write()
                .unwrap()
                .update_vote_account(pubkey, new_vote_account);
        } else if stake_program::check_id(account.owner()) {
            let new_delegation = stake_state::delegation_from(account).map(|delegation| {
                let stakes = self.stakes();
                let stake = if account.wens() != 0 {
                    delegation.stake(stakes.epoch, Some(&stakes.stake_history))
                } else {
                    // when account is removed (lamports == 0), this special `else` clause ensures
                    // resetting cached stake value below, even if the account happens to be
                    // still staked for some (odd) reason
                    0
                };
                (stake, delegation)
            });

            let remove_delegation = if remove_delegation_on_inactive {
                new_delegation.is_none()
            } else {
                account.wens() == 0
            };

            self.0.write().unwrap().update_stake_delegation(
                pubkey,
                new_delegation,
                remove_delegation,
            );
        }
    }

    pub fn stakes(&self) -> RwLockReadGuard<Stakes> {
        self.0.read().unwrap()
    }
}