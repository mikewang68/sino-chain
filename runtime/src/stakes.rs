//! Stakes serve as a cache of stake and vote accounts to derive
//! node stakes
use {
    crate::{
        stake_delegations::StakeDelegations,
        stake_history::StakeHistory,
        vote_account::{VoteAccounts},
    },
    sdk::{
        clock::{Epoch},
    },
    std::{
        sync::{RwLock},
    },
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
    pub fn vote_accounts(&self) -> &VoteAccounts {
        &self.vote_accounts
    }
}


#[derive(Default, Debug, Deserialize, Serialize, AbiExample)]
pub struct StakesCache(RwLock<Stakes>);