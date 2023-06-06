use vote_program::vote_state::Vote;

use {
    itertools::Itertools,
    serde::{
        ser::{Serialize,Serializer},
        de::{Deserialize, Deserializer},
    },
    sdk::{
        account::{Account},
        instruction::InstructionError,
        pubkey::Pubkey,
    },
    vote_program::vote_state::VoteState,
    std::{
        collections::{HashMap},
        sync::{Arc, Once, RwLock,RwLockReadGuard},
    },
};

// The value here does not matter. It will be overwritten
// at the first call to VoteAccount::vote_state().
const INVALID_VOTE_STATE: Result<VoteState, InstructionError> =
    Err(InstructionError::InvalidAccountData);

#[derive(Clone, Debug, Default, PartialEq, AbiExample)]
pub struct VoteAccount(Arc<VoteAccountInner>);

impl VoteAccount {
    pub fn vote_state(&self) -> RwLockReadGuard<Result<VoteState, InstructionError>> {
        let inner = &self.0;
        inner.vote_state_once.call_once(|| {
            let vote_state = VoteState::deserialize(&inner.account.data);
            *inner.vote_state.write().unwrap() = vote_state;
        });
        inner.vote_state.read().unwrap()
    }

    /// VoteState.node_pubkey of this vote-account.
    fn node_pubkey(&self) -> Option<Pubkey> {
        Some(self.vote_state().as_ref().ok()?.node_pubkey)
    }

}

impl Serialize for VoteAccount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.account.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VoteAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let account = Account::deserialize(deserializer)?;
        Ok(Self::from(account))
    }
}

impl From<Account> for VoteAccount {
    fn from(account: Account) -> Self {
        Self(Arc::new(VoteAccountInner::from(account)))
    }
}

#[derive(Debug, AbiExample)]
struct VoteAccountInner {
    account: Account,
    vote_state: RwLock<Result<VoteState, InstructionError>>,
    vote_state_once: Once,
}

impl Default for VoteAccountInner {
    fn default() -> Self {
        Self {
            account: Account::default(),
            vote_state: RwLock::new(INVALID_VOTE_STATE),
            vote_state_once: Once::new(),
        }
    }
}

impl PartialEq<VoteAccountInner> for VoteAccountInner {
    fn eq(&self, other: &Self) -> bool {
        self.account == other.account
    }
}

impl From<Account> for VoteAccountInner {
    fn from(account: Account) -> Self {
        Self {
            account,
            vote_state: RwLock::new(INVALID_VOTE_STATE),
            vote_state_once: Once::new(),
        }
    }
}

pub type VoteAccountsHashMap = HashMap<Pubkey, (/*stake:*/ u64, VoteAccount)>;

#[derive(Debug, AbiExample)]
pub struct VoteAccounts {
    vote_accounts: Arc<VoteAccountsHashMap>,
    // Inner Arc is meant to implement copy-on-write semantics as opposed to
    // sharing mutations (hence RwLock<Arc<...>> instead of Arc<RwLock<...>>).
    staked_nodes: RwLock<
        Arc<
            HashMap<
                Pubkey, // VoteAccount.vote_state.node_pubkey.
                u64,    // Total stake across all vote-accounts.
            >,
        >,
    >,
    staked_nodes_once: Once,
}

impl VoteAccounts{
    pub fn get(&self, pubkey: &Pubkey) -> Option<&(/*stake:*/ u64, VoteAccount)> {
        self.vote_accounts.get(pubkey)
    }

    pub fn staked_nodes(&self) -> Arc<HashMap<Pubkey, u64>> {
        self.staked_nodes_once.call_once(|| {
            let staked_nodes = self
                .vote_accounts
                .values()
                .filter(|(stake, _)| *stake != 0)
                .filter_map(|(stake, vote_account)| {
                    let node_pubkey = vote_account.node_pubkey()?;
                    Some((node_pubkey, stake))
                })
                .into_grouping_map()
                .aggregate(|acc, _node_pubkey, stake| Some(acc.unwrap_or_default() + stake));
            *self.staked_nodes.write().unwrap() = Arc::new(staked_nodes)
        });
        self.staked_nodes.read().unwrap().clone()
    }


}

impl Default for VoteAccounts {
    fn default() -> Self {
        Self {
            vote_accounts: Arc::default(),
            staked_nodes: RwLock::default(),
            staked_nodes_once: Once::new(),
        }
    }
}

impl Clone for VoteAccounts {
    fn clone(&self) -> Self {
        if self.staked_nodes_once.is_completed() {
            let staked_nodes = self.staked_nodes.read().unwrap().clone();
            let other = Self {
                vote_accounts: self.vote_accounts.clone(),
                staked_nodes: RwLock::new(staked_nodes),
                staked_nodes_once: Once::new(),
            };
            other.staked_nodes_once.call_once(|| {});
            other
        } else {
            Self {
                vote_accounts: self.vote_accounts.clone(),
                staked_nodes: RwLock::default(),
                staked_nodes_once: Once::new(),
            }
        }
    }
}

impl PartialEq<VoteAccounts> for VoteAccounts {
    fn eq(&self, other: &Self) -> bool {
        self.vote_accounts == other.vote_accounts
    }
}

impl From<Arc<VoteAccountsHashMap>> for VoteAccounts {
    fn from(vote_accounts: Arc<VoteAccountsHashMap>) -> Self {
        Self {
            vote_accounts,
            staked_nodes: RwLock::default(),
            staked_nodes_once: Once::new(),
        }
    }
}

impl AsRef<VoteAccountsHashMap> for VoteAccounts {
    fn as_ref(&self) -> &VoteAccountsHashMap {
        &self.vote_accounts
    }
}

impl From<&VoteAccounts> for Arc<VoteAccountsHashMap> {
    fn from(vote_accounts: &VoteAccounts) -> Self {
        Arc::clone(&vote_accounts.vote_accounts)
    }
}

impl FromIterator<(Pubkey, (/*stake:*/ u64, VoteAccount))> for VoteAccounts {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (Pubkey, (u64, VoteAccount))>,
    {
        Self::from(Arc::new(HashMap::from_iter(iter)))
    }
}

impl Serialize for VoteAccounts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.vote_accounts.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VoteAccounts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vote_accounts = VoteAccountsHashMap::deserialize(deserializer)?;
        Ok(Self::from(Arc::new(vote_accounts)))
    }
}