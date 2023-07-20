//! Map pubkeys to stake delegations
//!
//! This module implements clone-on-write semantics for `StakeDelegations` to reduce unnecessary
//! cloning of the underlying map.
use {
    sdk::{pubkey::Pubkey, stake::state::Delegation},
    std::{
        collections::HashMap,
        sync::Arc,
        ops::{Deref, DerefMut},
    },
};

/// A map of pubkey-to-stake-delegation with clone-on-write semantics
#[derive(Default, Clone, PartialEq, Debug, Deserialize, Serialize, AbiExample)]
pub struct StakeDelegations(Arc<StakeDelegationsInner>);

impl Deref for StakeDelegations {
    type Target = StakeDelegationsInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for StakeDelegations {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

/// The inner type, which maps pubkeys to stake delegations
type StakeDelegationsInner = HashMap<Pubkey, Delegation>;
