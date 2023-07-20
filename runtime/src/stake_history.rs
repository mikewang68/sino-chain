//! This module implements clone-on-write semantics for the SDK's `StakeHistory` to reduce
//! unnecessary cloning of the underlying vector.
use std::{
    sync::Arc,
    ops::{Deref, DerefMut},
};

/// The SDK's stake history with clone-on-write semantics
#[derive(Default, Clone, PartialEq, Debug, Deserialize, Serialize, AbiExample)]
pub struct StakeHistory(Arc<StakeHistoryInner>);

impl Deref for StakeHistory {
    type Target = StakeHistoryInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for StakeHistory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

/// The inner type, which is the SDK's stake history
type StakeHistoryInner = sdk::stake_history::StakeHistory;