//! This module implements clone-on-write semantics for the SDK's `StakeHistory` to reduce
//! unnecessary cloning of the underlying vector.
use std::{
    sync::Arc,
};

/// The SDK's stake history with clone-on-write semantics
#[derive(Default, Clone, PartialEq, Debug, Deserialize, Serialize, AbiExample)]
pub struct StakeHistory(Arc<StakeHistoryInner>);

/// The inner type, which is the SDK's stake history
type StakeHistoryInner = sdk::stake_history::StakeHistory;