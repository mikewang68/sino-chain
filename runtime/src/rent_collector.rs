//! calculate and collect rent from Accounts
use sdk::{
    clock::Epoch,
    epoch_schedule::EpochSchedule,
    rent::{Rent},
};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, AbiExample)]
pub struct RentCollector {
    pub epoch: Epoch,
    pub epoch_schedule: EpochSchedule,
    pub slots_per_year: f64,
    pub rent: Rent,
}

