///
/// A library for creating a trusted date oracle.
///
use bincode::{deserialize, serialized_size};
#[allow(deprecated)]
use {
    crate::{config_instruction, ConfigState},
    chrono::{
        prelude::{Date, DateTime, TimeZone, Utc},
        serde::ts_seconds,
    },
    serde_derive::{Deserialize, Serialize},
    sdk::{instruction::Instruction, pubkey::Pubkey},
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct DateConfig {
    #[serde(with = "ts_seconds")]
    pub date_time: DateTime<Utc>,
}

impl Default for DateConfig {
    #[allow(deprecated)]
    fn default() -> Self {
        Self {
            date_time: Utc.timestamp(0, 0),
        }
    }
}
impl DateConfig {
    #[allow(deprecated)]
    pub fn new(date: Date<Utc>) -> Self {
        Self {
            date_time: date.and_hms(0, 0, 0),
        }
    }

    pub fn deserialize(input: &[u8]) -> Option<Self> {
        deserialize(input).ok()
    }
}

impl ConfigState for DateConfig {
    fn max_space() -> u64 {
        serialized_size(&Self::default()).unwrap()
    }
}

/// Create a date account. The date is set to the Unix epoch.
pub fn create_account(
    payer_pubkey: &Pubkey,
    date_pubkey: &Pubkey,
    wens: u64,
) -> Vec<Instruction> {
    config_instruction::create_account::<DateConfig>(payer_pubkey, date_pubkey, wens, vec![])
}

/// Set the date in the date account. The account pubkey must be signed in the
/// transaction containing this instruction.
#[allow(deprecated)]
pub fn store(date_pubkey: &Pubkey, date: Date<Utc>) -> Instruction {
    let date_config = DateConfig::new(date);
    config_instruction::store(date_pubkey, true, vec![], &date_config)
}
