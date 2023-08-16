use {
    serde::{Deserialize, Serialize},
    account_decoder::{
        parse_token::{real_number_string_trimmed, UiTokenAmount},
        StringAmount,
    },
    sdk::{deserialize_utils::default_on_eof, transaction::Result},
    transaction_status::{
        InnerInstructions, Reward, RewardType, TransactionStatusMeta, TransactionTokenBalance,
    },
    std::str::FromStr,
};

pub mod convert;

pub type StoredExtendedRewards = Vec<StoredExtendedReward>;

#[derive(Serialize, Deserialize)]
pub struct StoredExtendedReward {
    pubkey: String,
    wens: i64,
    #[serde(deserialize_with = "default_on_eof")]
    post_balance: u64,
    #[serde(deserialize_with = "default_on_eof")]
    reward_type: Option<RewardType>,
    #[serde(deserialize_with = "default_on_eof")]
    commission: Option<u8>,
}

impl From<StoredExtendedReward> for Reward {
    fn from(value: StoredExtendedReward) -> Self {
        let StoredExtendedReward {
            pubkey,
            wens,
            post_balance,
            reward_type,
            commission,
        } = value;
        Self {
            pubkey,
            wens,
            post_balance,
            reward_type,
            commission,
        }
    }
}

impl From<Reward> for StoredExtendedReward {
    fn from(value: Reward) -> Self {
        let Reward {
            pubkey,
            wens,
            post_balance,
            reward_type,
            commission,
        } = value;
        Self {
            pubkey,
            wens,
            post_balance,
            reward_type,
            commission,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct StoredTokenAmount {
    pub ui_amount: f64,
    pub decimals: u8,
    pub amount: StringAmount,
}

impl From<StoredTokenAmount> for UiTokenAmount {
    fn from(value: StoredTokenAmount) -> Self {
        let StoredTokenAmount {
            ui_amount,
            decimals,
            amount,
        } = value;
        let ui_amount_string =
            real_number_string_trimmed(u64::from_str(&amount).unwrap_or(0), decimals);
        Self {
            ui_amount: Some(ui_amount),
            decimals,
            amount,
            ui_amount_string,
        }
    }
}

impl From<UiTokenAmount> for StoredTokenAmount {
    fn from(value: UiTokenAmount) -> Self {
        let UiTokenAmount {
            ui_amount,
            decimals,
            amount,
            ..
        } = value;
        Self {
            ui_amount: ui_amount.unwrap_or(0.0),
            decimals,
            amount,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct StoredTransactionTokenBalance {
    pub account_index: u8,
    pub mint: String,
    pub ui_token_amount: StoredTokenAmount,
    #[serde(deserialize_with = "default_on_eof")]
    pub owner: String,
}

impl From<StoredTransactionTokenBalance> for TransactionTokenBalance {
    fn from(value: StoredTransactionTokenBalance) -> Self {
        let StoredTransactionTokenBalance {
            account_index,
            mint,
            ui_token_amount,
            owner,
        } = value;
        Self {
            account_index,
            mint,
            ui_token_amount: ui_token_amount.into(),
            owner,
        }
    }
}

impl From<TransactionTokenBalance> for StoredTransactionTokenBalance {
    fn from(value: TransactionTokenBalance) -> Self {
        let TransactionTokenBalance {
            account_index,
            mint,
            ui_token_amount,
            owner,
        } = value;
        Self {
            account_index,
            mint,
            ui_token_amount: ui_token_amount.into(),
            owner,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct StoredTransactionStatusMeta {
    pub status: Result<()>,
    pub fee: u64,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
    #[serde(deserialize_with = "default_on_eof")]
    pub inner_instructions: Option<Vec<InnerInstructions>>,
    #[serde(deserialize_with = "default_on_eof")]
    pub log_messages: Option<Vec<String>>,
    #[serde(deserialize_with = "default_on_eof")]
    pub pre_token_balances: Option<Vec<StoredTransactionTokenBalance>>,
    #[serde(deserialize_with = "default_on_eof")]
    pub post_token_balances: Option<Vec<StoredTransactionTokenBalance>>,
    #[serde(deserialize_with = "default_on_eof")]
    pub rewards: Option<Vec<StoredExtendedReward>>,
}

impl From<StoredTransactionStatusMeta> for TransactionStatusMeta {
    fn from(value: StoredTransactionStatusMeta) -> Self {
        let StoredTransactionStatusMeta {
            status,
            fee,
            pre_balances,
            post_balances,
            inner_instructions,
            log_messages,
            pre_token_balances,
            post_token_balances,
            rewards,
        } = value;
        Self {
            status,
            fee,
            pre_balances,
            post_balances,
            inner_instructions,
            log_messages,
            pre_token_balances: pre_token_balances
                .map(|balances| balances.into_iter().map(|balance| balance.into()).collect()),
            post_token_balances: post_token_balances
                .map(|balances| balances.into_iter().map(|balance| balance.into()).collect()),
            rewards: rewards
                .map(|rewards| rewards.into_iter().map(|reward| reward.into()).collect()),
        }
    }
}

impl From<TransactionStatusMeta> for StoredTransactionStatusMeta {
    fn from(value: TransactionStatusMeta) -> Self {
        let TransactionStatusMeta {
            status,
            fee,
            pre_balances,
            post_balances,
            inner_instructions,
            log_messages,
            pre_token_balances,
            post_token_balances,
            rewards,
        } = value;
        Self {
            status,
            fee,
            pre_balances,
            post_balances,
            inner_instructions,
            log_messages,
            pre_token_balances: pre_token_balances
                .map(|balances| balances.into_iter().map(|balance| balance.into()).collect()),
            post_token_balances: post_token_balances
                .map(|balances| balances.into_iter().map(|balance| balance.into()).collect()),
            rewards: rewards
                .map(|rewards| rewards.into_iter().map(|reward| reward.into()).collect()),
        }
    }
}
