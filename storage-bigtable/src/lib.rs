use {
    crate::bigtable::RowKey,
    log::*,
    serde::{Deserialize, Serialize},
    metrics::inc_new_counter_debug,
    sdk::{
        clock::{Slot, UnixTimestamp},
    deserialize_utils::default_on_eof,
        pubkey::Pubkey,
        signature::Signature,
        sysvar::is_sysvar_id,
        transaction::{Transaction, TransactionError},
    },
    storage_proto::convert::generated_evm,
    storage_proto::convert::{generated, tx_by_addr},
    transaction_status::{
        extract_and_fmt_memos, ConfirmedBlock, ConfirmedBlockWithOptionalMetadata,
        ConfirmedTransactionStatusWithSignature, ConfirmedTransactionWithOptionalMetadata, Reward,
        TransactionByAddrInfo, TransactionConfirmationStatus, TransactionStatus,
        TransactionStatusMeta, TransactionWithMetadata, TransactionWithOptionalMetadata,
    },
    std::{
        collections::{HashMap, HashSet},
        convert::TryInto,
    },
    thiserror::Error,
};

pub struct LedgerStorage {
    connection: bigtable::BigTableConnection,
}