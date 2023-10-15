use {
    crate::rpc_response::RpcSimulateTransactionResult,
    derivative::Derivative,
    serde_json::{json, Value},
    sdk::{clock::Slot, pubkey::Pubkey},
    std::fmt,
    thiserror::Error,
};

#[derive(Derivative, Error)]
#[derivative(Debug)]
pub enum RpcError {
    #[error("RPC request error: {0}")]
    RpcRequestError(String),
    #[error("RPC response error {code}: {message} {data}")]
    RpcResponseError {
        code: i64,
        message: String,
        data: RpcResponseErrorData,
        #[derivative(Debug = "ignore")]
        original_err: serde_json::Value,
    },
    #[error("parse error: expected {0}")]
    ParseError(String), /* "expected" */
    // Anything in a `ForUser` needs to die.  The caller should be
    // deciding what to tell their user
    #[error("{0}")]
    ForUser(String), /* "direct-to-user message" */
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum RpcRequest {
    Custom {
        method: &'static str,
    },
    DeregisterNode,
    GetAccountInfo,
    GetBalance,
    GetBlock,
    GetBlockHeight,
    GetBlockProduction,
    GetBlocks,
    GetBlocksWithLimit,
    GetBlockTime,
    GetClusterNodes,
    #[deprecated(since = "1.7.0", note = "Please use RpcRequest::GetBlock instead")]
    GetConfirmedBlock,
    #[deprecated(since = "1.7.0", note = "Please use RpcRequest::GetBlocks instead")]
    GetConfirmedBlocks,
    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcRequest::GetBlocksWithLimit instead"
    )]
    GetConfirmedBlocksWithLimit,

    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcRequest::GetSignaturesForAddress instead"
    )]
    GetConfirmedSignaturesForAddress2,
    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcRequest::GetTransaction instead"
    )]
    GetConfirmedTransaction,
    GetEpochInfo,
    GetEpochSchedule,
    #[deprecated(
        since = "1.9.0",
        note = "Please use RpcRequest::GetFeeForMessage instead"
    )]
    GetFeeCalculatorForBlockhash,
    GetFeeForMessage,
    #[deprecated(
        since = "1.9.0",
        note = "Please do not use, will no longer be available in the future"
    )]
    GetFeeRateGovernor,
    #[deprecated(
        since = "1.9.0",
        note = "Please use RpcRequest::GetFeeForMessage instead"
    )]
    GetFees,
    GetFirstAvailableBlock,
    GetGenesisHash,
    GetHealth,
    GetIdentity,
    GetInflationGovernor,
    GetInflationRate,
    GetInflationReward,
    GetLargestAccounts,
    GetLatestBlockhash,
    GetLeaderSchedule,
    GetMinimumBalanceForRentExemption,
    GetMultipleAccounts,
    GetProgramAccounts,
    #[deprecated(
        since = "1.9.0",
        note = "Please use RpcRequest::GetLatestBlockhash instead"
    )]
    GetRecentBlockhash,
    GetRecentPerformanceSamples,
    GetHighestSnapshotSlot,
    #[deprecated(
        since = "1.9.0",
        note = "Please use RpcRequest::GetHighestSnapshotSlot instead"
    )]
    GetSnapshotSlot,
    GetSignaturesForAddress,
    GetSignatureStatuses,
    GetSlot,
    GetMaxRetransmitSlot,
    GetMaxShredInsertSlot,
    GetSlotLeader,
    GetSlotLeaders,
    GetStorageTurn,
    GetStorageTurnRate,
    GetSlotsPerSegment,
    GetStakeActivation,
    GetStoragePubkeysForSlot,
    GetSupply,
    GetTokenLargestAccounts,
    GetTokenAccountBalance,
    GetTokenAccountsByDelegate,
    GetTokenAccountsByOwner,
    GetTokenSupply,
    GetTransaction,
    GetTransactionCount,
    GetVersion,
    GetVoteAccounts,
    IsBlockhashValid,
    MinimumLedgerSlot,
    RegisterNode,
    RequestAirdrop,
    SendTransaction,
    SimulateTransaction,
    SignVote,

    /// EVM scope
    EthGetBlockTransactionCountByHash,
    EthGetBlockTransactionCountByNumber,
    EthGetTransactionByBlockHashAndIndex,
    EthGetTransactionByBlockNumberAndIndex,
    EthGetTransactionCount,
    EthGetBalance,
    EthGetBlockByNumber,
    EthGetBlockByHash,
    EthBlockNumber,
    EthGetStorageAt,
    EthGetCode,
    EthGetTransactionByHash,
    EthGetTransactionReceipt,
    EthCall,
    EthEstimateGas,
    EthGetLogs,
    EthSyncing,
    EthTraceCall,
    EthTraceCallMany,
    EthTraceReplayTransaction,
    EthTraceReplayBlock,

    /// Sino Account scope
    GetSinoAccountsByOperationalKey,
    GetSinoAccountsByOwnerKey,
    GetSinoRelyingPartiesByOwnerKey,

    /// Debug scope
    DebugRecoverBlockHeader,
}

#[allow(deprecated)]
impl fmt::Display for RpcRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let method = match self {
            RpcRequest::Custom { method } => method,
            RpcRequest::DeregisterNode => "deregisterNode",
            RpcRequest::GetAccountInfo => "getAccountInfo",
            RpcRequest::GetBalance => "getBalance",
            RpcRequest::GetBlock => "getBlock",
            RpcRequest::GetBlockHeight => "getBlockHeight",
            RpcRequest::GetBlockProduction => "getBlockProduction",
            RpcRequest::GetBlocks => "getBlocks",
            RpcRequest::GetBlocksWithLimit => "getBlocksWithLimit",
            RpcRequest::GetBlockTime => "getBlockTime",
            RpcRequest::GetClusterNodes => "getClusterNodes",
            RpcRequest::GetConfirmedBlock => "getConfirmedBlock",
            RpcRequest::GetConfirmedBlocks => "getConfirmedBlocks",
            RpcRequest::GetConfirmedBlocksWithLimit => "getConfirmedBlocksWithLimit",
            RpcRequest::GetConfirmedSignaturesForAddress2 => "getConfirmedSignaturesForAddress2",
            RpcRequest::GetConfirmedTransaction => "getConfirmedTransaction",
            RpcRequest::GetEpochInfo => "getEpochInfo",
            RpcRequest::GetEpochSchedule => "getEpochSchedule",
            RpcRequest::GetFeeCalculatorForBlockhash => "getFeeCalculatorForBlockhash",
            RpcRequest::GetFeeForMessage => "getFeeForMessage",
            RpcRequest::GetFeeRateGovernor => "getFeeRateGovernor",
            RpcRequest::GetFees => "getFees",
            RpcRequest::GetFirstAvailableBlock => "getFirstAvailableBlock",
            RpcRequest::GetGenesisHash => "getGenesisHash",
            RpcRequest::GetHealth => "getHealth",
            RpcRequest::GetIdentity => "getIdentity",
            RpcRequest::GetInflationGovernor => "getInflationGovernor",
            RpcRequest::GetInflationRate => "getInflationRate",
            RpcRequest::GetInflationReward => "getInflationReward",
            RpcRequest::GetLargestAccounts => "getLargestAccounts",
            RpcRequest::GetLatestBlockhash => "getLatestBlockhash",
            RpcRequest::GetLeaderSchedule => "getLeaderSchedule",
            RpcRequest::GetMaxRetransmitSlot => "getMaxRetransmitSlot",
            RpcRequest::GetMaxShredInsertSlot => "getMaxShredInsertSlot",
            RpcRequest::GetMinimumBalanceForRentExemption => "getMinimumBalanceForRentExemption",
            RpcRequest::GetMultipleAccounts => "getMultipleAccounts",
            RpcRequest::GetProgramAccounts => "getProgramAccounts",
            RpcRequest::GetRecentBlockhash => "getRecentBlockhash",
            RpcRequest::GetRecentPerformanceSamples => "getRecentPerformanceSamples",
            RpcRequest::GetHighestSnapshotSlot => "getHighestSnapshotSlot",
            RpcRequest::GetSnapshotSlot => "getSnapshotSlot",
            RpcRequest::GetSignaturesForAddress => "getSignaturesForAddress",
            RpcRequest::GetSignatureStatuses => "getSignatureStatuses",
            RpcRequest::GetSlot => "getSlot",
            RpcRequest::GetSlotLeader => "getSlotLeader",
            RpcRequest::GetSlotLeaders => "getSlotLeaders",
            RpcRequest::GetStakeActivation => "getStakeActivation",
            RpcRequest::GetStorageTurn => "getStorageTurn",
            RpcRequest::GetStorageTurnRate => "getStorageTurnRate",
            RpcRequest::GetSlotsPerSegment => "getSlotsPerSegment",
            RpcRequest::GetStoragePubkeysForSlot => "getStoragePubkeysForSlot",
            RpcRequest::GetSupply => "getSupply",
            RpcRequest::GetTokenLargestAccounts => "getTokenLargestAccounts",
            RpcRequest::GetTokenAccountBalance => "getTokenAccountBalance",
            RpcRequest::GetTokenAccountsByDelegate => "getTokenAccountsByDelegate",
            RpcRequest::GetTokenAccountsByOwner => "getTokenAccountsByOwner",
            RpcRequest::GetTokenSupply => "getTokenSupply",
            RpcRequest::GetTransaction => "getTransaction",
            RpcRequest::GetTransactionCount => "getTransactionCount",
            RpcRequest::GetVersion => "getVersion",
            RpcRequest::GetVoteAccounts => "getVoteAccounts",
            RpcRequest::IsBlockhashValid => "isBlockhashValid",
            RpcRequest::MinimumLedgerSlot => "minimumLedgerSlot",
            RpcRequest::RegisterNode => "registerNode",
            RpcRequest::RequestAirdrop => "requestAirdrop",
            RpcRequest::SendTransaction => "sendTransaction",
            RpcRequest::SimulateTransaction => "simulateTransaction",
            RpcRequest::SignVote => "signVote",
            RpcRequest::EthGetTransactionCount => "eth_getTransactionCount",
            RpcRequest::EthGetBalance => "eth_getBalance",
            RpcRequest::EthGetBlockByNumber => "eth_getBlockByNumber",
            RpcRequest::EthGetBlockByHash => "eth_getBlockByHash",
            RpcRequest::EthBlockNumber => "eth_blockNumber",
            RpcRequest::EthGetStorageAt => "eth_getStorageAt",
            RpcRequest::EthGetCode => "eth_getCode",
            RpcRequest::EthGetTransactionByHash => "eth_getTransactionByHash",
            RpcRequest::EthGetTransactionReceipt => "eth_getTransactionReceipt",
            RpcRequest::EthCall => "eth_call",
            RpcRequest::EthTraceCall => "trace_call",
            RpcRequest::EthTraceCallMany => "trace_callMany",
            RpcRequest::EthGetBlockTransactionCountByHash => "eth_getBlockTransactionCountByHash",
            RpcRequest::EthGetBlockTransactionCountByNumber => "eth_getBlockTransactionCountByNumber",
            RpcRequest::EthGetTransactionByBlockHashAndIndex => "eth_getTransactionByBlockHashAndIndex",
            RpcRequest::EthGetTransactionByBlockNumberAndIndex => "eth_getTransactionByBlockNumberAndIndex",
            RpcRequest::EthTraceReplayTransaction => "trace_replayTransaction",
            RpcRequest::EthTraceReplayBlock => "trace_replayBlockTransactions",
            RpcRequest::EthEstimateGas => "eth_estimateGas",
            RpcRequest::EthGetLogs => "eth_getLogs",
            RpcRequest::EthSyncing => "eth_syncing",
            RpcRequest::GetSinoAccountsByOperationalKey => "getSinoAccountsByOperationalKey",
            RpcRequest::GetSinoAccountsByOwnerKey => "getSinoAccountsByOwnerKey",
            RpcRequest::GetSinoRelyingPartiesByOwnerKey => "getSinoRelyingPartiesByOwnerKey",
            RpcRequest::DebugRecoverBlockHeader => "debug_recoverBlockHeader",
        };

        write!(f, "{}", method)
    }
}

pub const MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS: usize = 256;
pub const MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS_SLOT_RANGE: u64 = 10_000;
pub const MAX_GET_CONFIRMED_BLOCKS_RANGE: u64 = 500_000;
pub const MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS2_LIMIT: usize = 1_000;
pub const MAX_MULTIPLE_ACCOUNTS: usize = 100;
pub const NUM_LARGEST_ACCOUNTS: usize = 20;
pub const MAX_GET_PROGRAM_ACCOUNT_FILTERS: usize = 4;
pub const MAX_GET_SLOT_LEADERS: usize = 5000;

// Validators that are this number of slots behind are considered delinquent
pub const DELINQUENT_VALIDATOR_SLOT_DISTANCE: u64 = 128;

impl RpcRequest {
    pub fn build_request_json(self, id: u64, params: Value) -> Value {
        let jsonrpc = "2.0";
        json!({
           "jsonrpc": jsonrpc,
           "id": id,
           "method": format!("{}", self),
           "params": params,
        })
    }
}

#[derive(Debug)]
pub enum RpcResponseErrorData {
    Empty,
    SendTransactionPreflightFailure(RpcSimulateTransactionResult),
    NodeUnhealthy { num_slots_behind: Option<Slot> },
}

impl fmt::Display for RpcResponseErrorData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RpcResponseErrorData::SendTransactionPreflightFailure(
                RpcSimulateTransactionResult {
                    logs: Some(logs), ..
                },
            ) => {
                if logs.is_empty() {
                    Ok(())
                } else {
                    // Give the user a hint that there is more useful logging information available...
                    write!(f, "[{} log messages]", logs.len())
                }
            }
            _ => Ok(()),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum TokenAccountsFilter {
    Mint(Pubkey),
    ProgramId(Pubkey),
}

