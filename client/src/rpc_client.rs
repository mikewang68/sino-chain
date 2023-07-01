//! Communication with a Solana node over RPC.
//!
//! Software that interacts with the Solana blockchain, whether querying its
//! state or submitting transactions, communicates with a Solana node over
//! [JSON-RPC], using the [`RpcClient`] type.
//!
//! [JSON-RPC]: https://www.jsonrpc.org/specification

#[allow(deprecated)]
use crate::rpc_deprecated_config::{
    RpcConfirmedBlockConfig, RpcConfirmedTransactionConfig,
    RpcGetConfirmedSignaturesForAddress2Config,
};
use {
    crate::{
        client_error::{ClientError, ClientErrorKind, Result as ClientResult},
        http_sender::HttpSender,
        mock_sender::{MockSender, Mocks},
        rpc_config::{RpcAccountInfoConfig, *},
        rpc_request::{RpcError, RpcRequest, RpcResponseErrorData, TokenAccountsFilter},
        rpc_response::*,
        rpc_sender::*,
        spinner,
    },
    bincode::serialize,
    log::*,
    serde_json::{json, Value},
    solana_account_decoder::{
        parse_token::{TokenAccountType, UiTokenAccount, UiTokenAmount},
        UiAccount, UiAccountData, UiAccountEncoding,
    },
    solana_sdk::{
        account::Account,
        clock::{Epoch, Slot, UnixTimestamp, DEFAULT_MS_PER_SLOT, MAX_HASH_AGE_IN_SECONDS},
        commitment_config::{CommitmentConfig, CommitmentLevel},
        epoch_info::EpochInfo,
        epoch_schedule::EpochSchedule,
        fee_calculator::{FeeCalculator, FeeRateGovernor},
        hash::Hash,
        message::Message,
        pubkey::Pubkey,
        signature::Signature,
        transaction::{self, uses_durable_nonce, Transaction},
    },
    solana_transaction_status::{
        EncodedConfirmedBlock, EncodedConfirmedTransaction, TransactionStatus, UiConfirmedBlock,
        UiTransactionEncoding,
    },
    solana_vote_program::vote_state::MAX_LOCKOUT_HISTORY,
    std::{
        cmp::min,
        net::SocketAddr,
        str::FromStr,
        sync::RwLock,
        thread::sleep,
        time::{Duration, Instant},
    },
};

#[derive(Default)]
pub struct RpcClientConfig {
    commitment_config: CommitmentConfig,
    confirm_transaction_initial_timeout: Option<Duration>,
}

impl RpcClientConfig {
    fn with_commitment(commitment_config: CommitmentConfig) -> Self {
        RpcClientConfig {
            commitment_config,
            ..Self::default()
        }
    }
}

/// A client of a remote Solana node.
///
/// `RpcClient` communicates with a Solana node over [JSON-RPC], with the
/// [Solana JSON-RPC protocol][jsonprot]. It is the primary Rust interface for
/// querying and transacting with the network from external programs.
///
/// This type builds on the underlying RPC protocol, adding extra features such
/// as timeout handling, retries, and waiting on transaction [commitment levels][cl].
/// Some methods simply pass through to the underlying RPC protocol. Not all RPC
/// methods are encapsulated by this type, but `RpcClient` does expose a generic
/// [`send`](RpcClient::send) method for making any [`RpcRequest`].
///
/// The documentation for most `RpcClient` methods contains an "RPC Reference"
/// section that links to the documentation for the underlying JSON-RPC method.
/// The documentation for `RpcClient` does not reproduce the documentation for
/// the underlying JSON-RPC methods. Thus reading both is necessary for complete
/// understanding.
///
/// `RpcClient`s generally communicate over HTTP on port 8899, a typical server
/// URL being "http://localhost:8899".
///
/// Methods that query information from recent [slots], including those that
/// confirm transactions, decide the most recent slot to query based on a
/// [commitment level][cl], which determines how committed or finalized a slot
/// must be to be considered for the query. Unless specified otherwise, the
/// commitment level is [`Finalized`], meaning the slot is definitely
/// permanently committed. The default commitment level can be configured by
/// creating `RpcClient` with an explicit [`CommitmentConfig`], and that default
/// configured commitment level can be overridden by calling the various
/// `_with_commitment` methods, like
/// [`RpcClient::confirm_transaction_with_commitment`]. In some cases the
/// configured commitment level is ignored and `Finalized` is used instead, as
/// in [`RpcClient::get_blocks`], where it would be invalid to use the
/// [`Processed`] commitment level. These exceptions are noted in the method
/// documentation.
///
/// [`Finalized`]: CommitmentLevel::Finalized
/// [`Processed`]: CommitmentLevel::Processed
/// [jsonprot]: https://docs.solana.com/developing/clients/jsonrpc-api
/// [JSON-RPC]: https://www.jsonrpc.org/specification
/// [slots]: https://docs.solana.com/terminology#slot
/// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
///
/// # Errors
///
/// Methods on `RpcClient` return
/// [`client_error::Result`][crate::client_error::Result], and many of them
/// return the [`RpcResult`][crate::rpc_response::RpcResult] typedef, which
/// contains [`Response<T>`][crate::rpc_response::Response] on `Ok`. Both
/// `client_error::Result` and [`RpcResult`] contain `ClientError` on error. In
/// the case of `RpcResult`, the actual return value is in the
/// [`value`][crate::rpc_response::Response::value] field, with RPC contextual
/// information in the [`context`][crate::rpc_response::Response::context]
/// field, so it is common for the value to be accessed with `?.value`, as in
///
/// ```
/// # use solana_sdk::system_transaction;
/// # use solana_client::rpc_client::RpcClient;
/// # use solana_client::client_error::ClientError;
/// # use solana_sdk::signature::{Keypair, Signer};
/// # use solana_sdk::hash::Hash;
/// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
/// # let key = Keypair::new();
/// # let to = solana_sdk::pubkey::new_rand();
/// # let lamports = 50;
/// # let latest_blockhash = Hash::default();
/// # let tx = system_transaction::transfer(&key, &to, lamports, latest_blockhash);
/// let signature = rpc_client.send_transaction(&tx)?;
/// let statuses = rpc_client.get_signature_statuses(&[signature])?.value;
/// # Ok::<(), ClientError>(())
/// ```
///
/// Requests may timeout, in which case they return a [`ClientError`] where the
/// [`ClientErrorKind`] is [`ClientErrorKind::Reqwest`], and where the interior
/// [`reqwest::Error`](crate::client_error::reqwest::Error)s
/// [`is_timeout`](crate::client_error::reqwest::Error::is_timeout) method
/// returns `true`. The default timeout is 30 seconds, and may be changed by
/// calling an appropriate constructor with a `timeout` parameter.
pub struct RpcClient {
    sender: Box<dyn RpcSender + Send + Sync + 'static>,
    config: RpcClientConfig,
    node_version: RwLock<Option<semver::Version>>,
}

impl RpcClient {
    /// Create an `RpcClient` from an [`RpcSender`] and an [`RpcClientConfig`].
    ///
    /// This is the basic constructor, allowing construction with any type of
    /// `RpcSender`. Most applications should use one of the other constructors,
    /// such as [`new`] and [`new_mock`], which create an `RpcClient`
    /// encapsulating an [`HttpSender`] and [`MockSender`] respectively.
    pub fn new_sender<T: RpcSender + Send + Sync + 'static>(
        sender: T,
        config: RpcClientConfig,
    ) -> Self {
        Self {
            sender: Box::new(sender),
            node_version: RwLock::new(None),
            config,
        }
    }

    /// Create an HTTP `RpcClient`.
    ///
    /// The URL is an HTTP URL, usually for port 8899, as in
    /// "http://localhost:8899".
    ///
    /// The client has a default timeout of 30 seconds, and a default [commitment
    /// level][cl] of [`Finalized`](CommitmentLevel::Finalized).
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::rpc_client::RpcClient;
    /// let url = "http://localhost:8899".to_string();
    /// let client = RpcClient::new(url);
    /// ```
    pub fn new<U: ToString>(url: U) -> Self {
        Self::new_with_commitment(url, CommitmentConfig::default())
    }

    /// Create an HTTP `RpcClient` with specified [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// The URL is an HTTP URL, usually for port 8899, as in
    /// "http://localhost:8899".
    ///
    /// The client has a default timeout of 30 seconds, and a user-specified
    /// [`CommitmentLevel`] via [`CommitmentConfig`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # use solana_client::rpc_client::RpcClient;
    /// let url = "http://localhost:8899".to_string();
    /// let commitment_config = CommitmentConfig::processed();
    /// let client = RpcClient::new_with_commitment(url, commitment_config);
    /// ```
    pub fn new_with_commitment<U: ToString>(url: U, commitment_config: CommitmentConfig) -> Self {
        Self::new_sender(
            HttpSender::new(url),
            RpcClientConfig::with_commitment(commitment_config),
        )
    }

    /// Create an HTTP `RpcClient` with specified timeout.
    ///
    /// The URL is an HTTP URL, usually for port 8899, as in
    /// "http://localhost:8899".
    ///
    /// The client has and a default [commitment level][cl] of
    /// [`Finalized`](CommitmentLevel::Finalized).
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use solana_client::rpc_client::RpcClient;
    /// let url = "http://localhost::8899".to_string();
    /// let timeout = Duration::from_secs(1);
    /// let client = RpcClient::new_with_timeout(url, timeout);
    /// ```
    pub fn new_with_timeout<U: ToString>(url: U, timeout: Duration) -> Self {
        Self::new_sender(
            HttpSender::new_with_timeout(url, timeout),
            RpcClientConfig::with_commitment(CommitmentConfig::default()),
        )
    }

    /// Create an HTTP `RpcClient` with specified timeout and [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// The URL is an HTTP URL, usually for port 8899, as in
    /// "http://localhost:8899".
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use solana_client::rpc_client::RpcClient;
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// let url = "http://localhost::8899".to_string();
    /// let timeout = Duration::from_secs(1);
    /// let commitment_config = CommitmentConfig::processed();
    /// let client = RpcClient::new_with_timeout_and_commitment(
    ///     url,
    ///     timeout,
    ///     commitment_config,
    /// );
    /// ```
    pub fn new_with_timeout_and_commitment<U: ToString>(
        url: U,
        timeout: Duration,
        commitment_config: CommitmentConfig,
    ) -> Self {
        Self::new_sender(
            HttpSender::new_with_timeout(url, timeout),
            RpcClientConfig::with_commitment(commitment_config),
        )
    }

    /// Create an HTTP `RpcClient` with specified timeout and [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// The URL is an HTTP URL, usually for port 8899, as in
    /// "http://localhost:8899".
    ///
    /// The `confirm_transaction_initial_timeout` argument specifies, when
    /// confirming a transaction via one of the `_with_spinner` methods, like
    /// [`RpcClient::send_and_confirm_transaction_with_spinner`], the amount of
    /// time to allow for the server to initially process a transaction. In
    /// other words, setting `confirm_transaction_initial_timeout` to > 0 allows
    /// `RpcClient` to wait for confirmation of a transaction that the server
    /// has not "seen" yet.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use solana_client::rpc_client::RpcClient;
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// let url = "http://localhost::8899".to_string();
    /// let timeout = Duration::from_secs(1);
    /// let commitment_config = CommitmentConfig::processed();
    /// let confirm_transaction_initial_timeout = Duration::from_secs(10);
    /// let client = RpcClient::new_with_timeouts_and_commitment(
    ///     url,
    ///     timeout,
    ///     commitment_config,
    ///     confirm_transaction_initial_timeout,
    /// );
    /// ```
    pub fn new_with_timeouts_and_commitment<U: ToString>(
        url: U,
        timeout: Duration,
        commitment_config: CommitmentConfig,
        confirm_transaction_initial_timeout: Duration,
    ) -> Self {
        Self::new_sender(
            HttpSender::new_with_timeout(url, timeout),
            RpcClientConfig {
                commitment_config,
                confirm_transaction_initial_timeout: Some(confirm_transaction_initial_timeout),
            },
        )
    }

    /// Create a mock `RpcClient`.
    ///
    /// See the [`MockSender`] documentation for an explanation of
    /// how it treats the `url` argument.
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::rpc_client::RpcClient;
    /// // Create an `RpcClient` that always succeeds
    /// let url = "succeeds".to_string();
    /// let successful_client = RpcClient::new_mock(url);
    /// ```
    ///
    /// ```
    /// # use solana_client::rpc_client::RpcClient;
    /// // Create an `RpcClient` that always fails
    /// let url = "fails".to_string();
    /// let successful_client = RpcClient::new_mock(url);
    /// ```
    pub fn new_mock<U: ToString>(url: U) -> Self {
        Self::new_sender(
            MockSender::new(url),
            RpcClientConfig::with_commitment(CommitmentConfig::default()),
        )
    }

    /// Create a mock `RpcClient`.
    ///
    /// See the [`MockSender`] documentation for an explanation of how it treats
    /// the `url` argument.
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     rpc_request::RpcRequest,
    /// #     rpc_response::{Response, RpcResponseContext},
    /// # };
    /// # use std::collections::HashMap;
    /// # use serde_json::json;
    /// // Create a mock with a custom repsonse to the `GetBalance` request
    /// let account_balance = 50;
    /// let account_balance_response = json!(Response {
    ///     context: RpcResponseContext { slot: 1 },
    ///     value: json!(account_balance),
    /// });
    ///
    /// let mut mocks = HashMap::new();
    /// mocks.insert(RpcRequest::GetBalance, account_balance_response);
    /// let url = "succeeds".to_string();
    /// let client = RpcClient::new_mock_with_mocks(url, mocks);
    /// ```
    pub fn new_mock_with_mocks<U: ToString>(url: U, mocks: Mocks) -> Self {
        Self::new_sender(
            MockSender::new_with_mocks(url, mocks),
            RpcClientConfig::with_commitment(CommitmentConfig::default()),
        )
    }

    /// Create an HTTP `RpcClient` from a [`SocketAddr`].
    ///
    /// The client has a default timeout of 30 seconds, and a default [commitment
    /// level][cl] of [`Finalized`](CommitmentLevel::Finalized).
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::SocketAddr;
    /// # use solana_client::rpc_client::RpcClient;
    /// let addr = SocketAddr::from(([127, 0, 0, 1], 8899));
    /// let client = RpcClient::new_socket(addr);
    /// ```
    pub fn new_socket(addr: SocketAddr) -> Self {
        Self::new(get_rpc_request_str(addr, false))
    }

    /// Create an HTTP `RpcClient` from a [`SocketAddr`] with specified [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// The client has a default timeout of 30 seconds, and a user-specified
    /// [`CommitmentLevel`] via [`CommitmentConfig`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::SocketAddr;
    /// # use solana_client::rpc_client::RpcClient;
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// let addr = SocketAddr::from(([127, 0, 0, 1], 8899));
    /// let commitment_config = CommitmentConfig::processed();
    /// let client = RpcClient::new_socket_with_commitment(
    ///     addr,
    ///     commitment_config
    /// );
    /// ```
    pub fn new_socket_with_commitment(
        addr: SocketAddr,
        commitment_config: CommitmentConfig,
    ) -> Self {
        Self::new_with_commitment(get_rpc_request_str(addr, false), commitment_config)
    }

    /// Create an HTTP `RpcClient` from a [`SocketAddr`] with specified timeout.
    ///
    /// The client has a default [commitment level][cl] of [`Finalized`](CommitmentLevel::Finalized).
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::SocketAddr;
    /// # use std::time::Duration;
    /// # use solana_client::rpc_client::RpcClient;
    /// let addr = SocketAddr::from(([127, 0, 0, 1], 8899));
    /// let timeout = Duration::from_secs(1);
    /// let client = RpcClient::new_socket_with_timeout(addr, timeout);
    /// ```
    pub fn new_socket_with_timeout(addr: SocketAddr, timeout: Duration) -> Self {
        let url = get_rpc_request_str(addr, false);
        Self::new_with_timeout(url, timeout)
    }

    fn get_node_version(&self) -> Result<semver::Version, RpcError> {
        let r_node_version = self.node_version.read().unwrap();
        if let Some(version) = &*r_node_version {
            Ok(version.clone())
        } else {
            drop(r_node_version);
            let mut w_node_version = self.node_version.write().unwrap();
            let node_version = self.get_version().map_err(|e| {
                RpcError::RpcRequestError(format!("cluster version query failed: {}", e))
            })?;
            let node_version = semver::Version::parse(&node_version.solana_core).map_err(|e| {
                RpcError::RpcRequestError(format!("failed to parse cluster version: {}", e))
            })?;
            *w_node_version = Some(node_version.clone());
            Ok(node_version)
        }
    }

    /// Get the configured default [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// The commitment config may be specified during construction, and
    /// determines how thoroughly committed a transaction must be when waiting
    /// for its confirmation or otherwise checking for confirmation. If not
    /// specified, the default commitment level is
    /// [`Finalized`](CommitmentLevel::Finalized).
    ///
    /// The default commitment level is overridden when calling methods that
    /// explicitly provide a [`CommitmentConfig`], like
    /// [`RpcClient::confirm_transaction_with_commitment`].
    pub fn commitment(&self) -> CommitmentConfig {
        self.config.commitment_config
    }

    // to keep interface compatible with solana
    #[allow(clippy::unnecessary_wraps)]
    fn use_deprecated_commitment(&self) -> Result<bool, RpcError> {
        Ok(false)
    }

    fn maybe_map_commitment(
        &self,
        requested_commitment: CommitmentConfig,
    ) -> Result<CommitmentConfig, RpcError> {
        if matches!(
            requested_commitment.commitment,
            CommitmentLevel::Finalized | CommitmentLevel::Confirmed | CommitmentLevel::Processed
        ) && self.use_deprecated_commitment()?
        {
            return Ok(CommitmentConfig::use_deprecated_commitment(
                requested_commitment,
            ));
        }
        Ok(requested_commitment)
    }

    #[allow(deprecated)]
    fn maybe_map_request(&self, mut request: RpcRequest) -> Result<RpcRequest, RpcError> {
        if self.get_node_version()? < semver::Version::new(0, 6, 0) {
            request = match request {
                RpcRequest::GetBlock => RpcRequest::GetConfirmedBlock,
                RpcRequest::GetBlocks => RpcRequest::GetConfirmedBlocks,
                RpcRequest::GetBlocksWithLimit => RpcRequest::GetConfirmedBlocksWithLimit,
                RpcRequest::GetSignaturesForAddress => {
                    RpcRequest::GetConfirmedSignaturesForAddress2
                }
                RpcRequest::GetTransaction => RpcRequest::GetConfirmedTransaction,
                _ => request,
            };
        }
        Ok(request)
    }

    /// Submit a transaction and wait for confirmation.
    ///
    /// Once this function returns successfully, the given transaction is
    /// guaranteed to be processed with the configured [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// After sending the transaction, this method polls in a loop for the
    /// status of the transaction until it has ben confirmed.
    ///
    /// # Errors
    ///
    /// If the transaction is not signed then an error with kind [`RpcError`] is
    /// returned, containing an [`RpcResponseError`] with `code` set to
    /// [`JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE`].
    ///
    /// If the preflight transaction simulation fails then an error with kind
    /// [`RpcError`] is returned, containing an [`RpcResponseError`] with `code`
    /// set to [`JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE`].
    ///
    /// If the receiving node is unhealthy, e.g. it is not fully synced to
    /// the cluster, then an error with kind [`RpcError`] is returned,
    /// containing an [`RpcResponseError`] with `code` set to
    /// [`JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY`].
    ///
    /// [`RpcResponseError`]: RpcError::RpcResponseError
    /// [`JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE`]: crate::rpc_custom_error::JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE
    /// [`JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE`]: crate::rpc_custom_error::JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE
    /// [`JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY`]: crate::rpc_custom_error::JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`sendTransaction`] RPC method, and the
    /// [`getLatestBlockhash`] RPC method.
    ///
    /// [`sendTransaction`]: https://docs.solana.com/developing/clients/jsonrpc-api#sendtransaction
    /// [`getLatestBlockhash`]: https://docs.solana.com/developing/clients/jsonrpc-api#getlatestblockhash
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// # let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let signature = rpc_client.send_and_confirm_transaction(&tx)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn send_and_confirm_transaction_with_config(
        &self,
        transaction: &Transaction,
        config: RpcSendTransactionConfig,
    ) -> ClientResult<Signature> {
        const SEND_RETRIES: usize = 1;
        const GET_STATUS_RETRIES: usize = usize::MAX;

        'sending: for _ in 0..SEND_RETRIES {
            let signature = self.send_transaction_with_config(transaction, config)?;

            let recent_blockhash = if uses_durable_nonce(transaction).is_some() {
                let (recent_blockhash, ..) =
                    self.get_latest_blockhash_with_commitment(CommitmentConfig::processed())?;
                recent_blockhash
            } else {
                transaction.message.recent_blockhash
            };

            for status_retry in 0..GET_STATUS_RETRIES {
                match self.get_signature_status(&signature)? {
                    Some(Ok(_)) => return Ok(signature),
                    Some(Err(e)) => return Err(e.into()),
                    None => {
                        if !self
                            .is_blockhash_valid(&recent_blockhash, CommitmentConfig::processed())?
                        {
                            // Block hash is not found by some reason
                            break 'sending;
                        } else if cfg!(not(test))
                            // Ignore sleep at last step.
                            && status_retry < GET_STATUS_RETRIES
                        {
                            // Retry twice a second
                            sleep(Duration::from_millis(200));
                            continue;
                        }
                    }
                }
            }
        }

        Err(RpcError::ForUser(
            "unable to confirm transaction. \
             This can happen in situations such as transaction expiration \
             and insufficient fee-payer funds"
                .to_string(),
        )
        .into())
    }

    pub fn send_and_confirm_transaction(
        &self,
        transaction: &Transaction,
    ) -> ClientResult<Signature> {
        self.send_and_confirm_transaction_with_config(
            transaction,
            RpcSendTransactionConfig {
                preflight_commitment: Some(self.commitment().commitment),
                ..RpcSendTransactionConfig::default()
            },
        )
    }

    pub fn send_and_confirm_transaction_with_spinner(
        &self,
        transaction: &Transaction,
    ) -> ClientResult<Signature> {
        self.send_and_confirm_transaction_with_spinner_and_commitment(
            transaction,
            self.commitment(),
        )
    }

    pub fn send_and_confirm_transaction_with_spinner_and_commitment(
        &self,
        transaction: &Transaction,
        commitment: CommitmentConfig,
    ) -> ClientResult<Signature> {
        self.send_and_confirm_transaction_with_spinner_and_config(
            transaction,
            commitment,
            RpcSendTransactionConfig {
                preflight_commitment: Some(commitment.commitment),
                ..RpcSendTransactionConfig::default()
            },
        )
    }

    pub fn send_and_confirm_transaction_with_spinner_and_config(
        &self,
        transaction: &Transaction,
        commitment: CommitmentConfig,
        config: RpcSendTransactionConfig,
    ) -> ClientResult<Signature> {
        let recent_blockhash = if uses_durable_nonce(transaction).is_some() {
            self.get_latest_blockhash_with_commitment(CommitmentConfig::processed())?
                .0
        } else {
            transaction.message.recent_blockhash
        };
        let signature = self.send_transaction_with_config(transaction, config)?;
        self.confirm_transaction_with_spinner(&signature, &recent_blockhash, commitment)?;
        Ok(signature)
    }

    /// Submits a signed transaction to the network.
    ///
    /// Before a transaction is processed, the receiving node runs a "preflight
    /// check" which verifies signatures, checks that the node is healthy,
    /// and simulates the transaction. If the preflight check fails then an
    /// error is returned immediately. Preflight checks can be disabled by
    /// calling [`send_transaction_with_config`] and setting the
    /// [`skip_preflight`] field of [`RpcSendTransactionConfig`] to `true`.
    ///
    /// This method does not wait for the transaction to be processed or
    /// confirmed before returning successfully. To wait for the transaction to
    /// be processed or confirmed, use the [`send_and_confirm_transaction`]
    /// method.
    ///
    /// [`send_transaction_with_config`]: RpcClient::send_transaction_with_config
    /// [`skip_preflight`]: crate::rpc_config::RpcSendTransactionConfig::skip_preflight
    /// [`RpcSendTransactionConfig`]: crate::rpc_config::RpcSendTransactionConfig
    /// [`send_and_confirm_transaction`]: RpcClient::send_and_confirm_transaction
    ///
    /// # Errors
    ///
    /// If the transaction is not signed then an error with kind [`RpcError`] is
    /// returned, containing an [`RpcResponseError`] with `code` set to
    /// [`JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE`].
    ///
    /// If the preflight transaction simulation fails then an error with kind
    /// [`RpcError`] is returned, containing an [`RpcResponseError`] with `code`
    /// set to [`JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE`].
    ///
    /// If the receiving node is unhealthy, e.g. it is not fully synced to
    /// the cluster, then an error with kind [`RpcError`] is returned,
    /// containing an [`RpcResponseError`] with `code` set to
    /// [`JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY`].
    ///
    /// [`RpcResponseError`]: RpcError::RpcResponseError
    /// [`JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE`]: crate::rpc_custom_error::JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE
    /// [`JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE`]: crate::rpc_custom_error::JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE
    /// [`JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY`]: crate::rpc_custom_error::JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`sendTransaction`] RPC method.
    ///
    /// [`sendTransaction`]: https://docs.solana.com/developing/clients/jsonrpc-api#sendtransaction
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     hash::Hash,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Transfer lamports from Alice to Bob
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let signature = rpc_client.send_transaction(&tx)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn send_transaction(&self, transaction: &Transaction) -> ClientResult<Signature> {
        self.send_transaction_with_config(
            transaction,
            RpcSendTransactionConfig {
                preflight_commitment: Some(
                    self.maybe_map_commitment(self.commitment())?.commitment,
                ),
                ..RpcSendTransactionConfig::default()
            },
        )
    }

    /// Submits a signed transaction to the network.
    ///
    /// Before a transaction is processed, the receiving node runs a "preflight
    /// check" which verifies signatures, checks that the node is healthy, and
    /// simulates the transaction. If the preflight check fails then an error is
    /// returned immediately. Preflight checks can be disabled by setting the
    /// [`skip_preflight`] field of [`RpcSendTransactionConfig`] to `true`.
    ///
    /// This method does not wait for the transaction to be processed or
    /// confirmed before returning successfully. To wait for the transaction to
    /// be processed or confirmed, use the [`send_and_confirm_transaction`]
    /// method.
    ///
    /// [`send_transaction_with_config`]: RpcClient::send_transaction_with_config
    /// [`skip_preflight`]: crate::rpc_config::RpcSendTransactionConfig::skip_preflight
    /// [`RpcSendTransactionConfig`]: crate::rpc_config::RpcSendTransactionConfig
    /// [`send_and_confirm_transaction`]: RpcClient::send_and_confirm_transaction
    ///
    /// # Errors
    ///
    /// If preflight checks are enabled, if the transaction is not signed
    /// then an error with kind [`RpcError`] is returned, containing an
    /// [`RpcResponseError`] with `code` set to
    /// [`JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE`].
    ///
    /// If preflight checks are enabled, if the preflight transaction simulation
    /// fails then an error with kind [`RpcError`] is returned, containing an
    /// [`RpcResponseError`] with `code` set to
    /// [`JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE`].
    ///
    /// If the receiving node is unhealthy, e.g. it is not fully synced to
    /// the cluster, then an error with kind [`RpcError`] is returned,
    /// containing an [`RpcResponseError`] with `code` set to
    /// [`JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY`].
    ///
    /// [`RpcResponseError`]: RpcError::RpcResponseError
    /// [`JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE`]: crate::rpc_custom_error::JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE
    /// [`JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE`]: crate::rpc_custom_error::JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE
    /// [`JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY`]: crate::rpc_custom_error::JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`sendTransaction`] RPC method.
    ///
    /// [`sendTransaction`]: https://docs.solana.com/developing/clients/jsonrpc-api#sendtransaction
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// #     rpc_config::RpcSendTransactionConfig,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     hash::Hash,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Transfer lamports from Alice to Bob
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let config = RpcSendTransactionConfig {
    ///     skip_preflight: true,
    ///     .. RpcSendTransactionConfig::default()
    /// };
    /// let signature = rpc_client.send_transaction_with_config(
    ///     &tx,
    ///     config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn send_transaction_with_config(
        &self,
        transaction: &Transaction,
        config: RpcSendTransactionConfig,
    ) -> ClientResult<Signature> {
        let encoding = if let Some(encoding) = config.encoding {
            encoding
        } else {
            self.default_cluster_transaction_encoding()?
        };
        let preflight_commitment = CommitmentConfig {
            commitment: config.preflight_commitment.unwrap_or_default(),
        };
        let preflight_commitment = self.maybe_map_commitment(preflight_commitment)?;
        let config = RpcSendTransactionConfig {
            encoding: Some(encoding),
            preflight_commitment: Some(preflight_commitment.commitment),
            ..config
        };
        let serialized_encoded = serialize_and_encode::<Transaction>(transaction, encoding)?;
        let signature_base58_str: String = match self.send(
            RpcRequest::SendTransaction,
            json!([serialized_encoded, config]),
        ) {
            Ok(signature_base58_str) => signature_base58_str,
            Err(err) => {
                if let ClientErrorKind::RpcError(RpcError::RpcResponseError {
                    code,
                    message,
                    data,
                    original_err: _original_err,
                }) = &err.kind
                {
                    debug!("{} {}", code, message);
                    if let RpcResponseErrorData::SendTransactionPreflightFailure(
                        RpcSimulateTransactionResult {
                            logs: Some(logs), ..
                        },
                    ) = data
                    {
                        for (i, log) in logs.iter().enumerate() {
                            debug!("{:>3}: {}", i + 1, log);
                        }
                        debug!("");
                    }
                }
                return Err(err);
            }
        };

        let signature = signature_base58_str
            .parse::<Signature>()
            .map_err(|err| Into::<ClientError>::into(RpcError::ParseError(err.to_string())))?;
        // A mismatching RPC response signature indicates an issue with the RPC node, and
        // should not be passed along to confirmation methods. The transaction may or may
        // not have been submitted to the cluster, so callers should verify the success of
        // the correct transaction signature independently.
        if signature != transaction.signatures[0] {
            Err(RpcError::RpcRequestError(format!(
                "RPC node returned mismatched signature {:?}, expected {:?}",
                signature, transaction.signatures[0]
            ))
            .into())
        } else {
            Ok(transaction.signatures[0])
        }
    }

    pub fn send<T>(&self, request: RpcRequest, params: Value) -> ClientResult<T>
    where
        T: serde::de::DeserializeOwned,
    {
        assert!(params.is_array() || params.is_null());

        let response = self
            .sender
            .send(request, params)
            .map_err(|err| err.into_with_request(request))?;
        serde_json::from_value(response)
            .map_err(|err| ClientError::new_with_request(err.into(), request))
    }

    /// Check the confirmation status of a transaction.
    ///
    /// Returns `true` if the given transaction succeeded and has been committed
    /// with the configured [commitment level][cl], which can be retrieved with
    /// the [`commitment`](RpcClient::commitment) method.
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// Note that this method does not wait for a transaction to be confirmed
    /// &mdash; it only checks whether a transaction has been confirmed. To
    /// submit a transaction and wait for it to confirm, use
    /// [`send_and_confirm_transaction`][RpcClient::send_and_confirm_transaction].
    ///
    /// _This method returns `false` if the transaction failed, even if it has
    /// been confirmed._
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getSignatureStatuses`] RPC method.
    ///
    /// [`getSignatureStatuses`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturestatuses
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Transfer lamports from Alice to Bob and wait for confirmation
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let signature = rpc_client.send_transaction(&tx)?;
    ///
    /// loop {
    ///     let confirmed = rpc_client.confirm_transaction(&signature)?;
    ///     if confirmed {
    ///         break;
    ///     }
    /// }
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn confirm_transaction(&self, signature: &Signature) -> ClientResult<bool> {
        Ok(self
            .confirm_transaction_with_commitment(signature, self.commitment())?
            .value)
    }

    /// Check the confirmation status of a transaction.
    ///
    /// Returns an [`RpcResult`] with value `true` if the given transaction
    /// succeeded and has been committed with the given [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// Note that this method does not wait for a transaction to be confirmed
    /// &mdash; it only checks whether a transaction has been confirmed. To
    /// submit a transaction and wait for it to confirm, use
    /// [`send_and_confirm_transaction`][RpcClient::send_and_confirm_transaction].
    ///
    /// _This method returns an [`RpcResult`] with value `false` if the
    /// transaction failed, even if it has been confirmed._
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getSignatureStatuses`] RPC method.
    ///
    /// [`getSignatureStatuses`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturestatuses
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_sdk::{
    /// #     commitment_config::CommitmentConfig,
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     system_transaction,
    /// # };
    /// # use std::time::Duration;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Transfer lamports from Alice to Bob and wait for confirmation
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let signature = rpc_client.send_transaction(&tx)?;
    ///
    /// loop {
    ///     let commitment_config = CommitmentConfig::processed();
    ///     let confirmed = rpc_client.confirm_transaction_with_commitment(&signature, commitment_config)?;
    ///     if confirmed.value {
    ///         break;
    ///     }
    /// }
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn confirm_transaction_with_commitment(
        &self,
        signature: &Signature,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<bool> {
        let Response { context, value } = self.get_signature_statuses(&[*signature])?;

        Ok(Response {
            context,
            value: value[0]
                .as_ref()
                .filter(|result| result.satisfies_commitment(commitment_config))
                .map(|result| result.status.is_ok())
                .unwrap_or_default(),
        })
    }

    pub fn confirm_transaction_with_spinner(
        &self,
        signature: &Signature,
        recent_blockhash: &Hash,
        commitment: CommitmentConfig,
    ) -> ClientResult<()> {
        let desired_confirmations = if commitment.is_finalized() {
            MAX_LOCKOUT_HISTORY + 1
        } else {
            1
        };
        let mut confirmations = 0;

        let progress_bar = spinner::new_progress_bar();

        progress_bar.set_message(format!(
            "[{}/{}] Finalizing transaction {}",
            confirmations, desired_confirmations, signature,
        ));

        let now = Instant::now();
        let confirm_transaction_initial_timeout = self
            .config
            .confirm_transaction_initial_timeout
            .unwrap_or_default();
        let (signature, status) = loop {
            // Get recent commitment in order to count confirmations for successful transactions
            let status = self
                .get_signature_status_with_commitment(signature, CommitmentConfig::processed())?;
            if status.is_none() {
                let blockhash_not_found =
                    !self.is_blockhash_valid(recent_blockhash, CommitmentConfig::processed())?;
                if blockhash_not_found && now.elapsed() >= confirm_transaction_initial_timeout {
                    break (signature, status);
                }
            } else {
                break (signature, status);
            }

            if cfg!(not(test)) {
                sleep(Duration::from_millis(500));
            }
        };
        if let Some(result) = status {
            if let Err(err) = result {
                return Err(err.into());
            }
        } else {
            return Err(RpcError::ForUser(
                "unable to confirm transaction. \
                                      This can happen in situations such as transaction expiration \
                                      and insufficient fee-payer funds"
                    .to_string(),
            )
            .into());
        }
        let now = Instant::now();
        loop {
            // Return when specified commitment is reached
            // Failed transactions have already been eliminated, `is_some` check is sufficient
            if self
                .get_signature_status_with_commitment(signature, commitment)?
                .is_some()
            {
                progress_bar.set_message("Transaction confirmed");
                progress_bar.finish_and_clear();
                return Ok(());
            }

            progress_bar.set_message(format!(
                "[{}/{}] Finalizing transaction {}",
                min(confirmations + 1, desired_confirmations),
                desired_confirmations,
                signature,
            ));
            sleep(Duration::from_millis(500));
            confirmations = self
                .get_num_blocks_since_signature_confirmation(signature)
                .unwrap_or(confirmations);
            if now.elapsed().as_secs() >= MAX_HASH_AGE_IN_SECONDS as u64 {
                return Err(
                    RpcError::ForUser("transaction not finalized. \
                                      This can happen when a transaction lands in an abandoned fork. \
                                      Please retry.".to_string()).into(),
                );
            }
        }
    }

    fn default_cluster_transaction_encoding(&self) -> Result<UiTransactionEncoding, RpcError> {
        if self.get_node_version()? < semver::Version::new(1, 3, 16) {
            Ok(UiTransactionEncoding::Base58)
        } else {
            Ok(UiTransactionEncoding::Base64)
        }
    }

    /// Simulates sending a transaction.
    ///
    /// If the transaction fails, then the [`err`] field of the returned
    /// [`RpcSimulateTransactionResult`] will be `Some`. Any logs emitted from
    /// the transaction are returned in the [`logs`] field.
    ///
    /// [`err`]: crate::rpc_response::RpcSimulateTransactionResult::err
    /// [`logs`]: crate::rpc_response::RpcSimulateTransactionResult::logs
    ///
    /// Simulating a transaction is similar to the ["preflight check"] that is
    /// run by default when sending a transaction.
    ///
    /// ["preflight check"]: https://docs.solana.com/developing/clients/jsonrpc-api#sendtransaction
    ///
    /// By default, signatures are not verified during simulation. To verify
    /// signatures, call the [`simulate_transaction_with_config`] method, with
    /// the [`sig_verify`] field of [`RpcSimulateTransactionConfig`] set to
    /// `true`.
    ///
    /// [`simulate_transaction_with_config`]: RpcClient::simulate_transaction_with_config
    /// [`sig_verify`]: crate::rpc_config::RpcSimulateTransactionConfig::sig_verify
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`simulateTransaction`] RPC method.
    ///
    /// [`simulateTransaction`]: https://docs.solana.com/developing/clients/jsonrpc-api#simulatetransaction
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// #     rpc_response::RpcSimulateTransactionResult,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     hash::Hash,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Transfer lamports from Alice to Bob
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let result = rpc_client.simulate_transaction(&tx)?;
    /// assert!(result.value.err.is_none());
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn simulate_transaction(
        &self,
        transaction: &Transaction,
    ) -> RpcResult<RpcSimulateTransactionResult> {
        self.simulate_transaction_with_config(
            transaction,
            RpcSimulateTransactionConfig {
                commitment: Some(self.commitment()),
                ..RpcSimulateTransactionConfig::default()
            },
        )
    }

    /// Simulates sending a transaction.
    ///
    /// If the transaction fails, then the [`err`] field of the returned
    /// [`RpcSimulateTransactionResult`] will be `Some`. Any logs emitted from
    /// the transaction are returned in the [`logs`] field.
    ///
    /// [`err`]: crate::rpc_response::RpcSimulateTransactionResult::err
    /// [`logs`]: crate::rpc_response::RpcSimulateTransactionResult::logs
    ///
    /// Simulating a transaction is similar to the ["preflight check"] that is
    /// run by default when sending a transaction.
    ///
    /// ["preflight check"]: https://docs.solana.com/developing/clients/jsonrpc-api#sendtransaction
    ///
    /// By default, signatures are not verified during simulation. To verify
    /// signatures, call the [`simulate_transaction_with_config`] method, with
    /// the [`sig_verify`] field of [`RpcSimulateTransactionConfig`] set to
    /// `true`.
    ///
    /// [`simulate_transaction_with_config`]: RpcClient::simulate_transaction_with_config
    /// [`sig_verify`]: crate::rpc_config::RpcSimulateTransactionConfig::sig_verify
    ///
    /// This method can additionally query information about accounts by
    /// including them in the [`accounts`] field of the
    /// [`RpcSimulateTransactionConfig`] argument, in which case those results
    /// are reported in the [`accounts`][accounts2] field of the returned
    /// [`RpcSimulateTransactionResult`].
    ///
    /// [`accounts`]: crate::rpc_config::RpcSimulateTransactionConfig::accounts
    /// [accounts2]: crate::rpc_response::RpcSimulateTransactionResult::accounts
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`simulateTransaction`] RPC method.
    ///
    /// [`simulateTransaction`]: https://docs.solana.com/developing/clients/jsonrpc-api#simulatetransaction
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// #     rpc_config::RpcSimulateTransactionConfig,
    /// #     rpc_response::RpcSimulateTransactionResult,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     hash::Hash,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Transfer lamports from Alice to Bob
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let config = RpcSimulateTransactionConfig {
    ///     sig_verify: true,
    ///     .. RpcSimulateTransactionConfig::default()
    /// };
    /// let result = rpc_client.simulate_transaction_with_config(
    ///     &tx,
    ///     config,
    /// )?;
    /// assert!(result.value.err.is_none());
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn simulate_transaction_with_config(
        &self,
        transaction: &Transaction,
        config: RpcSimulateTransactionConfig,
    ) -> RpcResult<RpcSimulateTransactionResult> {
        let encoding = if let Some(encoding) = config.encoding {
            encoding
        } else {
            self.default_cluster_transaction_encoding()?
        };
        let commitment = config.commitment.unwrap_or_default();
        let commitment = self.maybe_map_commitment(commitment)?;
        let config = RpcSimulateTransactionConfig {
            encoding: Some(encoding),
            commitment: Some(commitment),
            ..config
        };
        let serialized_encoded = serialize_and_encode::<Transaction>(transaction, encoding)?;
        self.send(
            RpcRequest::SimulateTransaction,
            json!([serialized_encoded, config]),
        )
    }

    /// Returns the highest slot information that the node has snapshots for.
    ///
    /// This will find the highest full snapshot slot, and the highest incremental snapshot slot
    /// _based on_ the full snapshot slot, if there is one.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getHighestSnapshotSlot`] RPC method.
    ///
    /// [`getHighestSnapshotSlot`]: https://docs.solana.com/developing/clients/jsonrpc-api#gethighestsnapshotslot
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let snapshot_slot_info = rpc_client.get_highest_snapshot_slot()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_highest_snapshot_slot(&self) -> ClientResult<RpcSnapshotSlotInfo> {
        if self.get_node_version()? < semver::Version::new(0, 6, 0) {
            #[allow(deprecated)]
            self.get_snapshot_slot().map(|full| RpcSnapshotSlotInfo {
                full,
                incremental: None,
            })
        } else {
            self.send(RpcRequest::GetHighestSnapshotSlot, Value::Null)
        }
    }

    #[deprecated(
        since = "1.8.0",
        note = "Please use RpcClient::get_highest_snapshot_slot() instead"
    )]
    #[allow(deprecated)]
    pub fn get_snapshot_slot(&self) -> ClientResult<Slot> {
        self.send(RpcRequest::GetSnapshotSlot, Value::Null)
    }

    /// Check if a transaction has been processed with the default [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// If the transaction has been processed with the default commitment level,
    /// then this method returns `Ok` of `Some`. If the transaction has not yet
    /// been processed with the default commitment level, it returns `Ok` of
    /// `None`.
    ///
    /// If the transaction has been processed with the default commitment level,
    /// and the transaction succeeded, this method returns `Ok(Some(Ok(())))`.
    /// If the transaction has peen processed with the default commitment level,
    /// and the transaction failed, this method returns `Ok(Some(Err(_)))`,
    /// where the interior error is type [`TransactionError`].
    ///
    /// [`TransactionError`]: solana_sdk::transaction::TransactionError
    ///
    /// This function only searches a node's recent history, including all
    /// recent slots, plus up to
    /// [`MAX_RECENT_BLOCKHASHES`][solana_sdk::clock::MAX_RECENT_BLOCKHASHES]
    /// rooted slots. To search the full transaction history use the
    /// [`get_signature_statuse_with_commitment_and_history`][RpcClient::get_signature_status_with_commitment_and_history]
    /// method.
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getSignatureStatuses`] RPC method.
    ///
    /// [`getSignatureStatuses`]: https://docs.solana.com/developing/clients/jsonrpc-api#gitsignaturestatuses
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     hash::Hash,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// # let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// # let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let signature = rpc_client.send_transaction(&tx)?;
    /// let status = rpc_client.get_signature_status(&signature)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_signature_status(
        &self,
        signature: &Signature,
    ) -> ClientResult<Option<transaction::Result<()>>> {
        self.get_signature_status_with_commitment(signature, self.commitment())
    }

    /// Gets the statuses of a list of transaction signatures.
    ///
    /// The returned vector of [`TransactionStatus`] has the same length as the
    /// input slice.
    ///
    /// For any transaction that has not been processed by the network, the
    /// value of the corresponding entry in the returned vector is `None`. As a
    /// result, a transaction that has recently been submitted will not have a
    /// status immediately.
    ///
    /// To submit a transaction and wait for it to confirm, use
    /// [`send_and_confirm_transaction`][RpcClient::send_and_confirm_transaction].
    ///
    /// This function ignores the configured confirmation level, and returns the
    /// transaction status whatever it is. It does not wait for transactions to
    /// be processed.
    ///
    /// This function only searches a node's recent history, including all
    /// recent slots, plus up to
    /// [`MAX_RECENT_BLOCKHASHES`][solana_sdk::clock::MAX_RECENT_BLOCKHASHES]
    /// rooted slots. To search the full transaction history use the
    /// [`get_signature_statuses_with_history`][RpcClient::get_signature_statuses_with_history]
    /// method.
    ///
    /// # Errors
    ///
    /// Any individual `TransactionStatus` may have triggered an error during
    /// processing, in which case its [`err`][`TransactionStatus::err`] field
    /// will be `Some`.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getSignatureStatuses`] RPC method.
    ///
    /// [`getSignatureStatuses`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturestatuses
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     hash::Hash,
    /// #     system_transaction,
    /// # };
    /// # use std::time::Duration;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// // Send lamports from Alice to Bob and wait for the transaction to be processed
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let signature = rpc_client.send_transaction(&tx)?;
    ///
    /// let status = loop {
    ///    let statuses = rpc_client.get_signature_statuses(&[signature])?.value;
    ///    if let Some(status) = statuses[0].clone() {
    ///        break status;
    ///    }
    ///    std::thread::sleep(Duration::from_millis(100));
    /// };
    ///
    /// assert!(status.err.is_none());
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_signature_statuses(
        &self,
        signatures: &[Signature],
    ) -> RpcResult<Vec<Option<TransactionStatus>>> {
        let signatures: Vec<_> = signatures.iter().map(|s| s.to_string()).collect();
        self.send(RpcRequest::GetSignatureStatuses, json!([signatures]))
    }

    /// Gets the statuses of a list of transaction signatures.
    ///
    /// The returned vector of [`TransactionStatus`] has the same length as the
    /// input slice.
    ///
    /// For any transaction that has not been processed by the network, the
    /// value of the corresponding entry in the returned vector is `None`. As a
    /// result, a transaction that has recently been submitted will not have a
    /// status immediately.
    ///
    /// To submit a transaction and wait for it to confirm, use
    /// [`send_and_confirm_transaction`][RpcClient::send_and_confirm_transaction].
    ///
    /// This function ignores the configured confirmation level, and returns the
    /// transaction status whatever it is. It does not wait for transactions to
    /// be processed.
    ///
    /// This function searches a node's full ledger history and (if implemented) long-term storage. To search for
    /// transactions in recent slots only use the
    /// [`get_signature_statuses`][RpcClient::get_signature_statuses] method.
    ///
    /// # Errors
    ///
    /// Any individual `TransactionStatus` may have triggered an error during
    /// processing, in which case its [`err`][`TransactionStatus::err`] field
    /// will be `Some`.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getSignatureStatuses`] RPC
    /// method, with the `searchTransactionHistory` configuration option set to
    /// `true`.
    ///
    /// [`getSignatureStatuses`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturestatuses
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     hash::Hash,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # fn get_old_transaction_signature() -> Signature { Signature::default() }
    /// // Check if an old transaction exists
    /// let signature = get_old_transaction_signature();
    /// let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// let statuses = rpc_client.get_signature_statuses_with_history(&[signature])?.value;
    /// if statuses[0].is_none() {
    ///     println!("old transaction does not exist");
    /// }
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_signature_statuses_with_history(
        &self,
        signatures: &[Signature],
    ) -> RpcResult<Vec<Option<TransactionStatus>>> {
        let signatures: Vec<_> = signatures.iter().map(|s| s.to_string()).collect();
        self.send(
            RpcRequest::GetSignatureStatuses,
            json!([signatures, {
                "searchTransactionHistory": true
            }]),
        )
    }

    /// Check if a transaction has been processed with the given [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// If the transaction has been processed with the given commitment level,
    /// then this method returns `Ok` of `Some`. If the transaction has not yet
    /// been processed with the given commitment level, it returns `Ok` of
    /// `None`.
    ///
    /// If the transaction has been processed with the given commitment level,
    /// and the transaction succeeded, this method returns `Ok(Some(Ok(())))`.
    /// If the transaction has peen processed with the given commitment level,
    /// and the transaction failed, this method returns `Ok(Some(Err(_)))`,
    /// where the interior error is type [`TransactionError`].
    ///
    /// [`TransactionError`]: solana_sdk::transaction::TransactionError
    ///
    /// This function only searches a node's recent history, including all
    /// recent slots, plus up to
    /// [`MAX_RECENT_BLOCKHASHES`][solana_sdk::clock::MAX_RECENT_BLOCKHASHES]
    /// rooted slots. To search the full transaction history use the
    /// [`get_signature_statuse_with_commitment_and_history`][RpcClient::get_signature_status_with_commitment_and_history]
    /// method.
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getSignatureStatuses`] RPC method.
    ///
    /// [`getSignatureStatuses`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturestatuses
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     commitment_config::CommitmentConfig,
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// # let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// # let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let signature = rpc_client.send_and_confirm_transaction(&tx)?;
    /// let commitment_config = CommitmentConfig::processed();
    /// let status = rpc_client.get_signature_status_with_commitment(
    ///     &signature,
    ///     commitment_config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_signature_status_with_commitment(
        &self,
        signature: &Signature,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<Option<transaction::Result<()>>> {
        let result: Response<Vec<Option<TransactionStatus>>> = self.send(
            RpcRequest::GetSignatureStatuses,
            json!([[signature.to_string()]]),
        )?;
        Ok(result.value[0]
            .clone()
            .filter(|result| result.satisfies_commitment(commitment_config))
            .map(|status_meta| status_meta.status))
    }

    /// Check if a transaction has been processed with the given [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// If the transaction has been processed with the given commitment level,
    /// then this method returns `Ok` of `Some`. If the transaction has not yet
    /// been processed with the given commitment level, it returns `Ok` of
    /// `None`.
    ///
    /// If the transaction has been processed with the given commitment level,
    /// and the transaction succeeded, this method returns `Ok(Some(Ok(())))`.
    /// If the transaction has peen processed with the given commitment level,
    /// and the transaction failed, this method returns `Ok(Some(Err(_)))`,
    /// where the interior error is type [`TransactionError`].
    ///
    /// [`TransactionError`]: solana_sdk::transaction::TransactionError
    ///
    /// This method optionally searches a node's full ledger history and (if
    /// implemented) long-term storage.
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getSignatureStatuses`] RPC method.
    ///
    /// [`getSignatureStatuses`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturestatuses
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     commitment_config::CommitmentConfig,
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// # let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// # let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let signature = rpc_client.send_transaction(&tx)?;
    /// let commitment_config = CommitmentConfig::processed();
    /// let search_transaction_history = true;
    /// let status = rpc_client.get_signature_status_with_commitment_and_history(
    ///     &signature,
    ///     commitment_config,
    ///     search_transaction_history,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_signature_status_with_commitment_and_history(
        &self,
        signature: &Signature,
        commitment_config: CommitmentConfig,
        search_transaction_history: bool,
    ) -> ClientResult<Option<transaction::Result<()>>> {
        let result: Response<Vec<Option<TransactionStatus>>> = self.send(
            RpcRequest::GetSignatureStatuses,
            json!([[signature.to_string()], {
                "searchTransactionHistory": search_transaction_history
            }]),
        )?;
        Ok(result.value[0]
            .clone()
            .filter(|result| result.satisfies_commitment(commitment_config))
            .map(|status_meta| status_meta.status))
    }

    /// Returns the slot that has reached the configured [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getSlot`] RPC method.
    ///
    /// [`getSlot`]: https://docs.solana.com/developing/clients/jsonrpc-api#getslot
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let slot = rpc_client.get_slot()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_slot(&self) -> ClientResult<Slot> {
        self.get_slot_with_commitment(self.commitment())
    }

    /// Returns the slot that has reached the given [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getSlot`] RPC method.
    ///
    /// [`getSlot`]: https://docs.solana.com/developing/clients/jsonrpc-api#getslot
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let commitment_config = CommitmentConfig::processed();
    /// let slot = rpc_client.get_slot_with_commitment(commitment_config)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_slot_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<Slot> {
        self.send(
            RpcRequest::GetSlot,
            json!([self.maybe_map_commitment(commitment_config)?]),
        )
    }

    /// Returns the block height that has reached the configured [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method is corresponds directly to the [`getBlockHeight`] RPC method.
    ///
    /// [`getBlockHeight`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblockheight
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let block_height = rpc_client.get_block_height()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_block_height(&self) -> ClientResult<u64> {
        self.get_block_height_with_commitment(self.commitment())
    }

    /// Returns the block height that has reached the given [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method is corresponds directly to the [`getBlockHeight`] RPC method.
    ///
    /// [`getBlockHeight`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblockheight
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let commitment_config = CommitmentConfig::processed();
    /// let block_height = rpc_client.get_block_height_with_commitment(
    ///     commitment_config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_block_height_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<u64> {
        self.send(
            RpcRequest::GetBlockHeight,
            json!([self.maybe_map_commitment(commitment_config)?]),
        )
    }

    /// Returns the slot leaders for a given slot range.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getSlotLeaders`] RPC method.
    ///
    /// [`getSlotLeaders`]: https://docs.solana.com/developing/clients/jsonrpc-api#getslotleaders
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::slot_history::Slot;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let start_slot = 1;
    /// let limit = 3;
    /// let leaders = rpc_client.get_slot_leaders(start_slot, limit)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_slot_leaders(&self, start_slot: Slot, limit: u64) -> ClientResult<Vec<Pubkey>> {
        self.send(RpcRequest::GetSlotLeaders, json!([start_slot, limit]))
            .and_then(|slot_leaders: Vec<String>| {
                slot_leaders
                    .iter()
                    .map(|slot_leader| {
                        Pubkey::from_str(slot_leader).map_err(|err| {
                            ClientErrorKind::Custom(format!(
                                "pubkey deserialization failed: {}",
                                err
                            ))
                            .into()
                        })
                    })
                    .collect()
            })
    }

    /// Get block production for the current epoch.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBlockProduction`] RPC method.
    ///
    /// [`getBlockProduction`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblockproduction
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let production = rpc_client.get_block_production()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_block_production(&self) -> RpcResult<RpcBlockProduction> {
        self.send(RpcRequest::GetBlockProduction, Value::Null)
    }

    /// Get block production for the current or previous epoch.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBlockProduction`] RPC method.
    ///
    /// [`getBlockProduction`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblockproduction
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// #     rpc_config::RpcBlockProductionConfig,
    /// #     rpc_config::RpcBlockProductionConfigRange,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     commitment_config::CommitmentConfig,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let start_slot = 1;
    /// # let limit = 3;
    /// let leader = rpc_client.get_slot_leaders(start_slot, limit)?;
    /// let leader = leader[0];
    /// let range = RpcBlockProductionConfigRange {
    ///     first_slot: start_slot,
    ///     last_slot: Some(start_slot + limit),
    /// };
    /// let config = RpcBlockProductionConfig {
    ///     identity: Some(leader.to_string()),
    ///     range: Some(range),
    ///     commitment: Some(CommitmentConfig::processed()),
    /// };
    /// let production = rpc_client.get_block_production_with_config(
    ///     config
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_block_production_with_config(
        &self,
        config: RpcBlockProductionConfig,
    ) -> RpcResult<RpcBlockProduction> {
        self.send(RpcRequest::GetBlockProduction, json!([config]))
    }

    /// Returns epoch activation information for a stake account.
    ///
    /// This method uses the configured [commitment level].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getStakeActivation`] RPC method.
    ///
    /// [`getStakeActivation`]: https://docs.solana.com/developing/clients/jsonrpc-api#getstakeactivation
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// #     rpc_response::StakeActivationState,
    /// # };
    /// # use solana_sdk::{
    /// #     signer::keypair::Keypair,
    /// #     signature::Signer,
    /// #     pubkey::Pubkey,
    /// #     stake,
    /// #     stake::state::{Authorized, Lockup},
    /// #     transaction::Transaction
    /// # };
    /// # use std::str::FromStr;
    /// # let alice = Keypair::new();
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Find some vote account to delegate to
    /// let vote_accounts = rpc_client.get_vote_accounts()?;
    /// let vote_account = vote_accounts.current.get(0).unwrap_or_else(|| &vote_accounts.delinquent[0]);
    /// let vote_account_pubkey = &vote_account.vote_pubkey;
    /// let vote_account_pubkey = Pubkey::from_str(vote_account_pubkey).expect("pubkey");
    ///
    /// // Create a stake account
    /// let stake_account = Keypair::new();
    /// let stake_account_pubkey = stake_account.pubkey();
    ///
    /// // Build the instructions to create new stake account,
    /// // funded by alice, and delegate to a validator's vote account.
    /// let instrs = stake::instruction::create_account_and_delegate_stake(
    ///     &alice.pubkey(),
    ///     &stake_account_pubkey,
    ///     &vote_account_pubkey,
    ///     &Authorized::auto(&stake_account_pubkey),
    ///     &Lockup::default(),
    ///     1_000_000,
    /// );
    ///
    /// let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// let tx = Transaction::new_signed_with_payer(
    ///     &instrs,
    ///     Some(&alice.pubkey()),
    ///     &[&alice, &stake_account],
    ///     latest_blockhash,
    /// );
    ///
    /// rpc_client.send_and_confirm_transaction(&tx)?;
    ///
    /// let epoch_info = rpc_client.get_epoch_info()?;
    /// let activation = rpc_client.get_stake_activation(
    ///     stake_account_pubkey,
    ///     Some(epoch_info.epoch),
    /// )?;
    ///
    /// assert_eq!(activation.state, StakeActivationState::Activating);
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_stake_activation(
        &self,
        stake_account: Pubkey,
        epoch: Option<Epoch>,
    ) -> ClientResult<RpcStakeActivation> {
        self.send(
            RpcRequest::GetStakeActivation,
            json!([
                stake_account.to_string(),
                RpcEpochConfig {
                    epoch,
                    commitment: Some(self.commitment()),
                }
            ]),
        )
    }

    /// Returns information about the current supply.
    ///
    /// This method uses the configured [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getSupply`] RPC method.
    ///
    /// [`getSupply`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsupply
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let supply = rpc_client.supply()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn supply(&self) -> RpcResult<RpcSupply> {
        self.supply_with_commitment(self.commitment())
    }

    /// Returns information about the current supply.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getSupply`] RPC method.
    ///
    /// [`getSupply`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsupply
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let commitment_config = CommitmentConfig::processed();
    /// let supply = rpc_client.supply_with_commitment(
    ///     commitment_config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn supply_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<RpcSupply> {
        self.send(
            RpcRequest::GetSupply,
            json!([self.maybe_map_commitment(commitment_config)?]),
        )
    }

    /// Returns the 20 largest accounts, by lamport balance.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getLargestAccounts`] RPC
    /// method.
    ///
    /// [`getLargestAccounts`]: https://docs.solana.com/developing/clients/jsonrpc-api#getlargestaccounts
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// #     rpc_config::RpcLargestAccountsConfig,
    /// #     rpc_config::RpcLargestAccountsFilter,
    /// # };
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let commitment_config = CommitmentConfig::processed();
    /// let config = RpcLargestAccountsConfig {
    ///     commitment: Some(commitment_config),
    ///     filter: Some(RpcLargestAccountsFilter::Circulating),
    /// };
    /// let accounts = rpc_client.get_largest_accounts_with_config(
    ///     config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_largest_accounts_with_config(
        &self,
        config: RpcLargestAccountsConfig,
    ) -> RpcResult<Vec<RpcAccountBalance>> {
        let commitment = config.commitment.unwrap_or_default();
        let commitment = self.maybe_map_commitment(commitment)?;
        let config = RpcLargestAccountsConfig {
            commitment: Some(commitment),
            ..config
        };
        self.send(RpcRequest::GetLargestAccounts, json!([config]))
    }

    /// Returns the account info and associated stake for all the voting accounts
    /// that have reached the configured [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getVoteAccounts`]
    /// RPC method.
    ///
    /// [`getVoteAccounts`]: https://docs.solana.com/developing/clients/jsonrpc-api#getvoteaccounts
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let accounts = rpc_client.get_vote_accounts()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_vote_accounts(&self) -> ClientResult<RpcVoteAccountStatus> {
        self.get_vote_accounts_with_commitment(self.commitment())
    }

    /// Returns the account info and associated stake for all the voting accounts
    /// that have reached the given [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getVoteAccounts`] RPC method.
    ///
    /// [`getVoteAccounts`]: https://docs.solana.com/developing/clients/jsonrpc-api#getvoteaccounts
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let commitment_config = CommitmentConfig::processed();
    /// let accounts = rpc_client.get_vote_accounts_with_commitment(
    ///     commitment_config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_vote_accounts_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<RpcVoteAccountStatus> {
        self.get_vote_accounts_with_config(RpcGetVoteAccountsConfig {
            commitment: Some(self.maybe_map_commitment(commitment_config)?),
            ..RpcGetVoteAccountsConfig::default()
        })
    }

    /// Returns the account info and associated stake for all the voting accounts
    /// that have reached the given [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getVoteAccounts`] RPC method.
    ///
    /// [`getVoteAccounts`]: https://docs.solana.com/developing/clients/jsonrpc-api#getvoteaccounts
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// #     rpc_config::RpcGetVoteAccountsConfig,
    /// # };
    /// # use solana_sdk::{
    /// #     signer::keypair::Keypair,
    /// #     signature::Signer,
    /// #     commitment_config::CommitmentConfig,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let vote_keypair = Keypair::new();
    /// let vote_pubkey = vote_keypair.pubkey();
    /// let commitment = CommitmentConfig::processed();
    /// let config = RpcGetVoteAccountsConfig {
    ///     vote_pubkey: Some(vote_pubkey.to_string()),
    ///     commitment: Some(commitment),
    ///     keep_unstaked_delinquents: Some(true),
    ///     delinquent_slot_distance: Some(10),
    /// };
    /// let accounts = rpc_client.get_vote_accounts_with_config(
    ///     config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_vote_accounts_with_config(
        &self,
        config: RpcGetVoteAccountsConfig,
    ) -> ClientResult<RpcVoteAccountStatus> {
        self.send(RpcRequest::GetVoteAccounts, json!([config]))
    }

    pub fn wait_for_max_stake(
        &self,
        commitment: CommitmentConfig,
        max_stake_percent: f32,
    ) -> ClientResult<()> {
        let mut current_percent;
        loop {
            let vote_accounts = self.get_vote_accounts_with_commitment(commitment)?;

            let mut max = 0;
            let total_active_stake = vote_accounts
                .current
                .iter()
                .chain(vote_accounts.delinquent.iter())
                .map(|vote_account| {
                    max = std::cmp::max(max, vote_account.activated_stake);
                    vote_account.activated_stake
                })
                .sum::<u64>();
            current_percent = 100f32 * max as f32 / total_active_stake as f32;
            if current_percent < max_stake_percent {
                break;
            }
            info!(
                "Waiting for stake to drop below {} current: {:.1}",
                max_stake_percent, current_percent
            );
            sleep(Duration::from_secs(10));
        }
        Ok(())
    }

    /// Returns information about all the nodes participating in the cluster.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getClusterNodes`]
    /// RPC method.
    ///
    /// [`getClusterNodes`]: https://docs.solana.com/developing/clients/jsonrpc-api#getclusternodes
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let cluster_nodes = rpc_client.get_cluster_nodes()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_cluster_nodes(&self) -> ClientResult<Vec<RpcContactInfo>> {
        self.send(RpcRequest::GetClusterNodes, Value::Null)
    }

    /// Returns identity and transaction information about a confirmed block in the ledger.
    ///
    /// The encodings are returned in [`UiTransactionEncoding::Json`][uite]
    /// format. To return transactions in other encodings, use
    /// [`get_block_with_encoding`].
    ///
    /// [`get_block_with_encoding`]: RpcClient::get_block_with_encoding
    /// [uite]: UiTransactionEncoding::Json
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBlock`] RPC
    /// method.
    ///
    /// [`getBlock`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblock
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let slot = rpc_client.get_slot()?;
    /// let block = rpc_client.get_block(slot)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_block(&self, slot: Slot) -> ClientResult<EncodedConfirmedBlock> {
        self.get_block_with_encoding(slot, UiTransactionEncoding::Json)
    }

    /// Returns identity and transaction information about a confirmed block in the ledger.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBlock`] RPC method.
    ///
    /// [`getBlock`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblock
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_transaction_status::UiTransactionEncoding;
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let slot = rpc_client.get_slot()?;
    /// let encoding = UiTransactionEncoding::Base58;
    /// let block = rpc_client.get_block_with_encoding(
    ///     slot,
    ///     encoding,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_block_with_encoding(
        &self,
        slot: Slot,
        encoding: UiTransactionEncoding,
    ) -> ClientResult<EncodedConfirmedBlock> {
        self.send(
            self.maybe_map_request(RpcRequest::GetBlock)?,
            json!([slot, encoding]),
        )
    }

    /// Returns identity and transaction information about a confirmed block in the ledger.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBlock`] RPC method.
    ///
    /// [`getBlock`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblock
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_transaction_status::{
    /// #     TransactionDetails,
    /// #     UiTransactionEncoding,
    /// # };
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     rpc_config::RpcBlockConfig,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let slot = rpc_client.get_slot()?;
    /// let config = RpcBlockConfig {
    ///     encoding: Some(UiTransactionEncoding::Base58),
    ///     transaction_details: Some(TransactionDetails::None),
    ///     rewards: Some(true),
    ///     commitment: None,
    /// };
    /// let block = rpc_client.get_block_with_config(
    ///     slot,
    ///     config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_block_with_config(
        &self,
        slot: Slot,
        config: RpcBlockConfig,
    ) -> ClientResult<UiConfirmedBlock> {
        self.send(
            self.maybe_map_request(RpcRequest::GetBlock)?,
            json!([slot, config]),
        )
    }

    #[deprecated(since = "1.7.0", note = "Please use RpcClient::get_block() instead")]
    #[allow(deprecated)]
    pub fn get_confirmed_block(&self, slot: Slot) -> ClientResult<EncodedConfirmedBlock> {
        self.get_confirmed_block_with_encoding(slot, UiTransactionEncoding::Json)
    }

    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcClient::get_block_with_encoding() instead"
    )]
    #[allow(deprecated)]
    pub fn get_confirmed_block_with_encoding(
        &self,
        slot: Slot,
        encoding: UiTransactionEncoding,
    ) -> ClientResult<EncodedConfirmedBlock> {
        self.send(RpcRequest::GetConfirmedBlock, json!([slot, encoding]))
    }

    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcClient::get_block_with_config() instead"
    )]
    #[allow(deprecated)]
    pub fn get_confirmed_block_with_config(
        &self,
        slot: Slot,
        config: RpcConfirmedBlockConfig,
    ) -> ClientResult<UiConfirmedBlock> {
        self.send(RpcRequest::GetConfirmedBlock, json!([slot, config]))
    }

    /// Returns a list of finalized blocks between two slots.
    ///
    /// The range is inclusive, with results including the block for both
    /// `start_slot` and `end_slot`.
    ///
    /// If `end_slot` is not provided, then the end slot is for the latest
    /// finalized block.
    ///
    /// This method may not return blocks for the full range of slots if some
    /// slots do not have corresponding blocks. To simply get a specific number
    /// of sequential blocks, use the [`get_blocks_with_limit`] method.
    ///
    /// This method uses the [`Finalized`] [commitment level][cl].
    ///
    /// [`Finalized`]: CommitmentLevel::Finalized
    /// [`get_blocks_with_limit`]: RpcClient::get_blocks_with_limit.
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # Errors
    ///
    /// This method returns an error if the range is greater than 500,000 slots.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBlocks`] RPC method, unless
    /// the remote node version is less than 1.7, in which case it maps to the
    /// [`getConfirmedBlocks`] RPC method.
    ///
    /// [`getBlocks`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblocks
    /// [`getConfirmedBlocks`]: https://docs.solana.com/developing/clients/jsonrpc-api#getConfirmedblocks
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Get up to the first 10 blocks
    /// let start_slot = 0;
    /// let end_slot = 9;
    /// let blocks = rpc_client.get_blocks(start_slot, Some(end_slot))?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_blocks(&self, start_slot: Slot, end_slot: Option<Slot>) -> ClientResult<Vec<Slot>> {
        self.send(
            self.maybe_map_request(RpcRequest::GetBlocks)?,
            json!([start_slot, end_slot]),
        )
    }

    /// Returns a list of confirmed blocks between two slots.
    ///
    /// The range is inclusive, with results including the block for both
    /// `start_slot` and `end_slot`.
    ///
    /// If `end_slot` is not provided, then the end slot is for the latest
    /// block with the given [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// This method may not return blocks for the full range of slots if some
    /// slots do not have corresponding blocks. To simply get a specific number
    /// of sequential blocks, use the [`get_blocks_with_limit_and_commitment`]
    /// method.
    ///
    /// [`get_blocks_with_limit_and_commitment`]: RpcClient::get_blocks_with_limit_and_commitment.
    ///
    /// # Errors
    ///
    /// This method returns an error if the range is greater than 500,000 slots.
    ///
    /// This method returns an error if the given commitment level is below
    /// [`Confirmed`].
    ///
    /// [`Confirmed`]: CommitmentLevel::Confirmed
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBlocks`] RPC method, unless
    /// the remote node version is less than 1.7, in which case it maps to the
    /// [`getConfirmedBlocks`] RPC method.
    ///
    /// [`getBlocks`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblocks
    /// [`getConfirmedBlocks`]: https://docs.solana.com/developing/clients/jsonrpc-api#getConfirmedblocks
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Get up to the first 10 blocks
    /// let start_slot = 0;
    /// let end_slot = 9;
    /// // Method does not support commitment below `confirmed`
    /// let commitment_config = CommitmentConfig::confirmed();
    /// let blocks = rpc_client.get_blocks_with_commitment(
    ///     start_slot,
    ///     Some(end_slot),
    ///     commitment_config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_blocks_with_commitment(
        &self,
        start_slot: Slot,
        end_slot: Option<Slot>,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<Vec<Slot>> {
        let json = if end_slot.is_some() {
            json!([
                start_slot,
                end_slot,
                self.maybe_map_commitment(commitment_config)?
            ])
        } else {
            json!([start_slot, self.maybe_map_commitment(commitment_config)?])
        };
        self.send(self.maybe_map_request(RpcRequest::GetBlocks)?, json)
    }

    /// Returns a list of finalized blocks starting at the given slot.
    ///
    /// This method uses the [`Finalized`] [commitment level][cl].
    ///
    /// [`Finalized`]: CommitmentLevel::Finalized.
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # Errors
    ///
    /// This method returns an error if the limit is greater than 500,000 slots.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBlocksWithLimit`] RPC
    /// method, unless the remote node version is less than 1.7, in which case
    /// it maps to the [`getConfirmedBlocksWithLimit`] RPC method.
    ///
    /// [`getBlocksWithLimit`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblockswithlimit
    /// [`getConfirmedBlocksWithLimit`]: https://docs.solana.com/developing/clients/jsonrpc-api#getconfirmedblockswithlimit
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Get the first 10 blocks
    /// let start_slot = 0;
    /// let limit = 10;
    /// let blocks = rpc_client.get_blocks_with_limit(start_slot, limit)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_blocks_with_limit(&self, start_slot: Slot, limit: usize) -> ClientResult<Vec<Slot>> {
        self.send(
            self.maybe_map_request(RpcRequest::GetBlocksWithLimit)?,
            json!([start_slot, limit]),
        )
    }

    /// Returns a list of confirmed blocks starting at the given slot.
    ///
    /// # Errors
    ///
    /// This method returns an error if the limit is greater than 500,000 slots.
    ///
    /// This method returns an error if the given [commitment level][cl] is below
    /// [`Confirmed`].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    /// [`Confirmed`]: CommitmentLevel::Confirmed
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBlocksWithLimit`] RPC
    /// method, unless the remote node version is less than 1.7, in which case
    /// it maps to the `getConfirmedBlocksWithLimit` RPC method.
    ///
    /// [`getBlocksWithLimit`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblockswithlimit
    /// [`getConfirmedBlocksWithLimit`]: https://docs.solana.com/developing/clients/jsonrpc-api#getconfirmedblockswithlimit
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Get the first 10 blocks
    /// let start_slot = 0;
    /// let limit = 10;
    /// let commitment_config = CommitmentConfig::confirmed();
    /// let blocks = rpc_client.get_blocks_with_limit_and_commitment(
    ///     start_slot,
    ///     limit,
    ///     commitment_config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_blocks_with_limit_and_commitment(
        &self,
        start_slot: Slot,
        limit: usize,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<Vec<Slot>> {
        self.send(
            self.maybe_map_request(RpcRequest::GetBlocksWithLimit)?,
            json!([
                start_slot,
                limit,
                self.maybe_map_commitment(commitment_config)?
            ]),
        )
    }

    #[deprecated(since = "1.7.0", note = "Please use RpcClient::get_blocks() instead")]
    #[allow(deprecated)]
    pub fn get_confirmed_blocks(
        &self,
        start_slot: Slot,
        end_slot: Option<Slot>,
    ) -> ClientResult<Vec<Slot>> {
        self.send(
            RpcRequest::GetConfirmedBlocks,
            json!([start_slot, end_slot]),
        )
    }

    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcClient::get_blocks_with_commitment() instead"
    )]
    #[allow(deprecated)]
    pub fn get_confirmed_blocks_with_commitment(
        &self,
        start_slot: Slot,
        end_slot: Option<Slot>,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<Vec<Slot>> {
        let json = if end_slot.is_some() {
            json!([
                start_slot,
                end_slot,
                self.maybe_map_commitment(commitment_config)?
            ])
        } else {
            json!([start_slot, self.maybe_map_commitment(commitment_config)?])
        };
        self.send(RpcRequest::GetConfirmedBlocks, json)
    }

    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcClient::get_blocks_with_limit() instead"
    )]
    #[allow(deprecated)]
    pub fn get_confirmed_blocks_with_limit(
        &self,
        start_slot: Slot,
        limit: usize,
    ) -> ClientResult<Vec<Slot>> {
        self.send(
            RpcRequest::GetConfirmedBlocksWithLimit,
            json!([start_slot, limit]),
        )
    }

    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcClient::get_blocks_with_limit_and_commitment() instead"
    )]
    #[allow(deprecated)]
    pub fn get_confirmed_blocks_with_limit_and_commitment(
        &self,
        start_slot: Slot,
        limit: usize,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<Vec<Slot>> {
        self.send(
            RpcRequest::GetConfirmedBlocksWithLimit,
            json!([
                start_slot,
                limit,
                self.maybe_map_commitment(commitment_config)?
            ]),
        )
    }

    /// Get confirmed signatures for transactions involving an address.
    ///
    /// Returns up to 1000 signatures, ordered from newest to oldest.
    ///
    /// This method uses the [`Finalized`] [commitment level][cl].
    ///
    /// [`Finalized`]: CommitmentLevel::Finalized.
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getSignaturesForAddress`] RPC
    /// method, unless the remote node version is less than 1.7, in which case
    /// it maps to the [`getSignaturesForAddress2`] RPC method.
    ///
    /// [`getSignaturesForAddress`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturesforaddress
    /// [`getSignaturesForAddress2`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturesforaddress2
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     system_transaction,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// let signatures = rpc_client.get_signatures_for_address(
    ///     &alice.pubkey(),
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_signatures_for_address(
        &self,
        address: &Pubkey,
    ) -> ClientResult<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        self.get_signatures_for_address_with_config(
            address,
            GetConfirmedSignaturesForAddress2Config::default(),
        )
    }

    /// Get confirmed signatures for transactions involving an address.
    ///
    /// # Errors
    ///
    /// This method returns an error if the given [commitment level][cl] is below
    /// [`Confirmed`].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    /// [`Confirmed`]: CommitmentLevel::Confirmed
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getSignaturesForAddress`] RPC
    /// method, unless the remote node version is less than 1.7, in which case
    /// it maps to the [`getSignaturesForAddress2`] RPC method.
    ///
    /// [`getSignaturesForAddress`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturesforaddress
    /// [`getSignaturesForAddress2`]: https://docs.solana.com/developing/clients/jsonrpc-api#getsignaturesforaddress2
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// #     rpc_client::GetConfirmedSignaturesForAddress2Config,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     system_transaction,
    /// #     commitment_config::CommitmentConfig,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// # let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// # let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// # let signature = rpc_client.send_and_confirm_transaction(&tx)?;
    /// let config = GetConfirmedSignaturesForAddress2Config {
    ///     before: None,
    ///     until: None,
    ///     limit: Some(3),
    ///     commitment: Some(CommitmentConfig::confirmed()),
    /// };
    /// let signatures = rpc_client.get_signatures_for_address_with_config(
    ///     &alice.pubkey(),
    ///     config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_signatures_for_address_with_config(
        &self,
        address: &Pubkey,
        config: GetConfirmedSignaturesForAddress2Config,
    ) -> ClientResult<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        let config = RpcSignaturesForAddressConfig {
            before: config.before.map(|signature| signature.to_string()),
            until: config.until.map(|signature| signature.to_string()),
            limit: config.limit,
            commitment: config.commitment,
        };

        let result: Vec<RpcConfirmedTransactionStatusWithSignature> = self.send(
            self.maybe_map_request(RpcRequest::GetSignaturesForAddress)?,
            json!([address.to_string(), config]),
        )?;

        Ok(result)
    }

    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcClient::get_signatures_for_address() instead"
    )]
    #[allow(deprecated)]
    pub fn get_confirmed_signatures_for_address2(
        &self,
        address: &Pubkey,
    ) -> ClientResult<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        self.get_confirmed_signatures_for_address2_with_config(
            address,
            GetConfirmedSignaturesForAddress2Config::default(),
        )
    }

    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcClient::get_signatures_for_address_with_config() instead"
    )]
    #[allow(deprecated)]
    pub fn get_confirmed_signatures_for_address2_with_config(
        &self,
        address: &Pubkey,
        config: GetConfirmedSignaturesForAddress2Config,
    ) -> ClientResult<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        let config = RpcGetConfirmedSignaturesForAddress2Config {
            before: config.before.map(|signature| signature.to_string()),
            until: config.until.map(|signature| signature.to_string()),
            limit: config.limit,
            commitment: config.commitment,
        };

        let result: Vec<RpcConfirmedTransactionStatusWithSignature> = self.send(
            RpcRequest::GetConfirmedSignaturesForAddress2,
            json!([address.to_string(), config]),
        )?;

        Ok(result)
    }

    /// Returns transaction details for a confirmed transaction.
    ///
    /// This method uses the [`Finalized`] [commitment level][cl].
    ///
    /// [`Finalized`]: CommitmentLevel::Finalized
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getTransaction`] RPC method,
    /// unless the remote node version is less than 1.7, in which case it maps
    /// to the [`getConfirmedTransaction`] RPC method.
    ///
    /// [`getTransaction`]: https://docs.solana.com/developing/clients/jsonrpc-api#gettransaction
    /// [`getConfirmedTransaction`]: https://docs.solana.com/developing/clients/jsonrpc-api#getconfirmedtransaction
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     system_transaction,
    /// # };
    /// # use solana_transaction_status::UiTransactionEncoding;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// # let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// # let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let signature = rpc_client.send_and_confirm_transaction(&tx)?;
    /// let transaction = rpc_client.get_transaction(
    ///     &signature,
    ///     UiTransactionEncoding::Json,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_transaction(
        &self,
        signature: &Signature,
        encoding: UiTransactionEncoding,
    ) -> ClientResult<EncodedConfirmedTransaction> {
        self.send(
            self.maybe_map_request(RpcRequest::GetTransaction)?,
            json!([signature.to_string(), encoding]),
        )
    }

    /// Returns transaction details for a confirmed transaction.
    ///
    /// # Errors
    ///
    /// This method returns an error if the given [commitment level][cl] is below
    /// [`Confirmed`].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    /// [`Confirmed`]: CommitmentLevel::Confirmed
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getTransaction`] RPC method,
    /// unless the remote node version is less than 1.7, in which case it maps
    /// to the [`getConfirmedTransaction`] RPC method.
    ///
    /// [`getTransaction`]: https://docs.solana.com/developing/clients/jsonrpc-api#gettransaction
    /// [`getConfirmedTransaction`]: https://docs.solana.com/developing/clients/jsonrpc-api#getconfirmedtransaction
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// #     rpc_config::RpcTransactionConfig,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signature::Signature,
    /// #     signer::keypair::Keypair,
    /// #     system_transaction,
    /// #     commitment_config::CommitmentConfig,
    /// # };
    /// # use solana_transaction_status::UiTransactionEncoding;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// # let lamports = 50;
    /// # let latest_blockhash = rpc_client.get_latest_blockhash()?;
    /// # let tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, latest_blockhash);
    /// let signature = rpc_client.send_and_confirm_transaction(&tx)?;
    /// let config = RpcTransactionConfig {
    ///     encoding: Some(UiTransactionEncoding::Json),
    ///     commitment: Some(CommitmentConfig::confirmed()),
    /// };
    /// let transaction = rpc_client.get_transaction_with_config(
    ///     &signature,
    ///     config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_transaction_with_config(
        &self,
        signature: &Signature,
        config: RpcTransactionConfig,
    ) -> ClientResult<EncodedConfirmedTransaction> {
        self.send(
            self.maybe_map_request(RpcRequest::GetTransaction)?,
            json!([signature.to_string(), config]),
        )
    }

    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcClient::get_transaction() instead"
    )]
    #[allow(deprecated)]
    pub fn get_confirmed_transaction(
        &self,
        signature: &Signature,
        encoding: UiTransactionEncoding,
    ) -> ClientResult<EncodedConfirmedTransaction> {
        self.send(
            RpcRequest::GetConfirmedTransaction,
            json!([signature.to_string(), encoding]),
        )
    }

    #[deprecated(
        since = "1.7.0",
        note = "Please use RpcClient::get_transaction_with_config() instead"
    )]
    #[allow(deprecated)]
    pub fn get_confirmed_transaction_with_config(
        &self,
        signature: &Signature,
        config: RpcConfirmedTransactionConfig,
    ) -> ClientResult<EncodedConfirmedTransaction> {
        self.send(
            RpcRequest::GetConfirmedTransaction,
            json!([signature.to_string(), config]),
        )
    }

    /// Returns the estimated production time of a block.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBlockTime`] RPC method.
    ///
    /// [`getBlockTime`]: https://docs.solana.com/developing/clients/jsonrpc-api#getblocktime
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// // Get the time of the most recent finalized block
    /// let slot = rpc_client.get_slot()?;
    /// let block_time = rpc_client.get_block_time(slot)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_block_time(&self, slot: Slot) -> ClientResult<UnixTimestamp> {
        let request = RpcRequest::GetBlockTime;
        let response = self.sender.send(request, json!([slot]));

        response
            .map(|result_json| {
                if result_json.is_null() {
                    return Err(RpcError::ForUser(format!("Block Not Found: slot={}", slot)).into());
                }
                let result = serde_json::from_value(result_json)
                    .map_err(|err| ClientError::new_with_request(err.into(), request))?;
                trace!("Response block timestamp {:?} {:?}", slot, result);
                Ok(result)
            })
            .map_err(|err| err.into_with_request(request))?
    }

    /// Returns information about the current epoch.
    ///
    /// This method uses the configured default [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getEpochInfo`] RPC method.
    ///
    /// [`getEpochInfo`]: https://docs.solana.com/developing/clients/jsonrpc-api#getepochinfo
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let epoch_info = rpc_client.get_epoch_info()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_epoch_info(&self) -> ClientResult<EpochInfo> {
        self.get_epoch_info_with_commitment(self.commitment())
    }

    /// Returns information about the current epoch.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getEpochInfo`] RPC method.
    ///
    /// [`getEpochInfo`]: https://docs.solana.com/developing/clients/jsonrpc-api#getepochinfo
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let commitment_config = CommitmentConfig::confirmed();
    /// let epoch_info = rpc_client.get_epoch_info_with_commitment(
    ///     commitment_config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_epoch_info_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<EpochInfo> {
        self.send(
            RpcRequest::GetEpochInfo,
            json!([self.maybe_map_commitment(commitment_config)?]),
        )
    }

    /// Returns the leader schedule for an epoch.
    ///
    /// This method uses the configured default [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getLeaderSchedule`] RPC method.
    ///
    /// [`getLeaderSchedule`]: https://docs.solana.com/developing/clients/jsonrpc-api#getleaderschedule
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let slot = rpc_client.get_slot()?;
    /// let leader_schedule = rpc_client.get_leader_schedule(
    ///     Some(slot),
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_leader_schedule(
        &self,
        slot: Option<Slot>,
    ) -> ClientResult<Option<RpcLeaderSchedule>> {
        self.get_leader_schedule_with_commitment(slot, self.commitment())
    }

    /// Returns the leader schedule for an epoch.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getLeaderSchedule`] RPC method.
    ///
    /// [`getLeaderSchedule`]: https://docs.solana.com/developing/clients/jsonrpc-api#getleaderschedule
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let slot = rpc_client.get_slot()?;
    /// let commitment_config = CommitmentConfig::processed();
    /// let leader_schedule = rpc_client.get_leader_schedule_with_commitment(
    ///     Some(slot),
    ///     commitment_config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_leader_schedule_with_commitment(
        &self,
        slot: Option<Slot>,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<Option<RpcLeaderSchedule>> {
        self.get_leader_schedule_with_config(
            slot,
            RpcLeaderScheduleConfig {
                commitment: Some(self.maybe_map_commitment(commitment_config)?),
                ..RpcLeaderScheduleConfig::default()
            },
        )
    }

    /// Returns the leader schedule for an epoch.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getLeaderSchedule`] RPC method.
    ///
    /// [`getLeaderSchedule`]: https://docs.solana.com/developing/clients/jsonrpc-api#getleaderschedule
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_client::rpc_config::RpcLeaderScheduleConfig;
    /// # use solana_sdk::commitment_config::CommitmentConfig;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let slot = rpc_client.get_slot()?;
    /// # let validator_pubkey_str = "7AYmEYBBetok8h5L3Eo3vi3bDWnjNnaFbSXfSNYV5ewB".to_string();
    /// let config = RpcLeaderScheduleConfig {
    ///     identity: Some(validator_pubkey_str),
    ///     commitment: Some(CommitmentConfig::processed()),
    /// };
    /// let leader_schedule = rpc_client.get_leader_schedule_with_config(
    ///     Some(slot),
    ///     config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_leader_schedule_with_config(
        &self,
        slot: Option<Slot>,
        config: RpcLeaderScheduleConfig,
    ) -> ClientResult<Option<RpcLeaderSchedule>> {
        self.send(RpcRequest::GetLeaderSchedule, json!([slot, config]))
    }

    /// Returns epoch schedule information from this cluster's genesis config.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getEpochSchedule`] RPC method.
    ///
    /// [`getEpochSchedule`]: https://docs.solana.com/developing/clients/jsonrpc-api#getepochschedule
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let epoch_schedule = rpc_client.get_epoch_schedule()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_epoch_schedule(&self) -> ClientResult<EpochSchedule> {
        self.send(RpcRequest::GetEpochSchedule, Value::Null)
    }

    /// Returns a list of recent performance samples, in reverse slot order.
    ///
    /// Performance samples are taken every 60 seconds and include the number of
    /// transactions and slots that occur in a given time window.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getRecentPerformanceSamples`] RPC method.
    ///
    /// [`getRecentPerformanceSamples`]: https://docs.solana.com/developing/clients/jsonrpc-api#getrecentperformancesamples
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let limit = 10;
    /// let performance_samples = rpc_client.get_recent_performance_samples(
    ///     Some(limit),
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_recent_performance_samples(
        &self,
        limit: Option<usize>,
    ) -> ClientResult<Vec<RpcPerfSample>> {
        self.send(RpcRequest::GetRecentPerformanceSamples, json!([limit]))
    }

    /// Returns the identity pubkey for the current node.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getIdentity`] RPC method.
    ///
    /// [`getIdentity`]: https://docs.solana.com/developing/clients/jsonrpc-api#getidentity
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let identity = rpc_client.get_identity()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_identity(&self) -> ClientResult<Pubkey> {
        let rpc_identity: RpcIdentity = self.send(RpcRequest::GetIdentity, Value::Null)?;

        rpc_identity.identity.parse::<Pubkey>().map_err(|_| {
            ClientError::new_with_request(
                RpcError::ParseError("Pubkey".to_string()).into(),
                RpcRequest::GetIdentity,
            )
        })
    }

    /// Returns the current inflation governor.
    ///
    /// This method uses the [`Finalized`] [commitment level][cl].
    ///
    /// [`Finalized`]: CommitmentLevel::Finalized
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getInflationGovernor`] RPC
    /// method.
    ///
    /// [`getInflationGovernor`]: https://docs.solana.com/developing/clients/jsonrpc-api#getinflationgovernor
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let inflation_governor = rpc_client.get_inflation_governor()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_inflation_governor(&self) -> ClientResult<RpcInflationGovernor> {
        self.send(RpcRequest::GetInflationGovernor, Value::Null)
    }

    /// Returns the specific inflation values for the current epoch.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getInflationRate`] RPC method.
    ///
    /// [`getInflationRate`]: https://docs.solana.com/developing/clients/jsonrpc-api#getinflationrate
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let inflation_rate = rpc_client.get_inflation_rate()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_inflation_rate(&self) -> ClientResult<RpcInflationRate> {
        self.send(RpcRequest::GetInflationRate, Value::Null)
    }

    /// Returns the inflation reward for a list of addresses for an epoch.
    ///
    /// This method uses the configured [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getInflationReward`] RPC method.
    ///
    /// [`getInflationReward`]: https://docs.solana.com/developing/clients/jsonrpc-api#getinflationreward
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_sdk::signature::{Keypair, Signer};
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let epoch_info = rpc_client.get_epoch_info()?;
    /// # let epoch = epoch_info.epoch;
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// let addresses = vec![alice.pubkey(), bob.pubkey()];
    /// let inflation_reward = rpc_client.get_inflation_reward(
    ///     &addresses,
    ///     Some(epoch),
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_inflation_reward(
        &self,
        addresses: &[Pubkey],
        epoch: Option<Epoch>,
    ) -> ClientResult<Vec<Option<RpcInflationReward>>> {
        let addresses: Vec<_> = addresses
            .iter()
            .map(|address| address.to_string())
            .collect();
        self.send(
            RpcRequest::GetInflationReward,
            json!([
                addresses,
                RpcEpochConfig {
                    epoch,
                    commitment: Some(self.commitment()),
                }
            ]),
        )
    }

    /// Returns the current solana version running on the node.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getVersion`] RPC method.
    ///
    /// [`getVersion`]: https://docs.solana.com/developing/clients/jsonrpc-api#getversion
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # use solana_sdk::signature::{Keypair, Signer};
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let expected_version = semver::Version::new(0, 6, 0);
    /// let version = rpc_client.get_version()?;
    /// let version = semver::Version::parse(&version.solana_core)?;
    /// assert!(version >= expected_version);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn get_version(&self) -> ClientResult<RpcVersionInfo> {
        self.send(RpcRequest::GetVersion, Value::Null)
    }

    /// Returns the lowest slot that the node has information about in its ledger.
    ///
    /// This value may increase over time if the node is configured to purge
    /// older ledger data.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`minimumLedgerSlot`] RPC
    /// method.
    ///
    /// [`minimumLedgerSlot`]: https://docs.solana.com/developing/clients/jsonrpc-api#minimumledgerslot
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     client_error::ClientError,
    /// #     rpc_client::RpcClient,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let slot = rpc_client.minimum_ledger_slot()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn minimum_ledger_slot(&self) -> ClientResult<Slot> {
        self.send(RpcRequest::MinimumLedgerSlot, Value::Null)
    }

    /// Returns all information associated with the account of the provided pubkey.
    ///
    /// This method uses the configured [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// To get multiple accounts at once, use the [`get_multiple_accounts`] method.
    ///
    /// [`get_multiple_accounts`]: RpcClient::get_multiple_accounts
    ///
    /// # Errors
    ///
    /// If the account does not exist, this method returns
    /// [`RpcError::ForUser`]. This is unlike [`get_account_with_commitment`],
    /// which returns `Ok(None)` if the account does not exist.
    ///
    /// [`get_account_with_commitment`]: RpcClient::get_account_with_commitment
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getAccountInfo`] RPC method.
    ///
    /// [`getAccountInfo`]: https://docs.solana.com/developing/clients/jsonrpc-api#getaccountinfo
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::{self, RpcClient},
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     pubkey::Pubkey,
    /// # };
    /// # use std::str::FromStr;
    /// # let mocks = rpc_client::create_rpc_client_mocks();
    /// # let rpc_client = RpcClient::new_mock_with_mocks("succeeds".to_string(), mocks);
    /// let alice_pubkey = Pubkey::from_str("BgvYtJEfmZYdVKiptmMjxGzv8iQoo4MWjsP3QsTkhhxa").unwrap();
    /// let account = rpc_client.get_account(&alice_pubkey)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_account(&self, pubkey: &Pubkey) -> ClientResult<Account> {
        self.get_account_with_commitment(pubkey, self.commitment())?
            .value
            .ok_or_else(|| RpcError::ForUser(format!("AccountNotFound: pubkey={}", pubkey)).into())
    }

    /// Returns all information associated with the account of the provided pubkey.
    ///
    /// If the account does not exist, this method returns `Ok(None)`.
    ///
    /// To get multiple accounts at once, use the [`get_multiple_accounts_with_commitment`] method.
    ///
    /// [`get_multiple_accounts_with_commitment`]: RpcClient::get_multiple_accounts_with_commitment
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getAccountInfo`] RPC method.
    ///
    /// [`getAccountInfo`]: https://docs.solana.com/developing/clients/jsonrpc-api#getaccountinfo
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::{self, RpcClient},
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     pubkey::Pubkey,
    /// #     commitment_config::CommitmentConfig,
    /// # };
    /// # use std::str::FromStr;
    /// # let mocks = rpc_client::create_rpc_client_mocks();
    /// # let rpc_client = RpcClient::new_mock_with_mocks("succeeds".to_string(), mocks);
    /// let alice_pubkey = Pubkey::from_str("BgvYtJEfmZYdVKiptmMjxGzv8iQoo4MWjsP3QsTkhhxa").unwrap();
    /// let commitment_config = CommitmentConfig::processed();
    /// let account = rpc_client.get_account_with_commitment(
    ///     &alice_pubkey,
    ///     commitment_config,
    /// )?;
    /// assert!(account.value.is_some());
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_account_with_commitment(
        &self,
        pubkey: &Pubkey,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<Option<Account>> {
        let config = RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64Zstd),
            commitment: Some(self.maybe_map_commitment(commitment_config)?),
            data_slice: None,
        };
        let response = self.sender.send(
            RpcRequest::GetAccountInfo,
            json!([pubkey.to_string(), config]),
        );

        response
            .map(|result_json| {
                if result_json.is_null() {
                    return Err(
                        RpcError::ForUser(format!("AccountNotFound: pubkey={}", pubkey)).into(),
                    );
                }
                let Response {
                    context,
                    value: rpc_account,
                } = serde_json::from_value::<Response<Option<UiAccount>>>(result_json)?;
                trace!("Response account {:?} {:?}", pubkey, rpc_account);
                let account = rpc_account.and_then(|rpc_account| rpc_account.decode());

                Ok(Response {
                    context,
                    value: account,
                })
            })
            .map_err(|err| {
                Into::<ClientError>::into(RpcError::ForUser(format!(
                    "AccountNotFound: pubkey={}: {}",
                    pubkey, err
                )))
            })?
    }

    /// Get the max slot seen from retransmit stage.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getMaxRetransmitSlot`] RPC
    /// method.
    ///
    /// [`getMaxRetransmitSlot`]: https://docs.solana.com/developing/clients/jsonrpc-api#getmaxretransmitslot
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let slot = rpc_client.get_max_retransmit_slot()?;
    /// # Ok::<(), ClientError>(())
    pub fn get_max_retransmit_slot(&self) -> ClientResult<Slot> {
        self.send(RpcRequest::GetMaxRetransmitSlot, Value::Null)
    }

    /// Get the max slot seen from after [shred](https://docs.solana.com/terminology#shred) insert.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the
    /// [`getMaxShredInsertSlot`] RPC method.
    ///
    /// [`getMaxShredInsertSlot`]: https://docs.solana.com/developing/clients/jsonrpc-api#getmaxshredinsertslot
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let slot = rpc_client.get_max_shred_insert_slot()?;
    /// # Ok::<(), ClientError>(())
    pub fn get_max_shred_insert_slot(&self) -> ClientResult<Slot> {
        self.send(RpcRequest::GetMaxShredInsertSlot, Value::Null)
    }

    /// Returns the account information for a list of pubkeys.
    ///
    /// This method uses the configured [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getMultipleAccounts`] RPC method.
    ///
    /// [`getMultipleAccounts`]: https://docs.solana.com/developing/clients/jsonrpc-api#getmultipleaccounts
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// let pubkeys = vec![alice.pubkey(), bob.pubkey()];
    /// let accounts = rpc_client.get_multiple_accounts(&pubkeys)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_multiple_accounts(&self, pubkeys: &[Pubkey]) -> ClientResult<Vec<Option<Account>>> {
        Ok(self
            .get_multiple_accounts_with_commitment(pubkeys, self.commitment())?
            .value)
    }

    /// Returns the account information for a list of pubkeys.
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getMultipleAccounts`] RPC method.
    ///
    /// [`getMultipleAccounts`]: https://docs.solana.com/developing/clients/jsonrpc-api#getmultipleaccounts
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     commitment_config::CommitmentConfig,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// let pubkeys = vec![alice.pubkey(), bob.pubkey()];
    /// let commitment_config = CommitmentConfig::processed();
    /// let accounts = rpc_client.get_multiple_accounts_with_commitment(
    ///     &pubkeys,
    ///     commitment_config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_multiple_accounts_with_commitment(
        &self,
        pubkeys: &[Pubkey],
        commitment_config: CommitmentConfig,
    ) -> RpcResult<Vec<Option<Account>>> {
        self.get_multiple_accounts_with_config(
            pubkeys,
            RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64Zstd),
                commitment: Some(self.maybe_map_commitment(commitment_config)?),
                data_slice: None,
            },
        )
    }

    /// Returns the account information for a list of pubkeys.
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getMultipleAccounts`] RPC method.
    ///
    /// [`getMultipleAccounts`]: https://docs.solana.com/developing/clients/jsonrpc-api#getmultipleaccounts
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     rpc_config::RpcAccountInfoConfig,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     commitment_config::CommitmentConfig,
    /// # };
    /// # use solana_account_decoder::UiAccountEncoding;
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let bob = Keypair::new();
    /// let pubkeys = vec![alice.pubkey(), bob.pubkey()];
    /// let commitment_config = CommitmentConfig::processed();
    /// let config = RpcAccountInfoConfig {
    ///     encoding: Some(UiAccountEncoding::Base64),
    ///     commitment: Some(commitment_config),
    ///     .. RpcAccountInfoConfig::default()
    /// };
    /// let accounts = rpc_client.get_multiple_accounts_with_config(
    ///     &pubkeys,
    ///     config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_multiple_accounts_with_config(
        &self,
        pubkeys: &[Pubkey],
        config: RpcAccountInfoConfig,
    ) -> RpcResult<Vec<Option<Account>>> {
        let config = RpcAccountInfoConfig {
            commitment: config.commitment.or_else(|| Some(self.commitment())),
            ..config
        };
        let pubkeys: Vec<_> = pubkeys.iter().map(|pubkey| pubkey.to_string()).collect();
        let response = self.send(RpcRequest::GetMultipleAccounts, json!([pubkeys, config]))?;
        let Response {
            context,
            value: accounts,
        } = serde_json::from_value::<Response<Vec<Option<UiAccount>>>>(response)?;
        let accounts: Vec<Option<Account>> = accounts
            .into_iter()
            .map(|rpc_account| rpc_account.and_then(|a| a.decode()))
            .collect();
        Ok(Response {
            context,
            value: accounts,
        })
    }

    /// Gets the raw data associated with an account.
    ///
    /// This is equivalent to calling [`get_account`] and then accessing the
    /// [`data`] field of the returned [`Account`].
    ///
    /// [`get_account`]: RpcClient::get_account
    /// [`data`]: Account::data
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getAccountInfo`] RPC method.
    ///
    /// [`getAccountInfo`]: https://docs.solana.com/developing/clients/jsonrpc-api#getaccountinfo
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::{self, RpcClient},
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     pubkey::Pubkey,
    /// # };
    /// # use std::str::FromStr;
    /// # let mocks = rpc_client::create_rpc_client_mocks();
    /// # let rpc_client = RpcClient::new_mock_with_mocks("succeeds".to_string(), mocks);
    /// let alice_pubkey = Pubkey::from_str("BgvYtJEfmZYdVKiptmMjxGzv8iQoo4MWjsP3QsTkhhxa").unwrap();
    /// let account_data = rpc_client.get_account_data(&alice_pubkey)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_account_data(&self, pubkey: &Pubkey) -> ClientResult<Vec<u8>> {
        Ok(self.get_account(pubkey)?.data)
    }

    /// Returns minimum balance required to make an account with specified data length rent exempt.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the
    /// [`getMinimumBalanceForRentExemption`] RPC method.
    ///
    /// [`getMinimumBalanceForRentExemption`]: https://docs.solana.com/developing/clients/jsonrpc-api#getminimumbalanceforrentexemption
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// let data_len = 300;
    /// let balance = rpc_client.get_minimum_balance_for_rent_exemption(data_len)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> ClientResult<u64> {
        let request = RpcRequest::GetMinimumBalanceForRentExemption;
        let minimum_balance_json = self
            .sender
            .send(request, json!([data_len]))
            .map_err(|err| err.into_with_request(request))?;

        let minimum_balance: u64 = serde_json::from_value(minimum_balance_json)
            .map_err(|err| ClientError::new_with_request(err.into(), request))?;
        trace!(
            "Response minimum balance {:?} {:?}",
            data_len,
            minimum_balance
        );
        Ok(minimum_balance)
    }

    /// Request the balance of the provided account pubkey.
    ///
    /// This method uses the configured [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBalance`] RPC method.
    ///
    /// [`getBalance`]: https://docs.solana.com/developing/clients/jsonrpc-api#getbalance
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// let balance = rpc_client.get_balance(&alice.pubkey())?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_balance(&self, pubkey: &Pubkey) -> ClientResult<u64> {
        Ok(self
            .get_balance_with_commitment(pubkey, self.commitment())?
            .value)
    }

    /// Request the balance of the provided account pubkey.
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getBalance`] RPC method.
    ///
    /// [`getBalance`]: https://docs.solana.com/developing/clients/jsonrpc-api#getbalance
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     commitment_config::CommitmentConfig,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// let commitment_config = CommitmentConfig::processed();
    /// let balance = rpc_client.get_balance_with_commitment(
    ///     &alice.pubkey(),
    ///     commitment_config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_balance_with_commitment(
        &self,
        pubkey: &Pubkey,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<u64> {
        self.send(
            RpcRequest::GetBalance,
            json!([
                pubkey.to_string(),
                self.maybe_map_commitment(commitment_config)?
            ]),
        )
    }

    /// Returns all accounts owned by the provided program pubkey.
    ///
    /// This method uses the configured [commitment level][cl].
    ///
    /// [cl]: https://docs.solana.com/developing/clients/jsonrpc-api#configuring-state-commitment
    ///
    /// # RPC Reference
    ///
    /// This method corresponds directly to the [`getProgramAccounts`] RPC
    /// method.
    ///
    /// [`getProgramAccounts`]: https://docs.solana.com/developing/clients/jsonrpc-api#getprogramaccounts
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// # };
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// let accounts = rpc_client.get_program_accounts(&alice.pubkey())?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_program_accounts(&self, pubkey: &Pubkey) -> ClientResult<Vec<(Pubkey, Account)>> {
        self.get_program_accounts_with_config(
            pubkey,
            RpcProgramAccountsConfig {
                account_config: RpcAccountInfoConfig {
                    encoding: Some(UiAccountEncoding::Base64Zstd),
                    ..RpcAccountInfoConfig::default()
                },
                ..RpcProgramAccountsConfig::default()
            },
        )
    }

    /// Returns all accounts owned by the provided program pubkey.
    ///
    /// # RPC Reference
    ///
    /// This method is built on the [`getProgramAccounts`] RPC method.
    ///
    /// [`getProgramAccounts`]: https://docs.solana.com/developing/clients/jsonrpc-api#getprogramaccounts
    ///
    /// # Examples
    ///
    /// ```
    /// # use solana_client::{
    /// #     rpc_client::RpcClient,
    /// #     client_error::ClientError,
    /// #     rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
    /// #     rpc_filter::{MemcmpEncodedBytes, RpcFilterType, Memcmp},
    /// # };
    /// # use solana_sdk::{
    /// #     signature::Signer,
    /// #     signer::keypair::Keypair,
    /// #     commitment_config::CommitmentConfig,
    /// # };
    /// # use solana_account_decoder::{UiDataSliceConfig, UiAccountEncoding};
    /// # let rpc_client = RpcClient::new_mock("succeeds".to_string());
    /// # let alice = Keypair::new();
    /// # let base64_bytes = "\
    /// #     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    /// #     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    /// #     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    /// let memcmp = RpcFilterType::Memcmp(Memcmp {
    ///     offset: 0,
    ///     bytes: MemcmpEncodedBytes::Base64(base64_bytes.to_string()),
    ///     encoding: None,
    /// });
    /// let config = RpcProgramAccountsConfig {
    ///     filters: Some(vec![
    ///         RpcFilterType::DataSize(128),
    ///         memcmp,
    ///     ]),
    ///     account_config: RpcAccountInfoConfig {
    ///         encoding: Some(UiAccountEncoding::Base64),
    ///         data_slice: Some(UiDataSliceConfig {
    ///             offset: 0,
    ///             length: 5,
    ///         }),
    ///         commitment: Some(CommitmentConfig::processed()),
    ///     },
    ///     with_context: Some(false),
    /// };
    /// let accounts = rpc_client.get_program_accounts_with_config(
    ///     &alice.pubkey(),
    ///     config,
    /// )?;
    /// # Ok::<(), ClientError>(())
    /// ```
    pub fn get_program_accounts_with_config(
        &self,
        pubkey: &Pubkey,
        config: RpcProgramAccountsConfig,
    ) -> ClientResult<Vec<(Pubkey, Account)>> {
        let commitment = config
            .account_config
            .commitment
            .unwrap_or_else(|| self.commitment());
        let commitment = self.maybe_map_commitment(commitment)?;
        let account_config = RpcAccountInfoConfig {
            commitment: Some(commitment),
            ..config.account_config
        };
        let config = RpcProgramAccountsConfig {
            account_config,
            ..config
        };
        let accounts: Vec<RpcKeyedAccount> = self.send(
            RpcRequest::GetProgramAccounts,
            json!([pubkey.to_string(), config]),
        )?;
        parse_keyed_accounts(accounts, RpcRequest::GetProgramAccounts)
    }

    /// Request the transaction count.
    pub fn get_transaction_count(&self) -> ClientResult<u64> {
        self.get_transaction_count_with_commitment(self.commitment())
    }

    pub fn get_transaction_count_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<u64> {
        self.send(
            RpcRequest::GetTransactionCount,
            json!([self.maybe_map_commitment(commitment_config)?]),
        )
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please use `get_latest_blockhash` and `get_fee_for_message` instead"
    )]
    #[allow(deprecated)]
    pub fn get_fees(&self) -> ClientResult<Fees> {
        #[allow(deprecated)]
        Ok(self.get_fees_with_commitment(self.commitment())?.value)
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please use `get_latest_blockhash_with_commitment` and `get_fee_for_message` instead"
    )]
    #[allow(deprecated)]
    pub fn get_fees_with_commitment(&self, commitment_config: CommitmentConfig) -> RpcResult<Fees> {
        let Response {
            context,
            value: fees,
        } = self.send::<Response<RpcFees>>(
            RpcRequest::GetFees,
            json!([self.maybe_map_commitment(commitment_config)?]),
        )?;
        let blockhash = fees.blockhash.parse().map_err(|_| {
            ClientError::new_with_request(
                RpcError::ParseError("Hash".to_string()).into(),
                RpcRequest::GetFees,
            )
        })?;
        Ok(Response {
            context,
            value: Fees {
                blockhash,
                fee_calculator: fees.fee_calculator,
                last_valid_block_height: fees.last_valid_block_height,
            },
        })
    }

    #[deprecated(since = "1.9.0", note = "Please use `get_latest_blockhash` instead")]
    #[allow(deprecated)]
    pub fn get_recent_blockhash(&self) -> ClientResult<(Hash, FeeCalculator)> {
        #[allow(deprecated)]
        let (blockhash, fee_calculator, _last_valid_slot) = self
            .get_recent_blockhash_with_commitment(self.commitment())?
            .value;
        Ok((blockhash, fee_calculator))
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please use `get_latest_blockhash_with_commitment` instead"
    )]
    #[allow(deprecated)]
    pub fn get_recent_blockhash_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<(Hash, FeeCalculator, Slot)> {
        let (context, blockhash, fee_calculator, last_valid_slot) = if let Ok(Response {
            context,
            value:
                RpcFees {
                    blockhash,
                    fee_calculator,
                    last_valid_slot,
                    ..
                },
        }) = self
            .send::<Response<RpcFees>>(
                RpcRequest::GetFees,
                json!([self.maybe_map_commitment(commitment_config)?]),
            ) {
            (context, blockhash, fee_calculator, last_valid_slot)
        } else if let Ok(Response {
            context,
            value:
                DeprecatedRpcFees {
                    blockhash,
                    fee_calculator,
                    last_valid_slot,
                },
        }) = self.send::<Response<DeprecatedRpcFees>>(
            RpcRequest::GetFees,
            json!([self.maybe_map_commitment(commitment_config)?]),
        ) {
            (context, blockhash, fee_calculator, last_valid_slot)
        } else if let Ok(Response {
            context,
            value:
                RpcBlockhashFeeCalculator {
                    blockhash,
                    fee_calculator,
                },
        }) = self.send::<Response<RpcBlockhashFeeCalculator>>(
            RpcRequest::GetRecentBlockhash,
            json!([self.maybe_map_commitment(commitment_config)?]),
        ) {
            (context, blockhash, fee_calculator, 0)
        } else {
            return Err(ClientError::new_with_request(
                RpcError::ParseError("RpcBlockhashFeeCalculator or RpcFees".to_string()).into(),
                RpcRequest::GetRecentBlockhash,
            ));
        };

        let blockhash = blockhash.parse().map_err(|_| {
            ClientError::new_with_request(
                RpcError::ParseError("Hash".to_string()).into(),
                RpcRequest::GetRecentBlockhash,
            )
        })?;
        Ok(Response {
            context,
            value: (blockhash, fee_calculator, last_valid_slot),
        })
    }

    #[deprecated(since = "1.9.0", note = "Please `get_fee_for_message` instead")]
    #[allow(deprecated)]
    pub fn get_fee_calculator_for_blockhash(
        &self,
        blockhash: &Hash,
    ) -> ClientResult<Option<FeeCalculator>> {
        #[allow(deprecated)]
        Ok(self
            .get_fee_calculator_for_blockhash_with_commitment(blockhash, self.commitment())?
            .value)
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please `get_latest_blockhash_with_commitment` and `get_fee_for_message` instead"
    )]
    #[allow(deprecated)]
    pub fn get_fee_calculator_for_blockhash_with_commitment(
        &self,
        blockhash: &Hash,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<Option<FeeCalculator>> {
        let Response { context, value } = self.send::<Response<Option<RpcFeeCalculator>>>(
            RpcRequest::GetFeeCalculatorForBlockhash,
            json!([
                blockhash.to_string(),
                self.maybe_map_commitment(commitment_config)?
            ]),
        )?;

        Ok(Response {
            context,
            value: value.map(|rf| rf.fee_calculator),
        })
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please do not use, will no longer be available in the future"
    )]
    #[allow(deprecated)]
    pub fn get_fee_rate_governor(&self) -> RpcResult<FeeRateGovernor> {
        let Response {
            context,
            value: RpcFeeRateGovernor { fee_rate_governor },
        } =
            self.send::<Response<RpcFeeRateGovernor>>(RpcRequest::GetFeeRateGovernor, Value::Null)?;

        Ok(Response {
            context,
            value: fee_rate_governor,
        })
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please do not use, will no longer be available in the future"
    )]
    #[allow(deprecated)]
    pub fn get_new_blockhash(&self, blockhash: &Hash) -> ClientResult<(Hash, FeeCalculator)> {
        let mut num_retries = 0;
        let start = Instant::now();
        while start.elapsed().as_secs() < 5 {
            #[allow(deprecated)]
            if let Ok((new_blockhash, fee_calculator)) = self.get_recent_blockhash() {
                if new_blockhash != *blockhash {
                    return Ok((new_blockhash, fee_calculator));
                }
            }
            debug!("Got same blockhash ({:?}), will retry...", blockhash);

            // Retry ~twice during a slot
            sleep(Duration::from_millis(DEFAULT_MS_PER_SLOT / 2));
            num_retries += 1;
        }
        Err(RpcError::ForUser(format!(
            "Unable to get new blockhash after {}ms (retried {} times), stuck at {}",
            start.elapsed().as_millis(),
            num_retries,
            blockhash
        ))
        .into())
    }

    pub fn get_first_available_block(&self) -> ClientResult<Slot> {
        self.send(RpcRequest::GetFirstAvailableBlock, Value::Null)
    }

    pub fn get_genesis_hash(&self) -> ClientResult<Hash> {
        let hash_str: String = self.send(RpcRequest::GetGenesisHash, Value::Null)?;
        let hash = hash_str.parse().map_err(|_| {
            ClientError::new_with_request(
                RpcError::ParseError("Hash".to_string()).into(),
                RpcRequest::GetGenesisHash,
            )
        })?;
        Ok(hash)
    }

    pub fn get_health(&self) -> ClientResult<()> {
        self.send::<String>(RpcRequest::GetHealth, Value::Null)
            .map(|_| ())
    }

    pub fn get_token_account(&self, pubkey: &Pubkey) -> ClientResult<Option<UiTokenAccount>> {
        Ok(self
            .get_token_account_with_commitment(pubkey, self.commitment())?
            .value)
    }

    pub fn get_token_account_with_commitment(
        &self,
        pubkey: &Pubkey,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<Option<UiTokenAccount>> {
        let config = RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::JsonParsed),
            commitment: Some(self.maybe_map_commitment(commitment_config)?),
            data_slice: None,
        };
        let response = self.sender.send(
            RpcRequest::GetAccountInfo,
            json!([pubkey.to_string(), config]),
        );

        response
            .map(|result_json| {
                if result_json.is_null() {
                    return Err(
                        RpcError::ForUser(format!("AccountNotFound: pubkey={}", pubkey)).into(),
                    );
                }
                let Response {
                    context,
                    value: rpc_account,
                } = serde_json::from_value::<Response<Option<UiAccount>>>(result_json)?;
                trace!("Response account {:?} {:?}", pubkey, rpc_account);
                let response = {
                    if let Some(rpc_account) = rpc_account {
                        if let UiAccountData::Json(account_data) = rpc_account.data {
                            let token_account_type: TokenAccountType =
                                serde_json::from_value(account_data.parsed)?;
                            if let TokenAccountType::Account(token_account) = token_account_type {
                                return Ok(Response {
                                    context,
                                    value: Some(token_account),
                                });
                            }
                        }
                    }
                    Err(Into::<ClientError>::into(RpcError::ForUser(format!(
                        "Account could not be parsed as token account: pubkey={}",
                        pubkey
                    ))))
                };
                response?
            })
            .map_err(|err| {
                Into::<ClientError>::into(RpcError::ForUser(format!(
                    "AccountNotFound: pubkey={}: {}",
                    pubkey, err
                )))
            })?
    }

    pub fn get_token_account_balance(&self, pubkey: &Pubkey) -> ClientResult<UiTokenAmount> {
        Ok(self
            .get_token_account_balance_with_commitment(pubkey, self.commitment())?
            .value)
    }

    pub fn get_token_account_balance_with_commitment(
        &self,
        pubkey: &Pubkey,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<UiTokenAmount> {
        self.send(
            RpcRequest::GetTokenAccountBalance,
            json!([
                pubkey.to_string(),
                self.maybe_map_commitment(commitment_config)?
            ]),
        )
    }

    pub fn get_token_accounts_by_delegate(
        &self,
        delegate: &Pubkey,
        token_account_filter: TokenAccountsFilter,
    ) -> ClientResult<Vec<RpcKeyedAccount>> {
        Ok(self
            .get_token_accounts_by_delegate_with_commitment(
                delegate,
                token_account_filter,
                self.commitment(),
            )?
            .value)
    }

    pub fn get_token_accounts_by_delegate_with_commitment(
        &self,
        delegate: &Pubkey,
        token_account_filter: TokenAccountsFilter,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<Vec<RpcKeyedAccount>> {
        let token_account_filter = match token_account_filter {
            TokenAccountsFilter::Mint(mint) => RpcTokenAccountsFilter::Mint(mint.to_string()),
            TokenAccountsFilter::ProgramId(program_id) => {
                RpcTokenAccountsFilter::ProgramId(program_id.to_string())
            }
        };

        let config = RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::JsonParsed),
            commitment: Some(self.maybe_map_commitment(commitment_config)?),
            data_slice: None,
        };

        self.send(
            RpcRequest::GetTokenAccountsByOwner,
            json!([delegate.to_string(), token_account_filter, config]),
        )
    }

    pub fn get_token_accounts_by_owner(
        &self,
        owner: &Pubkey,
        token_account_filter: TokenAccountsFilter,
    ) -> ClientResult<Vec<RpcKeyedAccount>> {
        Ok(self
            .get_token_accounts_by_owner_with_commitment(
                owner,
                token_account_filter,
                self.commitment(),
            )?
            .value)
    }

    pub fn get_token_accounts_by_owner_with_commitment(
        &self,
        owner: &Pubkey,
        token_account_filter: TokenAccountsFilter,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<Vec<RpcKeyedAccount>> {
        let token_account_filter = match token_account_filter {
            TokenAccountsFilter::Mint(mint) => RpcTokenAccountsFilter::Mint(mint.to_string()),
            TokenAccountsFilter::ProgramId(program_id) => {
                RpcTokenAccountsFilter::ProgramId(program_id.to_string())
            }
        };

        let config = RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::JsonParsed),
            commitment: Some(self.maybe_map_commitment(commitment_config)?),
            data_slice: None,
        };

        self.send(
            RpcRequest::GetTokenAccountsByOwner,
            json!([owner.to_string(), token_account_filter, config]),
        )
    }

    pub fn get_token_supply(&self, mint: &Pubkey) -> ClientResult<UiTokenAmount> {
        Ok(self
            .get_token_supply_with_commitment(mint, self.commitment())?
            .value)
    }

    pub fn get_token_supply_with_commitment(
        &self,
        mint: &Pubkey,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<UiTokenAmount> {
        self.send(
            RpcRequest::GetTokenSupply,
            json!([
                mint.to_string(),
                self.maybe_map_commitment(commitment_config)?
            ]),
        )
    }

    pub fn request_airdrop(&self, pubkey: &Pubkey, lamports: u64) -> ClientResult<Signature> {
        self.request_airdrop_with_config(
            pubkey,
            lamports,
            RpcRequestAirdropConfig {
                commitment: Some(self.commitment()),
                ..RpcRequestAirdropConfig::default()
            },
        )
    }

    pub fn request_airdrop_with_blockhash(
        &self,
        pubkey: &Pubkey,
        lamports: u64,
        recent_blockhash: &Hash,
    ) -> ClientResult<Signature> {
        self.request_airdrop_with_config(
            pubkey,
            lamports,
            RpcRequestAirdropConfig {
                commitment: Some(self.commitment()),
                recent_blockhash: Some(recent_blockhash.to_string()),
            },
        )
    }

    pub fn request_airdrop_with_config(
        &self,
        pubkey: &Pubkey,
        lamports: u64,
        config: RpcRequestAirdropConfig,
    ) -> ClientResult<Signature> {
        let commitment = config.commitment.unwrap_or_default();
        let commitment = self.maybe_map_commitment(commitment)?;
        let config = RpcRequestAirdropConfig {
            commitment: Some(commitment),
            ..config
        };
        self.send(
            RpcRequest::RequestAirdrop,
            json!([pubkey.to_string(), lamports, config]),
        )
        .and_then(|signature: String| {
            Signature::from_str(&signature).map_err(|err| {
                ClientErrorKind::Custom(format!("signature deserialization failed: {}", err)).into()
            })
        })
        .map_err(|_| {
            RpcError::ForUser(
                "airdrop request failed. \
                This can happen when the rate limit is reached."
                    .to_string(),
            )
            .into()
        })
    }

    fn poll_balance_with_timeout_and_commitment(
        &self,
        pubkey: &Pubkey,
        polling_frequency: &Duration,
        timeout: &Duration,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<u64> {
        let now = Instant::now();
        loop {
            match self.get_balance_with_commitment(pubkey, commitment_config) {
                Ok(bal) => {
                    return Ok(bal.value);
                }
                Err(e) => {
                    sleep(*polling_frequency);
                    if now.elapsed() > *timeout {
                        return Err(e);
                    }
                }
            };
        }
    }

    pub fn poll_get_balance_with_commitment(
        &self,
        pubkey: &Pubkey,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<u64> {
        self.poll_balance_with_timeout_and_commitment(
            pubkey,
            &Duration::from_millis(100),
            &Duration::from_secs(1),
            commitment_config,
        )
    }

    pub fn wait_for_balance_with_commitment(
        &self,
        pubkey: &Pubkey,
        expected_balance: Option<u64>,
        commitment_config: CommitmentConfig,
    ) -> Option<u64> {
        const LAST: usize = 30;
        for run in 0..LAST {
            let balance_result = self.poll_get_balance_with_commitment(pubkey, commitment_config);
            if expected_balance.is_none() {
                return balance_result.ok();
            }
            trace!(
                "wait_for_balance_with_commitment [{}] {:?} {:?}",
                run,
                balance_result,
                expected_balance
            );
            if let (Some(expected_balance), Ok(balance_result)) = (expected_balance, balance_result)
            {
                if expected_balance == balance_result {
                    return Some(balance_result);
                }
            }
        }
        None
    }

    /// Poll the server to confirm a transaction.
    pub fn poll_for_signature(&self, signature: &Signature) -> ClientResult<()> {
        self.poll_for_signature_with_commitment(signature, self.commitment())
    }

    /// Poll the server to confirm a transaction.
    pub fn poll_for_signature_with_commitment(
        &self,
        signature: &Signature,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<()> {
        let now = Instant::now();
        loop {
            if let Ok(Some(_)) =
                self.get_signature_status_with_commitment(signature, commitment_config)
            {
                break;
            }
            if now.elapsed().as_secs() > 15 {
                return Err(RpcError::ForUser(format!(
                    "signature not found after {} seconds",
                    now.elapsed().as_secs()
                ))
                .into());
            }
            sleep(Duration::from_millis(250));
        }
        Ok(())
    }

    /// Poll the server to confirm a transaction.
    pub fn poll_for_signature_confirmation(
        &self,
        signature: &Signature,
        min_confirmed_blocks: usize,
    ) -> ClientResult<usize> {
        let mut now = Instant::now();
        let mut confirmed_blocks = 0;
        loop {
            let response = self.get_num_blocks_since_signature_confirmation(signature);
            match response {
                Ok(count) => {
                    if confirmed_blocks != count {
                        info!(
                            "signature {} confirmed {} out of {} after {} ms",
                            signature,
                            count,
                            min_confirmed_blocks,
                            now.elapsed().as_millis()
                        );
                        now = Instant::now();
                        confirmed_blocks = count;
                    }
                    if count >= min_confirmed_blocks {
                        break;
                    }
                }
                Err(err) => {
                    debug!("check_confirmations request failed: {:?}", err);
                }
            };
            if now.elapsed().as_secs() > 20 {
                info!(
                    "signature {} confirmed {} out of {} failed after {} ms",
                    signature,
                    confirmed_blocks,
                    min_confirmed_blocks,
                    now.elapsed().as_millis()
                );
                if confirmed_blocks > 0 {
                    return Ok(confirmed_blocks);
                } else {
                    return Err(RpcError::ForUser(format!(
                        "signature not found after {} seconds",
                        now.elapsed().as_secs()
                    ))
                    .into());
                }
            }
            sleep(Duration::from_millis(250));
        }
        Ok(confirmed_blocks)
    }

    pub fn get_num_blocks_since_signature_confirmation(
        &self,
        signature: &Signature,
    ) -> ClientResult<usize> {
        let result: Response<Vec<Option<TransactionStatus>>> = self.send(
            RpcRequest::GetSignatureStatuses,
            json!([[signature.to_string()]]),
        )?;

        let confirmations = result.value[0]
            .clone()
            .ok_or_else(|| {
                ClientError::new_with_request(
                    ClientErrorKind::Custom("signature not found".to_string()),
                    RpcRequest::GetSignatureStatuses,
                )
            })?
            .confirmations
            .unwrap_or(MAX_LOCKOUT_HISTORY + 1);
        Ok(confirmations)
    }

    pub fn get_latest_blockhash(&self) -> ClientResult<Hash> {
        let (blockhash, _) = self.get_latest_blockhash_with_commitment(self.commitment())?;
        Ok(blockhash)
    }

    #[allow(deprecated)]
    pub fn get_latest_blockhash_with_commitment(
        &self,
        commitment: CommitmentConfig,
    ) -> ClientResult<(Hash, u64)> {
        let (blockhash, last_valid_block_height) =
            if self.get_node_version()? < semver::Version::new(0, 6, 0) {
                let Fees {
                    blockhash,
                    last_valid_block_height,
                    ..
                } = self.get_fees_with_commitment(commitment)?.value;
                (blockhash, last_valid_block_height)
            } else {
                let RpcBlockhash {
                    blockhash,
                    last_valid_block_height,
                } = self
                    .send::<Response<RpcBlockhash>>(
                        RpcRequest::GetLatestBlockhash,
                        json!([self.maybe_map_commitment(commitment)?]),
                    )?
                    .value;
                let blockhash = blockhash.parse().map_err(|_| {
                    ClientError::new_with_request(
                        RpcError::ParseError("Hash".to_string()).into(),
                        RpcRequest::GetLatestBlockhash,
                    )
                })?;
                (blockhash, last_valid_block_height)
            };
        Ok((blockhash, last_valid_block_height))
    }

    #[allow(deprecated)]
    pub fn is_blockhash_valid(
        &self,
        blockhash: &Hash,
        commitment: CommitmentConfig,
    ) -> ClientResult<bool> {
        let result = if self.get_node_version()? < semver::Version::new(0, 6, 0) {
            self.get_fee_calculator_for_blockhash_with_commitment(blockhash, commitment)?
                .value
                .is_some()
        } else {
            self.send::<Response<bool>>(
                RpcRequest::IsBlockhashValid,
                json!([blockhash.to_string(), commitment,]),
            )?
            .value
        };
        Ok(result)
    }

    #[allow(deprecated)]
    pub fn get_fee_for_message(&self, message: &Message) -> ClientResult<u64> {
        if self.get_node_version()? < semver::Version::new(0, 6, 0) {
            let fee_calculator = self
                .get_fee_calculator_for_blockhash(&message.recent_blockhash)?
                .ok_or_else(|| ClientErrorKind::Custom("Invalid blockhash".to_string()))?;
            Ok(fee_calculator
                .lamports_per_signature
                .saturating_mul(message.header.num_required_signatures as u64))
        } else {
            let serialized_encoded =
                serialize_and_encode::<Message>(message, UiTransactionEncoding::Base64)?;
            let result = self.send::<Response<Option<u64>>>(
                RpcRequest::GetFeeForMessage,
                json!([serialized_encoded, self.commitment()]),
            )?;
            result
                .value
                .ok_or_else(|| ClientErrorKind::Custom("Invalid blockhash".to_string()).into())
        }
    }

    pub fn get_new_latest_blockhash(&self, blockhash: &Hash) -> ClientResult<Hash> {
        let mut num_retries = 0;
        let start = Instant::now();
        while start.elapsed().as_secs() < 5 {
            if let Ok(new_blockhash) = self.get_latest_blockhash() {
                if new_blockhash != *blockhash {
                    return Ok(new_blockhash);
                }
            }
            debug!("Got same blockhash ({:?}), will retry...", blockhash);

            // Retry ~twice during a slot
            sleep(Duration::from_millis(DEFAULT_MS_PER_SLOT / 2));
            num_retries += 1;
        }
        Err(RpcError::ForUser(format!(
            "Unable to get new blockhash after {}ms (retried {} times), stuck at {}",
            start.elapsed().as_millis(),
            num_retries,
            blockhash
        ))
        .into())
    }

    pub fn get_transport_stats(&self) -> RpcTransportStats {
        self.sender.get_transport_stats()
    }

    //
    // Evm scope
    //

    pub fn get_evm_transaction_count(
        &self,
        address: &evm_state::Address,
    ) -> ClientResult<evm_state::U256> {
        self.send::<evm_rpc::Hex<_>>(
            RpcRequest::EthGetTransactionCount,
            json!([evm_rpc::Hex(*address)]),
        )
        .map(|h| h.0)
    }

    pub fn get_evm_balance(&self, address: &evm_state::Address) -> ClientResult<evm_state::U256> {
        self.send::<evm_rpc::Hex<_>>(
            RpcRequest::EthGetBalance,
            json!([evm_rpc::Hex(*address), "latest"]),
        )
        .map(|h| h.0)
    }

    pub fn get_evm_transaction_receipt(
        &self,
        hash: &evm_state::H256,
    ) -> ClientResult<Option<evm_rpc::RPCReceipt>> {
        self.send::<Option<evm_rpc::RPCReceipt>>(
            RpcRequest::EthGetTransactionReceipt,
            json!([evm_rpc::Hex(*hash)]),
        )
    }
}

pub fn serialize_and_encode<T>(input: &T, encoding: UiTransactionEncoding) -> ClientResult<String>
where
    T: serde::ser::Serialize,
{
    let serialized = serialize(input)
        .map_err(|e| ClientErrorKind::Custom(format!("Serialization failed: {}", e)))?;
    let encoded = match encoding {
        UiTransactionEncoding::Base58 => bs58::encode(serialized).into_string(),
        UiTransactionEncoding::Base64 => base64::encode(serialized),
        _ => {
            return Err(ClientErrorKind::Custom(format!(
                "unsupported encoding: {}. Supported encodings: base58, base64",
                encoding
            ))
            .into())
        }
    };
    Ok(encoded)
}

#[derive(Debug, Default)]
pub struct GetConfirmedSignaturesForAddress2Config {
    pub before: Option<Signature>,
    pub until: Option<Signature>,
    pub limit: Option<usize>,
    pub commitment: Option<CommitmentConfig>,
}

fn get_rpc_request_str(rpc_addr: SocketAddr, tls: bool) -> String {
    if tls {
        format!("https://{}", rpc_addr)
    } else {
        format!("http://{}", rpc_addr)
    }
}

fn parse_keyed_accounts(
    accounts: Vec<RpcKeyedAccount>,
    request: RpcRequest,
) -> ClientResult<Vec<(Pubkey, Account)>> {
    let mut pubkey_accounts: Vec<(Pubkey, Account)> = Vec::with_capacity(accounts.len());
    for RpcKeyedAccount { pubkey, account } in accounts.into_iter() {
        let pubkey = pubkey.parse().map_err(|_| {
            ClientError::new_with_request(
                RpcError::ParseError("Pubkey".to_string()).into(),
                request,
            )
        })?;
        pubkey_accounts.push((
            pubkey,
            account.decode().ok_or_else(|| {
                ClientError::new_with_request(
                    RpcError::ParseError("Account from rpc".to_string()).into(),
                    request,
                )
            })?,
        ));
    }
    Ok(pubkey_accounts)
}

/// Mocks for documentation examples
#[doc(hidden)]
pub fn create_rpc_client_mocks() -> crate::mock_sender::Mocks {
    let mut mocks = std::collections::HashMap::new();

    let get_account_request = RpcRequest::GetAccountInfo;
    let get_account_response = serde_json::to_value(Response {
        context: RpcResponseContext { slot: 1 },
        value: {
            let pubkey = Pubkey::from_str("BgvYtJEfmZYdVKiptmMjxGzv8iQoo4MWjsP3QsTkhhxa").unwrap();
            let account = Account {
                lamports: 1_000_000,
                data: vec![],
                owner: pubkey,
                executable: false,
                rent_epoch: 0,
            };
            UiAccount::encode(&pubkey, &account, UiAccountEncoding::Base64, None, None)
        },
    })
    .unwrap();

    mocks.insert(get_account_request, get_account_response);

    mocks
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{client_error::ClientErrorKind, mock_sender::PUBKEY},
        assert_matches::assert_matches,
        jsonrpc_core::{futures::prelude::*, Error, IoHandler, Params},
        jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder},
        serde_json::Number,
        solana_sdk::{
            instruction::InstructionError,
            signature::{Keypair, Signer},
            system_transaction,
            transaction::TransactionError,
        },
        std::{io, sync::mpsc::channel, thread},
    };

    #[test]
    fn test_send() {
        _test_send();
    }

    #[tokio::test(flavor = "current_thread")]
    #[should_panic(expected = "can call blocking only when running on the multi-threaded runtime")]
    async fn test_send_async_current_thread_should_panic() {
        _test_send();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_send_async_multi_thread() {
        _test_send();
    }

    fn _test_send() {
        let (sender, receiver) = channel();
        thread::spawn(move || {
            let rpc_addr = "0.0.0.0:0".parse().unwrap();
            let mut io = IoHandler::default();
            // Successful request
            io.add_method("getBalance", |_params: Params| {
                future::ok(Value::Number(Number::from(50)))
            });
            // Failed request
            io.add_method("getRecentBlockhash", |params: Params| {
                if params != Params::None {
                    future::err(Error::invalid_request())
                } else {
                    future::ok(Value::String(
                        "deadbeefXjn8o3yroDHxUtKsZZgoy4GPkPPXfouKNHhx".to_string(),
                    ))
                }
            });

            let server = ServerBuilder::new(io)
                .threads(1)
                .cors(DomainsValidation::AllowOnly(vec![
                    AccessControlAllowOrigin::Any,
                ]))
                .start_http(&rpc_addr)
                .expect("Unable to start RPC server");
            sender.send(*server.address()).unwrap();
            server.wait();
        });

        let rpc_addr = receiver.recv().unwrap();
        let rpc_client = RpcClient::new_socket(rpc_addr);

        let balance: u64 = rpc_client
            .send(
                RpcRequest::GetBalance,
                json!(["deadbeefXjn8o3yroDHxUtKsZZgoy4GPkPPXfouKNHhx"]),
            )
            .unwrap();
        assert_eq!(balance, 50);

        #[allow(deprecated)]
        let blockhash: String = rpc_client
            .send(RpcRequest::GetRecentBlockhash, Value::Null)
            .unwrap();
        assert_eq!(blockhash, "deadbeefXjn8o3yroDHxUtKsZZgoy4GPkPPXfouKNHhx");

        // Send erroneous parameter
        #[allow(deprecated)]
        let blockhash: ClientResult<String> =
            rpc_client.send(RpcRequest::GetRecentBlockhash, json!(["parameter"]));
        assert!(blockhash.is_err());
    }

    #[test]
    fn test_send_transaction() {
        let rpc_client = RpcClient::new_mock("succeeds".to_string());

        let key = Keypair::new();
        let to = solana_sdk::pubkey::new_rand();
        let blockhash = Hash::default();
        let tx = system_transaction::transfer(&key, &to, 50, blockhash);

        let signature = rpc_client.send_transaction(&tx);
        assert_eq!(signature.unwrap(), tx.signatures[0]);

        let rpc_client = RpcClient::new_mock("fails".to_string());

        let signature = rpc_client.send_transaction(&tx);
        assert!(signature.is_err());

        // Test bad signature returned from rpc node
        let rpc_client = RpcClient::new_mock("malicious".to_string());
        let signature = rpc_client.send_transaction(&tx);
        assert!(signature.is_err());
    }

    #[test]
    fn test_get_recent_blockhash() {
        let rpc_client = RpcClient::new_mock("succeeds".to_string());

        let expected_blockhash: Hash = PUBKEY.parse().unwrap();

        let blockhash = rpc_client.get_latest_blockhash().expect("blockhash ok");
        assert_eq!(blockhash, expected_blockhash);

        let rpc_client = RpcClient::new_mock("fails".to_string());

        #[allow(deprecated)]
        let result = rpc_client.get_recent_blockhash();
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_request() {
        let rpc_client = RpcClient::new_mock("succeeds".to_string());

        let slot = rpc_client.get_slot().unwrap();
        assert_eq!(slot, 0);

        let custom_slot = rpc_client
            .send::<Slot>(RpcRequest::Custom { method: "getSlot" }, Value::Null)
            .unwrap();

        assert_eq!(slot, custom_slot);
    }

    #[test]
    fn test_get_signature_status() {
        let signature = Signature::default();

        let rpc_client = RpcClient::new_mock("succeeds".to_string());
        let status = rpc_client.get_signature_status(&signature).unwrap();
        assert_eq!(status, Some(Ok(())));

        let rpc_client = RpcClient::new_mock("sig_not_found".to_string());
        let status = rpc_client.get_signature_status(&signature).unwrap();
        assert_eq!(status, None);

        let rpc_client = RpcClient::new_mock("account_in_use".to_string());
        let status = rpc_client.get_signature_status(&signature).unwrap();
        assert_eq!(status, Some(Err(TransactionError::AccountInUse)));
    }

    #[test]
    fn test_send_and_confirm_transaction() {
        let rpc_client = RpcClient::new_mock("succeeds".to_string());

        let key = Keypair::new();
        let to = solana_sdk::pubkey::new_rand();
        let blockhash = Hash::default();
        let tx = system_transaction::transfer(&key, &to, 50, blockhash);
        let result = rpc_client.send_and_confirm_transaction(&tx);
        result.unwrap();

        let rpc_client = RpcClient::new_mock("account_in_use".to_string());
        let result = rpc_client.send_and_confirm_transaction(&tx);
        assert!(result.is_err());

        let rpc_client = RpcClient::new_mock("instruction_error".to_string());
        let result = rpc_client.send_and_confirm_transaction(&tx);
        assert_matches!(
            result.unwrap_err().kind(),
            ClientErrorKind::TransactionError(TransactionError::InstructionError(
                0,
                InstructionError::UninitializedAccount
            ))
        );

        let rpc_client = RpcClient::new_mock("sig_not_found".to_string());
        let result = rpc_client.send_and_confirm_transaction(&tx);
        if let ClientErrorKind::Io(err) = result.unwrap_err().kind() {
            assert_eq!(err.kind(), io::ErrorKind::Other);
        }
    }

    #[test]
    fn test_rpc_client_thread() {
        let rpc_client = RpcClient::new_mock("succeeds".to_string());
        thread::spawn(move || rpc_client);
    }

    // Regression test that the get_block_production_with_config
    // method internally creates the json params array correctly.
    #[test]
    fn get_block_production_with_config_no_error() -> ClientResult<()> {
        let rpc_client = RpcClient::new_mock("succeeds".to_string());

        let config = RpcBlockProductionConfig {
            identity: Some(Keypair::new().pubkey().to_string()),
            range: None,
            commitment: None,
        };

        let prod = rpc_client.get_block_production_with_config(config)?.value;

        assert!(!prod.by_identity.is_empty());

        Ok(())
    }

    #[test]
    fn test_get_latest_blockhash() {
        let rpc_client = RpcClient::new_mock("succeeds".to_string());

        let expected_blockhash: Hash = PUBKEY.parse().unwrap();

        let blockhash = rpc_client.get_latest_blockhash().expect("blockhash ok");
        assert_eq!(blockhash, expected_blockhash);

        let rpc_client = RpcClient::new_mock("fails".to_string());

        #[allow(deprecated)]
        let is_err = rpc_client.get_latest_blockhash().is_err();
        assert!(is_err);
    }
}
