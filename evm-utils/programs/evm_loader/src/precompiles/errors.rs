use crate::scope::*;
use evm_state::{CallScheme, ExitError};
use hex::FromHexError;
use sdk::instruction::InstructionError;

use snafu::Snafu;
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[snafu(context(suffix(false)))]
pub enum PrecompileErrors {
    #[snafu(display("Cannot parse function {} abi = {}", name, source))]
    FailedToParse { name: String, source: ethabi::Error },

    #[snafu(display("Cannot parse function input {} error = {}", arg_type, source))]
    FailedToParseInput {
        arg_type: String,
        source: FromHexError,
    },

    #[snafu(display(
        "Input len lesser than 4 bytes, expected to be function hash, input_len = {}",
        input_len
    ))]
    InputToShort { input_len: usize },

    #[snafu(display("Function hash, not equal, expected = {}, got = {}", expected, got))]
    MismatchFunctionHash { expected: String, got: String },

    #[snafu(display(
        "Received different params count, expected = {}, got = {}",
        expected,
        got
    ))]
    ParamsCountMismatch { expected: usize, got: usize },

    #[snafu(display(
        "Function received unexpected input, expected = {}, got = {}",
        expected,
        got
    ))]
    UnexpectedInput { expected: String, got: String },

    #[snafu(display("Failed to find account, account_pk = {}", public_key))]
    AccountNotFound { public_key: solana::Address },

    #[snafu(display(
        "No enough tokens, on EVM state account, to credit request = {}",
        wens
    ))]
    InsufficientFunds { wens: u64 },

    #[snafu(display("Native chain Instruction error source = {}", source))]
    #[snafu(context(suffix(Error)))]
    NativeChainInstructionError { source: InstructionError },

    #[snafu(display("Invalid call scheme, or code address schema = {:?}", scheme))]
    InvalidCallScheme { scheme: Option<CallScheme> },

    #[snafu(display("Failed to serialize log = {:?}", error))]
    LogSerializeError { error: bincode::Error },

    #[snafu(display("Cannot parse point: {}", message))]
    ParsePointError { message: String },

    #[snafu(display("Cannot parse coordinate: {}", message))]
    ParseCoordinateError { message: String },

    #[snafu(display("Bad input length: {}", length))]
    BadInputLength { length: usize },

    #[snafu(display("Incorrect final block indicator flag"))]
    IncorrectBlockIndicator,
}

impl From<PrecompileErrors> for ExitError {
    fn from(rhs: PrecompileErrors) -> Self {
        ExitError::Other(rhs.to_string().into())
    }
}
