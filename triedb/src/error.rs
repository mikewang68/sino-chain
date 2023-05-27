use primitive_types::H256;

use crate::ops::diff::verify::VerificationError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Decoder(#[from] rlp::DecoderError),
    #[error(transparent)]
    Verification(#[from] VerificationError),
    #[error("missing dependency node in DB `{0:?}`")]
    DiffPatchApply(H256),
}
