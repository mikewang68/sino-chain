use {
    crate::{
        client_error::{ClientError, ClientErrorKind, Result as ClientResult},
    },
    transaction_status::{
        UiTransactionEncoding,
    },
};

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