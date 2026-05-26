use crate::NautilusError;

/// Encodes bytes as lowercase hex.
pub fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}

/// Decodes hex, accepting an optional `0x` prefix.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, NautilusError> {
    let trimmed = input.trim();
    let value = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(value).map_err(|error| NautilusError::Hex(error.to_string()))
}
