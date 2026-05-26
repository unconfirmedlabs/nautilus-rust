//! AWS Nitro Secure Module adapter for Nautilus.

use std::{
    fs::OpenOptions,
    io,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use ciborium::value::Value;
use nautilus::{AttestationError, AttestationRequest, Attestor, EnclaveIdentity, NautilusContext};

const DEFAULT_NSM_DEVICE_PATH: &str = "/dev/nsm";
const NSM_REQUEST_MAX_SIZE: usize = 0x1000;
const NSM_RESPONSE_MAX_SIZE: usize = 0x3000;
const NSM_IOCTL_REQUEST: libc::c_ulong = 0xC020_0A00;

#[repr(C)]
struct Iovec {
    base: *mut libc::c_void,
    len: libc::size_t,
}

#[repr(C)]
struct NsmMessage {
    request: Iovec,
    response: Iovec,
}

/// Real AWS Nitro Secure Module attestation provider.
#[derive(Debug, Clone)]
pub struct NsmAttestor {
    device_path: PathBuf,
}

impl Default for NsmAttestor {
    fn default() -> Self {
        Self::new(DEFAULT_NSM_DEVICE_PATH)
    }
}

impl NsmAttestor {
    /// Creates an attestor that opens `device_path` for each request.
    pub fn new(device_path: impl Into<PathBuf>) -> Self {
        Self {
            device_path: device_path.into(),
        }
    }

    /// Returns the configured NSM device path.
    pub fn device_path(&self) -> &Path {
        &self.device_path
    }

    /// Creates a Nautilus context using this NSM attestor.
    ///
    /// The per-boot signing identity is generated from OS randomness mixed with
    /// NSM entropy, then bound into attestation documents through `public_key`.
    pub fn into_context(self) -> Result<NautilusContext, AttestationError> {
        let entropy = self.random(32)?;
        let identity = EnclaveIdentity::generate_with_entropy(&entropy);
        Ok(NautilusContext::new(identity, self))
    }

    fn transact(&self, request: &[u8]) -> Result<Vec<u8>, AttestationError> {
        if request.is_empty() {
            return Err(AttestationError::InvalidRequest(
                "NSM request cannot be empty".to_owned(),
            ));
        }
        if request.len() > NSM_REQUEST_MAX_SIZE {
            return Err(AttestationError::InvalidRequest(format!(
                "NSM request too large: {} > {}",
                request.len(),
                NSM_REQUEST_MAX_SIZE
            )));
        }

        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.device_path)
            .map_err(|error| {
                AttestationError::Unavailable(format!(
                    "failed to open {}: {error}",
                    self.device_path.display()
                ))
            })?;

        let mut response = vec![0u8; NSM_RESPONSE_MAX_SIZE];
        let mut request = request.to_vec();
        let mut message = NsmMessage {
            request: Iovec {
                base: request.as_mut_ptr().cast(),
                len: request.len(),
            },
            response: Iovec {
                base: response.as_mut_ptr().cast(),
                len: response.len(),
            },
        };

        // SAFETY: `message` points to live request/response buffers for the duration of the ioctl.
        // The ioctl number and layout match the AWS Nitro Enclaves NSM API on x86_64.
        let result = unsafe {
            libc::ioctl(
                device.as_raw_fd(),
                NSM_IOCTL_REQUEST,
                &mut message as *mut NsmMessage,
            )
        };
        if result < 0 {
            return Err(AttestationError::Io(io::Error::last_os_error()));
        }

        if message.response.len > response.len() {
            return Err(AttestationError::MalformedResponse(format!(
                "NSM response length {} exceeds buffer {}",
                message.response.len,
                response.len()
            )));
        }
        response.truncate(message.response.len);
        Ok(response)
    }
}

impl Attestor for NsmAttestor {
    fn attest(&self, request: AttestationRequest) -> Result<Vec<u8>, AttestationError> {
        if request.public_key.len() != 32 {
            return Err(AttestationError::InvalidRequest(format!(
                "public key must be 32 bytes, got {}",
                request.public_key.len()
            )));
        }

        let request = encode_attestation_request(&request)?;
        let response = self.transact(&request)?;
        decode_attestation_response(&response)
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, AttestationError> {
        let mut output = Vec::with_capacity(len);
        while output.len() < len {
            let request = encode_get_random_request()?;
            let response = self.transact(&request)?;
            let chunk = decode_get_random_response(&response)?;
            if chunk.is_empty() {
                return Err(AttestationError::MalformedResponse(
                    "NSM returned empty random response".to_owned(),
                ));
            }
            output.extend_from_slice(&chunk);
        }
        output.truncate(len);
        Ok(output)
    }
}

fn encode_attestation_request(request: &AttestationRequest) -> Result<Vec<u8>, AttestationError> {
    let value = Value::Map(vec![(
        Value::Text("Attestation".to_owned()),
        Value::Map(vec![
            (
                Value::Text("user_data".to_owned()),
                optional_bytes(request.user_data.as_deref()),
            ),
            (
                Value::Text("nonce".to_owned()),
                optional_bytes(request.nonce.as_deref()),
            ),
            (
                Value::Text("public_key".to_owned()),
                Value::Bytes(request.public_key.clone()),
            ),
        ]),
    )]);
    encode_value(&value)
}

fn encode_get_random_request() -> Result<Vec<u8>, AttestationError> {
    encode_value(&Value::Text("GetRandom".to_owned()))
}

fn optional_bytes(value: Option<&[u8]>) -> Value {
    match value {
        Some(bytes) => Value::Bytes(bytes.to_vec()),
        None => Value::Null,
    }
}

fn encode_value(value: &Value) -> Result<Vec<u8>, AttestationError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|error| AttestationError::Backend(error.to_string()))?;
    Ok(bytes)
}

fn decode_value(bytes: &[u8]) -> Result<Value, AttestationError> {
    ciborium::de::from_reader(bytes)
        .map_err(|error| AttestationError::MalformedResponse(error.to_string()))
}

fn decode_attestation_response(bytes: &[u8]) -> Result<Vec<u8>, AttestationError> {
    match decode_nsm_response(bytes)? {
        NsmResponse::Attestation { document } => Ok(document),
        NsmResponse::Error(error) => Err(AttestationError::Backend(error)),
        other => Err(AttestationError::MalformedResponse(format!(
            "expected Attestation response, got {other:?}"
        ))),
    }
}

fn decode_get_random_response(bytes: &[u8]) -> Result<Vec<u8>, AttestationError> {
    match decode_nsm_response(bytes)? {
        NsmResponse::GetRandom { random } => Ok(random),
        NsmResponse::Error(error) => Err(AttestationError::Backend(error)),
        other => Err(AttestationError::MalformedResponse(format!(
            "expected GetRandom response, got {other:?}"
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NsmResponse {
    Attestation { document: Vec<u8> },
    GetRandom { random: Vec<u8> },
    Error(String),
}

fn decode_nsm_response(bytes: &[u8]) -> Result<NsmResponse, AttestationError> {
    let value = decode_value(bytes)?;
    let Value::Map(entries) = value else {
        return Err(AttestationError::MalformedResponse(
            "NSM response must be a map".to_owned(),
        ));
    };

    if let Some(value) = map_get(&entries, "Attestation") {
        let inner = as_map(value)?;
        let document = map_get(inner, "document")
            .and_then(as_bytes)
            .ok_or_else(|| {
                AttestationError::MalformedResponse("missing attestation document".to_owned())
            })?;
        return Ok(NsmResponse::Attestation { document });
    }

    if let Some(value) = map_get(&entries, "GetRandom") {
        let inner = as_map(value)?;
        let random = map_get(inner, "random").and_then(as_bytes).ok_or_else(|| {
            AttestationError::MalformedResponse("missing random bytes".to_owned())
        })?;
        return Ok(NsmResponse::GetRandom { random });
    }

    if let Some(value) = map_get(&entries, "Error") {
        let error = as_text(value).ok_or_else(|| {
            AttestationError::MalformedResponse("NSM error must be text".to_owned())
        })?;
        return Ok(NsmResponse::Error(error));
    }

    Err(AttestationError::MalformedResponse(
        "unknown NSM response shape".to_owned(),
    ))
}

fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(entry_key, value)| {
        if matches!(entry_key, Value::Text(text) if text == key) {
            Some(value)
        } else {
            None
        }
    })
}

fn as_map(value: &Value) -> Result<&[(Value, Value)], AttestationError> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(AttestationError::MalformedResponse(
            "expected CBOR map".to_owned(),
        )),
    }
}

fn as_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    }
}

fn as_text(value: &Value) -> Option<String> {
    match value {
        Value::Text(text) => Some(text.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_response(value: Value) -> Vec<u8> {
        encode_value(&value).unwrap()
    }

    #[test]
    fn encodes_get_random_as_unit_variant_text() {
        let bytes = encode_get_random_request().unwrap();
        let value = decode_value(&bytes).unwrap();
        assert_eq!(value, Value::Text("GetRandom".to_owned()));
    }

    #[test]
    fn encodes_attestation_request_as_externally_tagged_map() {
        let request = AttestationRequest {
            public_key: vec![0x11; 32],
            nonce: Some(vec![0x22; 4]),
            user_data: None,
        };
        let bytes = encode_attestation_request(&request).unwrap();
        let value = decode_value(&bytes).unwrap();
        let Value::Map(outer) = value else {
            panic!("expected outer map");
        };
        let attestation = map_get(&outer, "Attestation").expect("attestation key");
        let inner = as_map(attestation).unwrap();

        assert_eq!(
            map_get(inner, "public_key").and_then(as_bytes).unwrap(),
            vec![0x11; 32]
        );
        assert_eq!(
            map_get(inner, "nonce").and_then(as_bytes).unwrap(),
            vec![0x22; 4]
        );
        assert!(matches!(map_get(inner, "user_data"), Some(Value::Null)));
    }

    #[test]
    fn decodes_attestation_response() {
        let response = encode_response(Value::Map(vec![(
            Value::Text("Attestation".to_owned()),
            Value::Map(vec![(
                Value::Text("document".to_owned()),
                Value::Bytes(vec![1, 2, 3]),
            )]),
        )]));

        assert_eq!(
            decode_attestation_response(&response).unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn decodes_random_response() {
        let response = encode_response(Value::Map(vec![(
            Value::Text("GetRandom".to_owned()),
            Value::Map(vec![(
                Value::Text("random".to_owned()),
                Value::Bytes(vec![0xde, 0xad]),
            )]),
        )]));

        assert_eq!(
            decode_get_random_response(&response).unwrap(),
            vec![0xde, 0xad]
        );
    }

    #[test]
    fn decodes_error_response_as_backend_error() {
        let response = encode_response(Value::Map(vec![(
            Value::Text("Error".to_owned()),
            Value::Text("InvalidArgument".to_owned()),
        )]));

        let error = decode_attestation_response(&response).unwrap_err();
        assert!(error.to_string().contains("InvalidArgument"));
    }

    #[test]
    fn rejects_wrong_public_key_length() {
        let attestor = NsmAttestor::new("/no/such/device");
        let error = attestor
            .attest(AttestationRequest::new(vec![0u8; 31]))
            .unwrap_err();
        assert!(error.to_string().contains("public key must be 32 bytes"));
    }
}
