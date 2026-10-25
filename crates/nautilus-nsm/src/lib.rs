//! AWS Nitro Secure Module driver for `/dev/nsm`.

use std::{
    fs::{File, OpenOptions},
    io,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use ciborium::value::Value;
use thiserror::Error;

/// Path of the NSM device inside a Nitro Enclave.
pub const DEVICE_PATH: &str = "/dev/nsm";

const PUBLIC_KEY_LEN: usize = 32;
const NSM_REQUEST_MAX_SIZE: usize = 0x1000;
const NSM_RESPONSE_MAX_SIZE: usize = 0x3000;
#[cfg(target_env = "musl")]
const NSM_IOCTL_REQUEST: libc::c_int = -1071642112;
#[cfg(not(target_env = "musl"))]
const NSM_IOCTL_REQUEST: libc::c_ulong = 0xC020_0A00;

/// Errors returned by the NSM driver.
#[derive(Debug, Error)]
pub enum NsmError {
    /// The NSM device could not be opened.
    #[error("NSM device {} unavailable: {source}", path.display())]
    Unavailable {
        /// Device path that failed to open.
        path: PathBuf,
        /// Underlying open error.
        source: io::Error,
    },
    /// The NSM ioctl failed.
    #[error("NSM I/O error: {0}")]
    Io(#[from] io::Error),
    /// The request was rejected before reaching the device.
    #[error("invalid NSM request: {0}")]
    InvalidRequest(String),
    /// The device returned a response that could not be decoded.
    #[error("malformed NSM response: {0}")]
    MalformedResponse(String),
    /// The device returned an explicit error.
    #[error("NSM device error: {0}")]
    Device(String),
}

/// Handle to an open NSM device.
#[derive(Debug)]
pub struct Nsm {
    device: Mutex<File>,
}

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

impl Nsm {
    /// Opens the NSM device at [`DEVICE_PATH`].
    pub fn open() -> Result<Self, NsmError> {
        Self::open_path(DEVICE_PATH)
    }

    /// Opens an NSM device at `path`.
    pub fn open_path(path: impl AsRef<Path>) -> Result<Self, NsmError> {
        let path = path.as_ref();
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|source| NsmError::Unavailable {
                path: path.to_owned(),
                source,
            })?;
        Ok(Self {
            device: Mutex::new(device),
        })
    }

    /// Requests an attestation document binding `public_key`, `nonce` and `user_data`.
    pub fn attestation(
        &self,
        public_key: &[u8],
        nonce: Option<&[u8]>,
        user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, NsmError> {
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(NsmError::InvalidRequest(format!(
                "public key must be {PUBLIC_KEY_LEN} bytes, got {}",
                public_key.len()
            )));
        }

        let request = encode_attestation_request(public_key, nonce, user_data)?;
        let response = self.transact(&request)?;
        decode_attestation_response(&response)
    }

    /// Returns `len` bytes from the NSM random number generator.
    pub fn random(&self, len: usize) -> Result<Vec<u8>, NsmError> {
        collect_random(len, |request| self.transact(request))
    }

    fn transact(&self, request: &[u8]) -> Result<Vec<u8>, NsmError> {
        if request.len() > NSM_REQUEST_MAX_SIZE {
            return Err(NsmError::InvalidRequest(format!(
                "NSM request too large: {} > {NSM_REQUEST_MAX_SIZE}",
                request.len()
            )));
        }

        let device = self.device.lock().unwrap_or_else(PoisonError::into_inner);
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
        let result = unsafe {
            libc::ioctl(
                device.as_raw_fd(),
                NSM_IOCTL_REQUEST,
                &mut message as *mut NsmMessage,
            )
        };
        if result < 0 {
            return Err(NsmError::Io(io::Error::last_os_error()));
        }

        response.truncate(checked_response_len(message.response.len, response.len())?);
        Ok(response)
    }
}

fn collect_random(
    len: usize,
    mut transact: impl FnMut(&[u8]) -> Result<Vec<u8>, NsmError>,
) -> Result<Vec<u8>, NsmError> {
    let request = encode_get_random_request()?;
    let mut output = Vec::with_capacity(len);
    while output.len() < len {
        let chunk = decode_get_random_response(&transact(&request)?)?;
        if chunk.is_empty() {
            return Err(NsmError::MalformedResponse(
                "NSM returned empty random response".to_owned(),
            ));
        }
        output.extend_from_slice(&chunk);
    }
    output.truncate(len);
    Ok(output)
}

fn checked_response_len(reported: usize, capacity: usize) -> Result<usize, NsmError> {
    if reported > capacity {
        return Err(NsmError::MalformedResponse(format!(
            "NSM response length {reported} exceeds buffer {capacity}"
        )));
    }
    Ok(reported)
}

fn encode_attestation_request(
    public_key: &[u8],
    nonce: Option<&[u8]>,
    user_data: Option<&[u8]>,
) -> Result<Vec<u8>, NsmError> {
    let value = Value::Map(vec![(
        Value::Text("Attestation".to_owned()),
        Value::Map(vec![
            (
                Value::Text("user_data".to_owned()),
                optional_bytes(user_data),
            ),
            (Value::Text("nonce".to_owned()), optional_bytes(nonce)),
            (
                Value::Text("public_key".to_owned()),
                Value::Bytes(public_key.to_vec()),
            ),
        ]),
    )]);
    encode_value(&value)
}

fn encode_get_random_request() -> Result<Vec<u8>, NsmError> {
    encode_value(&Value::Text("GetRandom".to_owned()))
}

fn optional_bytes(value: Option<&[u8]>) -> Value {
    match value {
        Some(bytes) => Value::Bytes(bytes.to_vec()),
        None => Value::Null,
    }
}

fn encode_value(value: &Value) -> Result<Vec<u8>, NsmError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|error| NsmError::InvalidRequest(error.to_string()))?;
    Ok(bytes)
}

fn decode_value(bytes: &[u8]) -> Result<Value, NsmError> {
    ciborium::de::from_reader(bytes).map_err(|error| NsmError::MalformedResponse(error.to_string()))
}

fn decode_attestation_response(bytes: &[u8]) -> Result<Vec<u8>, NsmError> {
    match decode_nsm_response(bytes)? {
        NsmResponse::Attestation { document } => Ok(document),
        NsmResponse::Error(error) => Err(NsmError::Device(error)),
        other => Err(NsmError::MalformedResponse(format!(
            "expected Attestation response, got {other:?}"
        ))),
    }
}

fn decode_get_random_response(bytes: &[u8]) -> Result<Vec<u8>, NsmError> {
    match decode_nsm_response(bytes)? {
        NsmResponse::GetRandom { random } => Ok(random),
        NsmResponse::Error(error) => Err(NsmError::Device(error)),
        other => Err(NsmError::MalformedResponse(format!(
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

fn decode_nsm_response(bytes: &[u8]) -> Result<NsmResponse, NsmError> {
    let value = decode_value(bytes)?;
    let Value::Map(entries) = value else {
        return Err(NsmError::MalformedResponse(
            "NSM response must be a map".to_owned(),
        ));
    };

    if let Some(value) = map_get(&entries, "Attestation") {
        let inner = as_map(value)?;
        let document = map_get(inner, "document")
            .and_then(as_bytes)
            .ok_or_else(|| {
                NsmError::MalformedResponse("missing attestation document".to_owned())
            })?;
        return Ok(NsmResponse::Attestation { document });
    }

    if let Some(value) = map_get(&entries, "GetRandom") {
        let inner = as_map(value)?;
        let random = map_get(inner, "random")
            .and_then(as_bytes)
            .ok_or_else(|| NsmError::MalformedResponse("missing random bytes".to_owned()))?;
        return Ok(NsmResponse::GetRandom { random });
    }

    if let Some(value) = map_get(&entries, "Error") {
        let error = as_text(value)
            .ok_or_else(|| NsmError::MalformedResponse("NSM error must be text".to_owned()))?;
        return Ok(NsmResponse::Error(error));
    }

    Err(NsmError::MalformedResponse(
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

fn as_map(value: &Value) -> Result<&[(Value, Value)], NsmError> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(NsmError::MalformedResponse("expected CBOR map".to_owned())),
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
        let bytes = encode_attestation_request(&[0x11; 32], Some(&[0x22; 4]), None).unwrap();
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
    fn decodes_error_response_as_device_error() {
        let response = encode_response(Value::Map(vec![(
            Value::Text("Error".to_owned()),
            Value::Text("InvalidArgument".to_owned()),
        )]));

        let error = decode_attestation_response(&response).unwrap_err();
        assert!(matches!(error, NsmError::Device(message) if message == "InvalidArgument"));
    }

    fn random_response(bytes: &[u8]) -> Vec<u8> {
        encode_response(Value::Map(vec![(
            Value::Text("GetRandom".to_owned()),
            Value::Map(vec![(
                Value::Text("random".to_owned()),
                Value::Bytes(bytes.to_vec()),
            )]),
        )]))
    }

    #[test]
    fn random_concatenates_chunks_and_truncates() {
        let mut calls = 0u8;
        let output = collect_random(10, |request| {
            assert_eq!(request, encode_get_random_request().unwrap());
            calls += 1;
            Ok(random_response(&[calls; 4]))
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(output, [1, 1, 1, 1, 2, 2, 2, 2, 3, 3]);
        assert!(collect_random(0, |_| unreachable!()).unwrap().is_empty());
    }

    #[test]
    fn random_rejects_empty_chunk() {
        let error = collect_random(4, |_| Ok(random_response(&[]))).unwrap_err();
        assert!(matches!(error, NsmError::MalformedResponse(_)));
    }

    #[test]
    fn random_propagates_device_error() {
        let error = collect_random(4, |_| {
            Ok(encode_response(Value::Map(vec![(
                Value::Text("Error".to_owned()),
                Value::Text("InternalError".to_owned()),
            )])))
        })
        .unwrap_err();
        assert!(matches!(error, NsmError::Device(message) if message == "InternalError"));
    }

    #[test]
    fn response_length_beyond_buffer_is_malformed() {
        assert_eq!(checked_response_len(0x3000, 0x3000).unwrap(), 0x3000);
        let error = checked_response_len(0x3001, 0x3000).unwrap_err();
        assert!(matches!(error, NsmError::MalformedResponse(_)));
        assert!(error.to_string().contains("12289 exceeds buffer 12288"));
    }

    #[test]
    fn open_missing_device_is_unavailable() {
        let error = Nsm::open_path("/no/such/nsm").unwrap_err();
        assert!(
            matches!(error, NsmError::Unavailable { ref path, .. } if path == Path::new("/no/such/nsm"))
        );
    }

    #[test]
    fn rejects_wrong_public_key_length() {
        let nsm = Nsm::open_path("/dev/null").unwrap();
        let error = nsm.attestation(&[0u8; 31], None, None).unwrap_err();
        assert!(matches!(error, NsmError::InvalidRequest(_)));
        assert!(error.to_string().contains("public key must be 32 bytes"));
    }

    #[test]
    fn ioctl_on_non_nsm_device_is_io_error() {
        let nsm = Nsm::open_path("/dev/null").unwrap();
        assert!(matches!(nsm.random(32).unwrap_err(), NsmError::Io(_)));
    }
}
