# Attestation

The enclave generates an Ed25519 key at boot and asks the Nitro Secure Module (NSM) for an attestation document that carries that public key. A verifier that checks the document and its PCRs can then trust signatures from the key.

## Flow

1. `NautilusContext::from_runtime()` opens `/dev/nsm` through `NsmAttestor` and generates the key from OS randomness mixed with 32 bytes of NSM entropy. It errors if the device is missing and never falls back to a development identity.
2. The verifier sends `POST /attestation` with a fresh random nonce.
3. `NautilusContext::attestation(nonce, user_data)` validates the request and calls the NSM. The document is returned as hex: `{"attestation": "<hex>"}`.
4. The verifier checks the COSE signature, the certificate chain to the AWS root, the PCRs, the nonce, and that `public_key` equals `GET /health_check`'s `pk`.
5. The verifier accepts `/process_data` signatures from that key. On Sui, Kagi does steps 4 and 5; see [kagi.md](kagi.md).

Attestation calls block on the device, so the server runs them on the blocking thread pool. They share the `max_concurrent` limit with `/process_data`.

## What Attestation Proves

It proves that the public key in the document was generated inside a Nitro Enclave whose image measured to the document's PCRs, at the time the document was produced.

It does not prove:

- freshness of later signatures: a signature is valid for as long as the key is trusted;
- that the host is honest about time: `timestamp_ms` in signed messages is the enclave's clock, which the parent instance can influence;
- anything about inputs from the host: request bodies, files and secrets delivered over vsock are unmeasured, untrusted input. Validate them inside the enclave as you would any network input.

## PCRs

AWS defines the measurements as follows. All are SHA-384, 48 bytes.

| PCR | Hash of |
| --- | --- |
| PCR0 | Enclave image file |
| PCR1 | Linux kernel and bootstrap |
| PCR2 | Application |
| PCR3 | IAM role of the parent instance |
| PCR4 | Instance ID of the parent instance |
| PCR8 | EIF signing certificate, only for signed EIFs |

`eif_build` writes PCR0, PCR1 and PCR2 to `out/nitro.pcrs`. Kagi pins all three. docs.sui.io describes PCR0..2 differently; the AWS definitions above are authoritative.

## Debug Mode

Enclaves started with `--debug-mode` or `--attach-console` report PCRs made entirely of zeros and cannot be used for attestation. Their memory is also readable from the host.

- Kagi's `set_pcrs` rejects all-zero PCRs (`EDebugPcrs`). Never register zeros "for development": that policy would admit every debug enclave.
- `make run-eif-debug` starts the enclave in debug mode, so that enclave cannot register. Use it to read the console only.

## Certificate Window

The document is signed by a leaf certificate that lives about three hours. Sui's `load_nitro_attestation` checks the whole chain against the on-chain `Clock`; it does not compare the document's own timestamp. Call `load_nitro_attestation` and `kagi::enclave::new` within about three hours of fetching the document, or registration aborts. Fetch a new document if the window has passed.

## Sui Limits

- `nonce` and `user_data`: at most 512 bytes each (Sui `MAX_USER_DATA_LENGTH`). Nautilus enforces this as `MAX_ATTESTATION_DATA_BYTES` before calling the NSM, returning `invalid_request`, so every document it returns can be loaded on Sui.
- `public_key`: always the 32-byte Ed25519 key of the context.
- Nitro attestation verification is enabled on Sui mainnet since protocol version 84.

## Nonces

`POST /attestation` requires a non-empty nonce. `ServerConfig::allow_unnonced_attestation` registers `GET /attestation` and accepts nonce-less `POST` requests for diagnostics. Those documents carry no verifier freshness.

On-chain registration does not check the nonce; its only freshness bound is the certificate window. Off-chain verifiers should check that the nonce is the one they sent.

## Local Development

With the `test-utils` feature, `NautilusContext::development()` uses `testing::FakeAttestor`, which returns a JSON stand-in, not a COSE document. It exercises routes and request validation only; it cannot be loaded on Sui.
