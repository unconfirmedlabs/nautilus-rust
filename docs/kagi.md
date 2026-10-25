# Kagi Integration

[Kagi](https://github.com/unconfirmedlabs/kagi) is the Sui Move companion to Nautilus Rust. Nautilus Rust runs in the enclave and produces an attestation document and intent signatures; Kagi registers the attested key on chain and verifies the signatures.

This page targets Kagi at `226cd10`, whose Move API is unchanged since `d2cf902` ("Harden policies and enclaves"). That version is not published yet; the earlier testnet package has a different API (PCRs set at creation, no versioning). Kagi's README names `NautilusContext::sign_intent` and pins the same intent message vector as [signing-vectors.md](signing-vectors.md).

## Kagi API

- `kagi::enclave_policy::new(otw, ctx)`: creates the one `EnclavePolicy<App>` for the app's one-time witness, with PCRs unset, and returns it with its `EnclavePolicyCap<App>`.
- `set_pcrs(policy, cap, pcr0, pcr1, pcr2)`: sets the expected PCRs. Each must be 48 bytes (`EInvalidPcrLength`) and not all zeros (`EDebugPcrs`). Every call increments `version`.
- `kagi::enclave::new(policy, cap, document)`: needs the policy cap, matches the document's PCR0, PCR1 and PCR2 by index against the policy, and returns `(Enclave<App>, EnclaveCap<App>)` with IDs derived from the policy and the public key. Registering the same key twice aborts.
- `verify_signature(enclave, intent, timestamp_ms, payload, &signature)`: checks Ed25519 over `bcs(IntentMessage { intent, timestamp_ms, payload })` and aborts `EInvalidSignature`. It does not read the policy.
- `destroy(enclave, enclave_cap)`, `destroy_stale(enclave, &policy)` (anyone, for enclaves registered under an older `version`), `destroy_cap(enclave_cap)`.

## App Module

```move
module my_app::my_app;

use kagi::enclave::{Self, Enclave};
use kagi::enclave_policy::{Self, EnclavePolicy, EnclavePolicyCap};
use sui::clock::Clock;
use sui::nitro_attestation::NitroAttestationDocument;

const EStale: u64 = 0;

const HASH_ATTESTATION_INTENT: u8 = 0;
const MAX_AGE_MS: u64 = 5 * 60 * 1000;
const MAX_SKEW_MS: u64 = 30 * 1000;

public struct MY_APP() has drop;

public struct HashAttestation has copy, drop {
    digest: vector<u8>,
    length: u64,
}

fun init(otw: MY_APP, ctx: &mut TxContext) {
    let (policy, cap) = enclave_policy::new(otw, ctx);
    policy.share();
    transfer::public_transfer(cap, ctx.sender());
}

public fun register(
    policy: &mut EnclavePolicy<MY_APP>,
    cap: &EnclavePolicyCap<MY_APP>,
    document: NitroAttestationDocument,
    ctx: &mut TxContext,
) {
    let (enclave, enclave_cap) = enclave::new(policy, cap, document);
    enclave.share();
    transfer::public_transfer(enclave_cap, ctx.sender());
}

public fun consume(
    enclave: &Enclave<MY_APP>,
    digest: vector<u8>,
    length: u64,
    timestamp_ms: u64,
    signature: vector<u8>,
    clock: &Clock,
) {
    let now = clock.timestamp_ms();
    assert!(timestamp_ms <= now + MAX_SKEW_MS && now <= timestamp_ms + MAX_AGE_MS, EStale);
    enclave.verify_signature(
        HASH_ATTESTATION_INTENT,
        timestamp_ms,
        HashAttestation { digest, length },
        &signature,
    );
}
```

`HashAttestation` mirrors the Rust payload in the README (`digest: ByteVec`, `length: u64`); see [contract.md](contract.md).

## Registration Flow

1. Publish the app package. Its `init` calls `enclave_policy::new`, shares the policy and keeps the cap.
2. Build the EIF (`make eif`) and record PCR0, PCR1 and PCR2 from `out/nitro.pcrs`.
3. Call `set_pcrs(policy, cap, pcr0, pcr1, pcr2)` with those 48-byte values.
4. Boot the enclave without `--debug-mode` or `--attach-console`; debug enclaves report zero PCRs and cannot match.
5. Fetch a document: `POST /attestation` with a fresh random nonce and hex-decode `attestation`. Nautilus Rust does not parse the document; if you check it off chain first, confirm the nonce and that `public_key` matches `/health_check`.
6. In one PTB, call `sui::nitro_attestation::load_nitro_attestation(document_bytes, clock)` and pass its result to `my_app::register(policy, cap, document)`, which calls `kagi::enclave::new` and `share`. Do this within about three hours of step 5 (see [attestation.md](attestation.md#certificate-window)).

`load_nitro_attestation` is an `entry` function returning `NitroAttestationDocument`, which has only `drop`. It cannot be stored or passed between transactions, so it must be consumed by `kagi::enclave::new` in the same PTB.

The signing key is per boot. Every enclave restart produces a new key and needs a new registration.

## Consuming Signatures

- Take `&Enclave<MY_APP>`, never a generic `Enclave<T>`: a generic parameter lets an enclave registered for any other app sign for yours.
- Use a distinct intent value per message kind, mirrored on both sides (`Intent(0)` in Rust, `0u8` in Move).
- `timestamp_ms` is the time the enclave claims, not attested time. Kagi has no freshness or replay check. Enforce a window against `Clock` as above, and/or a uniqueness key (for example a derived object keyed by the payload digest) if a message must be accepted only once.
- The enclave signs `SignedResponse { response: { intent, timestamp_ms, data }, signature }`. Pass `timestamp_ms`, the `data` fields and the hex-decoded `signature` to the consuming function.

## Retiring an Image

`verify_signature` does not read the policy, so an enclave registered under old PCRs keeps verifying until it is deleted. To retire an image, the cap holder calls `set_pcrs` with the new PCRs and `destroy(enclave, enclave_cap)` for each old enclave in the same PTB. Anyone can delete leftovers later with `destroy_stale(enclave, &policy)`.

## Signing Compatibility

Kagi's Move struct:

```move
public struct IntentMessage<Payload: drop> has copy, drop {
    intent: u8,
    timestamp_ms: u64,
    payload: Payload,
}
```

`nautilus::intent_message` produces the same BCS bytes, and `NautilusContext::sign_intent` signs them. The shared vector is in [signing-vectors.md](signing-vectors.md).
