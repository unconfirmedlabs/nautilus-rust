# Host Bridge

An enclave has no network interface. Its only I/O is vsock to the parent instance, so the parent has to bridge clients to the enclave. This repository covers the enclave side; the parent side is yours to run.

## Inbound

The app serves HTTP directly on enclave vsock port 3000 with `nautilus::serve_vsock` (feature `vsock`), with the same `ServerConfig` limits as TCP. There is no bridge process inside the enclave.

On the parent, forward a TCP port to the enclave's CID and port 3000. `make run-eif` starts the enclave with `--enclave-cid 16` (`ENCLAVE_CID`); otherwise read it with `nitro-cli describe-enclaves`, field `EnclaveCID`.

```shell
socat TCP-LISTEN:3000,bind=127.0.0.1,reuseaddr,fork,max-children=256 VSOCK-CONNECT:16:3000
```

Without `max-children`, socat forks one process per client connection without limit. The enclave closes connections beyond `max_connections`, but the parent's processes are still the parent's to bound. Bind to a public address only behind whatever access control the app needs.

## Outbound

The native listener covers inbound traffic only. An app that calls out, for example to a Sui fullnode, needs a bridge on both sides: inside the enclave, a loopback TCP listener that forwards to a parent vsock port, and on the parent, a vsock listener that forwards to the real host. `eif/run.sh` brings up the loopback interface for this even though inbound traffic no longer uses it.

[Argonaut](https://github.com/miraicloud/argonaut) provides both halves (`argonaut enclave` and `argonaut host`) with an endpoint list and `/etc/hosts` entries. It is not part of this repository or the image, and it does not work with an unmodified Nautilus image:

- `argonaut host <cid> <config>` first delivers its config to enclave vsock port 7777 and exits if nothing listens there. Nautilus images do not listen on 7777; the enclave side would have to run `argonaut config recv 7777 | argonaut enclave` or an equivalent receiver.
- Its config must have an `endpoints` array, even an empty one, plus `httpPort` and `httpVsockPort` for the host and `httpTcpPort` for the enclave.
- `argonaut enclave` always starts its own inbound bridge from vsock `httpVsockPort` to `127.0.0.1:<httpTcpPort>`. Either serve TCP on loopback and let it carry inbound traffic, or keep `serve_vsock` on 3000 and give Argonaut a different `httpVsockPort` so the two do not compete for the port.

Config delivered by the host is unmeasured input; see [attestation.md](attestation.md#what-attestation-proves).
