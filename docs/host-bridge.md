# Host Bridge

An enclave has no network interface. Its only I/O is vsock to the parent instance, so the parent has to bridge clients to the enclave. This repository covers the enclave side; the parent side is yours to run.

## Inbound

The app serves HTTP directly on enclave vsock port 3000 with `nautilus::serve_vsock` (feature `vsock`), with the same `ServerConfig` limits as TCP. There is no bridge process inside the enclave.

On the parent, forward a TCP port to the enclave's CID and port 3000. `make run-eif` starts the enclave with `--enclave-cid 16` (`ENCLAVE_CID`); otherwise read it with `nitro-cli describe-enclaves`, field `EnclaveCID`.

[Argonaut](https://github.com/miraicloud/argonaut) (v0.2 CLI) does this with one command and no config file:

```shell
argonaut host 16 --inbound 127.0.0.1:3000=3000 --max-connections 256
```

It listens on TCP `127.0.0.1:3000` and forwards each connection to `VSOCK:16:3000`. Connections beyond `--max-connections` (default 1024) are closed at once, and each direction has an idle timeout (`--idle-timeout`, default `5m`). The enclave closes connections beyond `max_connections`, but the parent's resources are still the parent's to bound. Bind to a public address (`0.0.0.0:3000=3000`) only behind whatever access control the app needs. Argonaut is not part of this repository or the image; nothing besides the app runs inside the enclave.

## Outbound

The native listener covers inbound traffic only. An app that calls out, for example to a Sui fullnode, needs a bridge on both sides: inside the enclave, a loopback TCP listener that forwards to a parent vsock port, and on the parent, a vsock listener that forwards to the real host. `eif/run.sh` brings up the loopback interface for this even though inbound traffic no longer uses it.

Argonaut provides both halves from one endpoint list: `argonaut host 16 --config FILE` on the parent and `argonaut enclave --config FILE` inside the enclave, which also writes `/etc/hosts` entries for the endpoint hosts. Inbound and outbound bridges are independent, so keep `serve_vsock` on 3000 and give `argonaut enclave` no `--inbound` flag. The enclave side has to be added to the image; Nautilus images do not ship it. See the Argonaut README for the config format.

Config delivered by the host is unmeasured input; see [attestation.md](attestation.md#what-attestation-proves). Building the endpoint list into the image instead of sending it with `argonaut host --send-config` keeps it under the measurement.
