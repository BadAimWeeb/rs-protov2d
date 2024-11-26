# rs-protov2d

> ⚠️ This package is in a VERY EARLY stage of development and IS NOT USABLE.

Rust implementation of original JavaScript/TypeScript [ProtoV2d](https://github.com/BadAimWeeb/js-protov2d) protocol, which in turns is a variant of [ProtoV2](https://github.com/BadAimWeeb/js-protov2) protocol (see the JS version for more details).

This package will expose a quantum-resistant encrypted tunnel, even when using unsecured WebSocket connections, and can be reconnectable even when using different client IP addresses.

Only client-side implementation should be expected, server-side implementation is not planned as of now.

## Technical notes

This package relies heavily on `tokio` and `websocket` crates.
