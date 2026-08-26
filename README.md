# AbsoluteJS key-transparency providers

Interchangeable providers for `@absolutejs/key-transparency`.

The first provider is intentionally narrow:

- `@absolutejs/key-transparency-memory` is a process-local development and
  conformance provider. It produces signed append-only log views and
  requires host-supplied update authorization, but it is not an implementation
  of the IETF KEYTRANS draft and cannot provide independent split-view detection.

Production IETF providers will be added only with pinned draft revisions,
cryptographic proof verification, official vectors where available, and
version-bound certification evidence. A provider boundary must never be used to
upgrade a development key directory into a production transparency claim.

## License

Apache-2.0
