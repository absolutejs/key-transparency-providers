# `@absolutejs/key-transparency-memory`

Development-only, process-local provider for `@absolutejs/key-transparency`.

It maintains an append-only log view, signs every tree head with an
ephemeral Ed25519 key, requires host-supplied update authorization, clones all
sensitive byte inputs, and rejects prior views it did not issue. It is useful for
tests, examples, and provider-neutral conformance.

It is intentionally **not** an implementation of the IETF KEYTRANS draft. It has
no durable history, combined tree, VRF, commitments, private remote queries,
independent monitor, or third-party auditor. Its manifest therefore uses the
distinct `absolute-memory-key-transparency-v1` protocol and does not claim
split-view detection.

```ts
import { createMemoryKeyTransparencyProvider } from "@absolutejs/key-transparency-memory";

const provider = await createMemoryKeyTransparencyProvider({
  logId: "local-development-log",
  verifyUpdateAuthorization: ({ authorization }) => authorization.length === 32,
});
```

Never use this provider for production identities.
