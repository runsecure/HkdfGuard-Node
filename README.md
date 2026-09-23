# HkdfGuard-Node

A TypeScript/Node.js port of HkdfGuard (originally a C# library) for protecting data-at-rest
encryption keys using native, platform-backed key management (TPM2 on Linux, Secure Enclave on
macOS, the Platform Crypto Provider/TPM on Windows - see `@runsecure/hkdfguard-keywrapping-v1`)
combined with AES-256-GCM for the actual data encryption. Application code works against a
`KeyRing` to encrypt/decrypt strings and binary data, with key-version tracking and purpose-scoped
Additional Authenticated Data (AAD).

## Key concepts

- **No plaintext key ever touches disk or this process's memory for longer than a single
  operation.** Wrapping/unwrapping a data encryption key (DEK) is delegated entirely to the native
  KMS library for the current OS (`NativeHkdfKeyWrapperV1`) - the KEK never leaves that native
  library, and this library only ever sees the wrapped payload plus the momentarily-revealed DEK.
- **Identified by service name, not a shared master key.** A key is identified to the native KMS
  library by a service name - not by any secret this library holds itself. `KeyRingBuilder`
  carries this, along with a cache-expiry/rotation policy, fluently.
- **One `KeyWrapper` per KEK, not per wrapped payload.** `KeyWrapper.decrypt` takes the wrapped
  payload as an explicit argument, so a single wrapper instance (bound only to a KEK - e.g. a
  `NativeHkdfKeyWrapperV1` for one service name) can reveal any number of different wrapped DEKs
  sharing that KEK, one per registered key file.
- **Cached, expiring, proactively-refreshed cipher sessions via `CryptoProvider`.** A revealed DEK
  is bound into an internal cipher session once, not re-derived on every encrypt/decrypt - the
  configured expiry (1-300 seconds) marks when it should be refreshed instead of reused.
  `CryptoProvider` owns that refresh itself, and does it ahead of time: a background
  `setInterval`, ticking every `expirySeconds`, reveals and builds the next session before the
  current one expires, then swaps it in and closes the outgoing one (zeroing its key) - Node's
  single-threaded, run-to-completion event loop means no lock is needed anywhere in that swap,
  unlike the C#/Java/Python originals. The concrete session type (`AesGcmCryptoSession`, built on
  Node's built-in `node:crypto`) is not exported from its package - callers only ever see it
  through the public `CryptoProvider` they were given (e.g. `AesGcmCryptoProvider`), which exposes
  encrypt/decrypt directly. `CryptoProviderFactory` is the single seam every consumer
  (`KeyRingBuilder`, `PipelineKeyFactory`) mints providers through, for each of the three ways a
  DEK is revealed: `create` (wrapped-on-disk), `createEphemeral` (generated fresh via
  `KeyWrapper.generateAndWrap`), and `createForPipeline` (an already-plaintext DEK, used as-is).
- **Versioned, rotatable keys via `KeyRing`.** A `KeyRing` tracks any number of independently
  wrapped keys by an integer version. The highest version added automatically becomes the ring's
  `currentVersion` - no separate "mark as current" step, so it can never drift out of sync with
  what's actually registered.
- **Purpose-scoped protectors.** `DataProtector` binds a `name` (purpose) to every operation as
  AAD, so a value protected for one purpose can never be decrypted under another - even using the
  same underlying key.
- **`Buffer`-based API; `aad` is an optional trailing parameter, not an overload.** TypeScript has
  no method overloading: where the C#/Java originals overload Encrypt/Decrypt with and without an
  `aad` parameter, the Node version always accepts an optional `aad?: Buffer`, so a caller with
  none just omits it. Secrets are zeroed via `zeroMemory` and never surface as interned strings.
- **No "I" prefix on interfaces, unlike Python's port.** Interfaces drop the C# `I` prefix
  (`CryptoProvider`, not `ICryptoProvider`), matching idiomatic TypeScript. Where that collides
  with a concrete class of the same name in the same package (`DataProtector`, `ProtectedCache`),
  the interface is imported under a local alias (`import type { DataProtector as
  DataProtectorContract }`) rather than adding an `Impl` suffix to the class.
- **Built-in telemetry.** Every package emits OpenTelemetry (`@opentelemetry/api`) spans/metrics
  via `HkdfGuardTelemetry`/`ComponentTelemetry`, with exceptions recorded on failure, and an
  opt-in sensitive-logging mode that emits operation metadata (never raw key/plaintext/ciphertext
  bytes).

## Architecture overview

```
                      +------------------------------------------+
                      | Hardware Security Module (TPM2 / Enclave) |
                      +------------------------------------------+
                                           |
                                  (Wraps / Unwraps)
                                           v
+---------------------+       +---------------------------------------+
| Native KMS Library  | <---> |   KeyWrapper (NativeHkdfKeyWrapperV1,  |
+---------------------+       |   bound via koffi)                    |
                               +---------------------------------------+
                                           |
                                  (Reveals DEK)
                                           v
                              +---------------------------+
                              |       CryptoProvider       |  <-- setInterval refreshes
                              |    (AesGcmCryptoProvider)  |      + zeroes the outgoing session
                              +---------------------------+
                                           |
                                   (AEAD encrypt/decrypt)
                                           v
                              +---------------------------+
                              |      DataEncryptionKey     |
                              |  (KeyWrapped / Pipeline,   |
                              |  via EncryptionKeyBase)    |
                              +---------------------------+
                                           |
                               (Version Management / AAD)
                                           v
               +-------------------------------------------------------+
               |                       KeyRing                         |
               +-------------------------------------------------------+
                                /                            \
                               v                              v
                +------------------------+     +--------------------------+
                |     DataProtector       |     |  ProtectedCache /        |
                | (strings)               |     |  ProtectedReadOnlyCache  |
                +------------------------+     +--------------------------+
```

Same shape as every other port in this workspace (the .NET repo drives the design, so
Java/Go/Node/Python mirror this layering, adding their own consumer branches as they catch up):

1. **KEK (Key Encryption Key)** - a hardware-backed key managed by the OS/TPM/Enclave, referenced
   only by a service name. The plaintext KEK never enters this process's memory.
2. **DEK (Data Encryption Key)** - a 256-bit symmetric key wrapped by the KEK. Can be persisted to
   disk or generated ephemerally in memory - both are a `KeyWrappedDataEncryptionKey` around a
   `CryptoProvider` minted via `CryptoProviderFactory.create`/`createEphemeral` respectively - or
   used unwrapped before a KEK exists yet (`PipelineDataEncryptionKey`, via `createForPipeline`).
3. **`CryptoProvider`** - the active AEAD (AES-256-GCM) cipher session holding the unwrapped DEK.
   Automatically rotates and zeroes expired sessions on a configured schedule (1-300 seconds).
4. **`KeyRing`** - manages multiple versioned keys. Adding a new key version doesn't break
   decryption of data already protected under older versions.
5. **Formatted encrypted value** - the standardized `enc::v{version}::{base64}` string, handled by
   `EncryptedFormatProvider`/`DefaultFormatProvider`.

## Package layout

npm workspaces (`package.json` → `packages/*`); each is its own `@runsecure/hkdfguard-*` package
with its own `tsconfig.json` composite build. Root `tsconfig.base.json` is the shared strict TS
config (`strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`,
ESM/NodeNext).

| Package | Purpose |
|---|---|
| `@runsecure/hkdfguard-diagnostics` | Every package's telemetry, centralized: `HkdfGuardTelemetry` (one `ComponentTelemetry` per component - `.tracer`, `.meter`, `.enableSensitiveLogging`, `ComponentTelemetry.recordException`, `.logSensitiveOperation`), `ActivityNames`/`AttributeNames`/`EventNames`/`MetricNames` (OpenTelemetry semantic-convention-style names, e.g. `hkdfguard.cache.add`), `recordCacheOperation`, and `sensitiveOperationLogged`/`operationFailed` (accepting any object shaped like the minimal `Logger` interface - `console` itself qualifies). No dependency on any other package in this workspace - the lowest layer, its naming/shape kept identical across every HkdfGuard port. |
| `@runsecure/hkdfguard-abstractions` | Interfaces and pure data types only (`KeyWrapper`, `CryptoProvider`, `CryptoProviderFactory`, `DataEncryptionKey`, `DataProtector`, `ProtectedCache`/`ProtectedReadOnlyCache`, `EncryptedFormatProvider`, `KeyTrackingValue`, `ProtectedCacheBase`, `isNullOrEmpty`/`zeroMemory`). Depends on `@runsecure/hkdfguard-diagnostics` (needed by `ProtectedCacheBase`'s own telemetry). |
| `@runsecure/hkdfguard-cryptosession-aesgcm256` | `AesGcmCryptoSession` (not exported from the package - key-bound at construction, built on Node's built-in `node:crypto`, no external cipher dependency) wrapped directly by the public `AesGcmCryptoProvider` (a `CryptoProvider` that reveals/refreshes it from a `KeyWrapper` + wrapped bytes via a `setInterval`, and is the sole place the 1-300 second expiry range is validated - it only ever holds one active session at a time; also exposes `getEncryptedAllocationLength`/`getDecryptedAllocationLength`, and a pipeline-only construction path - a second, overloaded constructor signature - with no background timer), minted via `AesGcmCryptoProviderFactory` (a `CryptoProviderFactory`). Depends on `@runsecure/hkdfguard-abstractions`/`@runsecure/hkdfguard-diagnostics`; its `cryptoSessionAesGcm256` telemetry component keeps its own independent `enableSensitiveLogging` flag rather than sharing `root`'s. |
| `@runsecure/hkdfguard-keywrapping-v1` | `NativeHkdfKeyWrapperV1` (a `KeyWrapper`) and per-OS native bindings (bound through `koffi`, a no-cgo-equivalent dynamic library binding) to wrap and unwrap a 32-byte DEK under a service-identified KEK held entirely outside this process. |
| `@runsecure/hkdfguard-dataencryptionkey` | The application-facing API: `KeyRing`/`KeyRingBuilder`, `DataProtector` (interface, not exported from the package as a concrete class - only `KeyRing.createProtector` can build one), `EncryptionKeyBase` (shared allocation-sizing/telemetry logic) and its two concrete keys `KeyWrappedDataEncryptionKey`/`PipelineDataEncryptionKey`, `PipelineKeyFactory` (mints a fresh-DEK `PipelineDataEncryptionKey` via a `CryptoProviderFactory`, through the inert, unexported `DummyKeyWrapper`), and `DefaultFormatProvider` (the default `enc::v{version}::{base64}` wire format). Depends on `@runsecure/hkdfguard-abstractions`/`@runsecure/hkdfguard-diagnostics`. |
| `@runsecure/hkdfguard-cache` | `ProtectedCache` (an `abstractions.ProtectedCache` backed by one `DataEncryptionKey` - encrypts on `add`/`addStr`/`addOrUpdate`/`addOrUpdateStr`, reveals on `decrypt`/`decryptStr`, nothing held as plaintext beyond a single call) and `ProtectedCacheCollection` (aggregates multiple `ProtectedReadOnlyCache` sources behind one read-only surface, checked in registration order). Depends on `@runsecure/hkdfguard-abstractions`/`@runsecure/hkdfguard-diagnostics`. |

Requires **Node.js 20+**.

## Getting started

### 1. Wrap or reveal a DEK

`NativeHkdfKeyWrapperV1` is a `KeyWrapper` bound to whichever native KMS library matches the
current OS, identified only by a service name. Since `decrypt` takes the wrapped payload as an
explicit argument rather than one bound at construction, a single instance freely handles both
directions, and any number of different wrapped payloads sharing that service name:

```ts
const wrapper = new NativeHkdfKeyWrapperV1('my-service');

// Protect a fresh 32-byte DEK under the KEK identified by "my-service":
const wrapped = Buffer.alloc(512); // native library's own payload format/size
const written = wrapper.encrypt(freshDek, wrapped);

// Later, reveal a DEK from a previously-wrapped payload for the same service:
const dek = Buffer.alloc(32);
wrapper.decrypt(wrapped.subarray(0, written), dek);
```

The native ABI has no concept of Additional Authenticated Data - `KeyWrapper` itself does not
expose an AAD-taking method.

### 2. Build a `KeyRing`

`KeyRingBuilder` fluently collects a service name/cache-expiry/rotation policy, a shared
`KeyWrapper` and a `CryptoProviderFactory`, and any number of wrapped-DEK files - one per version
- then reads each file, mints its own `CryptoProvider` (via `CryptoProviderFactory.create`), and
wires it into a `KeyWrappedDataEncryptionKey`. `withEphemeralKey` registers a version whose own
key is instead generated fresh in memory on first use (via `CryptoProviderFactory.
createEphemeral`) - it shares the same `KeyWrapper`/`CryptoProviderFactory`, so no extra
configuration is needed for it. `build` validates everything at once - including that
`withCachedKeyExpiry` was actually called; there's no default:

```ts
const ring = new KeyRingBuilder()
  .withServiceName('my-service')
  .withCachedKeyExpiry(60) // seconds, 0-300 - required before build
  .withKeyRotationDays(90) // 1-180
  .withKeyWrapper(wrapper)
  .withCryptoProviderFactory(new AesGcmCryptoProviderFactory())
  .withKeyFile(1, '/path/to/wrapped-dek-v1.bin')
  .withEphemeralKey(2)
  .build();
```

Registering additional key files at higher version numbers (e.g. during a rotation) is all that's
needed to advance `ring.currentVersion` - existing ciphertext tagged with older versions continues
to decrypt correctly as long as those files stay registered.

### 3. Encrypt and decrypt

```ts
const protector = ring.createProtector('cookie-auth'); // "cookie-auth" becomes this protector's AAD

const encrypted = protector.encrypt('secret value');
// e.g. "enc::v1::AbCdEf..."

const decrypted = protector.decrypt(encrypted);
```

A value encrypted by one protector name can never be decrypted by a protector created with a
different name, even from the same `KeyRing` - the name is bound in as AAD on every operation.

### Ephemeral, in-memory-only keys

For scenarios that don't need a durable, file-backed key at all, `CryptoProviderFactory.
createEphemeral` generates and wraps a fresh DEK once via `KeyWrapper.generateAndWrap` - the
plaintext DEK never crosses that call's return value, and nothing here is ever written to or read
from a file. Wrap the resulting `CryptoProvider` in a `KeyWrappedDataEncryptionKey`, exactly as
for a file-backed key (or just call `KeyRingBuilder.withEphemeralKey` - see above, which does
exactly this):

```ts
const factory = new AesGcmCryptoProviderFactory();
const provider = factory.createEphemeral(wrapper, 60);
const ephemeralKey = new KeyWrappedDataEncryptionKey(provider);
```

### Pipeline keys - encrypt now, wrap later

`PipelineDataEncryptionKey` is for the moment before a durable KEK even exists yet - e.g. a
provisioning pipeline that needs to encrypt secrets in-flight, then hand the same plaintext DEK to
the platform's native "initialize" CLI utility at the end of the chain, which independently
wraps/registers it against a real KEK. Unlike every other `DataEncryptionKey` here, its DEK is
never wrapped or unwrapped - it's used exactly as given via a trivial, unexported identity
`KeyWrapper` (`DummyKeyWrapper`). `PipelineKeyFactory` generates a fresh, random 32-byte DEK and
builds one around it via `CryptoProviderFactory.createForPipeline` - unlike the C#/Java
originals' `create`, which also accepts a format-provider argument and an optional key version
that its own implementation never reads, Node's `create` drops both rather than carrying two
parameters that do nothing:

```ts
const factory = new PipelineKeyFactory();
const pipelineKey = factory.create(new AesGcmCryptoProviderFactory());

const encrypted = pipelineKey.encrypt(Buffer.from('secret value'));

// At the end of the pipeline, hand the plaintext DEK off to be wrapped for real:
const dek = pipelineKey.asBuffer();
initializeWithNativeCli(dek);

pipelineKey.close(); // zeroes the DEK
```

## Diagnostics

All telemetry lives in `@runsecure/hkdfguard-diagnostics`. `HkdfGuardTelemetry` exposes one
`ComponentTelemetry` per component (`root`, `cache`, `dataProtection`, `encryptedConfiguration`,
`cryptoSessionAesGcm256`, `keyWrapping`), each with its own `.tracer`/`.meter` and an
`enableSensitiveLogging` flag - `root`/`cache`/`dataProtection`/`encryptedConfiguration` share one
flag (set any of them, all four read the new value); `cryptoSessionAesGcm256` and `keyWrapping`
each keep their own, independent flag. When enabled, operations emit a fixed-name
`hkdfguard.sensitive_operation` debug event carrying only non-sensitive metadata (lengths,
versions, identifiers) as attributes - raw key, plaintext, and ciphertext bytes are never logged,
regardless of this setting.

Span, event, attribute, and metric names all follow OpenTelemetry semantic-convention style -
lowercase, dot-separated (e.g. `hkdfguard.cache.add`, attribute `hkdfguard.plaintext_length`) - see
`ActivityNames`/`AttributeNames`/`EventNames`/`MetricNames`. This naming is the part of the design
meant to translate identically into every HkdfGuard port's own OpenTelemetry SDK usage, regardless
of implementation language.

`ProtectedCache` accepts an optional `Logger` (any object with `debug`/`error` methods - `console`
itself qualifies; `undefined` is a silent no-op) alongside its existing tracing, and records every
add/addOrUpdate via `recordCacheOperation` (a counter on `HkdfGuardTelemetry.cache`'s meter).

## Testing

```bash
npm install
npm run build       # tsc -b across every workspace package
npm run typecheck   # tsc -b at the root
npm test            # vitest --typecheck run, all packages/*/src/**/*.test.ts
npx vitest run packages/abstractions/src/some-file.test.ts   # single file
npx vitest run -t "test name"                                 # single test by name
```

Shared test doubles used across multiple `*.test.ts` files within one package live in a
`src/testHelpers/` directory, excluded from the `tsc` build so they're never shipped in `dist/`;
one-off doubles stay inline in the test file that uses them.
