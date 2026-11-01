# roc-jwt

JSON Web Tokens (RFC 7519) in the JWS compact form (RFC 7515) for Roc. Pure Roc: no effects, no crypto. The package decodes a token, refuses `alg` values that the caller does not accept, gives the exact bytes that the signature covers, selects the key from a JWK Set, and checks the registered claims with the clock of the caller. The caller verifies the signature with its own crypto (for example WebCrypto on Cloudflare Workers).

It is made for the registry Worker of [Talon](https://github.com/Karakatiza666/talon) (GitHub Actions OIDC tokens, Registry R-TP3), and has no Talon concept in its API (Talon Design R-GP1).

## Decision: a package, yes

The question was: does a package give real value, or is the code of the Worker enough?

| Reason | Detail |
| --- | --- |
| No Roc JWT package exists | `gh search repos`, `gh search code --language roc` (2026-11-01): only app code and an old-compiler example with a placeholder URL. |
| The Worker code is not reusable | `worker/lib/Oidc.roc` has its own base64url, a JWT parse that accepts RS256 only, a JWKS reader for RSA keys only, and claim checks with Talon texts. Each other Roc service that takes OIDC or OAuth tokens must write the same code again. |
| The hard parts are security rules, not code size | `alg` `none`, the `alg` allowlist (alg confusion), `crit`, strict and canonical base64url, the leeway compare, `aud` as a string or a list, a key of the wrong type with the right `kid`. One tested and mutated package is better than a copy in each app. |
| It can be pure | Roc has no RSA or ECDSA in pure code, but the signature step is one call of the platform. The package gives the signing input and the signature bytes, so it needs no effect and no platform. |
| JSON works with the builtins only | `Encoding.Json` (the builtin `Json`) parses into a record with `Try(T, [Missing])` fields in a plain package. A hand-written `parser_for` reads `aud` as a string or a list. `Jwt.claims_as` decodes the payload into a type of the caller. |
| Base64 is not new code | `niclas-ahden/roc-base64` 1.0.2 decodes. This package adds the JWS refusals only (`=`, non-canonical text). |

## API

Two modules, `Jwt` and `Jwk`.

| Function | Type |
| --- | --- |
| `Jwt.decode` | `Str, Jwt.Options -> Try(Jwt.Token, Jwt.Error)` |
| `Jwt.check` | `Jwt.Claims, Jwt.Rules -> Try({}, Jwt.Error)` |
| `Jwt.claims_as` | `Jwt.Token -> Try(c, Jwt.Error) where [c.Json.Parseable([InvalidJson(Str), ..errs])]` |
| `Jwt.alg_to_str` | `Jwt.Alg -> Str` |
| `Jwt.alg_from_str` | `Str -> Try(Jwt.Alg, [UnknownAlg])` |
| `Jwt.all_algs` | `List(Jwt.Alg)` |
| `Jwt.claim_to_str` | `Jwt.Claim -> Str` |
| `Jwt.err_to_str` | `Jwt.Error -> Str` |
| `Jwk.parse_set` | `Str -> Try(List(Jwk.Key), [BadJwks])` |
| `Jwk.parse` | `Str -> Try(Jwk.Key, [BadJwk])` |
| `Jwk.fits` | `Jwk.Key, Jwt.Alg -> Bool` |
| `Jwk.select` | `List(Jwk.Key), Jwt.Header -> Try(Jwk.Key, [NoKey, ManyKeys])` |
| `Jwk.to_public_json` | `Jwk.Key -> Str` |

| Type | Definition |
| --- | --- |
| `Jwt.Alg` | `[RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, HS256, HS384, HS512]` (no `none`) |
| `Jwt.Header` | `{ alg : Jwt.Alg, kid : Try(Str, [Missing]), typ : Try(Str, [Missing]), cty : Try(Str, [Missing]) }` |
| `Jwt.Claims` | `{ iss, sub, jti : Try(Str, [Missing]), aud : Try(List(Str), [Missing]), exp, nbf, iat : Try(Dec, [Missing]) }` |
| `Jwt.Token` | `{ header : Jwt.Header, claims : Jwt.Claims, payload : Str, signing_input : List(U8), signature : List(U8) }` |
| `Jwt.Options` | Nominal record: `algs : List(Jwt.Alg)` (no default), `max_token_bytes : U64 ?? 8192` |
| `Jwt.Rules` | Nominal record: `now_ms : U64`, `aud : Jwt.Want` (no defaults), `iss : Jwt.Want ?? Any`, `sub : Jwt.Want ?? Any`, `leeway_s : U64 ?? 0`, `require : List(Jwt.Claim) ?? [Exp]` |
| `Jwt.Want` | `[Any, OneOf(List(Str))]` |
| `Jwt.Claim` | `[Iss, Sub, Aud, Exp, Nbf, Iat, Jti]` |
| `Jwt.Part` | `[Header, Payload, Signature]` |
| `Jwk.Key` | `{ kid, alg, use : Try(Str, [Missing]), key_ops : Try(List(Str), [Missing]), material : Jwk.Material }` |
| `Jwk.Material` | `[Rsa({ n, e : List(U8) }), Ec({ crv : Jwk.Curve, x, y : List(U8) }), Okp({ crv : [Ed25519, Ed448], x : List(U8) })]` |
| `Jwk.Curve` | `[P256, P384, P521]` |

### How to verify a token

```roc
options = Jwt.Options.{ algs: [RS256] }
token = Jwt.decode(text, options)?                        # 1. form, alg allowlist, claims JSON
key = Jwk.select(keys, token.header)?                     # 2. the key: kid, key type, alg, use
# 3. the signature, with the crypto of the platform (WebCrypto here):
WebCrypto.verify!({ alg: RsaPkcs1(Sha256), key: Jwk(Jwk.to_public_json(key)), signature: token.signature, data: token.signing_input })?
# 4. the registered claims, with the clock of the caller:
Jwt.check(token.claims, Jwt.Rules.{ now_ms: Time.now_ms!(), aud: OneOf(["https://my.service"]), iss: OneOf(["https://issuer"]), leeway_s: 60 })?
# 5. the other claims, as a type of the caller (if needed):
mine : Try({ repository : Str, run_attempt : Try(Str, [Missing]) }, Jwt.Error)
mine = Jwt.claims_as(token)
```

Use the claims only after steps 3 and 4 are `Ok`. `token.claims` and `token.payload` come from a token with no verified signature.

The `alg` to WebCrypto map (the `cloudflare-workers` platform names):

| `alg` | WebCrypto `Alg` | Key import |
| --- | --- | --- |
| `RS256` / `RS384` / `RS512` | `RsaPkcs1(Sha256 / Sha384 / Sha512)` | `Jwk(Jwk.to_public_json(key))` |
| `PS256` / `PS384` / `PS512` | `RsaPss({ hash: Sha256, salt_length_bytes: 32 })` (48, 64) | same |
| `ES256` / `ES384` / `ES512` | `Ecdsa(P256, Sha256)` / `Ecdsa(P384, Sha384)` / `Ecdsa(P521, Sha512)` | same. The JWS signature is `R ‖ S` (not DER): WebCrypto takes this form. |
| `EdDSA` (Ed25519) | `Ed25519` | same |
| `HS256` / `HS384` / `HS512` | `Hmac(Sha256 / ...)` | a secret of the caller, never a JWK of the set |

## Rules

The tests name these ids (`# D3: ...`).

| Id | Rule |
| --- | --- |
| D1 | A token text of more than `max_token_bytes` bytes is `TooLong`. This is the first check. It also limits the header and payload JSON (3/4 of the text at most). |
| D2 | Exactly 3 parts with `.`, else `NotCompact` (a JWE has 5). |
| D3 | Each part is strict base64url (RFC 7515 2): no `=`, no `+` `/`, no white space, no length 4n+1, and the canonical text only (`Zh` is refused: it is a second text for `Zg`). Else `BadBase64(part)`. |
| D4 | The header is UTF-8 and a JSON object; `alg`, `kid`, `typ`, `cty` are strings when present. Else `BadUtf8(Header)` or `BadJson(Header)`. Other members (`jku`, `jwk`, `x5u`, `x5c`) are ignored. |
| D5 | No `alg`: `AlgMissing`. `alg` `none`: `AlgNone`, for each allowlist. An `alg` that is not in `algs` (exact compare, case-sensitive): `AlgNotAllowed(alg)`. |
| D6 | A header with `crit` is `CritUnsupported` (RFC 7515 4.1.11: this package knows no extension, `b64` too). |
| D7 | The payload is UTF-8 and a JSON object; `iss`, `sub`, `jti` are strings, `aud` is a string or a list of strings, `exp`, `nbf`, `iat` are numbers (with a fraction or an exponent). Else `BadUtf8(Payload)` or `BadJson(Payload)`. A JWS with a payload that is not a JSON object is not a JWT. |
| D8 | An empty signature is `EmptySignature`. |
| D9 | The signature length of ES256 (64), ES384 (96), ES512 (132), EdDSA (64 or 114), HS256 (32), HS384 (48), HS512 (64). Else `BadSignatureLength`. RS and PS depend on the key: the verify checks them. |
| D10 | `signing_input` is the text before the second `.`, as sent (not a re-encode). `signature` is the decode of the third part. |
| D11 | A JSON member two times: the last value counts (RFC 7515 4 accepts this). |
| C1 | `iss`: `OneOf(list)` needs the claim, equal to a value of the list (exact compare). Else `MissingClaim(Iss)` or `WrongIssuer`. |
| C2 | `aud`: `OneOf(list)` needs the claim, and one value of the token in the list. Else `MissingClaim(Aud)` or `WrongAudience(values)`. An empty token list fails. |
| C3 | `sub`: as `iss`, with `WrongSubject`. |
| C4 | `exp`: refused when `now - leeway >= exp` (now must be before `exp`), with `now = now_ms / 1000` and its fraction. `Expired`. |
| C5 | `nbf`: refused when `now + leeway < nbf`. `NotYetValid`. |
| C6 | `iat`: refused when `now + leeway < iat` (issued in the future). `IssuedInFuture`. |
| C7 | A claim in `require` must be in the token (`MissingClaim`). The default is `[Exp]`. |
| C8 | The order: `iss`, `aud`, `sub`, `exp`, `nbf`, `iat`, `jti`. The first fault is the error. |
| C9 | The defaults of `Rules`. `now_ms` and `aud` have none: the caller must give them (`aud: Any` is a choice that the code shows). |
| K1 | `Jwk.parse_set` reads `{"keys": [...]}`. A key member of the wrong JSON type, or no `keys` list, is `BadJwks`. Private members are never read. |
| K2 | A key that cannot be used is left out: `kty` not `RSA`, `EC` or `OKP` (an `oct` secret too), a missing member, a member that is not strict base64url, an empty `n` or `e`, an unknown `crv`, a coordinate of the wrong length. |
| K3 | `Jwk.fits`: RS and PS need RSA, ES256/384/512 need P-256/384/521, EdDSA needs OKP, HS never fits. When the key has them: `alg` equal, `use` is `sig`, `key_ops` has `verify`. |
| K4 | `Jwk.select`: with a `kid`, the first key with that `kid` that fits; a key with the `kid` that does not fit is `NoKey`. No `kid`: the one key that fits, else `NoKey` or `ManyKeys`. |
| K5 | `Jwk.to_public_json`: the public members of the key type only, in name order, strict base64url. |
| K6 | `Jwk.parse(Jwk.to_public_json(key))` gives the same material. |
| X1 | `Jwt.claims_as`: the payload as a type of the caller; a payload that does not fit is `BadJson(Payload)`. |
| X2 | `alg_to_str` and `alg_from_str` are exact inverses; other texts are `UnknownAlg`. |
| X3 | `err_to_str` gives an English text for each error (a proposal). |

## Errors

`Jwt.Error` is a closed tag union. `Jwt.err_to_str` gives a text for each.

| Error | Step |
| --- | --- |
| `TooLong({ bytes, max })` | D1 |
| `NotCompact` | D2 |
| `BadBase64(part)`, `BadUtf8(part)`, `BadJson(part)` | D3, D4, D7 |
| `AlgMissing`, `AlgNone`, `AlgNotAllowed(Str)` | D5 |
| `CritUnsupported(List(Str))` | D6 |
| `EmptySignature`, `BadSignatureLength({ alg, bytes, want })` | D8, D9 |
| `MissingClaim(claim)`, `WrongIssuer(Str)`, `WrongAudience(List(Str))`, `WrongSubject(Str)` | C1 to C3, C7 |
| `Expired({ exp, now_ms, leeway_s })`, `NotYetValid({ nbf, ... })`, `IssuedInFuture({ iat, ... })` | C4 to C6 |

## Security notes

What this package does NOT do. The caller must do these:

| Not done | What to do |
| --- | --- |
| Verify the signature | Verify `signature` over `signing_input` with the key of `Jwk.select` and the `alg` of `token.header`, before you use a claim. |
| Fetch keys | Get the JWK Set from a URL that you trust (configuration), never from `jku`, `x5u`, `jwk` or `x5c` of the token. |
| Key rotation and cache | Keep the JWK Set, and read it again for an unknown `kid` with a rate limit. |
| HMAC secrets | `Jwk` never gives an `oct` key. For HS algs, use your own secret, and never put HS and RS/ES algs in one allowlist. |
| Check `typ` | `token.header.typ` is given; compare it if your tokens have a fixed type (RFC 8725 3.11). |
| Check private claims | Use `Jwt.claims_as` and compare the fields (for example `repository`, `event_name` of GitHub). |
| Replay | `jti` is given; a replay cache is the caller's work. |
| Weak RSA keys | The modulus length is not checked; WebCrypto accepts 1024 bits. |
| JWE, JSON serialization, unencoded payload (`b64`) | Not supported: refused (D2, D6) or not a JWT (D7). |

Note: `decode` gives `token.claims` before the signature is verified, so that `Jwk.select` and a cheap `check` can run first. Do not trust them until the verify is `Ok`.

## Left out

| Item | Reason |
| --- | --- |
| Signing and encoding a token | Needs crypto with a private key: the platform does it. `signing_input` of a new token is `base64url(header).base64url(payload)`; this package has no builder yet. |
| A verify function argument | The verify of a platform is effectful (`=>`); a package function that takes it would be effectful too. The steps above keep the package pure. |
| `max_age` (a limit on `now - iat`) | Few callers need it; `Jwt.check` plus `token.claims.iat` does it. |
| Duplicate member refusal | The builtin JSON parser keeps the last value; RFC 7515 4 accepts this. A refusal would need a second JSON parser. |
| Separate JSON size limits | `max_token_bytes` limits them (D1). |

## Tests

| Level | What | Command |
| --- | --- | --- |
| L0 | `tests/decode.roc`, `tests/check.roc`, `tests/jwk.roc` (109 expects). Vectors: RFC 7515 A.1 to A.5, RFC 8037 A.4, and new RS256 (GitHub Actions OIDC shape), PS256, ES256, EdDSA tokens and a JWK Set. `research/vectors.py` makes `tests/lib/Vectors.roc` and verifies each signature with Python `cryptography`, so each signing input is proven by a key. | `roc test tests/<file>.roc` |
| L1 | `fuzz/decode.roc` (roc-fuzz): decode never crashes; when it is `Ok`, the signing input is the text before the second `.`, the signature re-encodes to the third part, the `alg` is in the allowlist. | `scripts/test.sh` |
| Mutants | `scripts/mutants.py`: 10 mutants of the trickiest rules (alg `none`, the allowlist, the `exp` and `nbf` leeway compare, `aud` list any/all, the `aud` list parse, canonical base64url, the signing input, `select` across key types, `crit`). All are killed. | `python3 -I scripts/mutants.py ROC` |

`scripts/test.sh [ROC]` runs `roc check`, `roc fmt --check`, the L0 tests and the L1 target. Use the nightly in `.roc-version` (nightly-2026-10-31-f7bef6b, the nightly of the Talon Worker).

## Dependencies

| Package | Use |
| --- | --- |
| [niclas-ahden/roc-base64](https://github.com/niclas-ahden/roc-base64) 1.0.2 | `Base64.decode_url`, `Base64.encode_url` |
| Builtins `Encoding.Json` | JSON |

## License

UPL-1.0, see `LICENSE`.
