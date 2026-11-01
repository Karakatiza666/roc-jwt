## JSON Web Tokens (RFC 7519) in the JWS Compact Serialization (RFC 7515 7.1).
##
## This module does not verify a signature: it has no crypto. The steps:
##
## 1. `Jwt.decode(text, options)`: the form, the base64url, the header, the
##    `alg` allowlist and the registered claims. It gives the bytes that the
##    signature covers (`signing_input`) and the signature bytes.
## 2. The caller verifies `signature` over `signing_input` with the key and the
##    `alg` of the header (for example WebCrypto). `Jwk.select` finds the key.
## 3. `Jwt.check(token.claims, rules)`: `iss`, `aud`, `sub`, `exp`, `nbf`,
##    `iat` with the clock and the leeway of the caller.
## 4. `Jwt.claims_as(token)`: the payload as a type of the caller, if needed.
##
## Use the claims only after steps 2 and 3 are `Ok`.
import B64u
import Aud

Jwt :: [].{

	## The JWS `alg` values (RFC 7518 3.1, RFC 8037 3.1). `none` is not here:
	## `decode` always refuses it. The names are case-sensitive: `rs256` is
	## not `RS256`.
	Alg : [RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, HS256, HS384, HS512]

	## A part of the compact form: `<header>.<payload>.<signature>`.
	Part : [Header, Payload, Signature]

	## The registered claims that `check` can check (RFC 7519 4.1).
	Claim : [Iss, Sub, Aud, Exp, Nbf, Iat, Jti]

	## The JOSE header members that this module reads. `decode` ignores the
	## other members (`jku`, `jwk`, `x5u`, `x5c` too: never take a key from the
	## token).
	Header : { alg : Jwt.Alg, kid : Try(Str, [Missing]), typ : Try(Str, [Missing]), cty : Try(Str, [Missing]) }

	## The registered claims of the payload. A claim that is not in the token
	## is `Err(Missing)`. `aud` is a list also when the token has one string.
	## The times are NumericDate: seconds since 1970-01-01T00:00:00Z, with a
	## fraction if the token has one.
	Claims : {
		iss : Try(Str, [Missing]),
		sub : Try(Str, [Missing]),
		aud : Try(List(Str), [Missing]),
		exp : Try(Dec, [Missing]),
		nbf : Try(Dec, [Missing]),
		iat : Try(Dec, [Missing]),
		jti : Try(Str, [Missing]),
	}

	## A token after `decode`. Its signature is NOT verified.
	##
	## | Field | Value |
	## | --- | --- |
	## | `header` | The JOSE header |
	## | `claims` | The registered claims |
	## | `payload` | The payload JSON text (UTF-8), for `claims` or `Json.parse` |
	## | `signing_input` | The bytes that the signature covers: the ASCII text `<header>.<payload>` as sent |
	## | `signature` | The base64url decode of the third part |
	Token : { header : Jwt.Header, claims : Jwt.Claims, payload : Str, signing_input : List(U8), signature : List(U8) }

	## The options of `decode`. `algs` has no default: the caller names each
	## `alg` that it accepts, and `decode` refuses all others. Use one `alg`, or
	## the `alg` values of one key type. `max_token_bytes` limits the token
	## text, so it also limits the JSON of the header and the payload (3/4 of
	## the text at most).
	Options := {
		algs : List(Jwt.Alg),
		max_token_bytes : U64 ?? 8192,
	}

	## A claim value that `check` accepts. `Any`: each value, and the claim
	## can be missing (unless `require` names it). `OneOf(list)`: the claim
	## must be in the token, and equal to one of the list (an exact compare,
	## no case fold).
	Want : [Any, OneOf(List(Str))]

	## The rules of `check`. `now_ms` and `aud` have no default: the caller
	## gives its clock, and says which audience it is (or `Any` when it has
	## none). RFC 7519 4.1.3: a token with an `aud` that does not name the
	## caller must be refused, so use `OneOf` when you can.
	##
	## | Field | Default | Meaning |
	## | --- | --- | --- |
	## | `now_ms` | none | The time now, in milliseconds since 1970 |
	## | `aud` | none | The audience values of the caller |
	## | `iss` | `Any` | The issuers that the caller accepts |
	## | `sub` | `Any` | The subjects that the caller accepts |
	## | `leeway_s` | 0 | Seconds of clock skew for `exp`, `nbf` and `iat` |
	## | `require` | `[Exp]` | The claims that must be in the token |
	Rules := {
		now_ms : U64,
		aud : Jwt.Want,
		iss : Jwt.Want ?? Any,
		sub : Jwt.Want ?? Any,
		leeway_s : U64 ?? 0,
		require : List(Jwt.Claim) ?? [Exp],
	}

	## The errors of `decode`, `check` and `claims`. `err_to_str` gives an
	## English text for each.
	Error : [
		TooLong({ bytes : U64, max : U64 }),
		NotCompact,
		BadBase64(Jwt.Part),
		BadUtf8(Jwt.Part),
		BadJson(Jwt.Part),
		AlgMissing,
		AlgNone,
		AlgNotAllowed(Str),
		CritUnsupported(List(Str)),
		EmptySignature,
		BadSignatureLength({ alg : Jwt.Alg, bytes : U64, want : List(U64) }),
		MissingClaim(Jwt.Claim),
		WrongIssuer(Str),
		WrongAudience(List(Str)),
		WrongSubject(Str),
		Expired({ exp : Dec, now_ms : U64, leeway_s : U64 }),
		NotYetValid({ nbf : Dec, now_ms : U64, leeway_s : U64 }),
		IssuedInFuture({ iat : Dec, now_ms : U64, leeway_s : U64 }),
	]

	## Decode a compact JWS and do every check that needs no key and no clock.
	## The order (the first fault is the error):
	##
	## | Step | Error |
	## | --- | --- |
	## | 1. The text is longer than `max_token_bytes` | `TooLong` |
	## | 2. Not exactly 3 parts with `.` (a JWE has 5) | `NotCompact` |
	## | 3. The header: base64url, UTF-8, a JSON object | `BadBase64(Header)`, `BadUtf8(Header)`, `BadJson(Header)` |
	## | 4. No `alg` / `alg` is `none` / `alg` not in `algs` | `AlgMissing` / `AlgNone` / `AlgNotAllowed(alg)` |
	## | 5. The header has `crit` (RFC 7515 4.1.11: this module knows no extension) | `CritUnsupported` |
	## | 6. The payload: base64url, UTF-8, a JSON object with registered claims of the right JSON types | `BadBase64(Payload)`, `BadUtf8(Payload)`, `BadJson(Payload)` |
	## | 7. The signature: base64url, not empty | `BadBase64(Signature)`, `EmptySignature` |
	## | 8. The signature length of a fixed-length `alg` (ES, EdDSA, HS) | `BadSignatureLength` |
	##
	## A JSON object with a member two times gives the last value (RFC 7515 4,
	## RFC 7519 4: accepted).
	decode : Str, Jwt.Options -> Try(Jwt.Token, Jwt.Error)
	decode = |text, options| {
		bytes = text.count_utf8_bytes()
		if bytes > options.max_token_bytes {
			return Err(TooLong({ bytes, max: options.max_token_bytes }))
		}
		match text.split_on(".") {
			[header_part, payload_part, signature_part] => {
				header = decode_header(header_part, options.algs)?
				payload = part_text(payload_part, Payload)?
				claims = parse_claims(payload)?
				signature = B64u.decode(signature_part) ? |_| BadBase64(Signature)
				if signature.is_empty() {
					return Err(EmptySignature)
				}
				signature_length_ok(header.alg, signature.len())?
				Ok({ header, claims, payload, signing_input: "${header_part}.${payload_part}".to_utf8(), signature })
			}
			_ => Err(NotCompact)
		}
	}

	## Check the registered claims against the rules of the caller. The order
	## (the first fault is the error): `iss`, `aud`, `sub`, `exp`, `nbf`,
	## `iat`, then `jti` if `require` names it. A claim that `require` names, or
	## that has a `OneOf` rule, must be in the token (`MissingClaim`).
	##
	## With `now` = `now_ms / 1000` (with the fraction) and `leeway` = `leeway_s`:
	##
	## | Claim | Refused when | Error |
	## | --- | --- | --- |
	## | `exp` | `now - leeway >= exp` (RFC 7519 4.1.4: now must be before `exp`) | `Expired` |
	## | `nbf` | `now + leeway < nbf` (RFC 7519 4.1.5) | `NotYetValid` |
	## | `iat` | `now + leeway < iat` (issued in the future) | `IssuedInFuture` |
	## | `aud` | no value of the token is in `OneOf` | `WrongAudience(values)` |
	check : Jwt.Claims, Jwt.Rules -> Try({}, Jwt.Error)
	check = |claims, rules| {
		required = |claim| rules.require.contains(claim)
		want_str(claims.iss, rules.iss, required(Iss), Iss, |v| WrongIssuer(v))?
		check_aud(claims.aud, rules.aud, required(Aud))?
		want_str(claims.sub, rules.sub, required(Sub), Sub, |v| WrongSubject(v))?
		now = rules.now_ms.to_dec() / 1000
		leeway = rules.leeway_s.to_dec()
		match claims.exp {
			Ok(exp) if now - leeway >= exp => return Err(Expired({ exp, now_ms: rules.now_ms, leeway_s: rules.leeway_s }))
			Ok(_) => {}
			Err(Missing) => if (required(Exp)) return Err(MissingClaim(Exp))
		}
		match claims.nbf {
			Ok(nbf) if now + leeway < nbf => return Err(NotYetValid({ nbf, now_ms: rules.now_ms, leeway_s: rules.leeway_s }))
			Ok(_) => {}
			Err(Missing) => if (required(Nbf)) return Err(MissingClaim(Nbf))
		}
		match claims.iat {
			Ok(iat) if now + leeway < iat => return Err(IssuedInFuture({ iat, now_ms: rules.now_ms, leeway_s: rules.leeway_s }))
			Ok(_) => {}
			Err(Missing) => if (required(Iat)) return Err(MissingClaim(Iat))
		}
		match claims.jti {
			Err(Missing) if required(Jti) => Err(MissingClaim(Jti))
			_ => Ok({})
		}
	}

	## The payload as a type of the caller (for example a record with
	## `Try(T, [Missing])` fields for the claims that can be missing). A
	## payload that does not fit the type is `BadJson(Payload)`.
	claims_as : Jwt.Token -> Try(c, Jwt.Error)
		where [c.Json.Parseable([InvalidJson(Str), ..errs])]
	claims_as = |token| Json.parse(token.payload).map_err(|_| BadJson(Payload))

	## The `alg` text of RFC 7518 (`RS256`, `EdDSA`, ...).
	alg_to_str : Jwt.Alg -> Str
	alg_to_str = |alg| match alg {
		RS256 => "RS256"
		RS384 => "RS384"
		RS512 => "RS512"
		PS256 => "PS256"
		PS384 => "PS384"
		PS512 => "PS512"
		ES256 => "ES256"
		ES384 => "ES384"
		ES512 => "ES512"
		EdDSA => "EdDSA"
		HS256 => "HS256"
		HS384 => "HS384"
		HS512 => "HS512"
	}

	## The `Alg` of an `alg` text. An exact compare: `rs256` and `none` are
	## `Err(UnknownAlg)`.
	alg_from_str : Str -> Try(Jwt.Alg, [UnknownAlg])
	alg_from_str = |text| match all_algs.find_first(|alg| alg_to_str(alg) == text) {
		Ok(alg) => Ok(alg)
		Err(NotFound) => Err(UnknownAlg)
	}

	## Each `Alg`, in the order of RFC 7518 3.1 (EdDSA last before HS).
	all_algs : List(Jwt.Alg)
	all_algs = [RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, HS256, HS384, HS512]

	## The name of a claim in the token (`Exp` is `exp`).
	claim_to_str : Jwt.Claim -> Str
	claim_to_str = |claim| match claim {
		Iss => "iss"
		Sub => "sub"
		Aud => "aud"
		Exp => "exp"
		Nbf => "nbf"
		Iat => "iat"
		Jti => "jti"
	}

	## An English text for each error.
	err_to_str : Jwt.Error -> Str
	err_to_str = |err| match err {
		TooLong({ bytes, max }) => "the token is ${bytes.to_str()} bytes, more than the limit of ${max.to_str()}"
		NotCompact => "the token is not a compact JWS: it must have 3 parts with \".\""
		BadBase64(part) => "the ${part_to_str(part)} is not base64url with no padding"
		BadUtf8(part) => "the ${part_to_str(part)} is not UTF-8"
		BadJson(Payload) => "the payload is not a JSON object with claims of the right types"
		BadJson(part) => "the ${part_to_str(part)} is not a JSON object with members of the right types"
		AlgMissing => "the header has no alg"
		AlgNone => "the token alg is \"none\": an unsigned token is not accepted"
		AlgNotAllowed(alg) => "the token alg \"${alg}\" is not accepted"
		CritUnsupported(names) => "the header has crit (${Str.join_with(names, ", ")}): no extension is supported"
		EmptySignature => "the signature is empty"
		BadSignatureLength({ alg, bytes, want }) => "the ${alg_to_str(alg)} signature is ${bytes.to_str()} bytes, expected ${Str.join_with(want.map(U64.to_str), " or ")}"
		MissingClaim(claim) => "the token has no ${claim_to_str(claim)} claim"
		WrongIssuer(iss) => "the token iss \"${iss}\" is not accepted"
		WrongAudience(aud) => "the token aud [${Str.join_with(aud.map(|a| "\"${a}\""), ", ")}] does not name this audience"
		WrongSubject(sub) => "the token sub \"${sub}\" is not accepted"
		Expired({ exp, now_ms, leeway_s }) => "the token expired: exp is ${exp.to_str()}, now is ${(now_ms.to_dec() / 1000).to_str()}, leeway ${leeway_s.to_str()} s"
		NotYetValid({ nbf, now_ms, leeway_s }) => "the token is not valid yet: nbf is ${nbf.to_str()}, now is ${(now_ms.to_dec() / 1000).to_str()}, leeway ${leeway_s.to_str()} s"
		IssuedInFuture({ iat, now_ms, leeway_s }) => "the token is issued in the future: iat is ${iat.to_str()}, now is ${(now_ms.to_dec() / 1000).to_str()}, leeway ${leeway_s.to_str()} s"
	}
}

part_to_str : Jwt.Part -> Str
part_to_str = |part| match part {
	Header => "header"
	Payload => "payload"
	Signature => "signature"
}

# The header members as sent. A member of the wrong JSON type (for example
# `"kid": 1` or `"alg": null`) is BadJson(Header).
RawHeader : {
	alg : Try(Str, [Missing]),
	kid : Try(Str, [Missing]),
	typ : Try(Str, [Missing]),
	cty : Try(Str, [Missing]),
	crit : Try(List(Str), [Missing]),
}

RawClaims : {
	iss : Try(Str, [Missing]),
	sub : Try(Str, [Missing]),
	aud : Try(Aud, [Missing]),
	exp : Try(Dec, [Missing]),
	nbf : Try(Dec, [Missing]),
	iat : Try(Dec, [Missing]),
	jti : Try(Str, [Missing]),
}

# The UTF-8 text of one base64url part.
part_text : Str, Jwt.Part -> Try(Str, Jwt.Error)
part_text = |part, which| {
	bytes = B64u.decode(part) ? |_| BadBase64(which)
	Str.from_utf8(bytes).map_err(|_| BadUtf8(which))
}

decode_header : Str, List(Jwt.Alg) -> Try(Jwt.Header, Jwt.Error)
decode_header = |part, algs| {
	json = part_text(part, Header)?
	raw : RawHeader
	raw = Json.parse(json) ? |_| BadJson(Header)
	alg_text = raw.alg ? |Missing| AlgMissing
	if alg_text == "none" {
		return Err(AlgNone)
	}
	alg = match Jwt.alg_from_str(alg_text) {
		Ok(known) if algs.contains(known) => known
		_ => return Err(AlgNotAllowed(alg_text))
	}
	match raw.crit {
		Ok(names) => Err(CritUnsupported(names))
		Err(Missing) => Ok({ alg, kid: raw.kid, typ: raw.typ, cty: raw.cty })
	}
}

parse_claims : Str -> Try(Jwt.Claims, Jwt.Error)
parse_claims = |json| {
	raw : RawClaims
	raw = Json.parse(json) ? |_| BadJson(Payload)
	Ok({ iss: raw.iss, sub: raw.sub, aud: raw.aud.map_ok(Aud.to_list), exp: raw.exp, nbf: raw.nbf, iat: raw.iat, jti: raw.jti })
}

# The signature lengths of the fixed-length algs: ES (RFC 7518 3.4, R and S
# with the octet length of the curve order), EdDSA (RFC 8037 3.1: Ed25519 64,
# Ed448 114), HS (RFC 7518 3.2: the full HMAC output). RS and PS depend on the
# key: the verify of the caller checks them.
signature_length_ok : Jwt.Alg, U64 -> Try({}, Jwt.Error)
signature_length_ok = |alg, bytes| {
	want = match alg {
		ES256 => [64]
		ES384 => [96]
		ES512 => [132]
		EdDSA => [64, 114]
		HS256 => [32]
		HS384 => [48]
		HS512 => [64]
		_ => []
	}
	if want.is_empty() or want.contains(bytes) {
		Ok({})
	} else {
		Err(BadSignatureLength({ alg, bytes, want }))
	}
}

want_str : Try(Str, [Missing]), Jwt.Want, Bool, Jwt.Claim, (Str -> Jwt.Error) -> Try({}, Jwt.Error)
want_str = |value, want, required, claim, wrong| match (value, want) {
	(Err(Missing), OneOf(_)) => Err(MissingClaim(claim))
	(Err(Missing), Any) => if (required) Err(MissingClaim(claim)) else Ok({})
	(Ok(_), Any) => Ok({})
	(Ok(v), OneOf(list)) => if (list.contains(v)) Ok({}) else Err(wrong(v))
}

check_aud : Try(List(Str), [Missing]), Jwt.Want, Bool -> Try({}, Jwt.Error)
check_aud = |value, want, required| match (value, want) {
	(Err(Missing), OneOf(_)) => Err(MissingClaim(Aud))
	(Err(Missing), Any) => if (required) Err(MissingClaim(Aud)) else Ok({})
	(Ok(_), Any) => Ok({})
	(Ok(values), OneOf(list)) => if (values.any(|v| list.contains(v))) Ok({}) else Err(WrongAudience(values))
}
