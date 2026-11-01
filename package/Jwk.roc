## Public JSON Web Keys (RFC 7517) for the verify of a `Jwt.Token`: read a
## JWK Set, select the key for a token, and give the key material to the
## crypto of the caller (the raw bytes, or a public JWK text to import).
import Jwt
import B64u

Jwk :: [].{

	## The elliptic curves of `EC` keys (RFC 7518 6.2.1.1).
	Curve : [P256, P384, P521]

	## The public key material. All values are bytes (the base64url decode of
	## the JWK members), big-endian, as RFC 7518 6 gives them.
	##
	## | Tag | `kty` | Members |
	## | --- | --- | --- |
	## | `Rsa` | `RSA` | `n` (modulus), `e` (exponent) |
	## | `Ec` | `EC` | `crv`, `x`, `y` (each coordinate has the octet length of the curve: 32, 48, 66) |
	## | `Okp` | `OKP` (RFC 8037) | `crv` (`Ed25519` or `Ed448`), `x` (32 or 57 bytes) |
	Material : [
		Rsa({ n : List(U8), e : List(U8) }),
		Ec({ crv : Jwk.Curve, x : List(U8), y : List(U8) }),
		Okp({ crv : [Ed25519, Ed448], x : List(U8) }),
	]

	## One public key. `kid`, `alg`, `use` and `key_ops` are as sent, or
	## `Err(Missing)`. A private member (`d`, `p`, `q`, ...) is never read.
	Key : {
		kid : Try(Str, [Missing]),
		alg : Try(Str, [Missing]),
		use : Try(Str, [Missing]),
		key_ops : Try(List(Str), [Missing]),
		material : Jwk.Material,
	}

	## The keys of a JWK Set text (RFC 7517 5: `{"keys": [...]}`). A key that
	## this module cannot use is left out, with no error:
	##
	## - a `kty` other than `RSA`, `EC`, `OKP` (for example `oct`, a secret key)
	## - a member that is missing or not strict base64url (`n`, `e`, `x`, `y`)
	## - an `EC` `crv` other than `P-256`, `P-384`, `P-521`, or a coordinate of the wrong length
	## - an `OKP` `crv` other than `Ed25519`, `Ed448`, or an `x` of the wrong length
	##
	## Members that are not in `Key` are ignored. `Err(BadJwks)`: the text is
	## not a JSON object with a `keys` list, or a key has a member of the
	## wrong JSON type (for example `"kid": 1`).
	parse_set : Str -> Try(List(Jwk.Key), [BadJwks])
	parse_set = |text| {
		set : Try({ keys : List(RawKey) }, _)
		set = Json.parse(text)
		match set {
			Ok({ keys }) => Ok(keys.keep_oks(from_raw))
			Err(_) => Err(BadJwks)
		}
	}

	## One JWK text (a JSON object). `Err(BadJwk)` for each reason of
	## `parse_set` that leaves a key out.
	parse : Str -> Try(Jwk.Key, [BadJwk])
	parse = |text| {
		raw : Try(RawKey, _)
		raw = Json.parse(text)
		match raw {
			Ok(key) => from_raw(key).map_err(|_| BadJwk)
			Err(_) => Err(BadJwk)
		}
	}

	## Can this key verify a signature of this `alg`? `RS*` and `PS*`: an RSA
	## key. `ES256`, `ES384`, `ES512`: an EC key on P-256, P-384, P-521.
	## `EdDSA`: an OKP key. `HS*`: never (a JWK Set has no secret keys). Also,
	## when the key has them: `alg` is equal to the `alg`, `use` is `sig`,
	## and `key_ops` has `verify`.
	fits : Jwk.Key, Jwt.Alg -> Bool
	fits = |key, alg| {
		kind_ok = match (key.material, alg) {
			(Rsa(_), RS256) | (Rsa(_), RS384) | (Rsa(_), RS512) => Bool.True
			(Rsa(_), PS256) | (Rsa(_), PS384) | (Rsa(_), PS512) => Bool.True
			(Ec({ crv: P256, .. }), ES256) => Bool.True
			(Ec({ crv: P384, .. }), ES384) => Bool.True
			(Ec({ crv: P521, .. }), ES512) => Bool.True
			(Okp(_), EdDSA) => Bool.True
			_ => Bool.False
		}
		alg_ok = match key.alg {
			Ok(text) => text == Jwt.alg_to_str(alg)
			Err(Missing) => Bool.True
		}
		use_ok = match key.use {
			Ok(text) => text == "sig"
			Err(Missing) => Bool.True
		}
		ops_ok = match key.key_ops {
			Ok(ops) => ops.contains("verify")
			Err(Missing) => Bool.True
		}
		kind_ok and alg_ok and use_ok and ops_ok
	}

	## The key for a token header, from the keys that `fits` its `alg`:
	##
	## | Header | Result |
	## | --- | --- |
	## | has `kid` | the first key with that `kid`, else `Err(NoKey)` |
	## | no `kid` | the key when exactly one fits, `Err(NoKey)` for none, `Err(ManyKeys)` for more |
	##
	## A key with the right `kid` that does not fit is `Err(NoKey)`: never a
	## key of another type.
	select : List(Jwk.Key), Jwt.Header -> Try(Jwk.Key, [NoKey, ManyKeys])
	select = |keys, header| {
		fit = keys.keep_if(|key| fits(key, header.alg))
		match header.kid {
			Ok(kid) => fit.find_first(|key| key.kid == Ok(kid)).map_err(|NotFound| NoKey)
			Err(Missing) => match fit {
				[key] => Ok(key)
				[] => Err(NoKey)
				_ => Err(ManyKeys)
			}
		}
	}

	## The public JWK text of the key material, for a crypto API that imports
	## a JWK (WebCrypto `importKey("jwk", ...)`). Only the members of the key
	## type, in name order: `{"e","kty","n"}`, `{"crv","kty","x","y"}`,
	## `{"crv","kty","x"}`. No `alg`, `use`, `key_ops` or `kid`.
	to_public_json : Jwk.Key -> Str
	to_public_json = |key| match key.material {
		Rsa({ n, e }) => Json.to_str({ kty: "RSA", n: B64u.encode(n), e: B64u.encode(e) })
		Ec({ crv, x, y }) => Json.to_str({ kty: "EC", crv: curve_to_str(crv), x: B64u.encode(x), y: B64u.encode(y) })
		Okp({ crv, x }) => Json.to_str({ kty: "OKP", crv: okp_to_str(crv), x: B64u.encode(x) })
	}
}

RawKey : {
	kty : Try(Str, [Missing]),
	kid : Try(Str, [Missing]),
	alg : Try(Str, [Missing]),
	use : Try(Str, [Missing]),
	key_ops : Try(List(Str), [Missing]),
	n : Try(Str, [Missing]),
	e : Try(Str, [Missing]),
	crv : Try(Str, [Missing]),
	x : Try(Str, [Missing]),
	y : Try(Str, [Missing]),
}

curve_to_str : Jwk.Curve -> Str
curve_to_str = |crv| match crv {
	P256 => "P-256"
	P384 => "P-384"
	P521 => "P-521"
}

okp_to_str : [Ed25519, Ed448] -> Str
okp_to_str = |crv| match crv {
	Ed25519 => "Ed25519"
	Ed448 => "Ed448"
}

# The bytes of a member that must be there.
member : Try(Str, [Missing]) -> Try(List(U8), [Unusable])
member = |value| match value {
	Ok(text) => B64u.decode(text).map_err(|_| Unusable)
	Err(Missing) => Err(Unusable)
}

# The bytes of a member with a fixed length.
sized : Try(Str, [Missing]), U64 -> Try(List(U8), [Unusable])
sized = |value, len| {
	bytes = member(value)?
	if (bytes.len() == len) Ok(bytes) else Err(Unusable)
}

from_raw : RawKey -> Try(Jwk.Key, [Unusable])
from_raw = |raw| {
	material = match (raw.kty, raw.crv) {
		(Ok("RSA"), _) => {
			n = member(raw.n)?
			e = member(raw.e)?
			if n.is_empty() or e.is_empty() {
				return Err(Unusable)
			}
			Rsa({ n, e })
		}
		(Ok("EC"), Ok(crv_text)) => {
			(crv, len) = match crv_text {
				"P-256" => (P256, 32)
				"P-384" => (P384, 48)
				"P-521" => (P521, 66)
				_ => return Err(Unusable)
			}
			x = sized(raw.x, len)?
			y = sized(raw.y, len)?
			Ec({ crv, x, y })
		}
		(Ok("OKP"), Ok(crv_text)) => {
			(crv, len) = match crv_text {
				"Ed25519" => (Ed25519, 32)
				"Ed448" => (Ed448, 57)
				_ => return Err(Unusable)
			}
			x = sized(raw.x, len)?
			Okp({ crv, x })
		}
		_ => return Err(Unusable)
	}
	Ok({ kid: raw.kid, alg: raw.alg, use: raw.use, key_ops: raw.key_ops, material })
}
