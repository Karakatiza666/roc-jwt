app [main!] {
	base64: "https://github.com/niclas-ahden/roc-base64/releases/download/1.0.2/DQBxATK6BtaCWe56bCmkMgdKJR2Ym8NiZZLhYCAgtLac.tar.zst",
	pkg: "../package/main.roc",
}

import pkg.Jwt
import pkg.Jwk
import lib/T as T
import lib/Vectors as V

main! = |_args| Ok({})

# Rule ids: README.md "Rules" (K1 to K6). tests/lib/Vectors.roc has the JWKS
# of research/vectors.py: RSA kid-1 (alg RS256, use sig), EC ec-1 (P-256),
# OKP ed-1 (Ed25519), oct hmac-1, RSA enc-1 (use enc).

keys : List(Jwk.Key)
keys = Jwk.parse_set(V.jwks) ?? []

kids : List(Jwk.Key) -> List(Try(Str, [Missing]))
kids = |list| list.map(|k| k.kid)

header : Jwt.Alg, Try(Str, [Missing]) -> Jwt.Header
header = |alg, kid| { alg, kid, typ: Err(Missing), cty: Err(Missing) }

# K1, K2: the key material as bytes; the oct key is left out.
expect kids(keys) == [Ok("kid-1"), Ok("ec-1"), Ok("ed-1"), Ok("enc-1")]
expect {
	match keys {
		[rsa, ec, ed, ..] =>
			(rsa.material == Rsa({ n: V.rsa_n, e: [1, 0, 1] }))
				and (rsa.alg == Ok("RS256"))
				and (rsa.use == Ok("sig"))
				and (rsa.key_ops == Err(Missing))
				and (ec.material == Ec({ crv: P256, x: V.ec_x, y: V.ec_y }))
				and (ed.material == Okp({ crv: Ed25519, x: V.ed_x }))
		_ => Bool.False
	}
}

# K1: RFC 7515 A.2 and A.3 public keys (n, e; x, y), as one JWK each.
expect Jwk.parse("{\"kty\":\"RSA\",\"n\":\"${V.rfc7515_a2_n_text}\",\"e\":\"AQAB\"}").map_ok(|k| k.material) == Ok(Rsa({ n: V.rfc7515_a2_n, e: [1, 0, 1] }))
expect Jwk.parse("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"${V.rfc7515_a3_x_text}\",\"y\":\"${V.rfc7515_a3_y_text}\"}").map_ok(|k| k.material) == Ok(Ec({ crv: P256, x: V.rfc7515_a3_x, y: V.rfc7515_a3_y }))
expect {
	match Jwk.parse("{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"${V.rfc7515_a4_x_text}\",\"y\":\"${V.rfc7515_a4_y_text}\"}") {
		Ok({ material: Ec({ crv: P521, x, y }), .. }) => (x.len() == 66) and (y.len() == 66)
		_ => Bool.False
	}
}
expect Jwk.parse("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}").map_ok(|k| k.material) == Ok(Okp({ crv: Ed25519, x: V.rfc8037_x }))

# K2: keys that cannot be used are left out of a set, and are BadJwk alone.
expect {
	bad = [
		"{\"kty\":\"oct\",\"k\":\"AQAB\"}",
		"{\"kty\":\"RSA\",\"n\":\"AQAB\"}",
		"{\"kty\":\"RSA\",\"e\":\"AQAB\"}",
		"{\"kty\":\"RSA\",\"n\":\"\",\"e\":\"AQAB\"}",
		"{\"kty\":\"RSA\",\"n\":\"AQ==\",\"e\":\"AQAB\"}",
		"{\"kty\":\"RSA\",\"n\":\"A+B/\",\"e\":\"AQAB\"}",
		"{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"${V.rfc7515_a3_x_text}\"}",
		"{\"kty\":\"EC\",\"crv\":\"P-256K\",\"x\":\"${V.rfc7515_a3_x_text}\",\"y\":\"${V.rfc7515_a3_y_text}\"}",
		"{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"${V.rfc7515_a3_x_text}\",\"y\":\"${V.rfc7515_a3_y_text}\"}",
		"{\"kty\":\"EC\",\"x\":\"${V.rfc7515_a3_x_text}\",\"y\":\"${V.rfc7515_a3_y_text}\"}",
		"{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}",
		"{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"AQAB\"}",
		"{\"n\":\"AQAB\",\"e\":\"AQAB\"}",
		"{\"kty\":\"rsa\",\"n\":\"AQAB\",\"e\":\"AQAB\"}",
	]
	bad.all(|text| Jwk.parse(text) == Err(BadJwk))
		and (Jwk.parse_set("{\"keys\":[${Str.join_with(bad, ",")}]}") == Ok([]))
}

# K1: a text that is not a JWK Set, or a key member of the wrong JSON type.
expect ["", "x", "[]", "{}", "{\"keys\":1}", "{\"keys\":[1]}", "{\"keys\":[{\"kty\":\"RSA\",\"kid\":1,\"n\":\"AQAB\",\"e\":\"AQAB\"}]}"].all(|t| Jwk.parse_set(t) == Err(BadJwks))
expect Jwk.parse_set("{\"keys\":[]}") == Ok([])

# K1: a private member is never read: the key has the public material only.
expect Jwk.parse("{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"d\":\"AQAB\",\"p\":\"AQAB\"}").map_ok(Jwk.to_public_json) == Ok("{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"AQAB\"}")

# K3: fits: the key type of the alg, and alg, use, key_ops when the key has them.
expect {
	match keys {
		[rsa, ec, ed, enc] =>
			Jwt.all_algs.keep_if(|a| Jwk.fits(rsa, a)) == [RS256]
				and (Jwt.all_algs.keep_if(|a| Jwk.fits({ ..rsa, alg: Err(Missing) }, a)) == [RS256, RS384, RS512, PS256, PS384, PS512])
				and (Jwt.all_algs.keep_if(|a| Jwk.fits(ec, a)) == [ES256])
				and (Jwt.all_algs.keep_if(|a| Jwk.fits(ed, a)) == [EdDSA])
				and (Jwt.all_algs.keep_if(|a| Jwk.fits(enc, a)) == [])
				and !(Jwk.fits({ ..rsa, key_ops: Ok(["sign"]) }, RS256))
				and Jwk.fits({ ..rsa, key_ops: Ok(["sign", "verify"]) }, RS256)
				and !(Jwk.fits({ ..rsa, alg: Ok("rs256") }, RS256))
		_ => Bool.False
	}
}

# K3: P-384 fits ES384 only, P-521 fits ES512 only.
expect {
	p384 = { kid: Err(Missing), alg: Err(Missing), use: Err(Missing), key_ops: Err(Missing), material: Ec({ crv: P384, x: [], y: [] }) }
	p521 = { ..p384, material: Ec({ crv: P521, x: [], y: [] }) }
	(Jwt.all_algs.keep_if(|a| Jwk.fits(p384, a)) == [ES384]) and (Jwt.all_algs.keep_if(|a| Jwk.fits(p521, a)) == [ES512])
}

# K4: select by kid and alg. A kid of another key type is NoKey (never a
# key of the wrong type). No kid: the one key that fits, else NoKey or ManyKeys.
expect Jwk.select(keys, header(RS256, Ok("kid-1"))).map_ok(|k| k.kid) == Ok(Ok("kid-1"))
expect Jwk.select(keys, header(ES256, Ok("ec-1"))).map_ok(|k| k.kid) == Ok(Ok("ec-1"))
expect Jwk.select(keys, header(EdDSA, Ok("ed-1"))).map_ok(|k| k.kid) == Ok(Ok("ed-1"))
expect Jwk.select(keys, header(RS256, Ok("ec-1"))) == Err(NoKey)
expect Jwk.select(keys, header(ES256, Ok("kid-1"))) == Err(NoKey)
expect Jwk.select(keys, header(HS256, Ok("hmac-1"))) == Err(NoKey)
expect Jwk.select(keys, header(RS256, Ok("enc-1"))) == Err(NoKey)
expect Jwk.select(keys, header(PS256, Ok("kid-1"))) == Err(NoKey)
expect Jwk.select(keys, header(RS256, Ok("kid-9"))) == Err(NoKey)
expect Jwk.select(keys, header(RS256, Err(Missing))).map_ok(|k| k.kid) == Ok(Ok("kid-1"))
expect Jwk.select([], header(RS256, Err(Missing))) == Err(NoKey)
expect {
	match keys {
		[rsa, ..] => Jwk.select([rsa, { ..rsa, kid: Ok("kid-2") }], header(RS256, Err(Missing))) == Err(ManyKeys)
		_ => Bool.False
	}
}

# K4: two keys with one kid: the first that fits.
expect {
	match keys {
		[rsa, ..] => Jwk.select([{ ..rsa, alg: Ok("RS512") }, { ..rsa, material: Rsa({ n: [1], e: [3] }) }], header(RS256, Ok("kid-1"))).map_ok(|k| k.material) == Ok(Rsa({ n: [1], e: [3] }))
		_ => Bool.False
	}
}

# K4: select with the header of a decoded token.
expect {
	match Jwt.decode(V.github, T.only(RS256)) {
		Ok(t) => Jwk.select(keys, t.header).map_ok(|k| k.material) == Ok(Rsa({ n: V.rsa_n, e: [1, 0, 1] }))
		Err(_) => Bool.False
	}
}

# K5: the public JWK text: the members of the key type only, in name order,
# strict base64url.
expect {
	match keys {
		[rsa, ec, ed, ..] =>
			(Jwk.to_public_json(rsa) == "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"${V.rsa_n_text}\"}")
				and (Jwk.to_public_json(ec) == "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"${T.enc_bytes(V.ec_x)}\",\"y\":\"${T.enc_bytes(V.ec_y)}\"}")
				and (Jwk.to_public_json(ed) == "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"${T.enc_bytes(V.ed_x)}\"}")
		_ => Bool.False
	}
}

# K5, K6: to_public_json and parse go and come back.
expect keys.all(|k| Jwk.parse(Jwk.to_public_json(k)).map_ok(|back| back.material) == Ok(k.material))
