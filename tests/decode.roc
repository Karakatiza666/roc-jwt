app [main!] {
	base64: "https://github.com/niclas-ahden/roc-base64/releases/download/1.0.2/DQBxATK6BtaCWe56bCmkMgdKJR2Ym8NiZZLhYCAgtLac.tar.zst",
	pkg: "../package/main.roc",
}

import pkg.Jwt
import lib/T as T
import lib/Vectors as V

main! = |_args| Ok({})

# Rule ids: README.md "Rules" (D1 to D11, X1 to X3). The vectors are from
# research/vectors.py (RFC 7515 A.1 to A.5, RFC 8037 A.4, new tokens that the
# script signs and verifies with Python `cryptography`).

rs256 = T.only(RS256)

# D10: RFC 7515 A.2 (RS256). The signing input is the text before the second
# `.`, the signature is the decode of the third part.
expect {
	match Jwt.decode(V.rfc7515_a2, rs256) {
		Ok(t) =>
			(t.signing_input == V.rfc7515_a2_signing_input.to_utf8())
				and (t.signature == V.rfc7515_a2_signature)
				and (t.header == { alg: RS256, kid: Err(Missing), typ: Err(Missing), cty: Err(Missing) })
				and (t.claims == { ..T.none, iss: Ok("joe"), exp: Ok(1300819380) })
				and (t.payload == "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}")
		Err(_) => Bool.False
	}
}

# D10, D4: RFC 7515 A.1 (HS256). The header JSON has CR LF and a space
# between members; the signing input keeps the header part as sent.
expect {
	match Jwt.decode(V.rfc7515_a1, T.only(HS256)) {
		Ok(t) =>
			(t.signing_input == V.rfc7515_a1_signing_input.to_utf8())
				and (t.signature == V.rfc7515_a1_signature)
				and (t.header.typ == Ok("JWT"))
				and (t.header.alg == HS256)
		Err(_) => Bool.False
	}
}

# D10, D9: RFC 7515 A.3 (ES256): a signature of 64 bytes (R and S).
expect {
	match Jwt.decode(V.rfc7515_a3, T.only(ES256)) {
		Ok(t) => (t.signing_input == V.rfc7515_a3_signing_input.to_utf8()) and (t.signature == V.rfc7515_a3_signature) and (t.signature.len() == 64)
		Err(_) => Bool.False
	}
}

# D7: RFC 7515 A.4 (ES512) has the payload text "Payload", and RFC 8037 A.4
# (EdDSA) the text "Example of Ed25519 signing": a JWS, but not a JWT.
expect Jwt.decode(V.rfc7515_a4, T.only(ES512)) == Err(BadJson(Payload))
expect Jwt.decode(V.rfc8037_a4, T.only(EdDSA)) == Err(BadJson(Payload))

# D5: RFC 7515 A.5, the unsecured JWS: alg none, empty signature. Refused
# for each allowlist, also the list of all algs.
expect Jwt.decode(V.rfc7515_a5, rs256) == Err(AlgNone)
expect Jwt.decode(V.rfc7515_a5, Jwt.Options.{ algs: Jwt.all_algs }) == Err(AlgNone)

# D5: "none" with a signature is also refused. Other case forms of "none" are
# not "none": they are not in the allowlist.
expect Jwt.decode(T.token("{\"alg\":\"none\"}", "{}", T.sig3), Jwt.Options.{ algs: Jwt.all_algs }) == Err(AlgNone)
expect Jwt.decode(T.token("{\"alg\":\"None\"}", "{}", T.sig3), Jwt.Options.{ algs: Jwt.all_algs }) == Err(AlgNotAllowed("None"))
expect Jwt.decode(T.token("{\"alg\":\"NONE\"}", "{}", T.sig3), Jwt.Options.{ algs: Jwt.all_algs }) == Err(AlgNotAllowed("NONE"))

# D5: the allowlist. HS256 with an RS256 list (the alg confusion attack), a
# lowercase name, an unknown name, an empty list.
expect Jwt.decode(V.rfc7515_a1, rs256) == Err(AlgNotAllowed("HS256"))
expect Jwt.decode(V.rfc7515_a2, T.only(PS256)) == Err(AlgNotAllowed("RS256"))
expect Jwt.decode(V.rfc7515_a2, Jwt.Options.{ algs: [] }) == Err(AlgNotAllowed("RS256"))
expect Jwt.decode(T.token("{\"alg\":\"rs256\"}", "{}", T.sig3), rs256) == Err(AlgNotAllowed("rs256"))
expect Jwt.decode(T.token("{\"alg\":\"RS256 \"}", "{}", T.sig3), rs256) == Err(AlgNotAllowed("RS256 "))
expect Jwt.decode(T.token("{\"alg\":\"XX999\"}", "{}", T.sig3), rs256) == Err(AlgNotAllowed("XX999"))
expect Jwt.decode(T.token("{\"typ\":\"JWT\"}", "{}", T.sig3), rs256) == Err(AlgMissing)
expect Jwt.decode(T.token("{\"alg\":null}", "{}", T.sig3), rs256) == Err(BadJson(Header))
expect Jwt.decode(T.token("{\"alg\":256}", "{}", T.sig3), rs256) == Err(BadJson(Header))

# D5: an allowlist with more algs accepts each of them.
expect {
	algs = Jwt.Options.{ algs: [RS256, ES256, EdDSA] }
	[V.github, V.es256, V.eddsa].all(|t| Jwt.decode(t, algs).is_ok())
}

# D11: a member two times: the last value counts (RFC 7515 4). The alg check
# sees the value that the caller sees.
expect Jwt.decode(T.token("{\"alg\":\"RS256\",\"alg\":\"none\"}", "{}", T.sig3), rs256) == Err(AlgNone)
expect T.error(Jwt.decode(T.token("{\"alg\":\"none\",\"alg\":\"RS256\"}", "{}", T.sig3), rs256)) == Err(Ok)

# D6: crit (RFC 7515 4.1.11): no extension is supported, so each crit is refused.
expect Jwt.decode(T.token("{\"alg\":\"RS256\",\"crit\":[\"exp\"],\"exp\":1}", "{}", T.sig3), rs256) == Err(CritUnsupported(["exp"]))
expect Jwt.decode(T.token("{\"alg\":\"RS256\",\"crit\":[\"b64\"],\"b64\":false}", "{}", T.sig3), rs256) == Err(CritUnsupported(["b64"]))
expect Jwt.decode(T.token("{\"alg\":\"RS256\",\"crit\":\"b64\"}", "{}", T.sig3), rs256) == Err(BadJson(Header))

# D4: the header members kid, typ, cty; other members are ignored (jku, jwk,
# x5u, x5c are never used).
expect {
	h = "{\"alg\":\"RS256\",\"kid\":\"k\",\"typ\":\"at+jwt\",\"cty\":\"x\",\"jku\":\"https://evil.example\",\"jwk\":{\"kty\":\"RSA\"},\"x5c\":[\"MII\"]}"
	match Jwt.decode(T.token(h, "{}", T.sig3), rs256) {
		Ok(t) => t.header == { alg: RS256, kid: Ok("k"), typ: Ok("at+jwt"), cty: Ok("x") }
		Err(_) => Bool.False
	}
}

# D4: the header is not a JSON object, a member has the wrong type, the JSON
# has text after the object.
expect ["[1,2]", "\"RS256\"", "", "{", "{\"alg\":\"RS256\"} x", "{\"alg\":\"RS256\",\"kid\":1}", "{\"alg\":\"RS256\",\"typ\":null}"].all(
	|h| Jwt.decode(T.token(h, "{}", T.sig3), rs256) == Err(BadJson(Header)),
)

# D3, D4: a header that is not UTF-8 (the bytes FF FE).
expect Jwt.decode("__4.e30.AQID", rs256) == Err(BadUtf8(Header))
expect Jwt.decode("${T.enc("{\"alg\":\"RS256\"}")}.__4.AQID", rs256) == Err(BadUtf8(Payload))

# D2: exactly 3 parts. A JWE (5 parts), 2 parts, 4 parts, no dot, the empty text.
expect {
	h = T.enc("{\"alg\":\"RS256\"}")
	p = T.enc("{}")
	["", "abc", "${h}.${p}", "${h}.${p}.AQID.AQID", "${h}.${p}.AQID.AQID.AQID", "...", "${h}..${p}.AQID"].all(|t| Jwt.decode(t, rs256) == Err(NotCompact))
}

# D2, D4: ".." has 3 empty parts: the empty header is not JSON.
expect Jwt.decode("..", rs256) == Err(BadJson(Header))

# D3: strict base64url in each part: no padding, no `+` `/`, no white space,
# no length of 4n+1, no bits that are not 0 at the end ("Zh" is not "Zg").
expect {
	h = T.enc("{\"alg\":\"RS256\"}")
	p = T.enc("{}")
	# The signature [1] in four wrong forms, and the right form AQ.
	(Jwt.decode("${h}.${p}.AQ==", rs256) == Err(BadBase64(Signature)))
		and (Jwt.decode("${h}.${p}.AQ=", rs256) == Err(BadBase64(Signature)))
		and (Jwt.decode("${h}.${p}.AR", rs256) == Err(BadBase64(Signature)))
		and (Jwt.decode("${h}.${p}.A", rs256) == Err(BadBase64(Signature)))
		and (Jwt.decode("${h}.${p}.A+B/", rs256) == Err(BadBase64(Signature)))
		and (Jwt.decode("${h}.${p}.AQ ", rs256) == Err(BadBase64(Signature)))
		and (Jwt.decode("${h}.${p}.AQ", rs256).map_ok(|t| t.signature) == Ok([1]))
}

# D3: the same refusals in the header and the payload. `e30` is "{}"; "e30="
# is padded, "e31" has bits that are not 0.
expect {
	h = T.enc("{\"alg\":\"RS256\"}")
	(Jwt.decode("${h}=.e30.AQID", rs256) == Err(BadBase64(Header)))
		and (Jwt.decode("${h}.e30=.AQID", rs256) == Err(BadBase64(Payload)))
		and (Jwt.decode("${h}.e31.AQID", rs256) == Err(BadBase64(Payload)))
		and (Jwt.decode("${h}.e3 0.AQID", rs256) == Err(BadBase64(Payload)))
		and (Jwt.decode("${h}.e30.AQID", rs256).is_ok())
}

# D3: each letter of the alphabet decodes. "-_-_" is FB FF BF, "AP-AP0A" is 00 FF 80 3F 40.
expect Jwt.decode("${T.enc("{\"alg\":\"RS256\"}")}.e30.-_-_", rs256).map_ok(|t| t.signature) == Ok([251, 255, 191])
expect Jwt.decode("${T.enc("{\"alg\":\"RS256\"}")}.e30.AP-AP0A", rs256).map_ok(|t| t.signature) == Ok([0, 255, 128, 63, 64])
expect Jwt.decode("${T.enc("{\"alg\":\"RS256\"}")}.e30.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", rs256).map_ok(|t| t.signature.len()) == Ok(48)

# D7: the payload must be a JSON object, with registered claims of the right
# JSON types. An empty payload part is the empty text: not JSON.
expect ["[1]", "\"x\"", "", "null", "{\"exp\":\"1\"}", "{\"iss\":1}", "{\"aud\":1}", "{\"aud\":[1]}", "{\"aud\":null}", "{\"sub\":[\"a\"]}", "{\"nbf\":true}", "{} {}"].all(
	|p| Jwt.decode(T.token("{\"alg\":\"RS256\"}", p, T.sig3), rs256) == Err(BadJson(Payload)),
)

# D7: aud is one string or a list of strings; the claims give a list.
expect {
	aud = |p| Jwt.decode(T.token("{\"alg\":\"RS256\"}", p, T.sig3), rs256).map_ok(|t| t.claims.aud)
	(aud("{\"aud\":\"a\"}") == Ok(Ok(["a"])))
		and (aud("{\"aud\":[\"a\",\"b\"]}") == Ok(Ok(["a", "b"])))
		and (aud("{\"aud\":[]}") == Ok(Ok([])))
		and (aud("{\"aud\": [ \"a\" , \"b\" ] }") == Ok(Ok(["a", "b"])))
		and (aud("{}") == Ok(Err(Missing)))
}

# D7: NumericDate with a fraction and with an exponent; a negative value.
expect {
	exp = |p| Jwt.decode(T.token("{\"alg\":\"RS256\"}", p, T.sig3), rs256).map_ok(|t| t.claims.exp)
	(exp("{\"exp\":1767225900.5}") == Ok(Ok(1767225900.5)))
		and (exp("{\"exp\":1.5e9}") == Ok(Ok(1500000000)))
		and (exp("{\"exp\":-1}") == Ok(Ok(-1)))
}

# D8: an empty signature part.
expect Jwt.decode(T.token("{\"alg\":\"RS256\"}", "{}", []), rs256) == Err(EmptySignature)

# D9: the fixed signature lengths of ES, EdDSA and HS. RS and PS are not checked.
expect {
	len = |alg, n| Jwt.decode(T.token("{\"alg\":\"${Jwt.alg_to_str(alg)}\"}", "{}", List.repeat(1, n)), T.only(alg))
	(len(ES256, 63) == Err(BadSignatureLength({ alg: ES256, bytes: 63, want: [64] })))
		and (len(ES256, 72) == Err(BadSignatureLength({ alg: ES256, bytes: 72, want: [64] })))
		and len(ES256, 64).is_ok()
		and len(ES384, 96).is_ok()
		and (len(ES384, 64) == Err(BadSignatureLength({ alg: ES384, bytes: 64, want: [96] })))
		and len(ES512, 132).is_ok()
		and (len(ES512, 130) == Err(BadSignatureLength({ alg: ES512, bytes: 130, want: [132] })))
		and len(EdDSA, 64).is_ok()
		and len(EdDSA, 114).is_ok()
		and (len(EdDSA, 65) == Err(BadSignatureLength({ alg: EdDSA, bytes: 65, want: [64, 114] })))
		and len(HS256, 32).is_ok()
		and (len(HS256, 16) == Err(BadSignatureLength({ alg: HS256, bytes: 16, want: [32] })))
		and len(HS384, 48).is_ok()
		and len(HS512, 64).is_ok()
		and len(RS256, 1).is_ok()
		and len(PS512, 1000).is_ok()
}

# D1: max_token_bytes: the default is 8192; equal is good, one more is TooLong.
expect Jwt.Options.{ algs: [] }.max_token_bytes == 8192
expect {
	t = V.github
	n = t.count_utf8_bytes()
	Jwt.decode(t, Jwt.Options.{ algs: [RS256], max_token_bytes: n }).is_ok()
		and (Jwt.decode(t, Jwt.Options.{ algs: [RS256], max_token_bytes: n - 1 }) == Err(TooLong({ bytes: n, max: n - 1 })))
}

# D1: the limit is checked first, before the form.
expect Jwt.decode("a.b", Jwt.Options.{ algs: [RS256], max_token_bytes: 2 }) == Err(TooLong({ bytes: 3, max: 2 }))

# D1 to D9: the order of the steps. Each token has two faults; the error is the first step.
expect {
	bad_sig = "A"
	(Jwt.decode("${T.enc("{\"alg\":\"none\"}")}.${T.enc("[]")}.${bad_sig}", rs256) == Err(AlgNone))
		and (Jwt.decode("${T.enc("{\"alg\":\"HS256\"}")}.${T.enc("[]")}.${bad_sig}", rs256) == Err(AlgNotAllowed("HS256")))
		and (Jwt.decode("${T.enc("{\"alg\":\"RS256\",\"crit\":[\"x\"]}")}.${T.enc("[]")}.${bad_sig}", rs256) == Err(CritUnsupported(["x"])))
		and (Jwt.decode("${T.enc("{\"alg\":\"RS256\"}")}.${T.enc("[]")}.${bad_sig}", rs256) == Err(BadJson(Payload)))
		and (Jwt.decode("${T.enc("{\"alg\":\"RS256\"}")}.${T.enc("{}")}.${bad_sig}", rs256) == Err(BadBase64(Signature)))
		and (Jwt.decode("${T.enc("[]")}.${T.enc("[]")}.${bad_sig}", rs256) == Err(BadJson(Header)))
		and (Jwt.decode("${T.enc("{\"alg\":\"ES256\"}")}.${T.enc("{}")}.", T.only(ES256)) == Err(EmptySignature))
}

# D10: the GitHub Actions OIDC token shape: header with kid and typ, all
# registered claims, the signing input and the signature that Python verified.
expect {
	match Jwt.decode(V.github, rs256) {
		Ok(t) =>
			(t.header == { alg: RS256, kid: Ok("kid-1"), typ: Ok("JWT"), cty: Err(Missing) })
				and (t.signing_input == V.github_signing_input.to_utf8())
				and (t.signature == V.github_signature)
				and (t.signature.len() == 256)
				and (t.payload == V.github_payload)
				and (
					t.claims
						== {
							iss: Ok("https://token.actions.githubusercontent.com"),
							sub: Ok("repo:roc-talon/talon:ref:refs/heads/main"),
							aud: Ok(["https://registry.example"]),
							exp: Ok(1767225900),
							nbf: Ok(1767225300),
							iat: Ok(1767225600),
							jti: Ok("j-1"),
						}
				)
		Err(_) => Bool.False
	}
}

# D10: the ES256 token: kid, aud as a list, exp with a fraction.
expect {
	match Jwt.decode(V.es256, T.only(ES256)) {
		Ok(t) => (t.header.kid == Ok("ec-1")) and (t.claims.aud == Ok(["a", "b"])) and (t.claims.exp == Ok(1767225900.5)) and (t.signature == V.es256_signature)
		Err(_) => Bool.False
	}
}

# X1: the payload as a type of the caller.
GitHub : {
	repository : Str,
	repository_id : Str,
	event_name : Str,
	run_attempt : Try(Str, [Missing]),
	environment : Try(Str, [Missing]),
}

expect {
	got : Try(GitHub, Jwt.Error)
	got = match Jwt.decode(V.github, rs256) {
		Ok(token) => Jwt.claims_as(token)
		Err(e) => Err(e)
	}
	got == Ok({ repository: "roc-talon/talon", repository_id: "900001", event_name: "schedule", run_attempt: Ok("1"), environment: Err(Missing) })
}

# X1: a payload that does not fit the type of the caller (a missing field, a
# wrong JSON type) is BadJson(Payload).
expect {
	need : Try({ environment : Str }, Jwt.Error)
	need = match Jwt.decode(V.github, rs256) {
		Ok(token) => Jwt.claims_as(token)
		Err(e) => Err(e)
	}
	need == Err(BadJson(Payload))
}
expect {
	wrong : Try({ repository_id : U64 }, Jwt.Error)
	wrong = match Jwt.decode(V.github, rs256) {
		Ok(token) => Jwt.claims_as(token)
		Err(e) => Err(e)
	}
	wrong == Err(BadJson(Payload))
}

# X2: alg_to_str and alg_from_str: each alg goes and comes back; the names
# are exact.
expect Jwt.all_algs.all(|alg| Jwt.alg_from_str(Jwt.alg_to_str(alg)) == Ok(alg))
expect Jwt.all_algs.map(Jwt.alg_to_str) == ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "HS256", "HS384", "HS512"]
expect ["none", "rs256", "EDDSA", "", "RS256 "].all(|s| Jwt.alg_from_str(s) == Err(UnknownAlg))

# X3: err_to_str gives a text for each error (the texts are a proposal).
expect Jwt.err_to_str(AlgNone) == "the token alg is \"none\": an unsigned token is not accepted"
expect Jwt.err_to_str(BadBase64(Signature)) == "the signature is not base64url with no padding"
expect Jwt.err_to_str(BadSignatureLength({ alg: EdDSA, bytes: 3, want: [64, 114] })) == "the EdDSA signature is 3 bytes, expected 64 or 114"
expect Jwt.err_to_str(WrongAudience(["a", "b"])) == "the token aud [\"a\", \"b\"] does not name this audience"
