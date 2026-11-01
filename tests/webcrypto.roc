app [main!] {
	base64: "https://github.com/niclas-ahden/roc-base64/releases/download/1.0.2/DQBxATK6BtaCWe56bCmkMgdKJR2Ym8NiZZLhYCAgtLac.tar.zst",
	pkg: "../package/main.roc",
}

import pkg.Jwt
import pkg.Jwk
import lib/Vectors as V

# K5: the input of scripts/webcrypto.sh (run: roc tests/webcrypto.roc). For for each test token, one line
# `<alg> TAB <Jwk.to_public_json of the selected key> TAB <signing_input> TAB <signature bytes, comma-separated>`.
# The key comes from Jwk.parse_set and Jwk.select, as an app does it.

line : Str, Jwt.Alg, List(Jwk.Key) -> Str
line = |text, alg, keys| {
	match Jwt.decode(text, Jwt.Options.{ algs: [alg] }) {
		Ok(t) =>
			match Jwk.select(keys, t.header) {
				Ok(key) => {
					sig = Str.join_with(t.signature.map(U8.to_str), ",")
					input = Str.from_utf8(t.signing_input) ?? ""
					"${Jwt.alg_to_str(alg)}\t${Jwk.to_public_json(key)}\t${input}\t${sig}"
				}
				Err(_) => "${Jwt.alg_to_str(alg)}\tNOKEY"
			}
		Err(e) => "${Jwt.alg_to_str(alg)}\tDECODE ${Jwt.err_to_str(e)}"
	}
}

lines : List(Str)
lines = {
	keys = Jwk.parse_set(V.jwks) ?? []
	# The RSA key of the set has alg RS256, so it does not fit PS256 (K3). The PS256 line uses it with no alg.
	no_alg = keys.map(|k| { ..k, alg: Err(Missing) })
	[line(V.github, RS256, keys), line(V.ps256, PS256, no_alg), line(V.es256, ES256, keys), line(V.eddsa, EdDSA, keys)]
}

# K5: each token decodes and gets a key.
expect lines.all(|l| l.split_on("\t").len() == 4)

main! = |_args| {
	echo!("${Str.join_with(lines, "\n")}\n")
	Ok({})
}
