app [main!] {
	base64: "https://github.com/niclas-ahden/roc-base64/releases/download/1.0.2/DQBxATK6BtaCWe56bCmkMgdKJR2Ym8NiZZLhYCAgtLac.tar.zst",
	pkg: "../package/main.roc",
}

import pkg.Jwt
import lib/T as T

main! = |_args| Ok({})

# Rule ids: README.md "Rules" (C1 to C9). The claims are the GitHub token
# shape of tests/lib/Vectors.roc: exp 1767225900, nbf 1767225300, iat 1767225600.

gh : Jwt.Claims
gh = {
	iss: Ok("https://token.actions.githubusercontent.com"),
	sub: Ok("repo:roc-talon/talon:ref:refs/heads/main"),
	aud: Ok(["https://registry.example"]),
	exp: Ok(1767225900),
	nbf: Ok(1767225300),
	iat: Ok(1767225600),
	jti: Ok("j-1"),
}

now = 1767225600000

aud = OneOf(["https://registry.example"])

rules : U64 -> Jwt.Rules
rules = |now_ms| Jwt.Rules.{ now_ms, aud }

# C9: the defaults.
expect {
	r = Jwt.Rules.{ now_ms: 0, aud: Any }
	(r.iss, r.sub, r.leeway_s, r.require) == (Any, Any, 0, [Exp])
}

# C1 to C6: a good token passes at its issue time.
expect Jwt.check(gh, rules(now)) == Ok({})

# C4: exp with no leeway: now must be before exp. 1 ms before passes, equal fails.
expect Jwt.check(gh, rules(1767225899999)) == Ok({})
expect Jwt.check(gh, rules(1767225900000)) == Err(Expired({ exp: 1767225900, now_ms: 1767225900000, leeway_s: 0 }))
expect Jwt.check(gh, rules(1767299999999)) == Err(Expired({ exp: 1767225900, now_ms: 1767299999999, leeway_s: 0 }))

# C4: exp with 60 s of leeway: refused when now - 60 >= exp.
expect {
	r = |now_ms| Jwt.Rules.{ now_ms, aud, leeway_s: 60 }
	(Jwt.check(gh, r(1767225959999)) == Ok({}))
		and (Jwt.check(gh, r(1767225960000)) == Err(Expired({ exp: 1767225900, now_ms: 1767225960000, leeway_s: 60 })))
}

# C4: exp with a fraction (1767225900.5).
expect {
	c = { ..gh, exp: Ok(1767225900.5) }
	(Jwt.check(c, rules(1767225900499)) == Ok({}))
		and (Jwt.check(c, rules(1767225900500)) == Err(Expired({ exp: 1767225900.5, now_ms: 1767225900500, leeway_s: 0 })))
}

# C5: nbf: refused when now + leeway < nbf. Equal passes. (iat is left
# out: at the nbf time it is in the future.)
expect Jwt.check({ ..gh, iat: Err(Missing) }, rules(1767225300000)) == Ok({})
expect Jwt.check({ ..gh, iat: Err(Missing) }, rules(1767225299999)) == Err(NotYetValid({ nbf: 1767225300, now_ms: 1767225299999, leeway_s: 0 }))
expect {
	r = |now_ms| Jwt.Rules.{ now_ms, aud, leeway_s: 60 }
	c = { ..gh, iat: Err(Missing) }
	(Jwt.check(c, r(1767225240000)) == Ok({}))
		and (Jwt.check(c, r(1767225239999)) == Err(NotYetValid({ nbf: 1767225300, now_ms: 1767225239999, leeway_s: 60 })))
}

# C6: iat in the future: refused when now + leeway < iat. Equal passes.
expect {
	c = { ..gh, nbf: Err(Missing) }
	(Jwt.check(c, rules(1767225600000)) == Ok({}))
		and (Jwt.check(c, rules(1767225599999)) == Err(IssuedInFuture({ iat: 1767225600, now_ms: 1767225599999, leeway_s: 0 })))
		and (Jwt.check(c, Jwt.Rules.{ now_ms: 1767225599999, aud, leeway_s: 1 }) == Ok({}))
}

# C4: a large leeway and a clock of 0 do not overflow.
expect Jwt.check(gh, Jwt.Rules.{ now_ms: 0, aud, leeway_s: 18446744073709551615 }) == Ok({})
expect Jwt.check({ ..gh, exp: Ok(-1), nbf: Err(Missing), iat: Err(Missing) }, rules(0)) == Err(Expired({ exp: -1, now_ms: 0, leeway_s: 0 }))
expect Jwt.check({ ..gh, exp: Ok(1), nbf: Err(Missing), iat: Err(Missing) }, rules(18446744073709551615)) == Err(Expired({ exp: 1, now_ms: 18446744073709551615, leeway_s: 0 }))

# C1: iss: OneOf is an exact compare; a missing iss fails OneOf.
expect {
	r = |want| Jwt.Rules.{ now_ms: now, aud, iss: want }
	(Jwt.check(gh, r(OneOf(["https://token.actions.githubusercontent.com"]))) == Ok({}))
		and (Jwt.check(gh, r(OneOf(["x", "https://token.actions.githubusercontent.com"]))) == Ok({}))
		and (Jwt.check(gh, r(OneOf(["https://token.actions.githubusercontent.com/"]))) == Err(WrongIssuer("https://token.actions.githubusercontent.com")))
		and (Jwt.check(gh, r(OneOf(["HTTPS://token.actions.githubusercontent.com"]))) == Err(WrongIssuer("https://token.actions.githubusercontent.com")))
		and (Jwt.check(gh, r(OneOf([]))) == Err(WrongIssuer("https://token.actions.githubusercontent.com")))
		and (Jwt.check({ ..gh, iss: Err(Missing) }, r(OneOf(["a"]))) == Err(MissingClaim(Iss)))
		and (Jwt.check({ ..gh, iss: Err(Missing) }, r(Any)) == Ok({}))
}

# C2: aud: one token value in OneOf is enough; a list token, an empty list,
# a missing aud; Any accepts each value.
expect {
	r = |want| Jwt.Rules.{ now_ms: now, aud: want }
	(Jwt.check({ ..gh, aud: Ok(["x", "https://registry.example"]) }, rules(now)) == Ok({}))
		and (Jwt.check({ ..gh, aud: Ok(["https://registry.example", "x"]) }, rules(now)) == Ok({}))
		and (Jwt.check({ ..gh, aud: Ok(["x", "y"]) }, rules(now)) == Err(WrongAudience(["x", "y"])))
		and (Jwt.check({ ..gh, aud: Ok(["https://registry.example/"]) }, rules(now)) == Err(WrongAudience(["https://registry.example/"])))
		and (Jwt.check({ ..gh, aud: Ok([]) }, rules(now)) == Err(WrongAudience([])))
		and (Jwt.check({ ..gh, aud: Err(Missing) }, rules(now)) == Err(MissingClaim(Aud)))
		and (Jwt.check(gh, r(OneOf(["a", "https://registry.example"]))) == Ok({}))
		and (Jwt.check({ ..gh, aud: Ok(["x"]) }, r(Any)) == Ok({}))
		and (Jwt.check({ ..gh, aud: Err(Missing) }, r(Any)) == Ok({}))
}

# C3: sub.
expect {
	r = |want| Jwt.Rules.{ now_ms: now, aud, sub: want }
	(Jwt.check(gh, r(OneOf(["repo:roc-talon/talon:ref:refs/heads/main"]))) == Ok({}))
		and (Jwt.check(gh, r(OneOf(["repo:roc-talon/talon:ref:refs/heads/dev"]))) == Err(WrongSubject("repo:roc-talon/talon:ref:refs/heads/main")))
		and (Jwt.check({ ..gh, sub: Err(Missing) }, r(OneOf(["a"]))) == Err(MissingClaim(Sub)))
}

# C7: require. The default requires exp only; each claim can be required.
expect Jwt.check({ ..gh, exp: Err(Missing) }, rules(now)) == Err(MissingClaim(Exp))
expect Jwt.check({ ..gh, exp: Err(Missing) }, Jwt.Rules.{ now_ms: now, aud, require: [] }) == Ok({})
expect Jwt.check({ ..gh, nbf: Err(Missing), iat: Err(Missing), jti: Err(Missing), sub: Err(Missing), iss: Err(Missing) }, rules(now)) == Ok({})
expect {
	r = |claim| Jwt.Rules.{ now_ms: now, aud: Any, require: [claim] }
	(Jwt.check(T.none, r(Iss)) == Err(MissingClaim(Iss)))
		and (Jwt.check(T.none, r(Sub)) == Err(MissingClaim(Sub)))
		and (Jwt.check(T.none, r(Aud)) == Err(MissingClaim(Aud)))
		and (Jwt.check(T.none, r(Exp)) == Err(MissingClaim(Exp)))
		and (Jwt.check(T.none, r(Nbf)) == Err(MissingClaim(Nbf)))
		and (Jwt.check(T.none, r(Iat)) == Err(MissingClaim(Iat)))
		and (Jwt.check(T.none, r(Jti)) == Err(MissingClaim(Jti)))
		and (Jwt.check(gh, Jwt.Rules.{ now_ms: now, aud: Any, require: [Iss, Sub, Aud, Exp, Nbf, Iat, Jti] }) == Ok({}))
}

# C8: the order: iss, aud, sub, exp, nbf, iat, jti. Each case has two faults.
expect {
	r = Jwt.Rules.{ now_ms: now, aud, iss: OneOf(["i"]), sub: OneOf(["s"]), require: [Exp, Nbf, Iat, Jti] }
	ok = { ..gh, iss: Ok("i"), sub: Ok("s") }
	(Jwt.check({ ..ok, iss: Ok("x"), aud: Ok(["x"]) }, r) == Err(WrongIssuer("x")))
		and (Jwt.check({ ..ok, aud: Ok(["x"]), sub: Ok("x") }, r) == Err(WrongAudience(["x"])))
		and (Jwt.check({ ..ok, sub: Ok("x"), exp: Ok(0) }, r) == Err(WrongSubject("x")))
		and (Jwt.check({ ..ok, exp: Ok(0), nbf: Ok(9999999999) }, r) == Err(Expired({ exp: 0, now_ms: now, leeway_s: 0 })))
		and (Jwt.check({ ..ok, nbf: Ok(9999999999), iat: Ok(9999999999) }, r) == Err(NotYetValid({ nbf: 9999999999, now_ms: now, leeway_s: 0 })))
		and (Jwt.check({ ..ok, iat: Ok(9999999999), jti: Err(Missing) }, r) == Err(IssuedInFuture({ iat: 9999999999, now_ms: now, leeway_s: 0 })))
		and (Jwt.check({ ..ok, jti: Err(Missing) }, r) == Err(MissingClaim(Jti)))
		and (Jwt.check(ok, r) == Ok({}))
}

# X3: the texts of the claim errors (a proposal).
expect Jwt.err_to_str(MissingClaim(Exp)) == "the token has no exp claim"
expect Jwt.err_to_str(Expired({ exp: 1767225900, now_ms: 1767225960000, leeway_s: 60 })) == "the token expired: exp is 1767225900.0, now is 1767225960.0, leeway 60 s"
