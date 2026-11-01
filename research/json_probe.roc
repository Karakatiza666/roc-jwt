# Probe: what Encoding.Json (builtins) does on the inputs that matter for JWT.
H : { alg : Try(Str, [Missing]), kid : Try(Str, [Missing]) }

h : Str -> Try(H, _)
h = |t| Json.parse(t)

N : { exp : Try(U64, [Missing]) }

n : Str -> Try(N, _)
n = |t| Json.parse(t)

D : { exp : Try(Dec, [Missing]) }

d : Str -> Try(D, _)
d = |t| Json.parse(t)

I : { exp : Try(I64, [Missing]) }

i : Str -> Try(I, _)
i = |t| Json.parse(t)

main! = |_args| {
	echo!("dup alg: ${Str.inspect(h("{\"alg\":\"RS256\",\"alg\":\"none\"}"))}\n")
	echo!("trailing: ${Str.inspect(h("{\"alg\":\"RS256\"} x"))}\n")
	echo!("trailing2: ${Str.inspect(h("{\"alg\":\"RS256\"}{}"))}\n")
	echo!("ws: ${Str.inspect(h(" {\"alg\" : \"RS256\"} \n"))}\n")
	echo!("null alg: ${Str.inspect(h("{\"alg\":null}"))}\n")
	echo!("num alg: ${Str.inspect(h("{\"alg\":1}"))}\n")
	echo!("escape: ${Str.inspect(h("{\"alg\":\"RS\\u0032\\u00356\"}"))}\n")
	echo!("esc key: ${Str.inspect(h("{\"al\\u0067\":\"none\"}"))}\n")
	echo!("bad utf: ${Str.inspect(h("{\"alg\":\"\\ud800\"}"))}\n")
	echo!("u64 1.5: ${Str.inspect(n("{\"exp\":1.5}"))}\n")
	echo!("u64 1e9: ${Str.inspect(n("{\"exp\":1e9}"))}\n")
	echo!("u64 -1: ${Str.inspect(n("{\"exp\":-1}"))}\n")
	echo!("u64 big: ${Str.inspect(n("{\"exp\":99999999999999999999999}"))}\n")
	echo!("u64 str: ${Str.inspect(n("{\"exp\":\"5\"}"))}\n")
	echo!("u64 null: ${Str.inspect(n("{\"exp\":null}"))}\n")
	echo!("dec 1.5: ${Str.inspect(d("{\"exp\":1767225900.5}"))}\n")
	echo!("dec 1e9: ${Str.inspect(d("{\"exp\":1e9}"))}\n")
	echo!("dec int: ${Str.inspect(d("{\"exp\":1767225900}"))}\n")
	echo!("dec -3: ${Str.inspect(d("{\"exp\":-3}"))}\n")
	echo!("i64 1.0: ${Str.inspect(i("{\"exp\":1.0}"))}\n")
	echo!("i64 -3: ${Str.inspect(i("{\"exp\":-3}"))}\n")
	Ok({})
}
