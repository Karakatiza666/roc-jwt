app [target] {
	base64: "https://github.com/niclas-ahden/roc-base64/releases/download/1.0.2/DQBxATK6BtaCWe56bCmkMgdKJR2Ym8NiZZLhYCAgtLac.tar.zst",
	fuzz: platform "https://github.com/lukewilliamboswell/roc-fuzz/releases/download/0.4.3/41NK5FShyGC9Z8HNpUdUeXMWwLmLNfFxsfmLvdPL4Fxb.tar.zst",
	pkg: "../package/main.roc",
}

import fuzz.Fuzz
import pkg.Jwt
import base64.Base64

# L1 (D1 to D10): decode never crashes, on any text. When it gives Ok:
# - signing_input is the text before the second ".", as sent,
# - the signature re-encodes to the third part (strict, canonical base64url),
# - the alg is in the allowlist,
# - the claims are the claims of a second decode (no state).
# The input is a seed token with a cut and an insert, or any bytes.

seeds : List(Str)
seeds = [
	"eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC0xIiwidHlwIjoiSldUIiwieDV0IjoienoifQ.eyJqdGkiOiJqLTEiLCJzdWIiOiJyZXBvOnJvYy10YWxvbi90YWxvbjpyZWY6cmVmcy9oZWFkcy9tYWluIiwiYXVkIjoiaHR0cHM6Ly9yZWdpc3RyeS5leGFtcGxlIiwicmVmIjoicmVmcy9oZWFkcy9tYWluIiwic2hhIjoiYWJjIiwicmVwb3NpdG9yeSI6InJvYy10YWxvbi90YWxvbiIsInJlcG9zaXRvcnlfb3duZXIiOiJyb2MtdGFsb24iLCJyZXBvc2l0b3J5X293bmVyX2lkIjoiNzAwMDAxIiwicnVuX2lkIjoiNDIiLCJydW5fbnVtYmVyIjoiNyIsInJ1bl9hdHRlbXB0IjoiMSIsInJlcG9zaXRvcnlfdmlzaWJpbGl0eSI6InB1YmxpYyIsInJlcG9zaXRvcnlfaWQiOiI5MDAwMDEiLCJhY3Rvcl9pZCI6IjUwMDAwMSIsImFjdG9yIjoiYm90Iiwid29ya2Zsb3ciOiJjb21wYXQtYm90IiwiaGVhZF9yZWYiOiIiLCJiYXNlX3JlZiI6IiIsImV2ZW50X25hbWUiOiJzY2hlZHVsZSIsInJlZl90eXBlIjoiYnJhbmNoIiwid29ya2Zsb3dfcmVmIjoicm9jLXRhbG9uL3RhbG9uLy5naXRodWIvd29ya2Zsb3dzL2NvbXBhdC1ib3QueW1sQHJlZnMvaGVhZHMvbWFpbiIsIndvcmtmbG93X3NoYSI6ImFiYyIsImpvYl93b3JrZmxvd19yZWYiOiJyb2MtdGFsb24vdGFsb24vLmdpdGh1Yi93b3JrZmxvd3MvY29tcGF0LWJvdC55bWxAcmVmcy9oZWFkcy9tYWluIiwiam9iX3dvcmtmbG93X3NoYSI6ImFiYyIsInJ1bm5lcl9lbnZpcm9ubWVudCI6ImdpdGh1Yi1ob3N0ZWQiLCJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwibmJmIjoxNzY3MjI1MzAwLCJleHAiOjE3NjcyMjU5MDAsImlhdCI6MTc2NzIyNTYwMH0.adzIBGWdcPXkfqRwLIcb1fIfw6ajuS5iROqmITZS1kRYvlz4qDkEkIWxGcUEbm-OJTWuYlEA0THhAgit5A-2nIb5Byh659PicZGJB1p4Rb0xIBPDie-LjsLT2gwhH4dTr3zTif8zS-EPy6hSuAo1NoRh0WI2veYo0oBuUbg-WtdpGhtGqOdjRsuEFsB5HoKx6iaurGPm3gvpknTV3XzFv9iqAXJ66tegOVLw_oIYFad9TgNiC3gMEpFMY8NfdTAU-DU4q7rY2BF_4SFC0APseLO9ouhK__fjK-ee0L9V3ikISh9ELFmQ8arHehZV3QJvct_8UKivv01ueo6dFj65KQ",
	"eyJhbGciOiJFUzI1NiIsImtpZCI6ImVjLTEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjpbImEiLCJiIl0sImV4cCI6MTc2NzIyNTkwMC41fQ.Jow8ggkdWRClUXy_XPz_pi4JW8BbIMnYukf5hV2PKNqkMwmA-MH26-omNlaeH5QvlXvey2EdXXOMozUiim_kDA",
	"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
]

algs : Jwt.Options
algs = Jwt.Options.{ algs: [RS256, ES256, HS256] }

Input := { seed : U64, cut : U64, drop : U64, insert : List(U8), raw : Bool }.{
	generator_for : Fuzz.FuzzEncoding -> Fuzz.Generator(Input)
	generator_for = |_| {
		seed: Fuzz.u64,
		cut: Fuzz.u64,
		drop: Fuzz.u64_in(0, 40),
		insert: Fuzz.bytes,
		raw: Fuzz.map(Fuzz.u8_in(0, 7), |b| b == 0),
	}.Fuzz
}

## The seed with `drop` bytes at `cut` replaced by `insert`.
bytes_of : Input -> List(U8)
bytes_of = |input| {
	if input.raw {
		return input.insert
	}
	bytes = (seeds.get(input.seed % seeds.len()) ?? "").to_utf8()
	at = input.cut % (bytes.len() + 1)
	bytes.take_first(at).concat(input.insert).concat(bytes.drop_first(at + input.drop))
}

test : Input -> Fuzz.Outcome
test = |input| {
	match Str.from_utf8(bytes_of(input)) {
		Err(_) => Fuzz.keep
		Ok(text) => {
			first = Jwt.decode(text, algs)
			match first {
				Err(_) => Fuzz.keep
				Ok(t) => {
					parts = text.split_on(".")
					expected = match parts {
						[h, p, s] => Ok(("${h}.${p}".to_utf8(), s))
						_ => Err(NotThree)
					}
					match expected {
						Ok((signing_input, s)) =>
							if t.signing_input != signing_input {
								crash "signing_input is not the text before the second dot"
							} else if Base64.encode_url(t.signature) != s {
								crash "the signature part is not canonical base64url"
							} else if !algs.algs.contains(t.header.alg) {
								crash "an alg that is not in the allowlist"
							} else if Jwt.decode(text, algs) != first {
								crash "two decodes differ"
							} else {
								Fuzz.keep
							}
						Err(NotThree) => crash "Ok for a text that is not 3 parts"
					}
				}
			}
		}
	}
}

target = Fuzz.target_with({
	name: "decode",
	generator: Input.generator_for(Default),
	test,
	show: |input| Str.inspect(input),
})
