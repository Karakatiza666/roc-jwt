# Builders of test tokens. This module is not in the package. It encodes with
# roc-base64 (`Base64.encode_url`), not with the code under test.
import base64.Base64
import pkg.Jwt

T :: [].{

	## The base64url of a text, with no padding.
	enc : Str -> Str
	enc = |text| Base64.encode_url(text.to_utf8())

	## The base64url of bytes, with no padding.
	enc_bytes : List(U8) -> Str
	enc_bytes = |bytes| Base64.encode_url(bytes)

	## A token of a header JSON, a payload JSON and signature bytes.
	token : Str, Str, List(U8) -> Str
	token = |header, payload, signature| "${enc(header)}.${enc(payload)}.${Base64.encode_url(signature)}"

	## A signature of 64 bytes (fits ES256 and EdDSA) or of 3 bytes.
	sig64 : List(U8)
	sig64 = List.repeat(7, 64)

	sig3 : List(U8)
	sig3 = [1, 2, 3]

	## The options with one alg.
	only : Jwt.Alg -> Jwt.Options
	only = |alg| Jwt.Options.{ algs: [alg] }

	## The error of a decode, or `Err(Ok)` for a token that decodes.
	error : Try(Jwt.Token, Jwt.Error) -> Try(Jwt.Error, [Ok])
	error = |r| match r {
		Ok(_) => Err(Ok)
		Err(e) => Ok(e)
	}

	## The claims with none present.
	none : Jwt.Claims
	none = { iss: Err(Missing), sub: Err(Missing), aud: Err(Missing), exp: Err(Missing), nbf: Err(Missing), iat: Err(Missing), jti: Err(Missing) }
}
