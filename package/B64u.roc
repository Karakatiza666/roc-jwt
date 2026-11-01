## The strict base64url of JWS (RFC 7515 2): the URL-safe alphabet of
## RFC 4648 5, no padding, no white space, no line breaks, and the canonical
## form only. The decode is `Base64.decode_url` of roc-base64. This module adds
## the refusals that a JWS needs and that `decode_url` does not do.
import base64.Base64

B64u :: [].{

	## The bytes of a base64url text. `Err(BadBase64)` for:
	##
	## | Input | Reason |
	## | --- | --- |
	## | a `=` | RFC 7515 2 has no padding |
	## | a character not in `A-Z a-z 0-9 - _` | not base64url (`+`, `/`, white space) |
	## | a length that leaves 1 character in the last group | no byte string encodes to it |
	## | a last character with bits that are not 0 (`Zh` for `Zg`) | not canonical: two texts for one value |
	##
	## The empty text is `Ok([])`.
	decode : Str -> Try(List(U8), [BadBase64])
	decode = |text| {
		bytes = Base64.decode_url(text) ? |_| BadBase64
		# The re-encode refuses `=` and the bits that are not 0: encode_url
		# gives one text for each byte string, with no padding.
		if Base64.encode_url(bytes) == text {
			Ok(bytes)
		} else {
			Err(BadBase64)
		}
	}

	## The base64url text of bytes, with no padding.
	encode : List(U8) -> Str
	encode = |bytes| Base64.encode_url(bytes)
}
