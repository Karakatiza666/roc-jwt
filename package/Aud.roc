## The JWT `aud` claim (RFC 7519 4.1.3): one string, or a list of strings.
## Internal: `Jwt.Claims` gives it as `List(Str)`.
Aud := [One(Str), Many(List(Str))].{

	## The JSON parser: a string, else a list of strings. Any other JSON
	## value (a number, `null`, a list with a value that is not a string) is
	## an error.
	parser_for : encoding -> (state -> Try({ value : Aud, rest : state }, err))
		where [
			encoding.parse_str : encoding, state -> Try({ value : Str, rest : state }, err),
			encoding.parse_list_start : encoding, state -> Try([Counted({ len : U64, rest : state }), Uncounted(state)], err),
			encoding.parse_list_next : encoding, state -> Try([Item(state), Done(state)], err),
			encoding.parse_list_after_item : encoding, state -> Try([Continue(state), Done(state)], err),
		]
	parser_for = |encoding| {
		Encoding : encoding

		|state| match Encoding.parse_str(encoding, state) {
			Ok(one) => Ok({ value: Aud.One(one.value), rest: one.rest })
			Err(_) => {
				start = Encoding.parse_list_start(encoding, state)?
				var $at = match start {
					Counted(c) => c.rest
					Uncounted(s) => s
				}
				var $items = []
				var $open = Bool.True
				while $open {
					match Encoding.parse_list_next(encoding, $at)? {
						Done(s) => {
							$at = s
							$open = Bool.False
						}
						Item(s) => {
							item = Encoding.parse_str(encoding, s)?
							$items = $items.append(item.value)
							match Encoding.parse_list_after_item(encoding, item.rest)? {
								Continue(next) => {
									$at = next
								}
								Done(next) => {
									$at = next
									$open = Bool.False
								}
							}
						}
					}
				}
				Ok({ value: Aud.Many($items), rest: $at })
			}
		}
	}

	## The values as a list: `One(s)` is `[s]`.
	to_list : Aud -> List(Str)
	to_list = |aud| match aud {
		One(s) => [s]
		Many(list) => list
	}
}
