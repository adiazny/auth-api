package diaz.rego

import rego.v1

default auth := false

# auth if {
# 	[valid, _, _] := io.jwt.decode_verify(input.Token, {
# 	"cert": input.Key,
# 	"iss": input.ISS,
# })
# 	valid == true
# }

auth if {
    input.is_admin == true
}