## Test vectors made by research/vectors.py (Python `cryptography`, apart from any Roc code). Do not edit: run the script again.
## Each signature here is verified by the script, so each `*_signing_input` is the text that the key signs.
Vectors :: [].{

	## RFC 7515 A.1
	rfc7515_a1 : Str
	rfc7515_a1 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	rfc7515_a1_signing_input : Str
	rfc7515_a1_signing_input = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

	## RFC 7515 A.2
	rfc7515_a2 : Str
	rfc7515_a2 = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

	rfc7515_a2_signing_input : Str
	rfc7515_a2_signing_input = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

	## RFC 7515 A.3
	rfc7515_a3 : Str
	rfc7515_a3 = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

	rfc7515_a3_signing_input : Str
	rfc7515_a3_signing_input = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

	## RFC 7515 A.4
	rfc7515_a4 : Str
	rfc7515_a4 = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"

	rfc7515_a4_signing_input : Str
	rfc7515_a4_signing_input = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA"

	## RFC 7515 A.5
	rfc7515_a5 : Str
	rfc7515_a5 = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

	rfc7515_a5_signing_input : Str
	rfc7515_a5_signing_input = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

	rfc7515_a1_signature : List(U8)
	rfc7515_a1_signature = [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121]

	rfc7515_a2_signature : List(U8)
	rfc7515_a2_signature = [112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69, 243, 65, 6, 174, 27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125, 131, 101, 109, 66, 10, 253, 60, 150, 238, 221, 115, 162, 102, 62, 81, 102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237, 16, 115, 249, 69, 229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219, 61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7, 16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31, 190, 127, 249, 217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244, 74, 230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18, 142, 212, 1, 48, 121, 91, 212, 189, 59, 65, 238, 202, 208, 102, 171, 101, 25, 129, 253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239, 177, 139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202, 173, 21, 145, 18, 115, 160, 95, 35, 185, 232, 56, 250, 175, 132, 157, 105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69, 34, 165, 68, 200, 242, 122, 122, 45, 184, 6, 99, 209, 108, 247, 202, 234, 86, 222, 64, 92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90, 193, 167, 72, 160, 112, 223, 200, 163, 42, 70, 149, 67, 208, 25, 238, 251, 71]

	rfc7515_a3_signature : List(U8)
	rfc7515_a3_signature = [14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101, 197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131, 163, 84, 213]

	rfc7515_a4_signature : List(U8)
	rfc7515_a4_signature = [1, 220, 12, 129, 231, 171, 194, 209, 232, 135, 233, 117, 247, 105, 122, 210, 26, 125, 192, 1, 217, 21, 82, 91, 45, 240, 255, 83, 19, 34, 239, 71, 48, 157, 147, 152, 105, 18, 53, 108, 163, 214, 68, 231, 62, 153, 150, 106, 194, 164, 246, 72, 143, 138, 24, 50, 129, 223, 133, 206, 209, 172, 63, 237, 119, 109, 0, 111, 6, 105, 44, 5, 41, 208, 128, 61, 152, 40, 92, 61, 152, 4, 150, 66, 60, 69, 247, 196, 170, 81, 193, 199, 78, 59, 194, 169, 16, 124, 9, 143, 42, 142, 131, 48, 206, 238, 34, 175, 83, 203, 220, 159, 3, 107, 155, 22, 27, 73, 111, 68, 68, 21, 238, 144, 229, 232, 148, 188, 222, 59, 242, 103]

	## The public RSA key of RFC 7515 A.2, as bytes.
	rfc7515_a2_n : List(U8)
	rfc7515_a2_n = [161, 248, 22, 10, 226, 227, 201, 180, 101, 206, 141, 45, 101, 98, 99, 54, 43, 146, 125, 190, 41, 225, 240, 36, 119, 252, 22, 37, 204, 144, 161, 54, 227, 139, 217, 52, 151, 197, 182, 234, 99, 221, 119, 17, 230, 124, 116, 41, 249, 86, 176, 251, 138, 143, 8, 154, 220, 75, 105, 137, 60, 193, 51, 63, 83, 237, 208, 25, 184, 119, 132, 37, 47, 236, 145, 79, 228, 133, 119, 105, 89, 75, 234, 66, 128, 211, 44, 15, 85, 191, 98, 148, 79, 19, 3, 150, 188, 110, 155, 223, 110, 189, 210, 189, 163, 103, 142, 236, 160, 198, 104, 247, 1, 179, 141, 191, 251, 56, 200, 52, 44, 226, 254, 109, 39, 250, 222, 74, 90, 72, 116, 151, 157, 212, 185, 207, 154, 222, 196, 199, 91, 5, 133, 44, 44, 15, 94, 248, 165, 193, 117, 3, 146, 249, 68, 232, 237, 100, 193, 16, 198, 182, 71, 96, 154, 164, 120, 58, 235, 156, 108, 154, 215, 85, 49, 48, 80, 99, 139, 131, 102, 92, 111, 111, 122, 130, 163, 150, 112, 42, 31, 100, 27, 130, 211, 235, 242, 57, 34, 25, 73, 31, 182, 134, 135, 44, 87, 22, 245, 10, 248, 53, 141, 154, 139, 157, 23, 195, 64, 114, 143, 127, 135, 216, 154, 24, 216, 252, 171, 103, 173, 132, 89, 12, 46, 207, 117, 147, 57, 54, 60, 7, 3, 77, 111, 96, 111, 158, 33, 224, 84, 86, 202, 229, 233, 161]

	rfc7515_a2_n_text : Str
	rfc7515_a2_n_text = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"

	rfc7515_a3_x : List(U8)
	rfc7515_a3_x = [127, 205, 206, 39, 112, 246, 196, 93, 65, 131, 203, 238, 111, 219, 75, 123, 88, 7, 51, 53, 123, 233, 239, 19, 186, 207, 110, 60, 123, 209, 84, 69]

	rfc7515_a3_y : List(U8)
	rfc7515_a3_y = [199, 241, 68, 205, 27, 189, 155, 126, 135, 44, 223, 237, 185, 238, 185, 244, 179, 105, 93, 110, 169, 11, 36, 173, 138, 70, 35, 40, 133, 136, 229, 173]

	rfc7515_a3_x_text : Str
	rfc7515_a3_x_text = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"

	rfc7515_a3_y_text : Str
	rfc7515_a3_y_text = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

	rfc7515_a4_x_text : Str
	rfc7515_a4_x_text = "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk"

	rfc7515_a4_y_text : Str
	rfc7515_a4_y_text = "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"

	## RFC 8037 A.4 (Ed25519; the payload is text, not JSON)
	rfc8037_a4 : Str
	rfc8037_a4 = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"

	rfc8037_x : List(U8)
	rfc8037_x = [215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26]

	## A GitHub Actions OIDC token shape, RS256, kid-1. Header: {"alg":"RS256","kid":"kid-1","typ":"JWT","x5t":"zz"}
	github : Str
	github = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC0xIiwidHlwIjoiSldUIiwieDV0IjoienoifQ.eyJqdGkiOiJqLTEiLCJzdWIiOiJyZXBvOnJvYy10YWxvbi90YWxvbjpyZWY6cmVmcy9oZWFkcy9tYWluIiwiYXVkIjoiaHR0cHM6Ly9yZWdpc3RyeS5leGFtcGxlIiwicmVmIjoicmVmcy9oZWFkcy9tYWluIiwic2hhIjoiYWJjIiwicmVwb3NpdG9yeSI6InJvYy10YWxvbi90YWxvbiIsInJlcG9zaXRvcnlfb3duZXIiOiJyb2MtdGFsb24iLCJyZXBvc2l0b3J5X293bmVyX2lkIjoiNzAwMDAxIiwicnVuX2lkIjoiNDIiLCJydW5fbnVtYmVyIjoiNyIsInJ1bl9hdHRlbXB0IjoiMSIsInJlcG9zaXRvcnlfdmlzaWJpbGl0eSI6InB1YmxpYyIsInJlcG9zaXRvcnlfaWQiOiI5MDAwMDEiLCJhY3Rvcl9pZCI6IjUwMDAwMSIsImFjdG9yIjoiYm90Iiwid29ya2Zsb3ciOiJjb21wYXQtYm90IiwiaGVhZF9yZWYiOiIiLCJiYXNlX3JlZiI6IiIsImV2ZW50X25hbWUiOiJzY2hlZHVsZSIsInJlZl90eXBlIjoiYnJhbmNoIiwid29ya2Zsb3dfcmVmIjoicm9jLXRhbG9uL3RhbG9uLy5naXRodWIvd29ya2Zsb3dzL2NvbXBhdC1ib3QueW1sQHJlZnMvaGVhZHMvbWFpbiIsIndvcmtmbG93X3NoYSI6ImFiYyIsImpvYl93b3JrZmxvd19yZWYiOiJyb2MtdGFsb24vdGFsb24vLmdpdGh1Yi93b3JrZmxvd3MvY29tcGF0LWJvdC55bWxAcmVmcy9oZWFkcy9tYWluIiwiam9iX3dvcmtmbG93X3NoYSI6ImFiYyIsInJ1bm5lcl9lbnZpcm9ubWVudCI6ImdpdGh1Yi1ob3N0ZWQiLCJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwibmJmIjoxNzY3MjI1MzAwLCJleHAiOjE3NjcyMjU5MDAsImlhdCI6MTc2NzIyNTYwMH0.adzIBGWdcPXkfqRwLIcb1fIfw6ajuS5iROqmITZS1kRYvlz4qDkEkIWxGcUEbm-OJTWuYlEA0THhAgit5A-2nIb5Byh659PicZGJB1p4Rb0xIBPDie-LjsLT2gwhH4dTr3zTif8zS-EPy6hSuAo1NoRh0WI2veYo0oBuUbg-WtdpGhtGqOdjRsuEFsB5HoKx6iaurGPm3gvpknTV3XzFv9iqAXJ66tegOVLw_oIYFad9TgNiC3gMEpFMY8NfdTAU-DU4q7rY2BF_4SFC0APseLO9ouhK__fjK-ee0L9V3ikISh9ELFmQ8arHehZV3QJvct_8UKivv01ueo6dFj65KQ"

	github_signing_input : Str
	github_signing_input = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC0xIiwidHlwIjoiSldUIiwieDV0IjoienoifQ.eyJqdGkiOiJqLTEiLCJzdWIiOiJyZXBvOnJvYy10YWxvbi90YWxvbjpyZWY6cmVmcy9oZWFkcy9tYWluIiwiYXVkIjoiaHR0cHM6Ly9yZWdpc3RyeS5leGFtcGxlIiwicmVmIjoicmVmcy9oZWFkcy9tYWluIiwic2hhIjoiYWJjIiwicmVwb3NpdG9yeSI6InJvYy10YWxvbi90YWxvbiIsInJlcG9zaXRvcnlfb3duZXIiOiJyb2MtdGFsb24iLCJyZXBvc2l0b3J5X293bmVyX2lkIjoiNzAwMDAxIiwicnVuX2lkIjoiNDIiLCJydW5fbnVtYmVyIjoiNyIsInJ1bl9hdHRlbXB0IjoiMSIsInJlcG9zaXRvcnlfdmlzaWJpbGl0eSI6InB1YmxpYyIsInJlcG9zaXRvcnlfaWQiOiI5MDAwMDEiLCJhY3Rvcl9pZCI6IjUwMDAwMSIsImFjdG9yIjoiYm90Iiwid29ya2Zsb3ciOiJjb21wYXQtYm90IiwiaGVhZF9yZWYiOiIiLCJiYXNlX3JlZiI6IiIsImV2ZW50X25hbWUiOiJzY2hlZHVsZSIsInJlZl90eXBlIjoiYnJhbmNoIiwid29ya2Zsb3dfcmVmIjoicm9jLXRhbG9uL3RhbG9uLy5naXRodWIvd29ya2Zsb3dzL2NvbXBhdC1ib3QueW1sQHJlZnMvaGVhZHMvbWFpbiIsIndvcmtmbG93X3NoYSI6ImFiYyIsImpvYl93b3JrZmxvd19yZWYiOiJyb2MtdGFsb24vdGFsb24vLmdpdGh1Yi93b3JrZmxvd3MvY29tcGF0LWJvdC55bWxAcmVmcy9oZWFkcy9tYWluIiwiam9iX3dvcmtmbG93X3NoYSI6ImFiYyIsInJ1bm5lcl9lbnZpcm9ubWVudCI6ImdpdGh1Yi1ob3N0ZWQiLCJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwibmJmIjoxNzY3MjI1MzAwLCJleHAiOjE3NjcyMjU5MDAsImlhdCI6MTc2NzIyNTYwMH0"

	github_signature : List(U8)
	github_signature = [105, 220, 200, 4, 101, 157, 112, 245, 228, 126, 164, 112, 44, 135, 27, 213, 242, 31, 195, 166, 163, 185, 46, 98, 68, 234, 166, 33, 54, 82, 214, 68, 88, 190, 92, 248, 168, 57, 4, 144, 133, 177, 25, 197, 4, 110, 111, 142, 37, 53, 174, 98, 81, 0, 209, 49, 225, 2, 8, 173, 228, 15, 182, 156, 134, 249, 7, 40, 122, 231, 211, 226, 113, 145, 137, 7, 90, 120, 69, 189, 49, 32, 19, 195, 137, 239, 139, 142, 194, 211, 218, 12, 33, 31, 135, 83, 175, 124, 211, 137, 255, 51, 75, 225, 15, 203, 168, 82, 184, 10, 53, 54, 132, 97, 209, 98, 54, 189, 230, 40, 210, 128, 110, 81, 184, 62, 90, 215, 105, 26, 27, 70, 168, 231, 99, 70, 203, 132, 22, 192, 121, 30, 130, 177, 234, 38, 174, 172, 99, 230, 222, 11, 233, 146, 116, 213, 221, 124, 197, 191, 216, 170, 1, 114, 122, 234, 215, 160, 57, 82, 240, 254, 130, 24, 21, 167, 125, 78, 3, 98, 11, 120, 12, 18, 145, 76, 99, 195, 95, 117, 48, 20, 248, 53, 56, 171, 186, 216, 216, 17, 127, 225, 33, 66, 208, 3, 236, 120, 179, 189, 162, 232, 74, 255, 247, 227, 43, 231, 158, 208, 191, 85, 222, 41, 8, 74, 31, 68, 44, 89, 144, 241, 170, 199, 122, 22, 85, 221, 2, 111, 114, 223, 252, 80, 168, 175, 191, 77, 110, 122, 142, 157, 22, 62, 185, 41]

	github_payload : Str
	github_payload = "{\"jti\":\"j-1\",\"sub\":\"repo:roc-talon/talon:ref:refs/heads/main\",\"aud\":\"https://registry.example\",\"ref\":\"refs/heads/main\",\"sha\":\"abc\",\"repository\":\"roc-talon/talon\",\"repository_owner\":\"roc-talon\",\"repository_owner_id\":\"700001\",\"run_id\":\"42\",\"run_number\":\"7\",\"run_attempt\":\"1\",\"repository_visibility\":\"public\",\"repository_id\":\"900001\",\"actor_id\":\"500001\",\"actor\":\"bot\",\"workflow\":\"compat-bot\",\"head_ref\":\"\",\"base_ref\":\"\",\"event_name\":\"schedule\",\"ref_type\":\"branch\",\"workflow_ref\":\"roc-talon/talon/.github/workflows/compat-bot.yml@refs/heads/main\",\"workflow_sha\":\"abc\",\"job_workflow_ref\":\"roc-talon/talon/.github/workflows/compat-bot.yml@refs/heads/main\",\"job_workflow_sha\":\"abc\",\"runner_environment\":\"github-hosted\",\"iss\":\"https://token.actions.githubusercontent.com\",\"nbf\":1767225300,\"exp\":1767225900,\"iat\":1767225600}"

	## PS256 with the RSA key, kid-1, claims {"sub":"s"}
	ps256 : Str
	ps256 = "eyJhbGciOiJQUzI1NiIsImtpZCI6ImtpZC0xIn0.eyJzdWIiOiJzIn0.gBt8UXBvOy5jULJvzILQhxm9BchxF1SciOWtwmUjrqWQnD41QO6oYOR38JeGZrCsJEeeTlaUZcgaNAFLcVJTbjYzGFTMBa8j6vsQxrkmTKBL_AjlEcRfhPdjNC6_AtDRyLgwQgGUOFQYqxLdr0bGaRGX0wNAaDVYmHPQMcBzSpqDQzFnuduuwOYxMwKurnblyUCO5mPVbPYznJMtXCd35YitoEwD_9Qa-X0U2yzDAbBWcVW1C4toBdmjWinOwGnwcOFVwLilBBGoF30OSG2PxxtmGd_y7XVtSIJ8RXuy3grOUhW2PUp4vKVdzar4DAnEBCKX_8Z3xdT3d7a5fL5Mxg"

	## ES256, kid ec-1, aud a list, exp with a fraction
	es256 : Str
	es256 = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVjLTEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjpbImEiLCJiIl0sImV4cCI6MTc2NzIyNTkwMC41fQ.Jow8ggkdWRClUXy_XPz_pi4JW8BbIMnYukf5hV2PKNqkMwmA-MH26-omNlaeH5QvlXvey2EdXXOMozUiim_kDA"

	es256_signature : List(U8)
	es256_signature = [38, 140, 60, 130, 9, 29, 89, 16, 165, 81, 124, 191, 92, 252, 255, 166, 46, 9, 91, 192, 91, 32, 201, 216, 186, 71, 249, 133, 93, 143, 40, 218, 164, 51, 9, 128, 248, 193, 246, 235, 234, 38, 54, 86, 158, 31, 148, 47, 149, 123, 222, 203, 97, 29, 93, 115, 140, 163, 53, 34, 138, 111, 228, 12]

	## EdDSA (Ed25519), kid ed-1
	eddsa : Str
	eddsa = "eyJhbGciOiJFZERTQSIsImtpZCI6ImVkLTEifQ.eyJzdWIiOiJ4IiwiZXhwIjoyMDAwMDAwMDAwfQ.Qd5X5ub4p_Z9VXkoeRsWaDzrnED5WgxSYWb8zCJ44mbEsOb90_UEcx14m1flSyurc8Q23KXJxW_gRghN3kq9AQ"

	## The JWKS of the new keys: RSA kid-1 (alg RS256, use sig), EC ec-1, OKP ed-1, oct hmac-1, RSA enc-1 (use enc)
	jwks : Str
	jwks = "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"kid-1\",\"n\":\"lSB0y7hd3ggEucNGcmfvKq181yX2VzqK3Zr510f-Ua0SZR9cINWwWXr5V2-K-GPqut7bSS-yIntdNm7i7Og1FriAlUunZLJJ9EeU0744agyc9wY2U6CVnz3B7XqByzUxPsnApdYzAV3MlriTT07ffODmuRyu9zkQ_eC0ubDjkF3LhwlJQHrZdbgdXJJQktu5mHs72rIEICRU2H4ZqwNraoS-wr1OmbvdCHftPjOM7KQws63nxJdSmjWcFOjxXf3-cUiPcnyN8abwwHXIXWthzl5rZ2_shko_9qBpMWslYsxfTSxTXYx-jrs22xd8Ywqr2QSs8g-eIOSm5CEQHoCQ4Q\",\"e\":\"AQAB\",\"x5c\":[\"MII\"]},{\"kty\":\"EC\",\"kid\":\"ec-1\",\"crv\":\"P-256\",\"x\":\"sTzdv1h9jONStQzxpNE72VBAmUAppZKDIow1bOCnNdo\",\"y\":\"DSZ3Pz6Xonxt-vKZRGogcVap0Va2jSNJPvaxUd528LM\"},{\"kty\":\"OKP\",\"kid\":\"ed-1\",\"crv\":\"Ed25519\",\"x\":\"5S-0tgFmfGvTWaad0nrP-sVhw3y93dQrfkrTHNSdZMU\"},{\"kty\":\"oct\",\"kid\":\"hmac-1\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ\"},{\"kty\":\"RSA\",\"kid\":\"enc-1\",\"use\":\"enc\",\"n\":\"lSB0y7hd3ggEucNGcmfvKq181yX2VzqK3Zr510f-Ua0SZR9cINWwWXr5V2-K-GPqut7bSS-yIntdNm7i7Og1FriAlUunZLJJ9EeU0744agyc9wY2U6CVnz3B7XqByzUxPsnApdYzAV3MlriTT07ffODmuRyu9zkQ_eC0ubDjkF3LhwlJQHrZdbgdXJJQktu5mHs72rIEICRU2H4ZqwNraoS-wr1OmbvdCHftPjOM7KQws63nxJdSmjWcFOjxXf3-cUiPcnyN8abwwHXIXWthzl5rZ2_shko_9qBpMWslYsxfTSxTXYx-jrs22xd8Ywqr2QSs8g-eIOSm5CEQHoCQ4Q\",\"e\":\"AQAB\"}]}"

	rsa_n : List(U8)
	rsa_n = [149, 32, 116, 203, 184, 93, 222, 8, 4, 185, 195, 70, 114, 103, 239, 42, 173, 124, 215, 37, 246, 87, 58, 138, 221, 154, 249, 215, 71, 254, 81, 173, 18, 101, 31, 92, 32, 213, 176, 89, 122, 249, 87, 111, 138, 248, 99, 234, 186, 222, 219, 73, 47, 178, 34, 123, 93, 54, 110, 226, 236, 232, 53, 22, 184, 128, 149, 75, 167, 100, 178, 73, 244, 71, 148, 211, 190, 56, 106, 12, 156, 247, 6, 54, 83, 160, 149, 159, 61, 193, 237, 122, 129, 203, 53, 49, 62, 201, 192, 165, 214, 51, 1, 93, 204, 150, 184, 147, 79, 78, 223, 124, 224, 230, 185, 28, 174, 247, 57, 16, 253, 224, 180, 185, 176, 227, 144, 93, 203, 135, 9, 73, 64, 122, 217, 117, 184, 29, 92, 146, 80, 146, 219, 185, 152, 123, 59, 218, 178, 4, 32, 36, 84, 216, 126, 25, 171, 3, 107, 106, 132, 190, 194, 189, 78, 153, 187, 221, 8, 119, 237, 62, 51, 140, 236, 164, 48, 179, 173, 231, 196, 151, 82, 154, 53, 156, 20, 232, 241, 93, 253, 254, 113, 72, 143, 114, 124, 141, 241, 166, 240, 192, 117, 200, 93, 107, 97, 206, 94, 107, 103, 111, 236, 134, 74, 63, 246, 160, 105, 49, 107, 37, 98, 204, 95, 77, 44, 83, 93, 140, 126, 142, 187, 54, 219, 23, 124, 99, 10, 171, 217, 4, 172, 242, 15, 158, 32, 228, 166, 228, 33, 16, 30, 128, 144, 225]

	rsa_n_text : Str
	rsa_n_text = "lSB0y7hd3ggEucNGcmfvKq181yX2VzqK3Zr510f-Ua0SZR9cINWwWXr5V2-K-GPqut7bSS-yIntdNm7i7Og1FriAlUunZLJJ9EeU0744agyc9wY2U6CVnz3B7XqByzUxPsnApdYzAV3MlriTT07ffODmuRyu9zkQ_eC0ubDjkF3LhwlJQHrZdbgdXJJQktu5mHs72rIEICRU2H4ZqwNraoS-wr1OmbvdCHftPjOM7KQws63nxJdSmjWcFOjxXf3-cUiPcnyN8abwwHXIXWthzl5rZ2_shko_9qBpMWslYsxfTSxTXYx-jrs22xd8Ywqr2QSs8g-eIOSm5CEQHoCQ4Q"

	ec_x : List(U8)
	ec_x = [177, 60, 221, 191, 88, 125, 140, 227, 82, 181, 12, 241, 164, 209, 59, 217, 80, 64, 153, 64, 41, 165, 146, 131, 34, 140, 53, 108, 224, 167, 53, 218]

	ec_y : List(U8)
	ec_y = [13, 38, 119, 63, 62, 151, 162, 124, 109, 250, 242, 153, 68, 106, 32, 113, 86, 169, 209, 86, 182, 141, 35, 73, 62, 246, 177, 81, 222, 118, 240, 179]

	ed_x : List(U8)
	ed_x = [229, 47, 180, 182, 1, 102, 124, 107, 211, 89, 166, 157, 210, 122, 207, 250, 197, 97, 195, 124, 189, 221, 212, 43, 126, 74, 211, 28, 212, 157, 100, 197]

}
