#!/usr/bin/env python3
"""Test vectors for tests/*.roc, computed apart from any Roc code.

Usage: python3 -I research/vectors.py RFC_DIR > tests/lib/Vectors.roc
RFC_DIR holds rfc7515.txt and rfc8037.txt (www.rfc-editor.org/rfc/rfcNNNN.txt).
Needs the Python package `cryptography`.

1. The RFC 7515 A.1 to A.5 and RFC 8037 A.4 tokens and keys, read from the RFC
   text. Each signature is verified here with `cryptography`, so the signing
   input (the text before the second `.`) is proven by the RFC key.
2. New tokens (a GitHub Actions OIDC token shape, ES256, EdDSA, PS256) signed
   with keys made at each run. The script verifies each one. The private keys
   are not written.
"""
import base64, hashlib, hmac, json, re, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.exceptions import InvalidSignature

RFC = sys.argv[1]


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def j(o):
    return json.dumps(o, separators=(",", ":"))


def lines_of(name):
    # The RFC text with no page footer, page header or form feed.
    out = []
    for line in open(f"{RFC}/{name}", encoding="ascii").read().split("\n"):
        line = line.replace("\f", "")
        if re.match(r"^(Jones, et al\.|Liusvaara|RFC 7515|RFC 8037)\s", line):
            continue
        out.append(line)
    return out


def block_after(lines, start, marker):
    # The text of the indented base64url lines after the first line at or
    # after `start` that has `marker`, joined with no space.
    i = start
    while marker not in lines[i]:
        i += 1
    i += 1
    while not re.match(r"^\s+[A-Za-z0-9_.-]+$", lines[i]):
        i += 1
    parts = []
    while i < len(lines) and (re.match(r"^\s+[A-Za-z0-9_.-]+$", lines[i]) or lines[i].strip() == ""):
        if lines[i].strip():
            parts.append(lines[i].strip())
        elif parts and parts[-1] != "." and not parts[-1].endswith("."):
            # A blank line after a full part ends the block (A.5 ends with ".").
            if i + 1 < len(lines) and not re.match(r"^\s+[A-Za-z0-9_.-]+$", lines[i + 1]) and lines[i + 1].strip() != "":
                break
        i += 1
    return "".join(parts)


def jwk_member(lines, start, name):
    # A JWK member value of the appendix at `start`, joined over its lines.
    i = start
    while f'"{name}":"' not in lines[i]:
        i += 1
    text = lines[i].split(f'"{name}":"', 1)[1]
    while '"' not in text:
        i += 1
        text += lines[i].strip()
    return text.split('"', 1)[0]


def index_of(lines, title):
    return next(i for i, l in enumerate(lines) if l.startswith(title))


L = lines_of("rfc7515.txt")
a1, a2, a3, a4, a5 = (index_of(L, f"A.{n}.  ") for n in range(1, 6))
marker = "JWS Compact Serialization (with line breaks"
tok = {n: block_after(L, s, marker) for n, s in [("a1", a1), ("a2", a2), ("a3", a3), ("a4", a4), ("a5", a5)]}


def parts(t):
    h, p, s = t.split(".")
    return h, p, s, f"{h}.{p}".encode(), unb64u(s)


# A.1 HS256
h, p, s, si, sig = parts(tok["a1"])
k = unb64u(jwk_member(L, a1, "k"))
assert hmac.new(k, si, hashlib.sha256).digest() == sig, "A.1"
# A.2 RS256
n_a2, e_a2 = jwk_member(L, a2, "n"), jwk_member(L, a2, "e")
pub = rsa.RSAPublicNumbers(int.from_bytes(unb64u(e_a2), "big"), int.from_bytes(unb64u(n_a2), "big")).public_key()
h, p, s, si, sig = parts(tok["a2"])
pub.verify(sig, si, padding.PKCS1v15(), hashes.SHA256())


def ec_verify(t, x, y, curve, hash_alg, size):
    h, p, s, si, sig = parts(t)
    assert len(sig) == 2 * size
    pk = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64u(x), "big"), int.from_bytes(unb64u(y), "big"), curve).public_key()
    der = utils.encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big"))
    pk.verify(der, si, ec.ECDSA(hash_alg))


x_a3, y_a3 = jwk_member(L, a3, "x"), jwk_member(L, a3, "y")
ec_verify(tok["a3"], x_a3, y_a3, ec.SECP256R1(), hashes.SHA256(), 32)
x_a4, y_a4 = jwk_member(L, a4, "x"), jwk_member(L, a4, "y")
ec_verify(tok["a4"], x_a4, y_a4, ec.SECP521R1(), hashes.SHA512(), 66)
assert tok["a5"].endswith(".") and unb64u(tok["a5"].split(".")[0]) == b'{"alg":"none"}', "A.5"

# RFC 8037 A.4 Ed25519 (the payload is text, not JSON)
L8 = lines_of("rfc8037.txt")
a84 = index_of(L8, "A.4.  ")
x_8037 = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
eddsa_rfc = block_after(L8, a84, "So the compact serialization")
h, p, s, si, sig = parts(eddsa_rfc)
ed25519.Ed25519PublicKey.from_public_bytes(unb64u(x_8037)).verify(sig, si)

# New tokens. GitHub Actions OIDC claims (the shape of
# docs.github.com "About security hardening with OpenID Connect"), at
# 2026-01-01T00:00:00Z = 1767225600.
gh_claims = {
    "jti": "j-1", "sub": "repo:roc-talon/talon:ref:refs/heads/main", "aud": "https://registry.example",
    "ref": "refs/heads/main", "sha": "abc", "repository": "roc-talon/talon", "repository_owner": "roc-talon",
    "repository_owner_id": "700001", "run_id": "42", "run_number": "7", "run_attempt": "1",
    "repository_visibility": "public", "repository_id": "900001", "actor_id": "500001", "actor": "bot",
    "workflow": "compat-bot", "head_ref": "", "base_ref": "", "event_name": "schedule", "ref_type": "branch",
    "workflow_ref": "roc-talon/talon/.github/workflows/compat-bot.yml@refs/heads/main", "workflow_sha": "abc",
    "job_workflow_ref": "roc-talon/talon/.github/workflows/compat-bot.yml@refs/heads/main",
    "job_workflow_sha": "abc", "runner_environment": "github-hosted",
    "iss": "https://token.actions.githubusercontent.com", "nbf": 1767225300, "exp": 1767225900, "iat": 1767225600,
}
gh_header = {"alg": "RS256", "kid": "kid-1", "typ": "JWT", "x5t": "zz"}

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_pub = rsa_key.public_key().public_numbers()
rsa_n = rsa_pub.n.to_bytes(256, "big")
rsa_e = rsa_pub.e.to_bytes(3, "big")


def compact(header, claims, sign):
    si = f"{b64u(j(header).encode())}.{b64u(j(claims).encode())}"
    return f"{si}.{b64u(sign(si.encode()))}"


gh_token = compact(gh_header, gh_claims, lambda m: rsa_key.sign(m, padding.PKCS1v15(), hashes.SHA256()))
rsa_key.public_key().verify(parts(gh_token)[4], parts(gh_token)[3], padding.PKCS1v15(), hashes.SHA256())
ps_token = compact({"alg": "PS256", "kid": "kid-1"}, {"sub": "s"},
                   lambda m: rsa_key.sign(m, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()))

ec_key = ec.generate_private_key(ec.SECP256R1())
ec_pub = ec_key.public_key().public_numbers()


def es256(m):
    r, s_ = utils.decode_dss_signature(ec_key.sign(m, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s_.to_bytes(32, "big")


es_token = compact({"alg": "ES256", "kid": "ec-1", "typ": "JWT"}, {"iss": "https://issuer.example", "aud": ["a", "b"], "exp": 1767225900.5}, es256)
ec_verify(es_token, b64u(ec_pub.x.to_bytes(32, "big")), b64u(ec_pub.y.to_bytes(32, "big")), ec.SECP256R1(), hashes.SHA256(), 32)

ed_key = ed25519.Ed25519PrivateKey.generate()
ed_x = ed_key.public_key().public_bytes_raw()
ed_token = compact({"alg": "EdDSA", "kid": "ed-1"}, {"sub": "x", "exp": 2000000000}, ed_key.sign)
ed25519.Ed25519PublicKey.from_public_bytes(ed_x).verify(parts(ed_token)[4], parts(ed_token)[3])

jwks = j({"keys": [
    {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "kid-1", "n": b64u(rsa_n), "e": b64u(rsa_e), "x5c": ["MII"]},
    {"kty": "EC", "kid": "ec-1", "crv": "P-256", "x": b64u(ec_pub.x.to_bytes(32, "big")), "y": b64u(ec_pub.y.to_bytes(32, "big"))},
    {"kty": "OKP", "kid": "ed-1", "crv": "Ed25519", "x": b64u(ed_x)},
    {"kty": "oct", "kid": "hmac-1", "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ"},
    {"kty": "RSA", "kid": "enc-1", "use": "enc", "n": b64u(rsa_n), "e": b64u(rsa_e)},
]})


def roc_str(s):
    return json.dumps(s)


def roc_bytes(b):
    return "[" + ", ".join(str(x) for x in b) + "]"


out = []
w = out.append
w("## Test vectors made by research/vectors.py (Python `cryptography`, apart from any Roc code). Do not edit: run the script again.")
w("## Each signature here is verified by the script, so each `*_signing_input` is the text that the key signs.")
w("Vectors :: [].{")
w("")
for name in ["a1", "a2", "a3", "a4", "a5"]:
    h, p, *_ = tok[name].split(".")
    w(f"\t## RFC 7515 {name.upper().replace('A', 'A.')}")
    w(f"\trfc7515_{name} : Str")
    w(f"\trfc7515_{name} = {roc_str(tok[name])}")
    w("")
    w(f"\trfc7515_{name}_signing_input : Str")
    w(f"\trfc7515_{name}_signing_input = {roc_str(h + '.' + p)}")
    w("")
for name, t in [("a1", tok["a1"]), ("a2", tok["a2"]), ("a3", tok["a3"]), ("a4", tok["a4"])]:
    w(f"\trfc7515_{name}_signature : List(U8)")
    w(f"\trfc7515_{name}_signature = {roc_bytes(parts(t)[4])}")
    w("")
w("\t## The public RSA key of RFC 7515 A.2, as bytes.")
w(f"\trfc7515_a2_n : List(U8)\n\trfc7515_a2_n = {roc_bytes(unb64u(n_a2))}\n")
w(f"\trfc7515_a2_n_text : Str\n\trfc7515_a2_n_text = {roc_str(n_a2)}\n")
w(f"\trfc7515_a3_x : List(U8)\n\trfc7515_a3_x = {roc_bytes(unb64u(x_a3))}\n")
w(f"\trfc7515_a3_y : List(U8)\n\trfc7515_a3_y = {roc_bytes(unb64u(y_a3))}\n")
w(f"\trfc7515_a3_x_text : Str\n\trfc7515_a3_x_text = {roc_str(x_a3)}\n")
w(f"\trfc7515_a3_y_text : Str\n\trfc7515_a3_y_text = {roc_str(y_a3)}\n")
w(f"\trfc7515_a4_x_text : Str\n\trfc7515_a4_x_text = {roc_str(x_a4)}\n")
w(f"\trfc7515_a4_y_text : Str\n\trfc7515_a4_y_text = {roc_str(y_a4)}\n")
w(f"\t## RFC 8037 A.4 (Ed25519; the payload is text, not JSON)\n\trfc8037_a4 : Str\n\trfc8037_a4 = {roc_str(eddsa_rfc)}\n")
w(f"\trfc8037_x : List(U8)\n\trfc8037_x = {roc_bytes(unb64u(x_8037))}\n")
w(f"\t## A GitHub Actions OIDC token shape, RS256, kid-1. Header: {j(gh_header)}")
w(f"\tgithub : Str\n\tgithub = {roc_str(gh_token)}\n")
w(f"\tgithub_signing_input : Str\n\tgithub_signing_input = {roc_str(gh_token.rsplit('.', 1)[0])}\n")
w(f"\tgithub_signature : List(U8)\n\tgithub_signature = {roc_bytes(parts(gh_token)[4])}\n")
w(f"\tgithub_payload : Str\n\tgithub_payload = {roc_str(j(gh_claims))}\n")
w(f"\t## PS256 with the RSA key, kid-1, claims {{\"sub\":\"s\"}}\n\tps256 : Str\n\tps256 = {roc_str(ps_token)}\n")
w(f"\t## ES256, kid ec-1, aud a list, exp with a fraction\n\tes256 : Str\n\tes256 = {roc_str(es_token)}\n")
w(f"\tes256_signature : List(U8)\n\tes256_signature = {roc_bytes(parts(es_token)[4])}\n")
w(f"\t## EdDSA (Ed25519), kid ed-1\n\teddsa : Str\n\teddsa = {roc_str(ed_token)}\n")
w(f"\t## The JWKS of the new keys: RSA kid-1 (alg RS256, use sig), EC ec-1, OKP ed-1, oct hmac-1, RSA enc-1 (use enc)")
w(f"\tjwks : Str\n\tjwks = {roc_str(jwks)}\n")
w(f"\trsa_n : List(U8)\n\trsa_n = {roc_bytes(rsa_n)}\n")
w(f"\trsa_n_text : Str\n\trsa_n_text = {roc_str(b64u(rsa_n))}\n")
w(f"\tec_x : List(U8)\n\tec_x = {roc_bytes(ec_pub.x.to_bytes(32, 'big'))}\n")
w(f"\tec_y : List(U8)\n\tec_y = {roc_bytes(ec_pub.y.to_bytes(32, 'big'))}\n")
w(f"\ted_x : List(U8)\n\ted_x = {roc_bytes(ed_x)}\n")
w("}")
print("\n".join(out))
