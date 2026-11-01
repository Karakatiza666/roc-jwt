#!/usr/bin/env python3
# Mutation check of the L0 tests: each mutant changes one tricky rule of a
# package module, runs `roc test` on each tests/*.roc, records which files
# have a failed expect (a run of more than 120 s counts as a fail), and
# restores the file.
# A mutant that no test kills (or that only gives compile errors) exits 1.
# Usage: python3 -I scripts/mutants.py ROC [ID...]
import pathlib, re, signal, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent.parent
ROC = sys.argv[1]
ONLY = set(sys.argv[2:])

MUTANTS = [
    ("M1", "Jwt.roc", "alg none: no special refusal (it is only not in the allowlist)",
     'if alg_text == "none" {', 'if alg_text == "nonE" {'),
    ("M2", "Jwt.roc", "allowlist: each known alg is accepted",
     "Ok(known) if algs.contains(known) => known", "Ok(known) => known"),
    ("M3", "Jwt.roc", "exp leeway: the token is good at now - leeway == exp",
     "Ok(exp) if now - leeway >= exp =>", "Ok(exp) if now - leeway > exp =>"),
    ("M4", "Jwt.roc", "nbf leeway: the leeway is taken off, not added",
     "Ok(nbf) if now + leeway < nbf =>", "Ok(nbf) if now - leeway < nbf =>"),
    ("M5", "Jwt.roc", "aud list: each value of the token must be accepted",
     "if (values.any(|v| list.contains(v)))", "if (values.all(|v| list.contains(v)))"),
    ("M6", "Aud.roc", "aud list: only the first value is kept",
     "Ok({ value: Aud.Many($items), rest: $at })", "Ok({ value: Aud.Many($items.take_first(1)), rest: $at })"),
    ("M7", "B64u.roc", "base64url: padding and bits that are not 0 are accepted",
     "if Base64.encode_url(bytes) == text {", "if bytes.len() >= 0 {"),
    ("M8", "Jwt.roc", "signing input: the payload part is followed by a dot",
     'signing_input: "${header_part}.${payload_part}".to_utf8()', 'signing_input: "${header_part}.${payload_part}.".to_utf8()'),
    ("M9", "Jwk.roc", "select: a key of any type with the right kid",
     "fit = keys.keep_if(|key| fits(key, header.alg))", "fit = keys"),
    ("M10", "Jwt.roc", "crit: an extension is ignored",
     "Ok(names) => Err(CritUnsupported(names))", "Ok(_) => Ok({ alg, kid: raw.kid, typ: raw.typ, cty: raw.cty })"),
]

signal.signal(signal.SIGTERM, lambda *_: sys.exit(2))
tests = sorted((HERE / "tests").glob("*.roc"))
survived = []
print("| Id | Mutant | Files with a failed test |")
print("| --- | --- | --- |")
for mid, file, what, old, new in MUTANTS:
    if ONLY and mid not in ONLY:
        continue
    src = HERE / "package" / file
    orig = src.read_text()
    assert orig.count(old) == 1, f"{mid}: the text is not in {file} once"
    try:
        src.write_text(orig.replace(old, new))
        failed = []
        for t in tests:
            try:
                r = subprocess.run([ROC, "test", str(t), "--no-cache"], cwd=HERE, capture_output=True, text=True, timeout=120)
            except subprocess.TimeoutExpired:
                failed.append(f"{t.name} (timeout)")
                continue
            out = r.stdout + r.stderr
            # A warning (for example an unused value) also gives a nonzero
            # exit, so count only a failed expect or a compile error.
            if re.search(r"^\s*[1-9][0-9]* failed", out, re.M):
                failed.append(f"{t.name} (fail)")
            elif re.search(r"^\s*[1-9][0-9]* compiler error|Compilation failed|── ✗", out, re.M):
                failed.append(f"{t.name} (compile error)")
    finally:
        src.write_text(orig)
    if not failed or all("compile error" in f for f in failed):
        survived.append(mid)
    print(f"| {mid} | {what} | {', '.join(failed) if failed else 'NONE: survived'} |", flush=True)
print()
print("ALL KILLED" if not survived else f"SURVIVED: {' '.join(survived)}")
sys.exit(1 if survived else 0)
