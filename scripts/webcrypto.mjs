// K5: the public JWK text of Jwk.to_public_json imports into a real WebCrypto
// (Node webcrypto), and the key verifies the signature of the token over its
// signing_input. Input on stdin: the lines of `roc tests/webcrypto.roc`
// (`alg TAB jwk TAB signing_input TAB signature bytes`). Exit 0 only when each
// line imports and verifies.
import { webcrypto } from 'node:crypto';

const { subtle } = webcrypto;
const PARAMS = {
  RS256: { imp: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, ver: { name: 'RSASSA-PKCS1-v1_5' } },
  PS256: { imp: { name: 'RSA-PSS', hash: 'SHA-256' }, ver: { name: 'RSA-PSS', saltLength: 32 } },
  ES256: { imp: { name: 'ECDSA', namedCurve: 'P-256' }, ver: { name: 'ECDSA', hash: 'SHA-256' } },
  EdDSA: { imp: { name: 'Ed25519' }, ver: { name: 'Ed25519' } },
};

let text = '';
for await (const chunk of process.stdin) text += chunk;
const lines = text.split('\n').filter((l) => l.trim() !== '');
let failed = 0;
for (const line of lines) {
  const [alg, jwk, input, sig] = line.split('\t');
  let result;
  try {
    if (sig === undefined) throw new Error(`no key or no decode: ${jwk}`);
    const p = PARAMS[alg];
    const key = await subtle.importKey('jwk', JSON.parse(jwk), p.imp, false, ['verify']);
    const ok = await subtle.verify(p.ver, key, Uint8Array.from(sig.split(',').map(Number)), new TextEncoder().encode(input));
    result = ok ? 'import ok, verify ok' : 'import ok, verify FALSE';
    if (!ok) failed++;
  } catch (e) {
    result = `FAILED: ${e.message}`;
    failed++;
  }
  console.log(`${alg}: ${result}`);
}
if (lines.length !== 4) { console.log(`expected 4 lines, got ${lines.length}`); failed++; }
process.exit(failed === 0 ? 0 : 1);
