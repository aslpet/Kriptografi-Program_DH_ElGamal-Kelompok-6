// Implementasi HMAC-SHA256 (RFC 2104) dan Constant-Time Comparison
import { sha256 } from './sha256.js';
import { utf8ToBytes, concatBytes } from './encoding.js';

export function hmacSha256(key, message) {
  let k = key;
  if (typeof k === 'string') k = utf8ToBytes(k);
  if (!(k instanceof Uint8Array)) throw new TypeError('Key hmacSha256 harus Uint8Array atau string');

  let m = message;
  if (typeof m === 'string') m = utf8ToBytes(m);
  if (!(m instanceof Uint8Array)) throw new TypeError('Message hmacSha256 harus Uint8Array atau string');

  const BLOCK_SIZE = 64;
  let keyBlock = new Uint8Array(BLOCK_SIZE);

  if (k.length > BLOCK_SIZE) {
    const hashedKey = sha256(k);
    keyBlock.set(hashedKey);
  } else {
    keyBlock.set(k);
  }

  const kIpad = new Uint8Array(BLOCK_SIZE);
  const kOpad = new Uint8Array(BLOCK_SIZE);

  for (let i = 0; i < BLOCK_SIZE; i++) {
    kIpad[i] = keyBlock[i] ^ 0x36;
    kOpad[i] = keyBlock[i] ^ 0x5c;
  }

  const innerHash = sha256(concatBytes(kIpad, m));
  const outerHash = sha256(concatBytes(kOpad, innerHash));
  return outerHash;
}

export function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    throw new TypeError('Argumen constantTimeEqual harus Uint8Array');
  }
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
