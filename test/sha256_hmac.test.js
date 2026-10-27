import test from 'node:test';
import assert from 'node:assert/strict';
import { sha256Hex } from '../shared/sha256.js';
import { hmacSha256, constantTimeEqual } from '../shared/hmac.js';
import { bytesToHex, utf8ToBytes } from '../shared/encoding.js';

test('SHA-256: NIST Standard Test Vectors', () => {
  // Empty string
  assert.equal(
    sha256Hex(''),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );

  // 'abc'
  assert.equal(
    sha256Hex('abc'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );

  // 448-bit / multi-block vector
  assert.equal(
    sha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
  );
});

test('HMAC-SHA256: RFC 4231 Standard Test Vectors', () => {
  // Test Case 1: Key = 20x 0x0b, Data = "Hi There"
  const key1 = new Uint8Array(20).fill(0x0b);
  const data1 = utf8ToBytes('Hi There');
  const mac1 = bytesToHex(hmacSha256(key1, data1));
  assert.equal(mac1, 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');

  // Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
  const key2 = utf8ToBytes('Jefe');
  const data2 = utf8ToBytes('what do ya want for nothing?');
  const mac2 = bytesToHex(hmacSha256(key2, data2));
  assert.equal(mac2, '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
});

test('constantTimeEqual: perbandingan byte aman', () => {
  const a = new Uint8Array([1, 2, 3, 4]);
  const b = new Uint8Array([1, 2, 3, 4]);
  const c = new Uint8Array([1, 2, 3, 5]);
  const d = new Uint8Array([1, 2, 3]);

  assert.ok(constantTimeEqual(a, b));
  assert.ok(!constantTimeEqual(a, c));
  assert.ok(!constantTimeEqual(a, d));
});
