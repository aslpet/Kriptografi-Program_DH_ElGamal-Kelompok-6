// Implementasi Pengamanan Saluran: Derivasi Kunci, Keystream XOR, dan Encrypt-then-MAC
import { sha256 } from './sha256.js';
import { hmacSha256, constantTimeEqual } from './hmac.js';
import { bigToBytes, toHex, utf8ToBytes, bytesToUtf8, hexToBytes, bytesToHex, concatBytes } from './encoding.js';
import { bitLength } from './math_utils.js';

// Derivasi kunci enkripsi (encKey) dan integritas (macKey) dari shared secret K Diffie-Hellman
// Rumus: Kbytes = bigToBytes(K, byteLength(p)), transcript = SHA256(sessionId || A || B)
// encKey = SHA256("ENC" || Kbytes || transcript)
// macKey = SHA256("MAC" || Kbytes || transcript)
export function deriveKeys(params, K, sessionId, A, B) {
  if (typeof K !== 'bigint') throw new TypeError('K harus bertipe BigInt');
  const byteLen = Math.ceil(bitLength(params.p) / 8);
  const Kbytes = bigToBytes(K, byteLen);

  const transcriptStr = `${sessionId}|${toHex(A)}|${toHex(B)}`;
  const transcript = sha256(utf8ToBytes(transcriptStr));

  const encKey = sha256(concatBytes(utf8ToBytes('ENC'), Kbytes, transcript));
  const macKey = sha256(concatBytes(utf8ToBytes('MAC'), Kbytes, transcript));

  return { encKey, macKey, transcriptStr };
}

function seqToBytes8(seq) {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  const bigSeq = BigInt(seq);
  const high = Number((bigSeq >> 32n) & 0xffffffffn);
  const low = Number(bigSeq & 0xffffffffn);
  view.setUint32(0, high, false);
  view.setUint32(4, low, false);
  return bytes;
}

function counterToBytes4(i) {
  const bytes = new Uint8Array(4);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, i, false);
  return bytes;
}

// Membangkitkan aliran keystream XOR dari encKey
function generateKeystream(encKey, dir, seq, length) {
  const seqBytes = seqToBytes8(seq);
  const dirByte = new Uint8Array([dir]);
  const keystream = new Uint8Array(length);
  let generated = 0;
  let blockIndex = 0;

  while (generated < length) {
    const block = sha256(concatBytes(encKey, dirByte, seqBytes, counterToBytes4(blockIndex)));
    const toCopy = Math.min(block.length, length - generated);
    keystream.set(block.subarray(0, toCopy), generated);
    generated += toCopy;
    blockIndex++;
  }

  return keystream;
}

// Membungkus payload ke dalam paket aman (Counter-mode Keystream XOR + Encrypt-then-MAC)
export function seal(keys, dir, seq, payload) {
  if (!keys || !keys.encKey || !keys.macKey) {
    throw new Error('Kunci encKey dan macKey diperlukan untuk seal');
  }
  if (typeof dir !== 'number' || (dir !== 1 && dir !== 2)) {
    throw new RangeError('dir harus 1 (Voter ke Server) atau 2 (Server ke Voter)');
  }
  if (typeof seq !== 'number' || seq <= 0) {
    throw new RangeError('seq harus integer positif');
  }

  const plaintextStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const plaintextBytes = utf8ToBytes(plaintextStr);

  const keystream = generateKeystream(keys.encKey, dir, seq, plaintextBytes.length);
  const ctBytes = new Uint8Array(plaintextBytes.length);
  for (let i = 0; i < plaintextBytes.length; i++) {
    ctBytes[i] = plaintextBytes[i] ^ keystream[i];
  }

  const seqBytes = seqToBytes8(seq);
  const dirByte = new Uint8Array([dir]);
  const tagBytes = hmacSha256(keys.macKey, concatBytes(dirByte, seqBytes, ctBytes));

  return {
    seq,
    ct: bytesToHex(ctBytes),
    tag: bytesToHex(tagBytes)
  };
}

// Membuka dan memverifikasi paket aman (Verify-before-Decrypt)
export function open(keys, expectedDir, packet, lastSeq = 0) {
  if (!keys || !keys.encKey || !keys.macKey) {
    throw new Error('Kunci encKey dan macKey diperlukan untuk open');
  }
  if (!packet || typeof packet.seq !== 'number' || !packet.ct || !packet.tag) {
    throw new Error('Format paket aman tidak valid');
  }

  // 1. Anti-replay check
  if (packet.seq <= lastSeq) {
    const err = new Error(`Replay attack terdeteksi: sequence number (${packet.seq}) tidak lebih besar dari lastSeq (${lastSeq})`);
    err.status = 409;
    throw err;
  }

  const ctBytes = hexToBytes(packet.ct);
  const tagBytes = hexToBytes(packet.tag);

  // 2. Integritas tag HMAC (Constant-time comparison)
  const seqBytes = seqToBytes8(packet.seq);
  const dirByte = new Uint8Array([expectedDir]);
  const expectedTag = hmacSha256(keys.macKey, concatBytes(dirByte, seqBytes, ctBytes));

  if (!constantTimeEqual(tagBytes, expectedTag)) {
    const err = new Error('Integritas paket gagal: tag HMAC tidak cocok (pesan telah dimodifikasi atau arah dir salah)');
    err.status = 401;
    throw err;
  }

  // 3. Dekripsi paket setelah verifikasi berhasil
  const keystream = generateKeystream(keys.encKey, expectedDir, packet.seq, ctBytes.length);
  const plaintextBytes = new Uint8Array(ctBytes.length);
  for (let i = 0; i < ctBytes.length; i++) {
    plaintextBytes[i] = ctBytes[i] ^ keystream[i];
  }

  const plaintextStr = bytesToUtf8(plaintextBytes);
  try {
    return JSON.parse(plaintextStr);
  } catch {
    return plaintextStr;
  }
}
