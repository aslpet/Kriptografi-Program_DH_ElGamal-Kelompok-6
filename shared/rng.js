// Pembangkit Bilangan Acak Seragam (RNG) Tanpa Bias Modulo
import { sha256 } from './sha256.js';
import { bytesToBig, concatBytes, utf8ToBytes } from './encoding.js';

let rngMode = 'os'; // 'os' atau 'custom_drbg'

// State internal untuk SHA-256 CTR-DRBG buatan sendiri (cadangan jika dilarang memakai getRandomValues)
let drbgSeed = sha256(utf8ToBytes(`seed-${Date.now()}-${performance.now()}`));
let drbgCounter = 0n;

export function setRngMode(mode) {
  if (mode !== 'os' && mode !== 'custom_drbg') {
    throw new Error(`Mode RNG tidak valid: ${mode}. Gunakan 'os' atau 'custom_drbg'`);
  }
  rngMode = mode;
}

export function getRngMode() {
  return rngMode;
}

export function randomBytes(length) {
  if (typeof length !== 'number' || length <= 0) {
    throw new TypeError('Panjang randomBytes harus integer positif');
  }

  if (rngMode === 'os') {
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  }

  // Pure custom DRBG berbasis SHA-256 (CTR mode)
  const result = new Uint8Array(length);
  let generated = 0;
  while (generated < length) {
    drbgCounter++;
    const counterBytes = utf8ToBytes(drbgCounter.toString(16));
    const block = sha256(concatBytes(drbgSeed, counterBytes));
    const toCopy = Math.min(block.length, length - generated);
    result.set(block.subarray(0, toCopy), generated);
    generated += toCopy;
    if (drbgCounter % 1000n === 0n) {
      drbgSeed = sha256(concatBytes(drbgSeed, block));
    }
  }
  return result;
}

function countBits(n) {
  if (n === 0n) return 1;
  return n.toString(2).length;
}

// Rejection sampling untuk menjamin distribusi acak seragam sempurna pada rentang [0, n)
export function randomBelow(n) {
  if (typeof n !== 'bigint') throw new TypeError('Input randomBelow harus BigInt');
  if (n <= 0n) throw new RangeError('Batas n pada randomBelow harus positif (> 0)');
  if (n === 1n) return 0n;

  const bits = countBits(n - 1n);
  const numBytes = Math.ceil(bits / 8);
  const excessBits = numBytes * 8 - bits;
  const mask = 0xff >>> excessBits;

  // Loop rejection sampling
  while (true) {
    const raw = randomBytes(numBytes);
    // Masking byte tertinggi agar tidak melebihi panjang bit yang dibutuhkan
    raw[0] &= mask;
    const val = bytesToBig(raw);
    if (val < n) {
      return val;
    }
  }
}

// Menghasilkan bilangan acak seragam pada rentang tertutup [lo, hi]
export function randomRange(lo, hi) {
  if (typeof lo !== 'bigint' || typeof hi !== 'bigint') {
    throw new TypeError('lo dan hi pada randomRange harus BigInt');
  }
  if (lo > hi) {
    throw new RangeError(`Batas bawah lo (${lo}) tidak boleh lebih besar dari hi (${hi})`);
  }
  const range = hi - lo + 1n;
  return lo + randomBelow(range);
}
