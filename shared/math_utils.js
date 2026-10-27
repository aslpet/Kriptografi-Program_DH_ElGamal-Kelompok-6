// Pustaka Aritmetika Modular dan Teori Bilangan Murni
// Semua algoritma ditulis sendiri tanpa library eksternal.
import { randomRange } from './rng.js';

// Square-and-multiply: menghitung (base^exp) mod mod dalam O(log exp)
// Rumus: jika bit_i = 1 -> result = (result * base) mod m; base = (base^2) mod m
export function modExp(base, exp, mod) {
  if (typeof base !== 'bigint' || typeof exp !== 'bigint' || typeof mod !== 'bigint') {
    throw new TypeError('Semua parameter modExp harus bertipe BigInt');
  }
  if (mod <= 0n) throw new RangeError('Modulus harus positif (> 0)');
  if (exp < 0n) throw new RangeError('Eksponen negatif tidak didukung langsung di modExp');
  if (mod === 1n) return 0n;

  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;

  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % mod;
    }
    e >>= 1n;
    b = (b * b) % mod;
  }

  return result;
}

// Versi modExp yang mengumpulkan riwayat langkah komputasi untuk visualisasi edukasi di Lab
export function modExpWithSteps(base, exp, mod) {
  if (typeof base !== 'bigint' || typeof exp !== 'bigint' || typeof mod !== 'bigint') {
    throw new TypeError('Semua parameter modExpWithSteps harus bertipe BigInt');
  }
  if (mod <= 0n) throw new RangeError('Modulus harus positif (> 0)');
  if (exp < 0n) throw new RangeError('Eksponen negatif tidak didukung langsung');
  if (mod === 1n) return { result: 0n, steps: [] };

  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  const steps = [];
  let bitIndex = 0;

  while (e > 0n) {
    const bit = Number(e & 1n);
    const prevResult = result;
    const baseBefore = b;

    if (bit === 1) {
      result = (result * b) % mod;
    }

    steps.push({
      bitIndex,
      bit,
      baseBefore,
      prevResult,
      resultAfter: result,
      nextBase: (b * b) % mod
    });

    e >>= 1n;
    b = (b * b) % mod;
    bitIndex++;
  }

  return { result, steps };
}

// Extended Euclidean Algorithm (Iteratif): gcd(a, b) = a*x + b*y
export function egcd(a, b) {
  if (typeof a !== 'bigint' || typeof b !== 'bigint') {
    throw new TypeError('Parameter egcd harus bertipe BigInt');
  }
  let old_r = a, r = b;
  let old_x = 1n, x = 0n;
  let old_y = 0n, y = 1n;

  while (r !== 0n) {
    const q = old_r / r;
    const tempR = r;
    r = old_r - q * r;
    old_r = tempR;

    const tempX = x;
    x = old_x - q * x;
    old_x = tempX;

    const tempY = y;
    y = old_y - q * y;
    old_y = tempY;
  }

  return { g: old_r, x: old_x, y: old_y };
}

// Invers modular: a * x === 1 (mod m)
export function modInv(a, m) {
  if (typeof a !== 'bigint' || typeof m !== 'bigint') {
    throw new TypeError('Parameter modInv harus bertipe BigInt');
  }
  if (m <= 0n) throw new RangeError('Modulus harus positif (> 0)');
  const normA = ((a % m) + m) % m;
  const { g, x } = egcd(normA, m);
  if (g !== 1n) {
    throw new Error(`Invers modular tidak ada karena gcd(${a}, ${m}) = ${g}`);
  }
  return ((x % m) + m) % m;
}

export function bitLength(n) {
  if (typeof n !== 'bigint') throw new TypeError('Input bitLength harus BigInt');
  if (n === 0n) return 1;
  const abs = n < 0n ? -n : n;
  return abs.toString(2).length;
}

// Saringan Eratosthenes untuk mengeliminasi komposit kecil secara cepat
let cachedSmallPrimes = null;
export function smallPrimeSieve(limit = 2000) {
  if (cachedSmallPrimes && limit <= 2000) return cachedSmallPrimes;
  const isPrime = new Uint8Array(limit + 1).fill(1);
  isPrime[0] = 0;
  isPrime[1] = 0;
  for (let p = 2; p * p <= limit; p++) {
    if (isPrime[p]) {
      for (let i = p * p; i <= limit; i += p) {
        isPrime[i] = 0;
      }
    }
  }
  const primes = [];
  for (let i = 2; i <= limit; i++) {
    if (isPrime[i]) primes.push(BigInt(i));
  }
  if (limit <= 2000) cachedSmallPrimes = primes;
  return primes;
}

// Pengujian primalitas Miller-Rabin (Rounds = 40 memberikan probabilitas kesalahan < 2^-80)
export function isProbablePrime(n, rounds = 40) {
  if (typeof n !== 'bigint') throw new TypeError('Input isProbablePrime harus BigInt');
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if ((n & 1n) === 0n) return false;

  const smallPrimes = smallPrimeSieve(2000);
  for (let i = 0; i < smallPrimes.length; i++) {
    const sp = smallPrimes[i];
    if (n === sp) return true;
    if (n % sp === 0n) return false;
  }

  // Faktorisasi n - 1 = 2^s * d dengan d ganjil
  let d = n - 1n;
  let s = 0n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s++;
  }

  // Pengujian dengan basis acak a in [2, n - 2]
  for (let i = 0; i < rounds; i++) {
    const a = randomRange(2n, n - 2n);
    let x = modExp(a, d, n);

    if (x === 1n || x === n - 1n) continue;

    let composite = true;
    for (let r = 1n; r < s; r++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }

    if (composite) return false;
  }

  return true;
}

// Pembangkitan bilangan prima acak dengan ukuran bit tertentu
export function genPrime(bits) {
  if (bits < 2) throw new RangeError('Ukuran bit prima minimal 2');
  if (bits === 2) return randomRange(0n, 1n) === 0n ? 2n : 3n;

  while (true) {
    // Bangkitkan bilangan ganjil dengan MSB bernilai 1
    const min = (1n << BigInt(bits - 1)) | 1n;
    const max = (1n << BigInt(bits)) - 1n;
    let candidate = randomRange(min, max);
    if ((candidate & 1n) === 0n) candidate |= 1n;

    if (isProbablePrime(candidate, 30)) {
      return candidate;
    }
  }
}

// Pembangkitan safe prime: p = 2q + 1 di mana q dan p keduanya prima
export function genSafePrime(bits, onProgress = null) {
  if (bits < 4) throw new RangeError('Safe prime membutuhkan minimal 4 bit');
  const smallPrimes = smallPrimeSieve(1000);
  let attempts = 0;

  const qMin = (1n << BigInt(bits - 2)) | 1n;
  const qMax = (1n << BigInt(bits - 1)) - 1n;

  while (true) {
    attempts++;
    if (onProgress && attempts % 50 === 0) {
      onProgress(attempts);
    }

    // Bangkitkan q ganjil
    let q = randomRange(qMin, qMax);
    if ((q & 1n) === 0n) q |= 1n;

    // Saringan cepat: cek apakah q atau 2q + 1 habis dibagi prima kecil
    let divisible = false;
    for (let i = 1; i < smallPrimes.length; i++) {
      const sp = smallPrimes[i];
      const qMod = q % sp;
      if (qMod === 0n) {
        divisible = true;
        break;
      }
      // 2q + 1 mod sp == (2 * qMod + 1) mod sp
      if ((2n * qMod + 1n) % sp === 0n) {
        divisible = true;
        break;
      }
    }
    if (divisible) continue;

    // Uji primalitas q
    if (!isProbablePrime(q, 25)) continue;

    // Hitung p = 2q + 1 dan uji primalitas p
    const p = 2n * q + 1n;
    if (isProbablePrime(p, 35)) {
      return { p, q, attempts };
    }
  }
}

// Mencari generator g untuk subgrup orde q dalam Z_p* (p = 2q + 1)
// Ambil h in [2, p - 2], g = h^2 mod p. Jika g != 1, maka orde g pasti q.
export function findGenerator(p, q) {
  if (p !== 2n * q + 1n) throw new Error('Parameter harus memenuhi p = 2q + 1');
  while (true) {
    const h = randomRange(2n, p - 2n);
    const g = modExp(h, 2n, p);
    if (g !== 1n && modExp(g, q, p) === 1n) {
      return g;
    }
  }
}

// Validasi keanggotaan subgrup orde q untuk kunci publik DH (A dan B):
// Mensyaratkan 1 < y < p - 1 dan y^q mod p == 1
export function isInSubgroup(y, p, q) {
  if (typeof y !== 'bigint' || typeof p !== 'bigint' || typeof q !== 'bigint') return false;
  if (y <= 1n || y >= p - 1n) return false;
  return modExp(y, q, p) === 1n;
}

// Validasi elemen subgrup untuk pesan ElGamal (mengizinkan y == 1n karena g^0 = 1)
export function isValidSubgroupElement(y, p, q) {
  if (typeof y !== 'bigint' || typeof p !== 'bigint' || typeof q !== 'bigint') return false;
  if (y < 1n || y >= p) return false;
  return modExp(y, q, p) === 1n;
}

// RFC 3526 Group 14 (2048-bit MODP Safe Prime Group)
// Dipakai untuk mode skala realistis instan dengan validasi mandiri
export const RFC3526_GROUP14_HEX = 
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AACAA68FFFFFFFFFFFFFFFF';

export function getRfc3526Group14() {
  const p = BigInt('0x' + RFC3526_GROUP14_HEX);
  const q = (p - 1n) / 2n;
  const g = 2n;
  return { p, q, g, bits: 2048 };
}
