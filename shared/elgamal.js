// Implementasi Exponential ElGamal, Agregasi Homomorfik, dan Tanda Tangan ElGamal
import { modExp, modInv, isValidSubgroupElement } from './math_utils.js';
import { randomRange } from './rng.js';
import { sha256 } from './sha256.js';
import { bytesToBig, utf8ToBytes } from './encoding.js';

// Pembangkitan kunci ElGamal (Election Authority)
// Rumus: x in [2, q-1] (rahasia), h = g^x mod p (publik)
export function elgamalKeygen(params, fixedX = null) {
  const { p, q, g } = params;
  if (!p || !q || !g) throw new Error('Parameter grup p, q, g diperlukan');

  const x = fixedX !== null ? fixedX : randomRange(2n, q - 1n);
  if (x < 2n || x > q - 1n) {
    throw new RangeError('Private key x ElGamal harus berada di [2, q-1]');
  }

  const h = modExp(g, x, p);
  return { x, h };
}

// Enkripsi pesan m in subgrup: c1 = g^k mod p, c2 = m * (h^k) mod p
export function elgamalEncrypt(params, h, m, fixedK = null) {
  const { p, q, g } = params;
  if (!isValidSubgroupElement(m, p, q)) {
    throw new Error('Pesan m harus berupa elemen subgrup orde q yang valid');
  }

  const k = fixedK !== null ? fixedK : randomRange(2n, q - 1n);
  if (k < 2n || k > q - 1n) {
    throw new RangeError('Nonce k harus berada di [2, q-1]');
  }

  // c1 = g^k mod p
  const c1 = modExp(g, k, p);
  // shared = h^k mod p
  const hk = modExp(h, k, p);
  // c2 = (m * h^k) mod p
  const c2 = (m * hk) % p;

  return { c1, c2, k };
}

// Dekripsi ciphertext (c1, c2): s = c1^x mod p, m = c2 * (s^-1) mod p
export function elgamalDecrypt(params, x, { c1, c2 }) {
  const { p } = params;
  // s = c1^x mod p
  const s = modExp(c1, x, p);
  // s^-1 mod p
  const sInv = modInv(s, p);
  // m = (c2 * sInv) mod p
  const m = (c2 * sInv) % p;
  return m;
}

// Perkalian homomorfik dua ciphertext: C1 = c1A * c1B mod p, C2 = c2A * c2B mod p
// Menghasilkan enkripsi dari (mA * mB) mod p.
// Pada varian eksponensial (m = g^v), menghasilkan g^(vA + vB).
export function elgamalMultiply(params, ctA, ctB) {
  const { p } = params;
  const c1 = (ctA.c1 * ctB.c1) % p;
  const c2 = (ctA.c2 * ctB.c2) % p;
  return { c1, c2 };
}

// Membuat representasi vektor pilihan suara (1 untuk pilihan terpilih, 0 untuk lainnya)
export function encodeVote(choiceIndex, numCandidates) {
  if (choiceIndex < 0 || choiceIndex >= numCandidates) {
    throw new RangeError(`Pilihan suara (${choiceIndex}) di luar rentang kandidat`);
  }
  const vector = Array.from({ length: numCandidates }, () => 0);
  vector[choiceIndex] = 1;
  return vector;
}

// Mengenkripsi seluruh ballot pemilih (vektor N ciphertext)
export function encryptBallot(params, h, choiceIndex, numCandidates, fixedNonces = null) {
  const { p, g } = params;
  const vector = encodeVote(choiceIndex, numCandidates);
  const cts = [];
  const nonces = [];
  const mValues = [];

  for (let i = 0; i < numCandidates; i++) {
    const v = BigInt(vector[i]);
    // m_i = g^v_i mod p (1 jika v_i = 0, g jika v_i = 1)
    const m = modExp(g, v, p);
    mValues.push(m);

    const k = fixedNonces && fixedNonces[i] !== undefined ? fixedNonces[i] : null;
    const enc = elgamalEncrypt(params, h, m, k);
    cts.push({ c1: enc.c1, c2: enc.c2 });
    nonces.push(enc.k);
  }

  return { cts, nonces, mValues, vector };
}

// Agregasi homomorfik seluruh ballot yang terkumpul
export function aggregateBallots(params, ballots, numCandidates) {
  if (ballots.length === 0) {
    throw new Error('Tidak ada ballot untuk diagregasikan');
  }

  const aggregates = [];
  for (let j = 0; j < numCandidates; j++) {
    let C1 = ballots[0].cts[j].c1;
    let C2 = ballots[0].cts[j].c2;

    for (let b = 1; b < ballots.length; b++) {
      const mult = elgamalMultiply(params, { c1: C1, c2: C2 }, ballots[b].cts[j]);
      C1 = mult.c1;
      C2 = mult.c2;
    }
    aggregates.push({ C1, C2 });
  }

  return aggregates;
}

// Pemulihan jumlah suara T dari g^T melalui discrete log rentang kecil [0, maxVotes]
export function recoverTally(params, gT, maxVotes) {
  const { p, g } = params;
  let current = 1n; // g^0 = 1
  for (let t = 0; t <= maxVotes; t++) {
    if (current === gT) {
      return { T: t, iterations: t + 1 };
    }
    current = (current * g) % p;
  }
  throw new Error(`Gagal memulihkan jumlah suara: g^T tidak ditemukan dalam rentang 0..${maxVotes}`);
}

// ========================================================
// [BONUS] Tanda Tangan Digital ElGamal di Subgrup Orde q
// ========================================================

export function elgamalSignKeygen(params, fixedXs = null) {
  const { p, q, g } = params;
  const xs = fixedXs !== null ? fixedXs : randomRange(2n, q - 1n);
  const ys = modExp(g, xs, p);
  return { xs, ys };
}

export function elgamalSign(params, xs, msgInput, fixedK = null) {
  const { p, q, g } = params;
  let msgBytes = msgInput;
  if (typeof msgBytes === 'string') msgBytes = utf8ToBytes(msgBytes);

  const hashBytes = sha256(msgBytes);
  let H = bytesToBig(hashBytes) % q;
  if (H === 0n) H = 1n;

  while (true) {
    const k = fixedK !== null ? fixedK : randomRange(2n, q - 1n);
    const r = modExp(g, k, p);
    const rModQ = r % q;
    if (rModQ === 0n) {
      if (fixedK !== null) throw new Error('fixedK menghasilkan r mod q == 0');
      continue;
    }

    const kInv = modInv(k, q);
    // s = k^-1 * (H - xs * rModQ) mod q
    let s = (kInv * (H - (xs * rModQ) % q)) % q;
    s = ((s % q) + q) % q;

    if (s !== 0n) {
      return { r, s };
    }
    if (fixedK !== null) throw new Error('fixedK menghasilkan s == 0');
  }
}

export function elgamalVerify(params, ys, msgInput, { r, s }) {
  const { p, q, g } = params;
  if (typeof r !== 'bigint' || typeof s !== 'bigint') return false;
  if (r <= 1n || r >= p || s < 1n || s >= q) return false;
  if (modExp(r, q, p) !== 1n) return false;

  let msgBytes = msgInput;
  if (typeof msgBytes === 'string') msgBytes = utf8ToBytes(msgBytes);

  const hashBytes = sha256(msgBytes);
  let H = bytesToBig(hashBytes) % q;
  if (H === 0n) H = 1n;

  // lhs = g^H mod p
  const lhs = modExp(g, H, p);
  // rhs = (ys^(r mod q) * r^s) mod p
  const rModQ = r % q;
  const ysR = modExp(ys, rModQ, p);
  const rS = modExp(r, s, p);
  const rhs = (ysR * rS) % p;

  return lhs === rhs;
}
