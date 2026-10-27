// Implementasi Protokol Diffie-Hellman di Subgrup Orde q
import { modExp, isInSubgroup } from './math_utils.js';
import { randomRange } from './rng.js';

// Membangkitkan pasangan kunci DH (privat dan publik)
// Rumus: a in [2, q-1], A = g^a mod p
export function dhGenerateKeyPair(params, fixedPriv = null) {
  const { p, q, g } = params;
  if (!p || !q || !g) throw new Error('Parameter grup p, q, g diperlukan');

  const priv = fixedPriv !== null ? fixedPriv : randomRange(2n, q - 1n);
  if (priv < 2n || priv > q - 1n) {
    throw new RangeError(`Kunci privat DH harus berada di rentang [2, q-1]`);
  }

  // A = g^a mod p
  const pub = modExp(g, priv, p);

  return {
    priv,
    pub,
    formula: 'A = g^a mod p'
  };
}

// Menghitung shared secret K dari kunci publik pihak lain
// Rumus: K = B^a mod p (voter) atau K = A^b mod p (server)
export function dhComputeShared(params, priv, otherPub) {
  const { p, q } = params;
  if (!isInSubgroup(otherPub, p, q)) {
    throw new Error('Nilai publik DH tidak valid (bukan anggota subgrup orde q)');
  }
  return modExp(otherPub, priv, p);
}

// Versi dengan metadata untuk logging dan edukasi
export function dhComputeSharedWithDetails(params, priv, otherPub) {
  const { p, q } = params;
  const valid = isInSubgroup(otherPub, p, q);
  if (!valid) {
    throw new Error('Nilai publik DH tidak valid (bukan anggota subgrup orde q)');
  }
  const K = modExp(otherPub, priv, p);
  return {
    K,
    validSubgroup: true,
    formula: 'K = otherPub^priv mod p'
  };
}
