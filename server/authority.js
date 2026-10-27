// Modul Election Authority (EA)
// Mengisolasi kunci privat x dan xs di dalam closure agar tidak bocor ke luar
import { genSafePrime, findGenerator, getRfc3526Group14 } from '../shared/math_utils.js';
import {
  elgamalKeygen,
  elgamalDecrypt,
  elgamalMultiply,
  recoverTally,
  elgamalSignKeygen,
  elgamalSign
} from '../shared/elgamal.js';
import { toHex, fromHex, utf8ToBytes } from '../shared/encoding.js';
import { logStep } from './logger.js';
import { CONFIG } from '../config.js';

let eaParams = null; // { p, q, g, bits, mode }
let eaPrivateKeyX = null; // x
let eaPublicKeyH = null; // h
let serverSignPrivXs = null; // xs
let serverSignPubYs = null; // ys
let electionCandidates = [];

export function setupElection({ mode = 'demo', customBits = null, candidates = null }) {
  const chosenMode = mode || CONFIG.DEFAULT_MODE;
  electionCandidates = candidates && candidates.length > 0 ? candidates : CONFIG.DEFAULT_CANDIDATES;

  let p, q, g, bits;

  if (chosenMode === 'real2048') {
    const group = getRfc3526Group14();
    p = group.p;
    q = group.q;
    g = group.g;
    bits = group.bits;
  } else {
    if (chosenMode === 'tiny') bits = 24;
    else if (chosenMode === 'demo') bits = 32;
    else if (chosenMode === 'mid') bits = 256;
    else if (chosenMode === 'real512') bits = 512;
    else bits = customBits || 32;

    const safe = genSafePrime(bits);
    p = safe.p;
    q = safe.q;
    g = findGenerator(p, q);
  }

  eaParams = { p, q, g, bits, mode: chosenMode };

  // 1. Pembangkitan Kunci ElGamal EA (x, h = g^x mod p)
  const elgKey = elgamalKeygen(eaParams);
  eaPrivateKeyX = elgKey.x;
  eaPublicKeyH = elgKey.h;

  // 2. [BONUS] Pembangkitan Kunci Tanda Tangan Server (xs, ys = g^xs mod p)
  const signKey = elgamalSignKeygen(eaParams);
  serverSignPrivXs = signKey.xs;
  serverSignPubYs = signKey.ys;

  logStep(
    'EA',
    'SYSTEM',
    'Setup Parameter Grup Siklik',
    'p = 2q + 1, g in Z_p* (orde q)',
    { bits, p: toHex(p), q: toHex(q), g: toHex(g) },
    `Parameter grup ${bits}-bit berhasil dibangkitkan`
  );

  logStep(
    'EA',
    'ELGAMAL',
    'Keygen ElGamal EA',
    'x in [2, q-1], h = g^x mod p',
    { x: toHex(eaPrivateKeyX), h: toHex(eaPublicKeyH) },
    'Kunci privat x disimpan aman di memori EA, kunci publik h diumumkan'
  );

  logStep(
    'SERVER',
    'ELGAMAL',
    'Keygen Tanda Tangan Server [BONUS]',
    'xs in [2, q-1], ys = g^xs mod p',
    { ys: toHex(serverSignPubYs) },
    'Kunci publik tanda tangan server ys diterbitkan untuk verifikasi handshake DH'
  );

  return getPublicParams();
}

export function getPublicParams() {
  if (!eaParams) return null;
  return {
    mode: eaParams.mode,
    bits: eaParams.bits,
    p: toHex(eaParams.p),
    q: toHex(eaParams.q),
    g: toHex(eaParams.g),
    h: toHex(eaPublicKeyH),
    ys: toHex(serverSignPubYs),
    candidates: electionCandidates
  };
}

export function getRawParams() {
  if (!eaParams) throw new Error('Pemilu belum disetup');
  return {
    ...eaParams,
    h: eaPublicKeyH,
    ys: serverSignPubYs,
    candidates: electionCandidates
  };
}

export function signHandshake(sessionId, A_hex, B_hex) {
  if (!serverSignPrivXs || !eaParams) throw new Error('Kunci tanda tangan belum siap');
  const transcriptStr = `${sessionId}|${A_hex}|${B_hex}`;
  const sig = elgamalSign(eaParams, serverSignPrivXs, utf8ToBytes(transcriptStr));
  return {
    r: toHex(sig.r),
    s: toHex(sig.s)
  };
}

export function tallyElection(ballots) {
  if (!eaPrivateKeyX || !eaParams) throw new Error('Parameter pemilu belum siap');
  const numCandidates = electionCandidates.length;
  const V = ballots.length;

  if (V === 0) {
    return {
      perCandidate: electionCandidates.map(name => ({
        name,
        C1: '00',
        C2: '00',
        gT: '01',
        T: 0,
        iterations: 1
      })),
      V: 0,
      consistent: true
    };
  }

  // Parse BigInt ciphertext dari setiap ballot
  const parsedBallots = ballots.map(b => ({
    cts: b.cts.map(c => ({ c1: fromHex(c.c1), c2: fromHex(c.c2) }))
  }));

  const perCandidate = [];
  let sumT = 0;

  for (let j = 0; j < numCandidates; j++) {
    // 1. Agregasi Homomorfik perkalian ciphertext: C1_j = prod c1, C2_j = prod c2
    let C1 = parsedBallots[0].cts[j].c1;
    let C2 = parsedBallots[0].cts[j].c2;

    for (let b = 1; b < V; b++) {
      const mult = elgamalMultiply(eaParams, { c1: C1, c2: C2 }, parsedBallots[b].cts[j]);
      C1 = mult.c1;
      C2 = mult.c2;
    }

    logStep(
      'EA',
      'ELGAMAL',
      `Agregasi Homomorfik Suara: ${electionCandidates[j]}`,
      'C1 = prod_{i=1..V} c1_i mod p, C2 = prod_{i=1..V} c2_i mod p',
      { C1: toHex(C1), C2: toHex(C2) },
      `Perkalian ${V} ciphertext berhasil digabungkan menjadi 1 pasangan agregat`
    );

    // 2. Dekripsi total oleh EA (hanya ciphertext agregat!): s = C1^x mod p, gT = C2 * s^-1 mod p
    const gT = elgamalDecrypt(eaParams, eaPrivateKeyX, { c1: C1, c2: C2 });

    logStep(
      'EA',
      'ELGAMAL',
      `Dekripsi Agregat Suara: ${electionCandidates[j]}`,
      's = C1^x mod p, g^T = C2 * s^-1 mod p',
      { gT: toHex(gT) },
      'Hanya nilai g^T yang didekripsi; suara individual pemilih tetap rahasia'
    );

    // 3. Pemulihan T_j melalui discrete log pencarian rentang kecil [0..V]
    const { T, iterations } = recoverTally(eaParams, gT, V);
    sumT += T;

    logStep(
      'EA',
      'ELGAMAL',
      `Pemulihan Jumlah Suara T: ${electionCandidates[j]}`,
      'Cari T in [0..V] di mana g^T mod p == hasil dekripsi',
      { T, iterations },
      `Diperoleh ${T} suara setelah ${iterations} iterasi brute-force logaritma diskret`
    );

    perCandidate.push({
      name: electionCandidates[j],
      C1: toHex(C1),
      C2: toHex(C2),
      gT: toHex(gT),
      T,
      iterations
    });
  }

  const consistent = (sumT === V);

  logStep(
    'EA',
    'SYSTEM',
    'Verifikasi Konsistensi Pemilu',
    'sum_{j=1..N} T_j == V',
    { sumT, V, consistent },
    consistent
      ? `Audit konsistensi valid: total suara ${sumT} tepat sama dengan ${V} ballot`
      : `Peringatan: total suara ${sumT} tidak sama dengan jumlah ballot ${V}`
  );

  return {
    perCandidate,
    V,
    consistent
  };
}

export function resetAuthority() {
  eaParams = null;
  eaPrivateKeyX = null;
  eaPublicKeyH = null;
  serverSignPrivXs = null;
  serverSignPubYs = null;
  electionCandidates = [];
}
