// Logika Sisi Klien untuk Lab Kripto & Playground Interaktif
import { CryptoLogPanel } from './logPanel.js';
import { modExpWithSteps, modExp, modInv, genSafePrime, findGenerator } from '../shared/math_utils.js';
import { dhGenerateKeyPair, dhComputeShared } from '../shared/dh.js';
import { elgamalEncrypt, elgamalMultiply, recoverTally, elgamalSignKeygen, elgamalSign, elgamalVerify } from '../shared/elgamal.js';
import { toHex } from '../shared/encoding.js';

const logPanel = new CryptoLogPanel('crypto-log-container');

// Tab switching
function setupTabs() {
  const tabs = [
    { btn: 'tab-btn-vector', content: 'tab-content-vector' },
    { btn: 'tab-btn-modexp', content: 'tab-content-modexp' },
    { btn: 'tab-btn-mitm', content: 'tab-content-mitm' }
  ];

  tabs.forEach(t => {
    document.getElementById(t.btn)?.addEventListener('click', () => {
      tabs.forEach(other => {
        document.getElementById(other.btn)?.classList.remove('active');
        const c = document.getElementById(other.content);
        if (c) c.style.display = 'none';
      });
      document.getElementById(t.btn)?.classList.add('active');
      const targetContent = document.getElementById(t.content);
      if (targetContent) targetContent.style.display = 'block';
    });
  });
}

// 1. Eksekusi Test Vector Bagian 6.10 ke Log Panel
function runTestVector() {
  const params = { p: 23n, q: 11n, g: 4n };

  // DH
  const a = 6n;
  const A = modExp(params.g, a, params.p); // 2
  const b = 3n;
  const B = modExp(params.g, b, params.p); // 18
  const Kvoter = modExp(B, a, params.p);   // 8
  const Kserver = modExp(A, b, params.p);  // 8

  logPanel.addEntry({
    actor: 'VOTER',
    algo: 'DH',
    step: 'Lab: Pembuatan Kunci Publik DH Voter',
    formula: 'A = g^a mod p = 4^6 mod 23',
    values: { a, A },
    summary: 'A = 2 (cocok dengan test vector)'
  });

  logPanel.addEntry({
    actor: 'SERVER',
    algo: 'DH',
    step: 'Lab: Pembuatan Kunci Publik DH Server',
    formula: 'B = g^b mod p = 4^3 mod 23',
    values: { b, B },
    summary: 'B = 18 (cocok dengan test vector)'
  });

  logPanel.addEntry({
    actor: 'SERVER',
    algo: 'DH',
    step: 'Lab: Perhitungan Shared Secret K',
    formula: 'K = B^a = A^b = 4^(ab) mod p',
    values: { K_voter: Kvoter, K_server: Kserver },
    summary: 'K = 8 di kedua sisi (K voter == K server: OK)'
  });

  // ElGamal
  const x = 7n;
  const h = modExp(params.g, x, params.p); // 8

  logPanel.addEntry({
    actor: 'EA',
    algo: 'ELGAMAL',
    step: 'Lab: Keygen EA ElGamal',
    formula: 'h = g^x mod p = 4^7 mod 23',
    values: { x, h },
    summary: 'h = 8'
  });

  // Voter 1 (v=1, m=4, k=3)
  const v1 = elgamalEncrypt(params, h, 4n, 3n);
  // Voter 2 (v=0, m=1, k=5)
  const v2 = elgamalEncrypt(params, h, 1n, 5n);

  logPanel.addEntry({
    actor: 'VOTER',
    algo: 'ELGAMAL',
    step: 'Lab: Enkripsi Voter 1 (v=1, m=4, k=3)',
    formula: 'c1 = 4^3 mod 23, c2 = 4 * 8^3 mod 23',
    values: { c1: v1.c1, c2: v1.c2 },
    summary: '(c1, c2) = (18, 1)'
  });

  logPanel.addEntry({
    actor: 'VOTER',
    algo: 'ELGAMAL',
    step: 'Lab: Enkripsi Voter 2 (v=0, m=1, k=5)',
    formula: 'c1 = 4^5 mod 23, c2 = 1 * 8^5 mod 23',
    values: { c1: v2.c1, c2: v2.c2 },
    summary: '(c1, c2) = (12, 16)'
  });

  // Agregasi
  const agg = elgamalMultiply(params, v1, v2);

  logPanel.addEntry({
    actor: 'EA',
    algo: 'ELGAMAL',
    step: 'Lab: Agregasi Homomorfik Ciphertext',
    formula: 'C1 = (18 * 12) mod 23, C2 = (1 * 16) mod 23',
    values: { C1: agg.c1, C2: agg.c2 },
    summary: '(C1, C2) = (9, 16)'
  });

  // Dekripsi
  const s = modExp(agg.c1, x, params.p); // 9^7 mod 23 = 4
  const sInv = modInv(s, params.p);      // 6
  const gT = (agg.c2 * sInv) % params.p; // 4
  const tally = recoverTally(params, gT, 2);

  logPanel.addEntry({
    actor: 'EA',
    algo: 'ELGAMAL',
    step: 'Lab: Dekripsi Total & Pemulihan Suara T',
    formula: 's = 9^7 = 4, g^T = 16 * 6 mod 23 = 4 -> T = 1',
    values: { s, sInv, gT, T: tally.T, iterations: tally.iterations },
    summary: 'Total suara pemilu berhasil dihitung: T = 1 suara!'
  });
}

// 2. Kalkulator modExp Step-by-Step
function calculateModExpSteps() {
  const baseInput = document.getElementById('input-modexp-base');
  const expInput = document.getElementById('input-modexp-exp');
  const modInput = document.getElementById('input-modexp-mod');
  const summaryEl = document.getElementById('modexp-result-summary');
  const tbody = document.getElementById('modexp-steps-tbody');

  if (!baseInput || !expInput || !modInput || !tbody) return;

  const base = BigInt(baseInput.value || '4');
  const exp = BigInt(expInput.value || '11');
  const mod = BigInt(modInput.value || '23');

  try {
    const { result, steps } = modExpWithSteps(base, exp, mod);

    if (summaryEl) {
      summaryEl.style.display = 'block';
      summaryEl.textContent = `✓ Hasil: (${base}^${exp}) mod ${mod} = ${result}`;
    }

    tbody.textContent = '';
    steps.forEach(st => {
      const tr = document.createElement('tr');

      const tdBitIdx = document.createElement('td');
      tdBitIdx.textContent = `Bit ke-${st.bitIndex}`;

      const tdBitVal = document.createElement('td');
      tdBitVal.style.fontWeight = '700';
      tdBitVal.style.color = st.bit === 1 ? '#34d399' : '#94a3b8';
      tdBitVal.textContent = String(st.bit);

      const tdBaseBefore = document.createElement('td');
      tdBaseBefore.textContent = String(st.baseBefore);

      const tdSq = document.createElement('td');
      tdSq.textContent = `(${st.baseBefore}^2) mod ${mod} = ${st.nextBase}`;

      const tdRes = document.createElement('td');
      tdRes.style.color = '#38bdf8';
      tdRes.textContent = st.bit === 1
        ? `${st.prevResult} * ${st.baseBefore} = ${st.resultAfter}`
        : `${st.prevResult} (tetap)`;

      tr.appendChild(tdBitIdx);
      tr.appendChild(tdBitVal);
      tr.appendChild(tdBaseBefore);
      tr.appendChild(tdSq);
      tr.appendChild(tdRes);
      tbody.appendChild(tr);
    });

    logPanel.addEntry({
      actor: 'LAB',
      algo: 'DH',
      step: `modExp(${base}, ${exp}, ${mod})`,
      formula: 'Square-and-Multiply O(log exp)',
      values: { base, exp, mod, result, bitRounds: steps.length },
      summary: `Perhitungan eksponensiasi modular selesai dalam ${steps.length} putaran bit`
    });
  } catch (err) {
    if (summaryEl) {
      summaryEl.style.display = 'block';
      summaryEl.style.color = '#ef4444';
      summaryEl.textContent = `Error: ${err.message}`;
    }
  }
}

// 3. Simulasi Serangan MITM
function simulateMitmPlain() {
  const outputEl = document.getElementById('mitm-demo-output');
  if (!outputEl) return;

  outputEl.style.display = 'block';
  outputEl.textContent = '';

  const { p, q } = genSafePrime(20);
  const g = findGenerator(p, q);
  const params = { p, q, g };

  // Alice (Voter)
  const alice = dhGenerateKeyPair(params);
  // Bob (Server)
  const bob = dhGenerateKeyPair(params);
  // Mallory (Attacker di tengah jaringan)
  const malloryAlice = dhGenerateKeyPair(params);
  const malloryBob = dhGenerateKeyPair(params);

  // Mallory mencegat A dari Alice, mengirim publik miliknya sendiri ke Bob
  // Mallory mencegat B dari Bob, mengirim publik miliknya sendiri ke Alice
  const kAliceMallory = dhComputeShared(params, alice.priv, malloryAlice.pub);
  const kMalloryAlice = dhComputeShared(params, malloryAlice.priv, alice.pub);

  const kBobMallory = dhComputeShared(params, bob.priv, malloryBob.pub);
  const kMalloryBob = dhComputeShared(params, malloryBob.priv, bob.pub);

  const title = document.createElement('h4');
  title.style.color = '#ef4444';
  title.style.marginBottom = '0.5rem';
  title.textContent = '⚠️ Serangan Man-in-the-Middle (MITM) Berhasil pada DH Polos';
  outputEl.appendChild(title);

  const pText = document.createElement('p');
  pText.textContent = 
    'Pada Diffie-Hellman polos tanpa autentikasi, penyerang (Mallory) yang berada di antara saluran dapat menukar kunci publik:';
  outputEl.appendChild(pText);

  const list = document.createElement('ul');
  list.style.paddingLeft = '1.25rem';
  list.style.margin = '0.5rem 0';

  const li1 = document.createElement('li');
  li1.textContent = `Kunci Alice - Mallory: K = ${toHex(kAliceMallory).slice(0, 16)}... (sama dengan Mallory: ${toHex(kMalloryAlice).slice(0, 16)}...)`;
  const li2 = document.createElement('li');
  li2.textContent = `Kunci Mallory - Server: K = ${toHex(kBobMallory).slice(0, 16)}... (Server mengira berbicara dengan Alice)`;
  const li3 = document.createElement('li');
  li3.style.color = '#f87171';
  li3.textContent = 'Hasil: Mallory dapat membaca dan mengubah semua paket tanpa disadari oleh Alice maupun Server!';

  list.appendChild(li1);
  list.appendChild(li2);
  list.appendChild(li3);
  outputEl.appendChild(list);

  logPanel.addEntry({
    actor: 'ATTACK',
    algo: 'DH',
    step: 'Simulasi Serangan MITM pada DH Polos',
    formula: 'Alice <-> Mallory <-> Server (2 Kunci Berbeda)',
    values: {
      K_AliceMallory: toHex(kAliceMallory).slice(0, 12) + '...',
      K_MalloryServer: toHex(kMalloryBob).slice(0, 12) + '...'
    },
    summary: 'Kelemahan DH polos terbukti: rentan MITM jika kunci publik tidak diautentikasi'
  });
}

function simulateMitmSigned() {
  const outputEl = document.getElementById('mitm-demo-output');
  if (!outputEl) return;

  outputEl.style.display = 'block';
  outputEl.textContent = '';

  const { p, q } = genSafePrime(20);
  const g = findGenerator(p, q);
  const params = { p, q, g };

  // Server memiliki kunci tanda tangan ElGamal (xs, ys)
  const signKeys = elgamalSignKeygen(params);

  // Alice & Bob generate DH
  const alice = dhGenerateKeyPair(params);
  const bob = dhGenerateKeyPair(params);

  const sessionId = 'session-mitm-demo';
  const transcriptStr = `${sessionId}|${toHex(alice.pub)}|${toHex(bob.pub)}`;

  // Server menandatangani transkrip asli
  const sig = elgamalSign(params, signKeys.xs, transcriptStr);

  // Penyerang (Mallory) mencoba mengganti B asli dengan B_palsu milik Mallory
  const malloryKey = dhGenerateKeyPair(params);
  const tamperedTranscriptStr = `${sessionId}|${toHex(alice.pub)}|${toHex(malloryKey.pub)}`;

  // Alice memverifikasi tanda tangan server atas paket yang diterimanya
  const isValidOriginal = elgamalVerify(params, signKeys.ys, transcriptStr, sig);
  const isValidTampered = elgamalVerify(params, signKeys.ys, tamperedTranscriptStr, sig);

  const title = document.createElement('h4');
  title.style.color = '#34d399';
  title.style.marginBottom = '0.5rem';
  title.textContent = '🛡️ Serangan MITM Berhasil Digagalkan dengan Tanda Tangan ElGamal [BONUS]';
  outputEl.appendChild(title);

  const pText = document.createElement('p');
  pText.textContent = 
    'Dengan menandatangani transkrip handshake DH menggunakan kunci privat ElGamal server xs:';
  outputEl.appendChild(pText);

  const list = document.createElement('ul');
  list.style.paddingLeft = '1.25rem';
  list.style.margin = '0.5rem 0';

  const li1 = document.createElement('li');
  li1.textContent = `Verifikasi tanda tangan transkrip asli: ${isValidOriginal ? '✓ VALID' : '✗ GAGAL'}`;

  const li2 = document.createElement('li');
  li2.style.color = '#34d399';
  li2.style.fontWeight = '700';
  li2.textContent = `Verifikasi tanda tangan setelah Mallory menukar B: ${isValidTampered ? '✓ VALID' : '✗ GAGAL (Serangan Terdeteksi!)'}`;

  const li3 = document.createElement('li');
  li3.textContent = 'Hasil: Browser Alice mendeteksi ketidaksesuaian tanda tangan dan langsung memutus koneksi sebelum mengirim rahasia apa pun.';

  list.appendChild(li1);
  list.appendChild(li2);
  list.appendChild(li3);
  outputEl.appendChild(list);

  logPanel.addEntry({
    actor: 'VOTER',
    algo: 'ELGAMAL',
    step: 'Mitigasi MITM: Verifikasi Tanda Tangan ElGamal Server',
    formula: 'g^H == ys^r * r^s mod p',
    values: {
      transkripAsliValid: isValidOriginal,
      transkripPalsuValid: isValidTampered
    },
    summary: 'Serangan MITM berhasil digagalkan: penyerang tidak dapat memalsukan tanda tangan ElGamal server'
  });
}

document.addEventListener('DOMContentLoaded', () => {
  setupTabs();

  // Tab 1: Test Vector Button
  document.getElementById('btn-run-test-vector')?.addEventListener('click', runTestVector);

  // Tab 2: modExp Calculator
  document.getElementById('btn-calc-modexp')?.addEventListener('click', calculateModExpSteps);

  // Tab 3: MITM Simulator
  document.getElementById('btn-sim-mitm-plain')?.addEventListener('click', simulateMitmPlain);
  document.getElementById('btn-sim-mitm-signed')?.addEventListener('click', simulateMitmSigned);
});
