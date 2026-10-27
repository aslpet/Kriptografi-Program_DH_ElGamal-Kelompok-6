// Skrip Pemeriksa Kepatuhan Ketentuan Tugas:
// Memastikan modul di shared/ tidak menggunakan library kriptografi eksternal
// atau API kripto bawaan untuk konsep DH/ElGamal/modular arithmetic.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sharedDir = path.resolve(__dirname, '../shared');

const BANNED_PATTERNS = [
  { pattern: /\bMath\.random\b/, name: 'Math.random (harus memakai RNG yang ditentukan)' },
  { pattern: /\bcreateDiffieHellman\b/, name: 'crypto.createDiffieHellman (DH harus ditulis sendiri)' },
  { pattern: /\bcreateECDH\b/, name: 'crypto.createECDH (DH harus ditulis sendiri)' },
  { pattern: /\bcreateCipher\w*\b/, name: 'crypto cipher API (enkripsi harus ditulis sendiri)' },
  { pattern: /\bcreateSign\w*\b/, name: 'crypto sign API (tanda tangan harus ditulis sendiri)' },
  { pattern: /\bsubtle\b/, name: 'crypto.subtle (SHA/kripto harus ditulis sendiri)' },
  { pattern: /\bmodPow\b/, name: 'modPow dari library (modExp harus ditulis sendiri)' },
  { pattern: /\bbigint-crypto-utils\b/, name: 'library bigint-crypto-utils dilarang' },
  { pattern: /\bnode-forge\b/, name: 'library node-forge dilarang' },
  { pattern: /\b(from\s+['"]node:crypto['"]|require\(['"]node:crypto['"]\))/, name: 'impor langsung node:crypto di shared (hanya getRandomValues via globalThis)' },
  { pattern: /(?<!\w)\*\*(?!\w)/, name: 'operator ** untuk eksponen (harus memakai modExp square-and-multiply)' }
];

function checkDirectory(dir) {
  if (!fs.existsSync(dir)) {
    console.log(`Direktori ${dir} belum ada.`);
    return 0;
  }

  const files = fs.readdirSync(dir).filter(f => f.endsWith('.js'));
  let violations = 0;

  for (const file of files) {
    const filePath = path.join(dir, file);
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      // Abaikan baris komentar penjelasan
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) {
        return;
      }

      for (const { pattern, name } of BANNED_PATTERNS) {
        if (pattern.test(line)) {
          console.error(`[PELANGGARAN] ${file}:${index + 1} - Ditemukan: ${name}`);
          console.error(`   Baris: ${line.trim()}`);
          violations++;
        }
      }
    });
  }

  return violations;
}

const totalViolations = checkDirectory(sharedDir);

if (totalViolations > 0) {
  console.error(`\nPemeriksaan gagal: ditemukan ${totalViolations} pelanggaran ketentuan kriptografi.`);
  process.exit(1);
} else {
  console.log('✓ Pemeriksaan kepatuhan sukses: tidak ada penggunaan library atau token terlarang di shared/.');
  process.exit(0);
}
