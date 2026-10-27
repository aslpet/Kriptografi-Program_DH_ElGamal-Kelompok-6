# Sistem E-Voting Berbasis Diffie-Hellman dan Exponential ElGamal

Aplikasi web pemilihan ketua BEM yang mendemonstrasikan **setiap tahapan matematis algoritma Diffie-Hellman (DH) dan ElGamal** dalam satu alur terpadu **tanpa menggunakan library/framework kriptografi**.

---

## 📋 Ringkasan Kepatuhan Tugas

| Komponen | Status | Implementasi di Kode | Keterangan |
|---|---|---|---|
| **Diffie-Hellman** | Ditulis Sendiri | `shared/dh.js` | Keygen $A = g^a \bmod p$, verifikasi subgrup, $K = B^a \bmod p$ |
| **Exponential ElGamal** | Ditulis Sendiri | `shared/elgamal.js` | Keygen $h = g^x \bmod p$, enkripsi $m = g^v$, perkalian homomorfik $\prod c_1, \prod c_2$, dekripsi total, pemulihan $T$ |
| **Aritmetika Modular** | Ditulis Sendiri | `shared/math_utils.js` | Square-and-multiply `modExp`, Extended Euclid `egcd`, `modInv`, Miller-Rabin `isProbablePrime`, safe prime `genSafePrime`, generator `findGenerator` |
| **Fungsi Hash SHA-256** | Ditulis Sendiri | `shared/sha256.js` | Standar FIPS 180-4, kompresi 64-putaran |
| **HMAC-SHA256** | Ditulis Sendiri | `shared/hmac.js` | Standar RFC 2104 & perbandingan waktu konstan `constantTimeEqual` |
| **Saluran Aman** | Ditulis Sendiri | `shared/channel.js` | Derivasi kunci KDF dari $K$, Keystream XOR counter-mode, Encrypt-then-MAC |
| **Tanda Tangan ElGamal [BONUS]** | Ditulis Sendiri | `shared/elgamal.js` | Autentikasi handshake DH server untuk menangkal serangan MITM |
| **Tipe Data BigInt** | Bawaan Bahasa | Tipe bawaan JS | Hanya dipakai sebagai wadah tipe bilangan besar tanpa library |
| **Sumber Bit Acak** | Bawaan OS / Custom | `shared/rng.js` | Mendukung `globalThis.crypto.getRandomValues` (OS) dan SHA-256 CTR-DRBG mandiri |
| **HTTP Server** | Bawaan/Framework | `server/server.js` | Express untuk routing REST API dan penyajian file statis |

---

## 🚀 Cara Menjalankan Program

### 1. Prasyarat

- Node.js versi 18 atau lebih baru (direkomendasikan Node.js v20/v24).

### 2. Instalasi Dependensi

```bash
npm install
```

### 3. Pemeriksaan Kepatuhan Banned Tokens

Memastikan tidak ada API kriptografi bawaan atau library eksternal di folder `shared/`:

```bash
npm run check-banned
```

### 4. Menjalankan Seluruh Pengujian Otomatis

Menjalankan 21 unit test & integrasi end-to-end:

```bash
npm test
```

### 5. Menjalankan Server Web

```bash
npm start
```

Buka browser di: [http://localhost:3000](http://localhost:3000)

---

## 🧭 Panduan Navigasi & Skenario Demo (10–12 Menit)

1. **Beranda (`/index.html`)**:
   - Melihat ringkasan arsitektur dan tabel peta 14 tahapan kriptografi.
2. **Lab Kripto Playground (`/lab.html`)**:
   - Tab 1: Menjalankan **Test Vector Bagian 6.10** ($p=23, q=11, g=4$) yang cocok persis dengan hitungan tangan ($A=2, B=18, K=8, T=1$).
   - Tab 2: Memeriksa kalkulator **Square-and-Multiply `modExp`** bit-demi-bit.
   - Tab 3: Menjalankan **Simulasi Serangan MITM** (DH polos vs DH terautentikasi tanda tangan ElGamal).
3. **Panel Panitia / EA (`/admin.html`)**:
   - Klik **Muat Pemilu Siap Demo (32-bit + 5 Voter)** untuk menyiapkan parameter dan 5 pemilih secara instan.
   - Status pemilu otomatis menjadi `VOTING`.
4. **Bilik Suara Pemilih (`/voter.html`)**:
   - Pilih `V001` (PIN: `111111`).
   - Langkah 1: Jalankan Handshake DH & verifikasi tanda tangan ElGamal server.
   - Langkah 2: Login PIN aman melalui saluran terenkripsi DH.
   - Langkah 3: Pilih Kandidat 1 & klik Enkripsi Suara (perhatikan vektor ciphertext $c_1, c_2$ di browser).
   - Langkah 4: Kirim ballot, catat kode **Receipt**, bandingkan 3 sudut pandang (Voter vs Network vs Server), dan uji coba tombol **Vote Ulang** serta **Kirim Ulang Paket Lama**.
5. **Simulasi Sisa Pemilih & Tally**:
   - Kembali ke `/admin.html`, klik tombol bantu **Simulasikan Suara V002–V005** (otomatis memilih: V002&rarr;K2, V003&rarr;K1, V004&rarr;K3, V005&rarr;K1).
   - Klik **Tutup Pemungutan Suara (CLOSED)**.
   - Klik **Jalankan Tally Homomorfik & Dekripsi Total (TALLIED)**.
6. **Audit Hasil Pemilu (`/results.html`) & Ballot Box (`/ballots.html`)**:
   - Periksa grafik perolehan: **Kandidat 1 = 3, Kandidat 2 = 1, Kandidat 3 = 1**, Total $V = 5$.
   - Periksa tabel audit matematis: perkalian agregat $C_1, C_2$, dekripsi $g^T$, dan iterasi pencarian $T$.
   - Indikator konsistensi menunjukkan: `✓ Konsistensi Valid (Σ T = V)`.

---

## 🔒 Batasan yang Diakui
1. **Model Anomitas Parsial**: Server membedakan identitas voter pada saat login saluran, tetapi ballot box menyimpan ciphertext tanpa menyertakan `voterId`.
2. **Ketiadaan Zero-Knowledge Proof (ZKP) Wajib**: Pada mode dasar, keabsahan pilihan $v \in \{0, 1\}$ dideteksi melalui audit konsistensi $\sum T_j = V$.
3. **Ukuran Demo (32-bit)**: Disediakan khusus untuk kemudahan visualisasi nilai angka dan verifikasi cepat pada presentasi kelas. Mode skala nyata didukung melalui 2048-bit RFC 3526.
