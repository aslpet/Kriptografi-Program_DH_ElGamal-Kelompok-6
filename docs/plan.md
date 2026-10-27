# Rencana Pengembangan Program E-Voting Berbasis Web
### Studi Kasus: Diffie-Hellman dan ElGamal Tanpa Library Kriptografi

| Item | Isi |
|---|---|
| Jenis dokumen | Rencana (planning) komprehensif sebelum implementasi |
| Platform | Web (Node.js + Express di sisi server, HTML/CSS/JavaScript murni di sisi browser) |
| Bahasa | JavaScript (ES Modules), memakai `BigInt` bawaan sebagai tipe data bilangan besar |
| Inti tugas | Menunjukkan fungsi **setiap tahapan** Diffie-Hellman (DH) dan ElGamal dalam **satu studi kasus** e-voting |
| Batasan utama | DH dan ElGamal **diimplementasikan sendiri** (tanpa library/framework untuk konsep tersebut) |

---

## Daftar Isi

0. [Cara membaca dokumen ini](#0-cara-membaca-dokumen-ini)
1. [Ringkasan eksekutif](#1-ringkasan-eksekutif)
2. [Ketentuan tugas dan interpretasinya](#2-ketentuan-tugas-dan-interpretasinya)
3. [Studi kasus](#3-studi-kasus)
4. [Arsitektur sistem](#4-arsitektur-sistem)
5. [Peta peran kriptografi per tahap](#5-peta-peran-kriptografi-per-tahap)
6. [Spesifikasi kriptografi](#6-spesifikasi-kriptografi)
7. [Protokol end-to-end dan format pesan](#7-protokol-end-to-end-dan-format-pesan)
8. [Desain backend](#8-desain-backend)
9. [Desain frontend](#9-desain-frontend)
10. [Struktur proyek dan spesifikasi modul](#10-struktur-proyek-dan-spesifikasi-modul)
11. [Keamanan: threat model dan batasan](#11-keamanan-threat-model-dan-batasan)
12. [Strategi pengujian](#12-strategi-pengujian)
13. [Rencana pengerjaan (fase, task, estimasi)](#13-rencana-pengerjaan)
14. [Skenario demo dan presentasi](#14-skenario-demo-dan-presentasi)
15. [Outline laporan](#15-outline-laporan)
16. [Risiko dan mitigasi](#16-risiko-dan-mitigasi)
17. [Checklist kepatuhan dan kriteria selesai](#17-checklist-kepatuhan-dan-kriteria-selesai)
18. [Pertanyaan terbuka untuk dosen](#18-pertanyaan-terbuka-untuk-dosen)
19. [Lampiran: pseudocode, rumus, glosarium](#19-lampiran)

---

## 0. Cara membaca dokumen ini

- Bagian **1-5** menjawab "apa yang dibuat dan kenapa".
- Bagian **6-7** adalah inti teknis: rumus, parameter, dan alur pesan. Bagian ini yang harus benar sebelum menulis kode.
- Bagian **8-10** menerjemahkan desain ke modul, API, dan UI.
- Bagian **11-12** membahas keamanan dan pengujian.
- Bagian **13-18** adalah rencana kerja, demo, laporan, dan checklist.
- Hal yang masih berupa **asumsi** ditandai `[ASUMSI]`. Hal yang sebaiknya **dikonfirmasi ke dosen** ditandai `[KONFIRMASI]` dan dikumpulkan di Bagian 18.
- Fitur tambahan yang tidak wajib ditandai `[BONUS]`.

---

## 1. Ringkasan Eksekutif

**Tujuan.** Membangun aplikasi e-voting berbasis web yang memperlihatkan, langkah demi langkah dan dengan nilai angka yang bisa diverifikasi, bagaimana **Diffie-Hellman** dan **ElGamal** bekerja bersama dalam satu alur pemilu.

**Ide inti.**

1. **Panitia (Election Authority, EA)** membuat keypair **ElGamal**. Public key `h` diumumkan, private key `x` disimpan EA.
2. Setiap voter membuka saluran ke server dengan **Diffie-Hellman**, sehingga keduanya memperoleh kunci sesi `K` yang sama tanpa pernah mengirim `K`.
3. Voter mengenkripsi suaranya dengan **ElGamal (varian eksponensial/homomorfik)** langsung **di browser**, sehingga server hanya menerima ciphertext. Paket kemudian diamankan lagi dengan kunci sesi turunan `K`.
4. **Ballot box** menyimpan ciphertext dan mencegah pemilihan ganda.
5. Saat penghitungan, ciphertext tiap kandidat **dikalikan** (sifat homomorfik), lalu **hanya total** yang didekripsi oleh EA. Pilihan individu tidak pernah terbuka.

**Nilai jual untuk penilaian.**

- Setiap tahap DH dan ElGamal punya **panel log** yang menampilkan rumus dan nilai antara (`a`, `A`, `b`, `B`, `K`, `k`, `c1`, `c2`, dst.).
- Ada halaman **Lab/Playground** yang menjalankan DH dan ElGamal dengan angka kecil supaya mudah dicocokkan dengan hitungan tangan.
- Bukti bahwa data di jaringan berupa ciphertext, bisa ditunjukkan lewat tab Network browser.

**Yang sengaja dibatasi (diakui di laporan).** Tidak ada zero-knowledge proof wajib, tidak ada pembagian private key EA, dan DH polos rentan MITM kecuali fitur `[BONUS]` tanda tangan ElGamal diaktifkan.

---

## 2. Ketentuan Tugas dan Interpretasinya

| # | Ketentuan dari tugas | Interpretasi yang dipakai | Cara dipenuhi di program | Status |
|---|---|---|---|---|
| T1 | Membuat sebuah program | Aplikasi e-voting yang bisa dijalankan dan didemokan | Aplikasi web lokal (`npm start`) | Pasti |
| T2 | Tanpa library atau framework **untuk konsep DH dan ElGamal** | Algoritma DH dan ElGamal beserta matematika pendukungnya ditulis sendiri. Bagian lain (server HTTP, UI) boleh memakai framework | `shared/math_utils.js`, `dh.js`, `elgamal.js` ditulis dari nol. Tidak ada `modPow`, `bigint-crypto-utils`, `node-forge`, `crypto.createDiffieHellman`, dan sejenisnya | Pasti |
| T3 | Menunjukkan fungsi setiap tahapan DH dan ElGamal | Setiap tahap (keygen, pertukaran kunci, enkripsi, dekripsi, dst.) terlihat dan bisa dijelaskan | Panel log kripto, halaman Lab, dan pemetaan tahap-ke-fitur di Bagian 5 | Pasti |
| T4 | Dalam **1 studi kasus** | Satu skenario yang utuh, bukan demo terpisah | Pemilihan Ketua BEM (Bagian 3), satu alur end-to-end | Pasti |
| T5 | Program e-voting | Ada registrasi/otorisasi voter, pemberian suara, penyimpanan, penghitungan, hasil | Halaman Admin, Voter, Ballot Box, Hasil | Pasti |
| T6 | Boleh memakai bagian lain | Tipe data `BigInt`, sumber bit acak browser, SHA-256 (jika tidak ditulis sendiri) dianggap bukan "konsep DH/ElGamal" | Diminimalkan: SHA-256 dan HMAC ditulis sendiri agar aman dari perdebatan | `[KONFIRMASI]` |

**Prinsip yang diambil jika ada keraguan:** tulis sendiri sebanyak mungkin, dan jelaskan di laporan bagian mana yang memakai fitur bawaan bahasa beserta alasannya.

---

## 3. Studi Kasus

**Judul:** Pemilihan Ketua BEM Fakultas secara elektronik. `[ASUMSI]` (bisa diganti studi kasus lain tanpa mengubah desain kripto)

| Elemen | Nilai demo |
|---|---|
| Kandidat | 3 orang: Kandidat 1, Kandidat 2, Kandidat 3 |
| Pemilih terdaftar | 5 orang (V001 sampai V005), bisa ditambah via halaman Admin |
| Aturan | Satu pemilih satu suara, suara bersifat rahasia, hasil hanya total per kandidat |
| Pihak | Voter, Server, Election Authority (EA), Ballot Box |
| Kebutuhan keamanan | Kerahasiaan suara, tidak ada pemilihan ganda, saluran voter-server tidak terbaca di jaringan, hasil dapat diverifikasi |

**Mengapa studi kasus ini cocok untuk DH dan ElGamal**

- Ada dua kebutuhan berbeda: **saluran aman antar dua pihak** (cocok untuk DH) dan **kerahasiaan isi suara sampai penghitungan** (cocok untuk ElGamal).
- Sifat homomorfik ElGamal eksponensial memungkinkan penghitungan tanpa membuka suara individu, sehingga nilai ElGamal terlihat jelas, tidak sekadar "enkripsi biasa".

---

## 4. Arsitektur Sistem

### 4.1 Aktor dan tanggung jawab

| Aktor | Bentuk di program | Tanggung jawab | Memegang rahasia |
|---|---|---|---|
| **Voter** | Halaman `voter.html` (browser) | Handshake DH, memilih, enkripsi ElGamal, mengirim | `a` (private DH), `k` (nonce enkripsi), kunci sesi |
| **Server** | Modul `server.js` + `session.js` | Handshake DH sisi server, memverifikasi paket, mengelola sesi, menerima suara | `b` (private DH per sesi), kunci sesi |
| **EA** | Modul `authority.js` + halaman `admin.html` | Membuat keypair ElGamal, mengumumkan `h`, melakukan tally dan dekripsi total | `x` (private ElGamal) |
| **Ballot Box** | Modul `ballotbox.js` | Menyimpan ciphertext, menandai voter sudah memilih, menolak double voting | Tidak ada. Hanya menyimpan data publik |

### 4.2 Lokasi eksekusi kode kripto

| Operasi | Dijalankan di | Alasan |
|---|---|---|
| Pembuatan `a`, `A`, hitung `K` (sisi voter) | Browser | `a` tidak boleh meninggalkan browser |
| Enkripsi ElGamal suara | Browser | Server tidak pernah melihat suara polos |
| Pembuatan `b`, `B`, hitung `K` (sisi server) | Backend | Mewakili pihak kedua DH |
| Keygen dan dekripsi ElGamal | Backend (modul EA) | `x` hanya ada di EA |
| Perkalian ciphertext (tally homomorfik) | Backend | Operasi publik, tidak butuh rahasia |
| Pencarian `T` dari `g^T` (brute force kecil) | Backend | Dilakukan setelah dekripsi total |

Karena modul kripto dipakai di dua sisi, semuanya ditulis sebagai **ES Module di folder `shared/`** yang diimpor oleh browser (lewat static file) dan oleh Node.js.

### 4.3 Diagram komponen

```
 +-------------------- BROWSER (Voter) --------------------+          +------------------- SERVER (Node.js) -------------------+
 |  voter.html / app.js                                     |          |  server.js (Express, routing, validasi)               |
 |   - UI: login, pilih kandidat, panel log kripto          |          |   - session.js   : handshake DH, kunci sesi, seq      |
 |   - shared/dh.js        (a, A, K)                        |  HTTP    |   - ballotbox.js : simpan ciphertext, anti-double     |
 |   - shared/elgamal.js   (enkripsi suara -> c1, c2)       | <------> |   - authority.js : keygen ElGamal, tally, dekripsi    |
 |   - shared/channel.js   (keystream XOR + HMAC)           |  (JSON)  |   - shared/*     : modul kripto yang sama             |
 |   - shared/math_utils.js, sha256.js, rng.js              |          |   - state.json / in-memory (voter, ballot, params)    |
 +----------------------------------------------------------+          +--------------------------------------------------------+
                         ^                                                                      ^
                         |                          admin.html / results.html                   |
                         +----------------------- (Panitia & publik) --------------------------+
```

### 4.4 State machine pemilu

```
SETUP  --(admin: generate parameter + keypair EA)-->  REGISTRATION
REGISTRATION  --(admin: kunci daftar voter)-->  VOTING
VOTING  --(admin: tutup pemungutan suara)-->  CLOSED
CLOSED  --(admin: jalankan tally)-->  TALLIED
```

Aturan: server menolak handshake voter jika state bukan `VOTING`, dan menolak tally jika state bukan `CLOSED`. State tidak boleh mundur (kecuali tombol reset demo untuk keperluan presentasi).

---

## 5. Peta Peran Kriptografi per Tahap

Tabel ini adalah **jawaban langsung untuk ketentuan T3** ("fungsi setiap tahapan"). Setiap baris harus punya tampilan di UI.

| Tahap | Algoritma | Langkah rinci | Input | Output | Tampil di UI |
|---|---|---|---|---|---|
| 1. Setup parameter | DH/ElGamal (parameter grup) | Bangkitkan prima aman `p = 2q+1`, cari generator `g` subgrup orde `q` | ukuran bit | `p`, `q`, `g` | Admin: log "Parameter publik" |
| 2. Keygen EA | **ElGamal** | `x` acak, `h = g^x mod p` | `p`, `q`, `g` | `x` (rahasia), `h` (publik) | Admin: log + `h` ditampilkan, `x` disembunyikan |
| 3. Handshake: sisi voter | **DH** | `a` acak, `A = g^a mod p` | `p`, `g` | `a`, `A` | Voter: log |
| 4. Handshake: sisi server | **DH** | `b` acak, `B = g^b mod p` | `A` | `b`, `B` | Panel server (log) |
| 5. Kunci sesi | **DH** | Voter: `K = B^a mod p`. Server: `K = A^b mod p` | `B` atau `A` | `K` sama di dua sisi | Voter dan panel server menampilkan `K` yang cocok |
| 6. Turunan kunci | (pendukung) | `encKey` dan `macKey` dari `K` lewat SHA-256 | `K`, transkrip | dua kunci 256-bit | Log |
| 7. Enkripsi suara | **ElGamal** | Untuk tiap kandidat `i`: `m_i = g^{v_i}`, `c1_i = g^{k_i}`, `c2_i = m_i * h^{k_i}` | `h`, pilihan | vektor `(c1_i, c2_i)` | Voter: log + tabel ciphertext |
| 8. Pengamanan saluran | **DH** (lewat `K`) | Keystream XOR + HMAC atas paket | `encKey`, `macKey` | paket `{seq, ct, tag}` | Voter: log. Network tab: terlihat ciphertext |
| 9. Penerimaan | - | Verifikasi HMAC, dekripsi saluran, cek double voting, simpan | paket | ballot tersimpan, `receipt` | Ballot Box publik |
| 10. Agregasi | **ElGamal (homomorfik)** | `C1_j = prod c1`, `C2_j = prod c2` per kandidat | semua ballot | 3 ciphertext agregat | Hasil: log |
| 11. Dekripsi total | **ElGamal** | `s = C1^x`, `g^T = C2 * s^{-1}` | `x`, agregat | `g^T` per kandidat | Hasil: log |
| 12. Pemulihan `T` | (pendukung) | Cari `T` dengan `g^T = nilai` untuk `T = 0..N` | `g^T`, `N` | jumlah suara `T` | Hasil: tabel dan jumlah iterasi |
| 13. Verifikasi | - | Jumlah `T` semua kandidat harus sama dengan jumlah ballot | hasil | OK / tidak valid | Hasil: indikator |
| 14. `[BONUS]` Autentikasi DH | **ElGamal signature** | Server menandatangani `(A, B)` dengan kunci tanda tangan ElGamal | transkrip | `(r, s)` | Voter: log "tanda tangan server valid" |

---

## 6. Spesifikasi Kriptografi

### 6.1 Notasi

| Simbol | Arti |
|---|---|
| `p` | Bilangan prima aman (*safe prime*), `p = 2q + 1` |
| `q` | Bilangan prima, orde subgrup yang dipakai |
| `g` | Generator subgrup orde `q` (bukan generator seluruh `Z_p*`) |
| `a`, `A` | Private dan public DH milik voter, `A = g^a mod p` |
| `b`, `B` | Private dan public DH milik server, `B = g^b mod p` |
| `K` | Shared secret DH, `K = g^(ab) mod p` |
| `x`, `h` | Private dan public ElGamal milik EA, `h = g^x mod p` |
| `k` | Nonce acak sekali pakai pada enkripsi ElGamal |
| `(c1, c2)` | Ciphertext ElGamal |
| `v` | Nilai suara per kandidat, `v` bernilai 0 atau 1 |
| `T` | Jumlah suara satu kandidat |

### 6.2 Parameter grup

**Keputusan: memakai prima aman `p = 2q + 1` dan generator subgrup orde `q`.**

Alasan:

- Subgrup orde `q` (prima besar) menghindari kebocoran informasi lewat *Legendre symbol* pada ElGamal, dan membuat pengecekan keanggotaan subgrup sederhana.
- Semua eksponen cukup dipilih di `[2, q-1]` dan aritmetika eksponen dilakukan `mod q`.
- Mencari generator mudah: ambil `h` acak di `[2, p-2]`, hitung `g = h^2 mod p`. Jika `g != 1`, maka `g` otomatis berorde `q`.

**Mode parameter**

| Mode | Ukuran `p` | Pembangkitan | Tujuan |
|---|---|---|---|
| **Demo** | 32 bit (opsional 24 bit untuk presentasi) | Dibangkitkan di browser/server, hitungan instan | Angka mudah dibaca dan dicocokkan |
| **Menengah** | 256 bit | Dibangkitkan dengan Miller-Rabin | Realistis namun tetap cepat |
| **Realistis** | 512 bit (dibangkitkan) dan opsional 2048 bit (konstanta standar RFC 3526 grup 14, `g = 2`) | 512 bit di Web Worker. 2048 bit memakai konstanta publik | Menunjukkan skala nyata. `[KONFIRMASI]` apakah memakai konstanta standar boleh |

Catatan teknis:

- Pembangkitan prima aman 1024 bit ke atas dengan `BigInt` murni bisa memakan menit. Karena itu mode 2048 bit memakai konstanta publik, dan **validasi** tetap dijalankan program: `q` prima (Miller-Rabin), `g^q mod p == 1`, `g != 1`.
- Pembangkitan di browser dijalankan di **Web Worker** agar UI tidak membeku.

### 6.3 Modul matematika (`math_utils.js`)

Semua ditulis sendiri, memakai `BigInt` hanya sebagai tipe data.

| Fungsi | Deskripsi | Catatan |
|---|---|---|
| `modExp(base, exp, mod)` | *Square-and-multiply* | **Dilarang** memakai `**` untuk eksponen besar dan dilarang memakai `modPow` dari library |
| `egcd(a, b)` | Extended Euclid (iteratif) | Mengembalikan `{g, x, y}` |
| `modInv(a, m)` | Invers modular lewat `egcd` | Melempar error jika `gcd != 1` |
| `isProbablePrime(n, rounds)` | Miller-Rabin | Basis tetap untuk `n` kecil, basis acak untuk `n` besar (rounds 40) |
| `smallPrimeSieve(limit)` | Daftar prima kecil untuk *trial division* | Mempercepat pencarian prima |
| `genPrime(bits)` | Bangkitkan prima `bits` bit | Bit tertinggi dan bit terendah di-set 1 |
| `genSafePrime(bits)` | Bangkitkan `q` lalu cek `p = 2q+1` | Mengembalikan `{p, q}` |
| `findGenerator(p, q)` | `g = h^2 mod p`, cek `g != 1` | Orde `q` terjamin |
| `isInSubgroup(y, p, q)` | `1 < y < p` dan `y^q mod p == 1` | Dipakai untuk validasi `A`, `B`, ciphertext |
| `bitLength(n)` | Panjang bit | Untuk validasi ukuran |
| `bigToBytes(n, len)` / `bytesToBig(bytes)` | Konversi dengan panjang tetap | Penting agar `K` identik di dua sisi |
| `toHex(n)` / `fromHex(s)` | Serialisasi JSON | Semua `BigInt` dikirim sebagai string hex |

**Sumber acak (`rng.js`)**

- `randomBytes(n)`: memakai `crypto.getRandomValues` (browser) atau padanannya di Node (`node:crypto` `webcrypto`). Ini hanya **sumber bit acak** dari OS, bukan implementasi DH/ElGamal. `[KONFIRMASI]`
- `randomBelow(n)`: *rejection sampling* agar distribusi seragam di `[0, n)`.
- `randomRange(lo, hi)`: bilangan acak di `[lo, hi]`.
- **Dilarang** memakai `Math.random()` untuk kunci dan nonce.
- Alternatif jika dosen melarang bit acak bawaan: PRNG sendiri berbasis SHA-256 (CTR-DRBG sederhana) yang di-seed dari waktu dan input pengguna, dicatat sebagai keterbatasan untuk demo.

### 6.4 Diffie-Hellman (`dh.js`)

**Langkah**

1. Parameter publik `(p, q, g)` diketahui kedua pihak.
2. Voter: `a = randomRange(2, q-1)`, `A = modExp(g, a, p)`.
3. Server: `b = randomRange(2, q-1)`, `B = modExp(g, b, p)`.
4. Pertukaran: `A` dikirim ke server, `B` dikirim ke voter.
5. **Validasi** nilai publik yang diterima: `isInSubgroup(A, p, q)`. Tolak jika gagal (mencegah *small-subgroup attack* dan nilai 1, `p-1`).
6. Voter: `K = modExp(B, a, p)`. Server: `K = modExp(A, b, p)`. Keduanya sama karena `B^a = g^(ba) = g^(ab) = A^b`.
7. Turunan kunci (Bagian 6.8): `encKey` dan `macKey`.

**Antarmuka**

```js
dhGenerateKeyPair(params)          // -> { priv, pub }
dhComputeShared(params, priv, otherPub)  // -> K (BigInt), melempar error jika otherPub tidak valid
```

**Yang ditampilkan:** `a` (hanya sisi voter), `A`, `B`, dan `K` di kedua sisi dengan pesan "K voter == K server: OK". Pada mode demo `K` ditampilkan penuh, pada mode realistis cukup beberapa karakter awal dan akhir.

### 6.5 ElGamal (`elgamal.js`)

**Pembangkitan kunci (EA)**

```
x = randomRange(2, q-1)           // private
h = g^x mod p                      // public
```

**Enkripsi pesan `m` di subgrup**

```
k  = randomRange(2, q-1)           // nonce unik tiap enkripsi, tidak boleh dipakai ulang
c1 = g^k mod p
c2 = m * h^k mod p
```

**Dekripsi**

```
s = c1^x mod p                     // shared secret ElGamal
m = c2 * s^(-1) mod p              // s^(-1) = modInv(s, p), setara c1^(q-x) mod p
```

**Antarmuka**

```js
elgamalKeygen(params)                   // -> { x, h }
elgamalEncrypt(params, h, m, k?)        // -> { c1, c2, k }  (k dikembalikan hanya untuk log/demo)
elgamalDecrypt(params, x, {c1, c2})     // -> m
elgamalMultiply(params, ctA, ctB)       // -> { c1: c1A*c1B mod p, c2: c2A*c2B mod p }
```

**Syarat keamanan yang dijaga**

- `k` baru untuk setiap ciphertext. Tes khusus memastikan dua enkripsi pesan yang sama menghasilkan ciphertext berbeda.
- `m` harus anggota subgrup (`g^v` selalu anggota). Validasi pada enkripsi.
- Nilai `c1`, `c2` yang diterima server diperiksa `isInSubgroup`.

### 6.6 Exponential ElGamal dan encoding suara

**Mengapa eksponensial.** ElGamal biasa bersifat *multiplicative homomorphic*: `Enc(m1) * Enc(m2) = Enc(m1 * m2)`. Dengan memasukkan suara sebagai eksponen, `m = g^v`, perkalian ciphertext menjadi **penjumlahan suara**: `g^v1 * g^v2 = g^(v1+v2)`.

**Encoding ballot (satu pilihan dari `N` kandidat)**

Ballot adalah **vektor `N` ciphertext**. Jika voter memilih kandidat `j`:

```
v_i = 1  jika i = j
v_i = 0  jika i != j
ballot[i] = Enc(g^{v_i})   // k_i berbeda untuk setiap i
```

Contoh 3 kandidat, memilih kandidat 2: `v = (0, 1, 0)`, sehingga ballot = `[Enc(g^0), Enc(g^1), Enc(g^0)]` dengan tiga nonce berbeda. Hasil enkripsi dari `g^0 = 1` dan `g^1 = g` tidak bisa dibedakan tanpa `x`.

### 6.7 Tally homomorfik

Untuk kandidat `j` dan `V` ballot yang tersimpan:

```
C1_j = prod_{voter} c1_{voter, j} mod p
C2_j = prod_{voter} c2_{voter, j} mod p
```

Dekripsi `(C1_j, C2_j)` dengan `x` menghasilkan `g^{T_j}` dengan `T_j` jumlah suara kandidat `j`. Pemulihan `T_j`:

```
for T = 0 .. V:
    if modExp(g, T, p) == hasil: return T
```

Brute force ini aman karena `T <= V` dan `V` kecil. Jumlah iterasi ditampilkan sebagai bukti.

**Pengecekan konsistensi:** `sum_j T_j == V` (setiap ballot sah punya tepat satu nilai 1). Jika tidak sama, ada ballot tidak valid (lihat keterbatasan di Bagian 11 dan fitur `[BONUS]` ZKP).

### 6.8 Pengaman saluran (`sha256.js`, `hmac.js`, `channel.js`)

DH hanya menghasilkan `K`, bukan cipher. Agar `K` benar-benar dipakai, dibuat saluran sederhana yang ditulis sendiri.

**SHA-256** ditulis sendiri (sekitar 60-80 baris). Alasan: `crypto.subtle` hanya tersedia di *secure context* (HTTPS atau `localhost`) dan bersifat asinkron, sehingga implementasi sendiri lebih konsisten dan memperkuat klaim "tanpa library".

**Turunan kunci**

```
Kbytes  = bigToBytes(K, byteLength(p))           // panjang tetap
transcript = SHA256(sessionId || A || B)
encKey  = SHA256("ENC" || Kbytes || transcript)
macKey  = SHA256("MAC" || Kbytes || transcript)
```

**Enkripsi paket (stream cipher berbasis hash, mode counter)**

```
keystreamBlock(i) = SHA256(encKey || dir || seq(8 byte) || i(4 byte))
ct = plaintext XOR keystream
tag = HMAC-SHA256(macKey, dir || seq || ct)        // encrypt-then-MAC
```

- `dir` = `0x01` (voter ke server) atau `0x02` (server ke voter), mencegah serangan pantulan (*reflection*).
- `seq` naik monoton tiap pesan, sehingga paket yang diputar ulang (*replay*) ditolak.
- Penerima **memverifikasi `tag` dulu** (perbandingan waktu-konstan), baru mendekripsi.

**Catatan laporan:** ini bukan cipher standar industri. Tujuannya demonstrasi bahwa `K` dari DH dipakai untuk mengamankan saluran. Pada sistem nyata dipakai AES-GCM atau ChaCha20-Poly1305 lewat TLS.

### 6.9 `[BONUS]` DH terautentikasi dengan tanda tangan ElGamal

DH polos tidak mengautentikasi pihak lawan, sehingga rentan *man-in-the-middle* (MITM). Perbaikan: server memiliki keypair tanda tangan ElGamal `(xs, ys = g^xs mod p)`, dan `ys` diketahui voter (disematkan di `/api/params`, di sistem nyata lewat sertifikat).

**Tanda tangan (server)**

```
H = SHA256(sessionId || A || B) mod q
k = randomRange(1, q-1)
r = g^k mod p
s = k^(-1) * (H - xs * r) mod q       // jika s = 0, ulang dengan k baru
signature = (r, s)
```

**Verifikasi (voter)**

```
syarat: 1 <= r <= p-1 dan 1 <= s <= q-1
g^H mod p  ==  ys^r * r^s mod p
```

Bukti: `ys^r * r^s = g^(xs*r) * g^(k*s) = g^(xs*r + k*s) = g^H`. Ini juga menunjukkan **fungsi tambahan ElGamal** (tanda tangan) selain enkripsi.

Demo MITM: halaman Lab menyediakan tombol "Simulasikan penyerang" yang menukar `B` dengan nilai penyerang. Tanpa tanda tangan, voter tidak sadar. Dengan tanda tangan, verifikasi gagal.

### 6.10 Contoh numerik kecil (untuk Lab dan laporan)

Sudah diverifikasi manual. Parameter: `p = 23`, `q = 11`, `g = 4` (`4^11 mod 23 = 1`, jadi `g` berorde 11).

**Diffie-Hellman**

| Langkah | Perhitungan | Hasil |
|---|---|---|
| Voter memilih `a = 6` | `A = 4^6 mod 23` | `A = 2` |
| Server memilih `b = 3` | `B = 4^3 mod 23` | `B = 18` |
| Voter hitung `K` | `18^6 mod 23` | `K = 8` |
| Server hitung `K` | `2^3 mod 23` | `K = 8` (sama) |

**ElGamal eksponensial, 1 kandidat, 2 voter**

- EA: `x = 7`, `h = 4^7 mod 23 = 8`.
- Voter 1 memilih kandidat ini (`v = 1`, `m = g^1 = 4`), `k = 3`: `c1 = 4^3 mod 23 = 18`, `h^k = 8^3 mod 23 = 6`, `c2 = 4 * 6 mod 23 = 1`. Ciphertext `(18, 1)`.
- Voter 2 tidak memilih (`v = 0`, `m = 1`), `k = 5`: `c1 = 4^5 mod 23 = 12`, `h^k = 8^5 mod 23 = 16`, `c2 = 1 * 16 = 16`. Ciphertext `(12, 16)`.
- Agregasi: `C1 = 18 * 12 mod 23 = 9`, `C2 = 1 * 16 mod 23 = 16`.
- Dekripsi: `s = 9^7 mod 23 = 4`, `s^(-1) = 6` (karena `4 * 6 = 24 = 1 mod 23`), `g^T = 16 * 6 mod 23 = 4`.
- `g^T = 4 = g^1`, jadi **`T = 1`** (benar, satu voter memilih kandidat ini).

Contoh ini dipakai sebagai **test vector otomatis** di unit test dan sebagai isian awal (preset) halaman Lab.

---

## 7. Protokol End-to-End dan Format Pesan

### 7.1 Konvensi

- Transport: HTTP + JSON. Semua `BigInt` dikirim sebagai **string hex huruf kecil tanpa prefix** (`"1f3a..."`).
- Semua endpoint berawalan `/api`.
- Setelah handshake, body request yang sensitif berbentuk **paket aman** (Bagian 7.4), bukan JSON polos.

### 7.2 Fase A: Setup pemilu (Admin/EA)

```
Admin  -> Server : POST /api/admin/setup  { mode: "demo"|"mid"|"real", candidates: [...], adminToken }
Server (EA):
   1. genSafePrime(bits) -> p, q ; findGenerator -> g          (atau muat konstanta standar)
   2. elgamalKeygen -> x (disimpan di authority.js), h
   3. [BONUS] keygen tanda tangan server -> (xs, ys)
Server -> Admin  : { p, q, g, h, ys?, log[] }                  // x TIDAK pernah dikirim
State: SETUP -> REGISTRATION
```

### 7.3 Fase B: Registrasi voter

```
Admin -> Server : POST /api/admin/voters  { voters: [ {id:"V001", pin:"..."} , ... ] }
Server          : simpan { id, salt, pinHash = SHA256(salt || pin), hasVoted:false }
Admin -> Server : POST /api/admin/open   // state -> VOTING
```

PIN tidak pernah disimpan polos. Untuk demo, PIN dicetak/ditampilkan satu kali di halaman Admin.

### 7.4 Fase C: Handshake DH (voter ke server)

```
(1) Voter -> Server : POST /api/handshake/init     { voterId, A }
      Voter : a = randomRange(2,q-1) ; A = g^a mod p                       [LOG: a, A]
(2) Server           : cek state=VOTING, voterId terdaftar, isInSubgroup(A)
                       b = randomRange(2,q-1) ; B = g^b mod p
                       K = A^b mod p ; sessionId = acak 128 bit
                       turunkan encKey, macKey ; [BONUS] sig = ElGamalSign(sessionId||A||B)
(3) Server -> Voter  : { sessionId, B, sig? }
(4) Voter            : isInSubgroup(B) ; [BONUS] verifikasi sig
                       K = B^a mod p ; turunkan encKey, macKey              [LOG: K]
(5) Voter -> Server : POST /api/handshake/confirm   { sessionId, seq:1, ct, tag }
                       plaintext = "READY|" + sessionId  (dienkripsi dengan kunci sesi)
(6) Server           : verifikasi tag -> bukti kedua pihak memegang K yang sama
Server -> Voter      : paket aman { seq:1 (dir=2), ct("OK"), tag }
```

**Bukti kunci sama:** langkah (5)-(6) memverifikasi secara kriptografis bahwa `K` identik, tanpa pernah mengirim `K`. Di UI ditampilkan "Handshake berhasil, kunci sesi cocok".

### 7.5 Fase D: Login voter (di dalam saluran aman)

```
Voter -> Server : POST /api/login   paket aman { seq:2, ct = Enc{ voterId, pin }, tag }
Server          : verifikasi tag dan seq -> dekripsi -> cek pinHash
                  gagal 3 kali -> sesi dibatalkan
Server -> Voter : paket aman { ok:true, candidates:[...], publicKey:{p,q,g,h} }
```

PIN lewat saluran terenkripsi `K`, jadi ini **penggunaan nyata kunci DH** (bukan hanya dipamerkan).

### 7.6 Fase E: Pemungutan suara

```
Voter (browser):
   pilihan j ; untuk i = 1..N: v_i = (i==j ? 1 : 0)
   m_i = g^{v_i} mod p ; k_i = randomRange(2,q-1)
   c1_i = g^{k_i} ; c2_i = m_i * h^{k_i}                              [LOG tabel ciphertext]
   ballot = [ {c1_i, c2_i} ]_{i=1..N}
   receipt = SHA256(kanonik(ballot))
Voter -> Server : POST /api/vote   paket aman { seq:3, ct = Enc{ ballot }, tag }

Server:
   1. verifikasi tag, seq, state=VOTING
   2. dekripsi saluran -> ballot ; validasi: panjang = N, tiap c1,c2 isInSubgroup
   3. ballotbox.cast(voterId, ballot): jika hasVoted -> tolak (409)
      jika belum: hasVoted=true (atomik) lalu simpan {receipt, ballot, waktu} TANPA voterId
Server -> Voter : paket aman { ok:true, receipt }
```

Server Node.js berjalan single-thread, sehingga pengecekan `hasVoted` dan penandaan tidak bisa berselisih antar request. Voter bisa mencocokkan `receipt` miliknya di halaman Ballot Box publik.

### 7.7 Fase F: Penutupan, tally, dan hasil

```
Admin -> Server : POST /api/admin/close                // VOTING -> CLOSED
Admin -> Server : POST /api/admin/tally                // CLOSED -> TALLIED
Server (EA):
   untuk tiap kandidat j:
      C1_j = prod c1 ; C2_j = prod c2                                   [LOG: agregasi]
      s = C1_j^x ; gT = C2_j * s^{-1} mod p                             [LOG: dekripsi]
      T_j = cari T di 0..V dengan g^T == gT                              [LOG: iterasi]
   verifikasi: sum T_j == V
Server -> Admin/Publik : GET /api/results  { perCandidate:[{name,T,C1,C2,gT}], V, consistent }
```

Dekripsi **hanya** dijalankan pada ciphertext agregat. Tidak ada endpoint yang mendekripsi ballot individual.

### 7.8 Format paket aman

```json
{
  "sessionId": "9f2c...",
  "seq": 3,
  "ct": "hex ciphertext dari JSON payload",
  "tag": "hex HMAC-SHA256"
}
```

Aturan penerima: (1) sesi ada dan belum kedaluwarsa, (2) `seq` lebih besar dari `seq` terakhir, (3) `tag` valid, (4) baru dekripsi, (5) parse JSON dan validasi skema.

### 7.9 Kode status dan error

| Kode | Arti | Contoh |
|---|---|---|
| 200 | Sukses | Handshake selesai |
| 400 | Format salah / nilai publik tidak valid | `A` bukan anggota subgrup |
| 401 | Autentikasi gagal | PIN salah, tag HMAC tidak valid |
| 403 | State tidak sesuai | Voting belum dibuka |
| 409 | Konflik | Voter sudah memilih (double voting), `seq` ulang (replay) |
| 429 | Terlalu banyak percobaan | PIN salah 3 kali |

---

## 8. Desain Backend

### 8.1 Modul server

| Modul | Tanggung jawab | Fungsi utama |
|---|---|---|
| `server.js` | Routing Express, validasi request, middleware error, penyajian file statis `public/` dan `shared/` | `createApp()`, `start()` |
| `session.js` | Handshake DH sisi server, penyimpanan kunci sesi, pengecekan `seq`, kedaluwarsa | `initHandshake()`, `confirmHandshake()`, `openPacket()`, `sealPacket()`, `cleanup()` |
| `authority.js` | Pemegang `x`, keygen, agregasi, dekripsi, pemulihan `T` | `setupElection()`, `getPublic()`, `tally()` |
| `ballotbox.js` | Menyimpan ballot, anti-double voting, daftar receipt | `cast()`, `list()`, `count()`, `hasVoted()` |
| `voters.js` | Registrasi, verifikasi PIN, pembatasan percobaan | `register()`, `verify()` |
| `electionState.js` | State machine (Bagian 4.4) | `get()`, `transition()` |
| `storage.js` | Simpan/muat `state.json` (opsional) | `save()`, `load()` |
| `logger.js` | Menghimpun log kripto sisi server untuk ditampilkan | `logStep(actor, algo, step, data)` |

### 8.2 Struktur data

```js
// params (publik)
{ bits, p, q, g, h, ys? }            // semua BigInt di memori, hex di JSON

// authority (rahasia, hanya di authority.js)
{ x, xs? }

// voter
{ id, salt, pinHash, hasVoted: false, failedAttempts: 0 }

// session
{ id, voterId, A, B, b, K, encKey, macKey, lastSeqIn, seqOut, authed, createdAt }

// ballot (tanpa voterId)
{ receipt, cts: [ { c1, c2 }, ... ], castAt }

// results
{ perCandidate: [ { name, C1, C2, gT, T, iterations } ], V, consistent }
```

Penyimpanan: **in-memory** dengan opsi dump ke `state.json` agar data bertahan saat server restart. Tidak butuh database. `x` tidak ditulis ke `state.json` pada mode normal (EA harus melakukan setup ulang jika server restart), atau ditulis ke berkas terpisah yang diabaikan git dan hanya untuk kenyamanan demo. `[ASUMSI]`

### 8.3 Daftar API

| Metode | Endpoint | Akses | Fungsi |
|---|---|---|---|
| GET | `/api/params` | Publik | `p, q, g, h, ys`, daftar kandidat, state pemilu |
| POST | `/api/admin/setup` | Admin | Bangkitkan parameter dan keypair EA |
| POST | `/api/admin/voters` | Admin | Daftarkan voter |
| POST | `/api/admin/open` | Admin | Buka pemungutan suara |
| POST | `/api/admin/close` | Admin | Tutup pemungutan suara |
| POST | `/api/admin/tally` | Admin | Hitung dan dekripsi total |
| POST | `/api/admin/reset` | Admin | Reset data demo |
| POST | `/api/handshake/init` | Voter | `{voterId, A}` -> `{sessionId, B, sig?}` |
| POST | `/api/handshake/confirm` | Voter | Konfirmasi kunci sesi |
| POST | `/api/login` | Voter (aman) | PIN lewat paket aman |
| POST | `/api/vote` | Voter (aman) | Kirim ballot terenkripsi |
| GET | `/api/ballots` | Publik | Daftar receipt dan ciphertext (tanpa identitas) |
| GET | `/api/results` | Publik | Hasil setelah `TALLIED` |
| GET | `/api/log` | Admin/Publik | Log kripto sisi server (untuk panel) |
| POST | `/api/lab/*` | Publik | Endpoint Lab (mode demo, tidak mengubah data pemilu) |

Autentikasi admin: token sederhana dari kata sandi admin di berkas konfigurasi `[ASUMSI]` (cukup untuk tugas).

### 8.4 Validasi dan penanganan kesalahan

- Semua input hex divalidasi (panjang, karakter).
- Nilai publik `A`, `c1`, `c2` divalidasi dengan `isInSubgroup`.
- Sesi kedaluwarsa 10 menit. Sesi dipakai satu kali untuk satu voter.
- Batas percobaan login 3 kali, lalu sesi dibatalkan.
- Pesan error **tidak membocorkan detail rahasia** (mis. tidak membedakan "voter tidak ada" dan "PIN salah" pada tahap login).

---

## 9. Desain Frontend

### 9.1 Teknologi

HTML, CSS, JavaScript ES Modules tanpa framework UI (cukup untuk tugas dan mengurangi risiko "framework" bercampur dengan kripto). Modul `shared/` diimpor langsung oleh browser.

### 9.2 Halaman

| Halaman | Pengguna | Isi utama |
|---|---|---|
| `index.html` | Semua | Pintu masuk, penjelasan singkat alur, tautan ke halaman lain |
| `admin.html` | Panitia/EA | Pilih mode parameter, tombol Setup, tampilan `p, q, g, h`, registrasi voter, buka/tutup voting, tombol Tally, log kripto EA |
| `voter.html` | Voter | Stepper 4 langkah: (1) Handshake DH, (2) Login, (3) Pilih + Enkripsi, (4) Kirim dan Receipt. Panel log kripto di samping |
| `ballots.html` | Publik | Tabel receipt dan ciphertext `(c1, c2)` per kandidat, jumlah ballot, status voter (sudah/belum memilih, tanpa pilihan) |
| `results.html` | Publik | Agregasi, dekripsi, hasil `T` per kandidat, grafik batang sederhana, indikator konsistensi |
| `lab.html` | Penonton/dosen | Playground DH dan ElGamal dengan angka kecil, tombol "Simulasikan penyerang" `[BONUS]` |

### 9.3 Komponen UI penting

**Panel Log Kripto (komponen terpenting untuk T3).** Setiap entri berbentuk:

```
[waktu] [AKTOR] [ALGORITMA] langkah
   rumus   : A = g^a mod p
   nilai   : g=4, a=6, p=23 -> A=2
```

- Label warna: `DH` (biru), `ELGAMAL` (hijau), `CHANNEL` (abu), `SERVER` (oranye).
- Tombol **"Tampilkan angka penuh"** (untuk mode realistis, angka panjang dipotong dengan `...`).
- Tombol **"Salin log"** untuk memudahkan lampiran laporan.
- Mode **langkah demi langkah**: tombol "Berikutnya" agar presenter mengontrol kecepatan.
- **Rahasia** (`a`, `k`, `x`) ditampilkan di log hanya pada **mode demo**, dengan sakelar "Mode edukasi". Di luar mode itu disembunyikan.

**Tampilan pembuktian**

- Ikon dan pesan "K voter == K server" setelah handshake.
- Tabel "Apa yang dilihat server" vs "Apa yang dilihat jaringan" vs "Apa yang diketahui voter", untuk menunjukkan siapa tahu apa.
- Tombol "Lihat paket di jaringan" yang menampilkan JSON paket aman (`ct`, `tag`) sehingga mudah dibandingkan dengan tab Network.

### 9.4 Halaman Lab (Playground)

Isi:

1. **DH:** input `p, g, a, b` (preset `23, 4, 6, 3`), tombol hitung bertahap `A`, `B`, `K` di dua sisi.
2. **ElGamal:** input `x, k, m`, tahap keygen, enkripsi, dekripsi.
3. **Homomorfik:** dua ciphertext dikalikan, lalu didekripsi, menunjukkan penjumlahan suara.
4. **Kalkulator `modExp` bertahap:** menampilkan tabel *square-and-multiply* per bit eksponen.
5. `[BONUS]` simulasi MITM dengan dan tanpa tanda tangan.

Lab memakai modul `shared/` yang **sama** dengan aplikasi utama, sehingga membuktikan bahwa implementasi yang didemokan adalah implementasi yang dipakai.

### 9.5 Aksesibilitas dan kerapian

- Responsif (laptop/proyektor), kontras tinggi, font monospace untuk angka.
- Pesan error berbahasa Indonesia yang jelas.
- Tidak menyimpan rahasia di `localStorage`. Kunci `a` dan `K` hanya di memori halaman.

---

## 10. Struktur Proyek dan Spesifikasi Modul

### 10.1 Struktur folder

```
evoting-dh-elgamal/
├─ package.json                  # "type": "module", script: start, test
├─ README.md                     # cara menjalankan, struktur, batasan
├─ config.js                     # port, mode default, kandidat, kata sandi admin
├─ shared/                       # dipakai browser DAN server
│  ├─ rng.js                     # randomBytes, randomBelow, randomRange
│  ├─ math_utils.js              # modExp, egcd, modInv, Miller-Rabin, prima, generator
│  ├─ sha256.js                  # SHA-256 buatan sendiri
│  ├─ hmac.js                    # HMAC-SHA256
│  ├─ encoding.js                # hex, bytes, kanonikalisasi JSON
│  ├─ dh.js                      # Diffie-Hellman
│  ├─ elgamal.js                 # keygen, enkripsi, dekripsi, perkalian, [BONUS] tanda tangan
│  └─ channel.js                 # derive key, seal/open paket aman
├─ server/
│  ├─ server.js
│  ├─ session.js
│  ├─ authority.js
│  ├─ ballotbox.js
│  ├─ voters.js
│  ├─ electionState.js
│  ├─ storage.js
│  └─ logger.js
├─ public/
│  ├─ index.html
│  ├─ admin.html     + js/admin.js
│  ├─ voter.html     + js/voter.js
│  ├─ ballots.html   + js/ballots.js
│  ├─ results.html   + js/results.js
│  ├─ lab.html       + js/lab.js
│  ├─ js/logPanel.js             # komponen panel log kripto
│  ├─ js/paramWorker.js          # Web Worker pembangkit prima
│  └─ css/style.css
├─ test/
│  ├─ math_utils.test.js
│  ├─ sha256_hmac.test.js
│  ├─ dh.test.js
│  ├─ elgamal.test.js
│  ├─ channel.test.js
│  ├─ ballotbox.test.js
│  └─ e2e.test.js
└─ docs/
   ├─ laporan.md                 # bahan laporan
   └─ screenshots/
```

### 10.2 Spesifikasi fungsi tiap modul `shared/`

**`rng.js`**
```js
randomBytes(n): Uint8Array
randomBelow(n: bigint): bigint                // seragam di [0, n)
randomRange(lo: bigint, hi: bigint): bigint   // seragam di [lo, hi]
```

**`math_utils.js`**
```js
modExp(base, exp, mod): bigint
egcd(a, b): { g, x, y }
modInv(a, m): bigint
isProbablePrime(n, rounds = 40): boolean
genPrime(bits): bigint
genSafePrime(bits, onProgress?): { p, q }
findGenerator(p, q): bigint
isInSubgroup(y, p, q): boolean
bitLength(n): number
```

**`sha256.js` / `hmac.js`**
```js
sha256(bytes: Uint8Array): Uint8Array
hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array
constantTimeEqual(a, b): boolean
```

**`dh.js`**
```js
dhGenerateKeyPair(params): { priv, pub }
dhComputeShared(params, priv, otherPub): bigint
```

**`elgamal.js`**
```js
elgamalKeygen(params): { x, h }
elgamalEncrypt(params, h, m, k?): { c1, c2, k }
elgamalDecrypt(params, x, ct): bigint
elgamalMultiply(params, ctA, ctB): { c1, c2 }
encodeVote(params, choiceIndex, numCandidates): number[]     // vektor 0/1
encryptBallot(params, h, choiceIndex, numCandidates): { cts, ks }
recoverTally(params, gT, maxVotes): { T, iterations }
// [BONUS]
elgamalSignKeygen(params): { xs, ys }
elgamalSign(params, xs, msgHashInt): { r, s }
elgamalVerify(params, ys, msgHashInt, { r, s }): boolean
```

**`channel.js`**
```js
deriveKeys(params, K, sessionId, A, B): { encKey, macKey }
seal(keys, dir, seq, plaintextBytes): { seq, ct, tag }
open(keys, dir, packet, lastSeq): plaintextBytes             // melempar error jika tag/seq salah
```

### 10.3 Aturan kode

- ES Modules, tanpa dependensi kripto. Dependensi yang diizinkan: `express` (server). `[KONFIRMASI]` Jika dosen tidak setuju, pakai `node:http` bawaan.
- Setiap fungsi kripto diberi komentar rumus (mis. `// A = g^a mod p`) agar mudah dijelaskan.
- Tidak ada `Math.random()`, `**` pada eksponen besar, atau `crypto.createDiffieHellman`/`createCipheriv` untuk DH/ElGamal.
- Skrip pemeriksaan sederhana (`npm run check-banned`) yang mencari kata terlarang di `shared/` untuk membuktikan kepatuhan ketentuan.

---

## 11. Keamanan: Threat Model dan Batasan

### 11.1 Aset dan ancaman

| Aset | Ancaman | Mitigasi di desain |
|---|---|---|
| Isi suara individu | Penyadap di jaringan | Ciphertext ElGamal di dalam saluran DH |
| Isi suara individu | Server mengintip | Server hanya menyimpan ciphertext, `x` hanya di `authority.js`, tidak ada endpoint dekripsi per ballot |
| PIN voter | Penyadap di jaringan | PIN hanya dikirim di dalam paket aman |
| Integritas paket | Modifikasi di jalan | HMAC (encrypt-then-MAC) |
| Pemilihan ganda | Voter kirim dua kali | `hasVoted` atomik di ballot box |
| Replay | Paket lama dikirim ulang | `seq` monoton, sesi satu kali pakai |
| Nilai DH berbahaya | `A = 1`, `A = p-1`, subgrup kecil | `isInSubgroup` |
| Nonce `k` berulang | Bocornya hubungan antar ciphertext | `k` acak baru, ada tes unik |
| MITM pada DH | Penyerang menukar `A`/`B` | `[BONUS]` tanda tangan ElGamal atas transkrip |

### 11.2 Batasan yang diakui (masuk laporan)

1. **DH polos tidak terautentikasi.** Rentan MITM tanpa `[BONUS]` tanda tangan.
2. **Tidak ada bukti validitas suara.** Voter jahat bisa mengirim `v = 5` atau lebih dari satu `1`. Deteksi parsial: `sum T_j != V`. Solusi penuh: *disjunctive Chaum-Pedersen ZKP* (`[BONUS]`, Bagian 13 Fase 7).
3. **Server dan EA satu proses.** Secara teori operator server bisa memanggil dekripsi pada ballot individu. Mitigasi demo: pemisahan modul dan tidak ada jalur kode untuk itu. Solusi nyata: *threshold ElGamal* atau pembagian kunci (di luar cakupan).
4. **Anonimitas parsial.** Saat ballot diterima, server tahu sesi siapa yang mengirim. Ballot box tidak menyimpan identitas, tetapi log jaringan bisa menghubungkan. Solusi nyata: *mix-net* atau *blind signature* (di luar cakupan).
5. **Saluran buatan sendiri bukan standar industri.** Hanya demonstrasi penggunaan `K`.
6. **Parameter mode demo (32 bit) tidak aman secara kriptografis.** Hanya untuk visualisasi. Mode 512 bit ke atas untuk ilustrasi skala.
7. **Tidak ada verifikasi *end-to-end* penuh** (hanya receipt dan konsistensi total).

---


## 12. Strategi Pengujian

Pengujian memakai runner bawaan Node.js (`node --test`) atau skrip `assert` sederhana, tanpa library uji eksternal.

### 12.1 Unit test per modul

| Modul | Kasus uji | Hasil yang diharapkan |
|---|---|---|
| `modExp` | Bandingkan dengan perhitungan naif `(b**e) % m` untuk nilai kecil (1000 acak). Kasus tepi: `exp=0`, `base=0`, `mod=1` | Selalu sama |
| `modExp` | `4^11 mod 23`, `4^6 mod 23`, `18^6 mod 23` | `1`, `2`, `8` |
| `egcd` / `modInv` | `a * modInv(a,m) mod m == 1` untuk 1000 pasangan koprima. `modInv(4,23) = 6` | Benar. Error jika tidak koprima |
| `isProbablePrime` | Prima: 2, 3, 97, 7919, 104729. Komposit: 1, 4, 561 (Carmichael), 1105, 1729, 2047 | Benar |
| `genSafePrime(32)` | `p`, `q` prima, `p = 2q+1`, `bitLength(p) = 32` | Benar |
| `findGenerator` | `g != 1`, `g^q mod p == 1`, `g^1 != 1` | Benar |
| `isInSubgroup` | Tolak `0, 1, p-1, p`. Terima `g^k` | Benar |
| `rng` | Semua nilai di rentang, distribusi kasar seragam (histogram 10 kotak) | Dalam rentang |
| `sha256` | `""` -> `e3b0c442...b855`. `"abc"` -> `ba7816bf...15ad` | Cocok dengan vektor standar |
| `hmac` | Vektor uji RFC 4231 | Cocok |
| `dh` | 1000 kali: `K_voter == K_server` | Selalu sama |
| `dh` | `A` tidak valid ditolak | Error |
| `elgamal` | Dekripsi(Enkripsi(m)) = m untuk 1000 `m` acak di subgrup | Selalu benar |
| `elgamal` | Dua enkripsi `m` yang sama menghasilkan ciphertext berbeda | Berbeda |
| `elgamal` | Test vector Bagian 6.10 (`p=23, g=4, x=7`, `k=3` dan `k=5`) | `(18,1)`, `(12,16)`, agregat `(9,16)`, `T=1` |
| Homomorfik | `Dec(Enc(g^a) * Enc(g^b)) = g^(a+b)` | Benar |
| Tanda tangan `[BONUS]` | Valid lolos. Pesan diubah 1 bit ditolak. `r` atau `s` di luar rentang ditolak | Benar |
| `channel` | `open(seal(m)) = m`. Ubah 1 bit `ct` atau `tag` ditolak. `seq` ulang ditolak. `dir` ditukar ditolak | Benar |
| `ballotbox` | `cast` kedua dari voter sama ditolak. Receipt unik | Benar |

### 12.2 Uji integrasi

1. **Handshake:** klien dan server menghasilkan `encKey` dan `macKey` identik. Paket konfirmasi diterima.
2. **Login:** PIN benar diterima, salah ditolak, 3 kali salah membatalkan sesi.
3. **Alur sah:** 5 voter memilih kombinasi kandidat, tally sama dengan hitungan manual.
4. **Double voting:** percobaan kedua dari voter yang sama ditolak (409).
5. **Replay:** mengirim ulang paket `/api/vote` yang sama ditolak.
6. **Tamper:** mengubah `ct` pada paket ditolak (401) tanpa mendekripsi.
7. **State:** voting sebelum `VOTING` dan tally sebelum `CLOSED` ditolak (403).
8. **Konsistensi:** `sum T_j == V`. Ballot sengaja tidak valid (`v=5`) memunculkan peringatan konsistensi.

### 12.3 Uji non-fungsional

- **Kinerja:** waktu `genSafePrime` untuk 32/128/256/512 bit dicatat untuk laporan. Waktu enkripsi ballot 3 kandidat pada 512 bit.
- **Kepatuhan "tanpa library":** `npm run check-banned` memindai `shared/` untuk kata `Math.random`, `createDiffieHellman`, `createECDH`, `subtle`, `modPow`, `require('crypto')`, dan impor modul pihak ketiga.
- **Pemindaian jaringan manual:** buka tab Network, pastikan `/api/login` dan `/api/vote` tidak memuat PIN atau ballot polos.
- **Uji lintas browser:** Chrome dan Firefox terbaru.

---

## 13. Rencana Pengerjaan

Estimasi jam kerja bersih untuk satu orang `[ASUMSI]`. Sesuaikan dengan tenggat sebenarnya.

| Fase | Nama | Tugas utama | Estimasi | Deliverable | Kriteria selesai |
|---|---|---|---|---|---|
| **0** | Persiapan dan konfirmasi | Kirim pertanyaan ke dosen (Bagian 18). Siapkan repo, `package.json`, struktur folder, `README` awal. Putuskan studi kasus final | 2-3 jam | Repo kosong terstruktur, jawaban dosen dicatat | Keputusan T6 jelas |
| **1** | Fondasi matematika | `rng.js`, `math_utils.js` (`modExp`, `egcd`, `modInv`, Miller-Rabin, prima, safe prime, generator, subgroup), `encoding.js`. Uji unit lengkap | 6-8 jam | Modul + `math_utils.test.js` hijau | Semua tes Bagian 12.1 untuk math lulus |
| **2** | Hash dan saluran | `sha256.js`, `hmac.js`, `channel.js` (derive key, seal, open). Uji dengan vektor standar | 5-6 jam | Modul + tes | SHA-256 dan HMAC cocok dengan vektor. Tamper/replay ditolak |
| **3** | DH dan ElGamal | `dh.js`, `elgamal.js` (keygen, enkripsi, dekripsi, perkalian, encode ballot, recover tally). Test vector Bagian 6.10 | 5-6 jam | Modul + tes | Test vector `p=23` lulus, 1000 uji acak lulus |
| **4** | Backend | `server.js`, `session.js`, `authority.js`, `ballotbox.js`, `voters.js`, `electionState.js`, `logger.js`. Semua endpoint Bagian 8.3 | 8-10 jam | Server berjalan, bisa diuji dengan klien Node | Uji integrasi 12.2 poin 1-7 lulus (tanpa UI) |
| **5** | Frontend | Panel log, halaman admin, voter (stepper), ballots, results, lab. Web Worker untuk prima besar | 10-12 jam | UI lengkap | Satu alur penuh bisa dijalankan murni lewat UI |
| **6** | Integrasi dan pengerasan | E2E test, perbaikan bug, validasi input, pesan error, `check-banned`, rapikan komentar rumus | 4-6 jam | `e2e.test.js`, daftar bug tertutup | Semua test hijau, tidak ada pelanggaran `check-banned` |
| **7** | `[BONUS]` | (a) Tanda tangan ElGamal + demo MITM. (b) ZKP Chaum-Pedersen untuk validitas suara. (c) Mode langkah demi langkah | 6-10 jam | Fitur bonus + tes | Demo MITM berhasil digagalkan |
| **8** | Laporan dan presentasi | Laporan (Bagian 15), tangkapan layar, latihan demo (Bagian 14), cadangan video demo | 8-10 jam | Laporan + slide + video cadangan | Dua kali geladi bersih tanpa error |

**Total:** sekitar 54-71 jam, dengan Fase 7 yang bisa dilewati bila waktu mepet.

### 13.1 Urutan prioritas jika waktu terbatas

1. **Wajib (inti penilaian):** Fase 1, 3, 4, 5 (versi minimal), 6, 8.
2. **Sangat dianjurkan:** Fase 2 (membuat `K` DH benar-benar dipakai). Versi paling ringan: SHA-256 sendiri + keystream XOR + HMAC.
3. **Bonus:** Fase 7 (a) lebih bernilai daripada (b), karena langsung menjawab kelemahan DH yang pasti ditanyakan.

### 13.2 Detail Fase 7 (bonus)

**(b) ZKP validitas suara (opsional lanjutan).** Untuk tiap ciphertext `(c1, c2)` buktikan bahwa `m` adalah `g^0` atau `g^1` dengan *disjunctive Chaum-Pedersen proof* (dibuat non-interaktif lewat Fiat-Shamir memakai SHA-256 sendiri). Tambahkan bukti bahwa jumlah `v_i` dalam satu ballot adalah 1. Server memverifikasi sebelum menyimpan. Ini menutup batasan nomor 2 di Bagian 11.2. Perkiraan tambahan 6-8 jam, **hanya** jika Fase 1-6 sudah stabil.

### 13.3 Strategi kontrol versi

- Satu cabang `main`, commit kecil per fungsi.
- Pesan commit mengikuti fase (mis. `fase1: modExp + tes`).
- Tag `v1-inti` setelah Fase 6, `v2-bonus` setelah Fase 7, sebagai titik aman sebelum presentasi.

---

## 14. Skenario Demo dan Presentasi

Durasi sasaran: 10-12 menit. Mode default: **demo (32 bit)** dengan sakelar "Mode edukasi" aktif.

### 14.1 Naskah demo

| Menit | Adegan | Yang ditunjukkan | Poin yang disampaikan |
|---|---|---|---|
| 0-1 | Pembuka | Studi kasus dan arsitektur (diagram 4.3) | Dua masalah: saluran aman dan suara rahasia |
| 1-3 | **Lab:** DH dan ElGamal angka kecil | `p=23, g=4`, hitung bertahap, cocok dengan Bagian 6.10 | Penjelasan rumus tiap tahap sebelum masuk aplikasi |
| 3-4 | **Admin:** Setup | Parameter `p, q, g` terbentuk, keypair EA, `h` tampil, `x` tersembunyi | Tahap 1-2 pada tabel Bagian 5 |
| 4-5 | **Admin:** daftar 5 voter, buka voting | PIN dicetak sekali | - |
| 5-7 | **Voter V001:** handshake DH | `a, A, B, K` di panel log, "K voter == K server" | Tahap 3-6: DH menghasilkan `K` tanpa mengirimnya |
| 7-8 | V001 login dan memilih | PIN lewat saluran aman, ciphertext `(c1, c2)` per kandidat | Tahap 7-8: ElGamal di browser, ruang lingkup saluran DH |
| 8 | **Tab Network** | Payload `/api/vote` berupa `ct` dan `tag` | Penyadap tidak melihat apa pun |
| 8-9 | **Serangan: double voting** | V001 mencoba lagi, ditolak. Replay paket ditolak | Fungsi ballot box dan `seq` |
| 9 | **Voter V002-V005** memilih (dipercepat) | Ballot box publik berisi ciphertext tanpa identitas | Server tidak tahu isi suara |
| 9-11 | **Admin:** tutup, tally | Agregasi `(C1, C2)`, dekripsi hanya total, pemulihan `T`, konsistensi | Tahap 10-13: sifat homomorfik |
| 11-12 | `[BONUS]` **Serangan MITM** | Tanpa tanda tangan lolos, dengan tanda tangan gagal | Kelemahan DH dan solusinya |
| 12 | Penutup | Ringkasan batasan (Bagian 11.2) | Kejujuran ilmiah |

### 14.2 Data demo yang disiapkan

- 5 voter: V001-V005 dengan PIN tetap untuk demo.
- Pilihan: V001 -> K1, V002 -> K2, V003 -> K1, V004 -> K3, V005 -> K1. **Hasil yang diharapkan:** K1 = 3, K2 = 1, K3 = 1, total = 5.
- Cadangan: `state.json` demo siap pakai dan video rekaman jika ada kendala teknis.

### 14.3 Pertanyaan yang mungkin diajukan dosen dan jawaban singkat

| Pertanyaan | Poin jawaban |
|---|---|
| Mengapa memakai ElGamal eksponensial? | Agar perkalian ciphertext menjadi penjumlahan suara, sehingga hanya total yang didekripsi |
| Apa fungsi DH di sini? | Membangun `K` untuk saluran aman voter-server tanpa mengirim `K` |
| Mengapa `k` harus acak tiap kali? | Pemakaian ulang `k` membocorkan rasio plaintext dan menghilangkan kerahasiaan |
| Bagaimana mencegah MITM? | Tanda tangan ElGamal atas transkrip DH `[BONUS]` atau sertifikat |
| Apakah suara palsu bisa dikirim? | Ya tanpa ZKP. Dideteksi sebagian lewat konsistensi total |
| Mengapa prima aman? | Subgrup orde prima `q`, mencegah serangan subgrup kecil dan menyederhanakan validasi |
| Mengapa 32 bit di demo? | Hanya untuk visualisasi. Mode 512/2048 bit untuk skala nyata |

---

## 15. Outline Laporan

| Bab | Isi | Sumber di dokumen ini |
|---|---|---|
| 1. Pendahuluan | Latar belakang, tujuan, ketentuan tugas, ruang lingkup | Bagian 1-2 |
| 2. Landasan teori | Aritmetika modular, grup siklik, masalah logaritma diskret, DH, ElGamal (enkripsi, tanda tangan), sifat homomorfik, prima aman | Bagian 6, 19 |
| 3. Studi kasus dan kebutuhan | Skenario BEM, aktor, kebutuhan keamanan | Bagian 3 |
| 4. Perancangan | Arsitektur, peta peran kripto, protokol, format pesan, struktur data | Bagian 4, 5, 7, 8 |
| 5. Implementasi | Modul-modul, potongan kode inti dengan komentar rumus, UI, tangkapan layar panel log | Bagian 9, 10 |
| 6. Pengujian | Hasil unit/integrasi, bukti Network, tabel waktu pembangkitan prima | Bagian 12 |
| 7. Analisis keamanan | Threat model, serangan yang dicoba (double voting, replay, tamper, MITM), batasan | Bagian 11 |
| 8. Kesimpulan dan saran | Ringkasan pencapaian, pengembangan (threshold ElGamal, ZKP, mix-net, TLS) | - |
| Lampiran | Contoh numerik, log lengkap satu alur, panduan menjalankan, daftar pernyataan "bagian bawaan yang dipakai" | Bagian 6.10 |

**Bagian khusus yang disarankan:** satu tabel "Apa yang ditulis sendiri vs apa yang bawaan" agar kepatuhan ketentuan T2 terlihat jelas:

| Komponen | Sendiri? | Keterangan |
|---|---|---|
| Diffie-Hellman, ElGamal | Ya | `dh.js`, `elgamal.js` |
| `modExp`, `modInv`, Miller-Rabin, generator | Ya | `math_utils.js` |
| SHA-256, HMAC | Ya | `sha256.js`, `hmac.js` |
| Tipe `BigInt` | Tidak (tipe data) | Fitur bahasa JavaScript |
| Sumber bit acak | Tidak (dari OS) | `crypto.getRandomValues` hanya untuk bit acak |
| Server HTTP | Tidak | Express / `node:http` |

---

## 16. Risiko dan Mitigasi

| # | Risiko | Dampak | Kemungkinan | Mitigasi |
|---|---|---|---|---|
| R1 | Dosen menganggap `BigInt` atau `getRandomValues` tidak boleh | Perlu desain ulang kecil | Rendah | Tanyakan di Fase 0. Cadangan: kelas `BigNum` sederhana dan PRNG sendiri |
| R2 | Pembangkitan prima aman besar terlalu lama | Demo macet | Sedang | Web Worker, mode demo 32 bit default, 2048 bit pakai konstanta standar, cache parameter |
| R3 | `K` browser dan server berbeda (beda panjang byte, endian) | Handshake gagal | Sedang | Serialisasi panjang tetap, tes lintas sisi sejak Fase 2 |
| R4 | Bug aritmetika `BigInt` negatif pada `egcd` | Hasil invers salah | Sedang | Normalisasi `((x % m) + m) % m`, tes acak 1000 kali |
| R5 | Waktu tidak cukup | Fitur kurang | Sedang | Prioritas pada 13.1, tag versi aman, bonus dilewati |
| R6 | Server restart menghilangkan state saat demo | Demo gagal | Sedang | `state.json` dan skrip seed demo |
| R7 | Kegagalan jaringan/perangkat saat presentasi | Demo gagal | Rendah | Video cadangan, jalankan lokal tanpa internet |
| R8 | Ballot tidak valid (tanpa ZKP) merusak hasil | Hasil salah | Rendah (demo) | Indikator konsistensi, jelaskan sebagai batasan |
| R9 | Timing attack pada `modExp` | Tidak relevan untuk demo | Sangat rendah | Dicatat sebagai batasan, bukan target |
| R10 | Klaim "aman" berlebihan | Dosen mempertanyakan | Sedang | Laporan jujur soal batasan (Bagian 11.2) |

---

## 17. Checklist Kepatuhan dan Kriteria Selesai

### 17.1 Kepatuhan ketentuan tugas

- [ ] DH ditulis sendiri (`dh.js`) tanpa library atau API DH bawaan
- [ ] ElGamal ditulis sendiri (`elgamal.js`) tanpa library atau API bawaan
- [ ] `modExp`, `modInv`, uji primalitas, pembangkit prima, pencari generator ditulis sendiri
- [ ] Setiap tahap DH tampil: `a`, `A`, `b`, `B`, `K` (dua sisi), validasi nilai publik
- [ ] Setiap tahap ElGamal tampil: keygen, enkripsi (`k`, `c1`, `c2`), dekripsi, perkalian homomorfik
- [ ] Satu studi kasus yang utuh dari setup sampai hasil
- [ ] Program e-voting memiliki registrasi, pemungutan suara, ballot box, tally, hasil
- [ ] Tabel "ditulis sendiri vs bawaan" ada di laporan
- [ ] `check-banned` bersih

### 17.2 Kriteria fungsional

- [ ] Handshake menghasilkan `K` identik di dua sisi dan konfirmasi HMAC lolos
- [ ] PIN dan ballot tidak terlihat polos di tab Network
- [ ] Double voting dan replay ditolak
- [ ] Paket yang diubah ditolak sebelum didekripsi
- [ ] Hanya total yang didekripsi, tidak ada endpoint dekripsi ballot individual
- [ ] Hasil tally sama dengan hitungan manual pada data demo (K1=3, K2=1, K3=1)
- [ ] Indikator konsistensi `sum T == V` tampil
- [ ] Lab memuat test vector `p=23, g=4` dengan hasil sesuai Bagian 6.10

### 17.3 Kriteria kualitas

- [ ] Semua unit test dan E2E test lulus
- [ ] Kode berkomentar rumus pada setiap fungsi kripto
- [ ] README berisi cara menjalankan, struktur, batasan
- [ ] Dua kali geladi bersih demo tanpa error
- [ ] Video demo cadangan tersedia

### 17.4 Definition of Done

Proyek dianggap selesai bila seluruh butir 17.1 dan 17.2 terpenuhi, tes lulus, laporan lengkap, dan demo berjalan sesuai naskah Bagian 14. Butir `[BONUS]` tidak menjadi syarat selesai.

---

## 18. Pertanyaan Terbuka untuk Dosen

1. Apakah tipe bilangan besar bawaan bahasa (`BigInt`) boleh dipakai sebagai tipe data, selama seluruh algoritma ditulis sendiri?
2. Apakah sumber bit acak dari sistem operasi/browser (`crypto.getRandomValues`) boleh dipakai, atau PRNG harus buatan sendiri?
3. Apakah fungsi hash (SHA-256) boleh memakai implementasi bawaan, atau sebaiknya ditulis sendiri? (Rencana ini menulis sendiri untuk aman.)
4. Apakah Express (framework web) untuk server HTTP diperbolehkan? Alternatif: `node:http` bawaan.
5. Apakah konstanta parameter standar (RFC 3526, 2048 bit) boleh dipakai untuk mode realistis, atau parameter harus dibangkitkan sendiri?
6. Apakah ada ketentuan studi kasus tertentu, atau studi kasus bebas (Pemilihan Ketua BEM diasumsikan)?
7. Apakah fitur tanda tangan ElGamal (bonus) dihargai, atau cukup enkripsi dan DH?
8. Format pengumpulan dan penilaian: kode, laporan, demo langsung, atau video?
9. Apakah ada batas ukuran parameter minimal yang diharapkan (misal minimal 512 bit)?

---

## 19. Lampiran

### 19.1 Pseudocode inti

**Square-and-multiply**

```
function modExp(base, exp, mod):
    if mod == 1: return 0
    result = 1
    base = base mod mod
    while exp > 0:
        if exp is odd:
            result = (result * base) mod mod
        exp = exp >> 1
        base = (base * base) mod mod
    return result
```

**Extended Euclid dan invers modular**

```
function egcd(a, b):
    (old_r, r) = (a, b)
    (old_x, x) = (1, 0)
    (old_y, y) = (0, 1)
    while r != 0:
        q = old_r div r
        (old_r, r) = (r, old_r - q*r)
        (old_x, x) = (x, old_x - q*x)
        (old_y, y) = (y, old_y - q*y)
    return (old_r, old_x, old_y)          // gcd, koefisien x, y

function modInv(a, m):
    (g, x, _) = egcd(a mod m, m)
    if g != 1: error "tidak punya invers"
    return ((x mod m) + m) mod m
```

**Miller-Rabin**

```
function isProbablePrime(n, rounds):
    if n < 2: return false
    for p in smallPrimes: 
        if n == p: return true
        if n mod p == 0: return false
    write n-1 = 2^s * d  dengan d ganjil
    repeat rounds kali:
        a = random in [2, n-2]
        x = modExp(a, d, n)
        if x == 1 or x == n-1: lanjut
        ulangi s-1 kali:
            x = (x*x) mod n
            if x == n-1: lanjut ke putaran berikutnya
        return false                      // komposit
    return true                           // kemungkinan prima
```

**Pembangkit prima aman dan generator**

```
function genSafePrime(bits):
    loop:
        q = random bilangan (bits-1) bit, bit tertinggi dan terendah = 1
        if q habis dibagi prima kecil: ulang
        if not isProbablePrime(q): ulang
        p = 2*q + 1
        if isProbablePrime(p): return (p, q)

function findGenerator(p, q):
    loop:
        h = random in [2, p-2]
        g = modExp(h, 2, p)
        if g != 1: return g               // pasti berorde q
```

**Aliran protokol ringkas**

```
SETUP : (p,q,g) <- genSafePrime ; x <- rand ; h <- g^x
LOGIN : a <- rand ; A <- g^a  ->  server: b <- rand ; B <- g^b ; K <- A^b
        voter: K <- B^a ; encKey,macKey <- KDF(K)
VOTE  : v_i in {0,1} ; (c1_i, c2_i) <- (g^k_i , g^{v_i} * h^k_i)  -> kirim lewat saluran (encKey,macKey)
TALLY : C1_j <- prod c1 ; C2_j <- prod c2 ; gT <- C2_j * (C1_j^x)^{-1} ; T <- dlog kecil
```

### 19.2 Ringkasan rumus

| Konsep | Rumus |
|---|---|
| Kunci publik DH | `A = g^a mod p`, `B = g^b mod p` |
| Kunci bersama | `K = B^a = A^b = g^(ab) mod p` |
| Kunci publik ElGamal | `h = g^x mod p` |
| Enkripsi | `c1 = g^k`, `c2 = m * h^k (mod p)` |
| Dekripsi | `m = c2 * (c1^x)^(-1) mod p` |
| Homomorfik (perkalian ciphertext) | `(c1,c2)*(c1',c2') = (c1*c1', c2*c2')` mengenkripsikan `m*m'` |
| Enkripsi suara | `m = g^v`, sehingga perkalian menjumlahkan `v` |
| Tanda tangan `[BONUS]` | `r = g^k`, `s = k^(-1)(H - xs*r) mod q`, verifikasi `g^H = ys^r * r^s` |
| Prima aman | `p = 2q + 1`, `p` dan `q` prima |
| Keanggotaan subgrup | `y^q mod p == 1` |

### 19.3 Glosarium

| Istilah | Arti |
|---|---|
| EA (Election Authority) | Panitia pemilu yang memegang private key ElGamal |
| Ballot box | Penyimpan ciphertext suara |
| Receipt | Hash ballot sebagai bukti terima bagi voter |
| Prima aman | Prima `p` dengan `(p-1)/2` juga prima |
| Subgrup orde `q` | Himpunan `{g^i}` dengan `q` elemen |
| Exponential ElGamal | Varian ElGamal dengan pesan `g^m` sehingga homomorfik aditif |
| Replay | Pengiriman ulang paket lama |
| MITM | *Man-in-the-middle*, penyerang yang berada di tengah saluran |
| ZKP | *Zero-knowledge proof*, bukti tanpa membuka rahasia |
| Encrypt-then-MAC | Enkripsi dulu, lalu hitung MAC atas ciphertext |

---

*Akhir dokumen rencana. Langkah berikutnya setelah rencana disetujui: mulai Fase 0 (konfirmasi dosen) dan Fase 1 (`rng.js` dan `math_utils.js`).*