# Laporan Pengembangan Sistem E-Voting Berbasis Diffie-Hellman dan Exponential ElGamal Tanpa Library Kriptografi

---

## Bab 1: Pendahuluan

### 1.1 Latar Belakang
Pemilihan umum secara elektronik (*e-voting*) membutuhkan pemenuhan dua sifat keamanan yang tampak bertentangan: kerahasiaan pilihan pemilih (*ballot secrecy*) dan keterverifikasian hasil pemilu (*auditability*). Selain itu, komunikasi antara perangkat pemilih (*voter*) dan server pemilihan rentan terhadap penyadapan dan manipulasi pada jaringan publik.

Algoritma pertukaran kunci **Diffie-Hellman (DH)** dan sistem kriptografi kunci publik **ElGamal** merupakan dua pilar utama dalam kriptografi modern yang memanfaatkan kesulitan komputasi masalah logaritma diskret (*Discrete Logarithm Problem / DLP*). Dalam tugas ini, kedua algoritma tersebut diintegrasikan ke dalam satu arsitektur terpadu:
1. **Diffie-Hellman** digunakan untuk membangun saluran komunikasi terenkripsi dan terotentikasi (*secure session channel*) antara browser pemilih dan server.
2. **Exponential ElGamal** digunakan untuk mengenkripsi surat suara secara langsung di browser pemilih serta memanfaatkan sifat homomorfik aditif pada eksponen untuk menjumlahkan perolehan suara tanpa pernah mendekripsi pilihan suara individu.

### 1.2 Ketentuan Tugas dan Batasan
Sesuai dengan ketentuan tugas (T1 s.d. T6):
- Seluruh konsep DH dan ElGamal beserta matematika pendukungnya (eksponensiasi modular *square-and-multiply*, Extended Euclidean, invers modular, uji primalitas Miller-Rabin, pembangkitan *safe prime*, dan generator subgrup) **diimplementasikan sendiri dari nol**.
- Penggunaan library kriptografi eksternal maupun API bawaan untuk DH/ElGamal (`crypto.createDiffieHellman`, `crypto.subtle`, library `modPow`, dll.) dilarang secara mutlak.
- Program mendemonstrasikan setiap tahapan perhitungan secara transparan dengan nilai variabel yang dapat diverifikasi melalui antarmuka web dan panel log kriptografi.

---

## Bab 2: Landasan Teori

### 2.1 Grup Siklik dan Masalah Logaritma Diskret (DLP)
Diberikan grup siklik $\mathbb{G}$ berorde $q$ dengan generator $g$. Masalah logaritma diskret adalah: diberikan $g \in \mathbb{G}$ dan $y = g^x \in \mathbb{G}$, tentukan nilai eksponen rahasia $x$. Dalam grup perkalian $\mathbb{Z}_p^*$, keamanan bergantung pada ukuran prima $p$ dan subgrup prima besar $q$.

### 2.2 Bilangan Prima Aman (*Safe Prime*) dan Subgrup Orde $q$
Untuk mencegah serangan *Pohlig-Hellman* dan *small-subgroup confinement attack*, sistem menggunakan bilangan prima aman berordo:
$$p = 2q + 1$$
di mana $q$ adalah bilangan prima (*Sophie Germain prime*). Orde dari $\mathbb{Z}_p^*$ adalah $p - 1 = 2q$. Subgrup kuadratik residu berorde $q$ dapat dibangkitkan oleh elemen:
$$g = h^2 \bmod p \quad (\text{dengan } g \neq 1)$$
Setiap elemen $y$ dalam subgrup orde $q$ memenuhi syarat keanggotaan:
$$y^q \equiv 1 \pmod p$$

### 2.3 Protokol Pertukaran Kunci Diffie-Hellman
1. Parameter bersama: $(p, q, g)$.
2. Pemilih memilih $a \in [2, q-1]$, menghitung $A = g^a \bmod p$.
3. Server memilih $b \in [2, q-1]$, menghitung $B = g^b \bmod p$.
4. Pertukaran nilai publik $A$ dan $B$.
5. Masing-masing pihak memverifikasi $A, B \in \text{Subgrup}(q)$ dan menghitung *shared secret*:
   $$K = B^a \equiv (g^b)^a \equiv g^{ab} \equiv (g^a)^b \equiv A^b \pmod p$$

### 2.4 Exponential ElGamal dan Sifat Homomorfik Aditif
Pada ElGamal standar, enkripsi dari pesan $m$ adalah:
$$c_1 = g^k \bmod p, \quad c_2 = m \cdot h^k \bmod p$$
Pada varian eksponensial untuk suara $v \in \{0, 1\}$, pesan disandikan sebagai eksponen dari generator:
$$m = g^v \bmod p$$
Diberikan dua ciphertext untuk pilihan $v_1$ dan $v_2$:
$$\text{Enc}(v_1) = (g^{k_1}, g^{v_1} h^{k_1}), \quad \text{Enc}(v_2) = (g^{k_2}, g^{v_2} h^{k_2})$$
Perkalian komponen demi komponen menghasilkan:
$$C_1 = c_{1,1} \cdot c_{1,2} = g^{k_1 + k_2} \bmod p$$
$$C_2 = c_{2,1} \cdot c_{2,2} = g^{v_1 + v_2} \cdot h^{k_1 + k_2} \bmod p$$
Saat didekripsi menggunakan kunci privat EA $x$ (di mana $h = g^x \bmod p$):
$$s = C_1^x = g^{x(k_1+k_2)} = h^{k_1+k_2} \bmod p$$
$$g^T = C_2 \cdot s^{-1} = g^{v_1 + v_2} \pmod p$$
Jumlah total suara $T = \sum v_i$ dapat dipulihkan dengan pencarian logaritma diskret rentang kecil ($T \in [0, V]$) karena $V$ bernilai kecil.

---

## Bab 3: Studi Kasus dan Kebutuhan

### 3.1 Studi Kasus: Pemilihan Ketua BEM Fakultas
- **Kandidat**: 3 Calon (Andi Pratama, Citra Lestari, Dimas Wibowo).
- **Pemilih**: 5 pemilih terdaftar (V001 s.d. V005) dengan PIN rahasia.
- **Kebutuhan Fungsional**:
  1. Panitia (Election Authority/EA) dapat membangkitkan parameter dan pasangan kunci.
  2. Pemilih dapat melakukan login terenkripsi dan memilih 1 dari 3 kandidat.
  3. Ballot box publik menyimpan suara terenkripsi tanpa identitas pemilih (*ballot secrecy*).
  4. Mencegah pemilihan ganda (*anti-double voting*) dan pengiriman ulang (*anti-replay*).
  5. Penghitungan suara dilakukan secara homomorfik: EA hanya mendekripsi total suara.

---

## Bab 4: Perancangan Sistem & Protokol Kriptografi

### 4.1 Peta 14 Tahapan Kriptografi
1. **Setup Parameter**: Pembangkitan $(p, q, g)$ pada subgrup orde $q$.
2. **Keygen EA**: Kunci privat $x \in [2, q-1]$, kunci publik $h = g^x \bmod p$.
3. **Handshake Voter**: Voter membangkitkan $(a, A = g^a \bmod p)$.
4. **Handshake Server**: Server membangkitkan $(b, B = g^b \bmod p)$.
5. **Kunci Sesi Bersama**: Voter menghitung $K = B^a$, Server menghitung $K = A^b$.
6. **Penurunan Kunci Sesi**: `encKey` dan `macKey` via KDF SHA-256.
7. **Enkripsi Suara**: Browser mengenkripsi vektor suara $(c_{1,i}, c_{2,i})$.
8. **Pengamanan Saluran**: Paket aman dengan Keystream XOR + HMAC-SHA256 Encrypt-then-MAC.
9. **Kotak Suara Anonim**: Penyimpanan tanpa identitas pemilih dan penerbitan *receipt*.
10. **Agregasi Homomorfik**: Perkalian ciphertext per kandidat: $C_1 = \prod c_1$, $C_2 = \prod c_2$.
11. **Dekripsi Total EA**: $s = C_1^x$, $g^T = C_2 \cdot s^{-1} \bmod p$.
12. **Pemulihan Suara $T$**: Pencarian $T \in [0, V]$ sehingga $g^T = \text{hasil dekripsi}$.
13. **Verifikasi Konsistensi**: Audit $\sum_{j=1}^N T_j = V$.
14. **[BONUS] Autentikasi DH**: Tanda tangan ElGamal server atas transkrip handshake untuk menangkal MITM.

---

## Bab 5: Implementasi Modul

### 5.1 Struktur Berkas
- `shared/math_utils.js`: Implementasi `modExp`, `egcd`, `modInv`, `isProbablePrime`, `genSafePrime`, `findGenerator`, `isInSubgroup`.
- `shared/sha256.js`: Implementasi mandiri hash SHA-256 (FIPS 180-4).
- `shared/hmac.js`: Implementasi HMAC-SHA256 (RFC 2104) dan `constantTimeEqual`.
- `shared/rng.js`: Pembangkit bit acak seragam dengan *rejection sampling* dan cadangan CTR-DRBG.
- `shared/dh.js`: Pembangkitan kunci dan komputasi *shared secret* Diffie-Hellman.
- `shared/elgamal.js`: Exponential ElGamal, enkripsi ballot, agregasi homomorfik, pemulihan tally, dan tanda tangan digital ElGamal.
- `shared/channel.js`: Derivasi kunci KDF, enkripsi paket *keystream* XOR, dan verifikasi HMAC.
- `server/*`: State machine pemilu, manajemen sesi DH, otoritas pemilu EA, ballot box, dan server HTTP Express.
- `public/*`: Antarmuka bilik suara stepper 4 langkah, panel admin, ballot box audit, hasil pemilu, dan playground lab interaktif.

---

## Bab 6: Pengujian dan Hasil Evaluasi

### 6.1 Hasil Pengujian Otomatis (`npm test`)
Pengujian mencakup 20 unit test dan integrasi end-to-end tanpa framework testing eksternal:
1. `math_utils.test.js`: Verifikasi `modExp`, invers modular, uji komposit/Carmichael, dan pembangkitan prima aman.
2. `sha256_hmac.test.js`: Verifikasi terhadap test vector NIST SHA-256 dan RFC 4231 HMAC-SHA256.
3. `dh.test.js`: Verifikasi $K_{\text{voter}} = K_{\text{server}}$ dan penolakan nilai publik di luar subgrup.
4. `elgamal.test.js`: Verifikasi test vector eksak Bagian 6.10 ($p=23, q=11, g=4, x=7 \Rightarrow T=1$), agregasi multi-kandidat, dan tanda tangan digital.
5. `channel.test.js`: Verifikasi anti-tamper (1-bit modifikasi ditolak), anti-replay, dan anti-reflection.
6. `ballotbox.test.js`: Verifikasi pencegahan pemilihan ganda (HTTP 409 Conflict) dan penyimpanan anonim.
7. `e2e.test.js`: Simulasi pemilu utuh dengan 5 pemilih:
   - Hasil akhir: **Kandidat 1 = 3 suara, Kandidat 2 = 1 suara, Kandidat 3 = 1 suara**.
   - Total suara = 5, konsistensi $\sum T_j = V$ terbukti valid (`consistent: true`).

### 6.2 Pemeriksaan Kepatuhan Banned Tokens (`npm run check-banned`)
Pemindaian seluruh berkas di `shared/` membuktikan **0 pelanggaran**: tidak ada penggunaan `Math.random`, `crypto.createDiffieHellman`, `subtle`, `modPow`, maupun library pihak ketiga.

---

## Bab 7: Analisis Keamanan & Batasan Sistem

1. **Kerahasiaan Suara**: Terjamin karena server hanya menerima ciphertext ElGamal. Pemulihan total suara hanya didekripsi pada hasil kali agregat.
2. **Keamanan Saluran**: PIN dan komunikasi diamankan menggunakan kunci sesi DH yang diturunkan melalui KDF SHA-256 dan dilindungi otentikasi HMAC-SHA256.
3. **Pencegahan Double Voting & Replay**: Server memverifikasi status `hasVoted` secara atomik dan menolak *sequence number* paket yang tidak monotonik.
4. **Mitigasi MITM**: Transkrip pertukaran kunci DH ditandatangani oleh server menggunakan kunci ElGamal $x_s$ dan diverifikasi oleh browser pemilih sebelum kunci sesi digunakan.

---

## Bab 8: Kesimpulan

Sistem e-voting berbasis web telah berhasil dibangun dan memenuhi seluruh ketentuan tugas tanpa library kriptografi. Integrasi Diffie-Hellman untuk pengamanan saluran komunikasi dan Exponential ElGamal untuk enkripsi suara homomorfik terbukti dapat berjalan berdampingan secara harmonis, transparan, dan dapat diaudit secara matematis.
