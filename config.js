// Konfigurasi Terpusat E-Voting Diffie-Hellman & ElGamal

export const CONFIG = {
  PORT: process.env.PORT ? parseInt(process.env.PORT, 10) : 3000,
  ADMIN_TOKEN: process.env.ADMIN_TOKEN || 'bem-kripto-2026',
  DEFAULT_MODE: 'demo', // tiny (24), demo (32), mid (256), real512 (512), real2048 (2048)
  RNG_MODE: 'os', // 'os' (getRandomValues) atau 'custom_drbg' (SHA-256 PRNG buatan sendiri)
  DEFAULT_CANDIDATES: [
    'Kandidat 1 - Andi Pratama',
    'Kandidat 2 - Citra Lestari',
    'Kandidat 3 - Dimas Wibowo'
  ],
  DEFAULT_VOTERS: [
    { id: 'V001', pin: '111111' },
    { id: 'V002', pin: '222222' },
    { id: 'V003', pin: '333333' },
    { id: 'V004', pin: '444444' },
    { id: 'V005', pin: '555555' }
  ],
  SESSION_TTL_MS: 10 * 60 * 1000, // 10 menit
  MAX_LOGIN_ATTEMPTS: 3
};
