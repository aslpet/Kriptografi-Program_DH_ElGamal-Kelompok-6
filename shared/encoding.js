// Modul Encoding & Serialisasi Representasi Data Bersama
// Memastikan konsistensi format BigInt, byte, hex, dan JSON kanonikal antara browser dan server.

export function toHex(n) {
  if (typeof n !== 'bigint') throw new TypeError('Input toHex harus berupa BigInt');
  if (n < 0n) throw new RangeError('toHex hanya mendukung BigInt non-negatif');
  const hex = n.toString(16);
  return hex.length % 2 !== 0 ? '0' + hex : hex;
}

export function fromHex(hexStr) {
  if (typeof hexStr !== 'string') throw new TypeError('Input fromHex harus berupa string');
  const cleaned = hexStr.startsWith('0x') || hexStr.startsWith('0X') ? hexStr.slice(2) : hexStr;
  if (cleaned.length === 0) return 0n;
  if (!/^[0-9a-fA-F]+$/.test(cleaned)) throw new Error(`String hex tidak valid: ${hexStr}`);
  return BigInt('0x' + cleaned);
}

export function bytesToHex(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('Input bytesToHex harus Uint8Array');
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hexStr) {
  if (typeof hexStr !== 'string') throw new TypeError('Input hexToBytes harus string');
  let cleaned = hexStr.startsWith('0x') || hexStr.startsWith('0X') ? hexStr.slice(2) : hexStr;
  if (cleaned.length % 2 !== 0) cleaned = '0' + cleaned;
  if (cleaned.length === 0) return new Uint8Array(0);
  if (!/^[0-9a-fA-F]+$/.test(cleaned)) throw new Error(`String hex tidak valid: ${hexStr}`);
  const len = cleaned.length / 2;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bigToBytes(n, fixedLength = null) {
  if (typeof n !== 'bigint') throw new TypeError('Input bigToBytes harus BigInt');
  if (n < 0n) throw new RangeError('bigToBytes hanya mendukung BigInt non-negatif');
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const rawBytes = hexToBytes(hex);

  if (fixedLength === null) {
    return rawBytes.length === 0 ? new Uint8Array([0]) : rawBytes;
  }

  if (rawBytes.length > fixedLength) {
    throw new Error(`Ukuran byte (${rawBytes.length}) melebihi fixedLength (${fixedLength})`);
  }

  const result = new Uint8Array(fixedLength);
  result.set(rawBytes, fixedLength - rawBytes.length);
  return result;
}

export function bytesToBig(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('Input bytesToBig harus Uint8Array');
  if (bytes.length === 0) return 0n;
  return fromHex(bytesToHex(bytes));
}

export function utf8ToBytes(str) {
  if (typeof str !== 'string') throw new TypeError('Input utf8ToBytes harus string');
  return new TextEncoder().encode(str);
}

export function bytesToUtf8(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('Input bytesToUtf8 harus Uint8Array');
  return new TextDecoder().decode(bytes);
}

export function concatBytes(...arrays) {
  let totalLen = 0;
  for (const arr of arrays) {
    if (!(arr instanceof Uint8Array)) throw new TypeError('Semua argumen concatBytes harus Uint8Array');
    totalLen += arr.length;
  }
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const entries = keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k]));
  return '{' + entries.join(',') + '}';
}
