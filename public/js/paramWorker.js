// Web Worker untuk Pembangkitan Safe Prime Besar di Background Thread
import { genSafePrime, findGenerator } from '../../shared/math_utils.js';
import { toHex } from '../../shared/encoding.js';

self.onmessage = function (e) {
  const { bits } = e.data;
  const startTime = performance.now();

  try {
    const { p, q, attempts } = genSafePrime(bits, (currentAttempts) => {
      self.postMessage({ type: 'progress', attempts: currentAttempts });
    });

    const g = findGenerator(p, q);
    const durationMs = Math.round(performance.now() - startTime);

    self.postMessage({
      type: 'done',
      bits,
      p: toHex(p),
      q: toHex(q),
      g: toHex(g),
      attempts,
      durationMs
    });
  } catch (err) {
    self.postMessage({ type: 'error', error: err.message });
  }
};
