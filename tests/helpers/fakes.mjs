/**
 * Deterministic fake credentials for tests. Generated at runtime so the repository
 * never contains contiguous token strings (keeps GitHub push protection quiet).
 */
export const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const UPPER32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const HEX = '0123456789abcdef';

/** Pseudo-random but reproducible string of `len` chars from `set`. */
export const fake = (len, set = ALNUM) =>
  Array.from({ length: len }, (_, i) => set[(i * 7919 + len * 31 + i * i) % set.length]).join('');

const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');

export const jwt = (payload, header = { alg: 'HS256', typ: 'JWT' }) =>
  `${b64u(header)}.${b64u(payload)}.${fake(43, `${ALNUM}_-`)}`;

/** Join parts at runtime ("gh" + "p_") so scanners of this repo don't see a literal prefix. */
export const p = (...parts) => parts.join('');
