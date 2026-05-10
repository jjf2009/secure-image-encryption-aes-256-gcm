/**
 * KEY_DERIVATION.JS
 * =================
 * PBKDF2 key derivation for generating encryption keys from passwords.
 *
 * WHY PBKDF2?
 * - Slows down brute-force attacks by using many iterations
 * - Standard for password-based key derivation (RFC 2898)
 * - Built-in to Web Crypto API with no external dependencies
 *
 * ITERATION COUNT:
 * - 100,000 iterations provides ~1.2 seconds on modern devices
 * - This makes each password guess very expensive for attackers
 * - Trade-off: slow for legitimate users but worth it for security
 */

import { PBKDF2_ITERATIONS } from "../utils/constants.js";

/**
 * Internal key derivation implementation.
 * Uses PBKDF2-SHA256 to derive a 256-bit AES key from password + salt.
 *
 * ALGORITHM DETAILS:
 * - Hash function: SHA-256
 * - Output length: 256 bits (AES-256 requirement)
 * - Input: password + random salt
 * - Operations: PBKDF2 with specified iteration count
 *
 * @param {string} password - User's password
 * @param {Uint8Array} salt - Random salt (prevents rainbow tables)
 * @param {number} iterations - Number of PBKDF2 iterations
 * @returns {Promise<CryptoKey>} Derived key ready for AES-GCM
 */
const deriveKeyInternal = async (password, salt, iterations) => {
  const encoder = new TextEncoder();

  // Step 1: Import password as PBKDF2 key material
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  // Step 2: Derive the actual encryption key using PBKDF2
  // This is where the heavy computation happens (iterations parameter)
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: iterations,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 }, // Output is AES-GCM compatible
    false, // Not extractable (stays in crypto context)
    ["encrypt", "decrypt"], // Can be used for both operations
  );
};

/**
 * Derives an encryption key using standard iteration count.
 * This is the primary function used for encryption/decryption operations.
 *
 * @param {string} password - User's password
 * @param {Uint8Array} salt - Random salt from the file or generated new
 * @returns {Promise<CryptoKey>} Derived encryption key
 */
export const deriveKey = (password, salt) =>
  deriveKeyInternal(password, salt, PBKDF2_ITERATIONS);

/**
 * Derives an encryption key with custom iteration count.
 * Used for benchmarking to test performance at different iteration levels.
 *
 * @param {string} password - User's password
 * @param {Uint8Array} salt - Random salt
 * @param {number} iterations - Custom iteration count
 * @returns {Promise<CryptoKey>} Derived encryption key
 */
export const deriveKeyWithIterations = (
  password,
  salt,
  iterations = PBKDF2_ITERATIONS,
) => deriveKeyInternal(password, salt, iterations);

/**
 * Derives a key and measures the time taken.
 * Used for performance monitoring and to warn users if PBKDF2 is too fast.
 *
 * WHY MEASURE?
 * - If PBKDF2 completes in <200ms, something might be wrong
 * - Could indicate a system issue or that we're being run on a very fast machine
 * - Helps diagnose performance problems
 *
 * @param {string} password - User's password
 * @param {Uint8Array} salt - Random salt
 * @param {number} iterations - Iteration count to use
 * @returns {Promise<Object>} { key: CryptoKey, duration: milliseconds }
 */
export const deriveKeyWithTiming = async (
  password,
  salt,
  iterations = PBKDF2_ITERATIONS,
) => {
  const start = performance.now();
  const key = await deriveKeyInternal(password, salt, iterations);
  const duration = performance.now() - start;
  return { key, duration };
};
