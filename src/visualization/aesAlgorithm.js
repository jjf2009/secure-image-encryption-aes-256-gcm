/**
 * AES_ALGORITHM.JS
 * ================
 * AES-256 round operations for cryptographic visualization.
 *
 * WHAT THIS DOES:
 * - Visualizes how AES encrypts image data through 14 rounds
 * - Shows the diffusion and confusion properties of AES
 * - NOT used for actual encryption (we use Web Crypto API for that)
 * - Used only for educational visualization of the cipher rounds
 *
 * ROUND OPERATIONS:
 * 1. SubBytes: Substitution layer using S-box (byte-by-byte transformation)
 * 2. ShiftRows: Permutation layer (rotate rows by different amounts)
 * 3. MixColumns: Diffusion layer (mix columns using polynomial arithmetic)
 * 4. AddRoundKey: XOR with round key derived from main key
 */

import { AES_SBOX } from "../utils/constants.js";

/**
 * GF(2^8) multiplication by x (used in MixColumns).
 * Implements polynomial multiplication in Galois Field 2^8.
 *
 * In GF(2^8), we work with polynomials modulo x^8 + x^4 + x^3 + x + 1
 *
 * @param {number} b - Byte to multiply by x
 * @returns {number} Result of b * x in GF(2^8)
 */
const xtime = (b) => {
  const shifted = (b << 1) & 0xff;
  // If high bit was set, XOR with reduction polynomial 0x1b
  return b & 0x80 ? shifted ^ 0x1b : shifted;
};

/**
 * GF(2^8) multiplication by 3.
 * Computed as 3*b = 2*b + b = x*b + b
 *
 * @param {number} b - Byte to multiply by 3
 * @returns {number} Result of b * 3 in GF(2^8)
 */
const gmul3 = (b) => xtime(b) ^ b;

/**
 * AES SubBytes Operation
 * ======================
 * Substitution layer - byte-level confusion.
 * Each byte is independently replaced using the AES S-box.
 *
 * PURPOSE:
 * - Introduces non-linearity to the cipher
 * - Makes it computationally hard to find patterns
 * - Even small input changes produce completely different outputs
 *
 * @param {Uint8ClampedArray} data - Image data to transform
 * @returns {Uint8ClampedArray} Data after S-box substitution
 */
export const applySubBytes = (data) => {
  const out = new Uint8ClampedArray(data.length);
  // Apply S-box to RGB channels, preserve alpha
  for (let i = 0; i < data.length; i += 4) {
    out[i] = AES_SBOX[data[i]]; // R
    out[i + 1] = AES_SBOX[data[i + 1]]; // G
    out[i + 2] = AES_SBOX[data[i + 2]]; // B
    out[i + 3] = data[i + 3]; // A (unchanged)
  }
  return out;
};

/**
 * AES ShiftRows Operation
 * =======================
 * Permutation layer - position-level diffusion.
 * Each row is shifted left by a different amount (0, 1, 2, 3 positions).
 *
 * PURPOSE:
 * - Creates position-dependent diffusion
 * - Ensures changes spread across image positions
 * - Works in conjunction with MixColumns for full diffusion
 *
 * ROW SHIFTS:
 * - Row 0: No shift
 * - Row 1: Shift left by 1
 * - Row 2: Shift left by 2
 * - Row 3: Shift left by 3
 *
 * @param {Uint8ClampedArray} data - Image data
 * @param {number} width - Image width in pixels
 * @param {number} height - Image height in pixels
 * @returns {Uint8ClampedArray} Data after row shifts
 */
export const applyShiftRows = (data, width, height) => {
  const out = new Uint8ClampedArray(data.length);
  const rowStride = width * 4; // Each pixel is 4 bytes (RGBA)

  for (let y = 0; y < height; y++) {
    // Shift amount depends on row index
    const shift = y % 4;

    for (let x = 0; x < width; x++) {
      // Calculate destination position after shift
      const destX = (x - shift + width) % width;

      // Copy pixel from source to destination
      const srcIndex = y * rowStride + x * 4;
      const destIndex = y * rowStride + destX * 4;

      out[destIndex] = data[srcIndex]; // R
      out[destIndex + 1] = data[srcIndex + 1]; // G
      out[destIndex + 2] = data[srcIndex + 2]; // B
      out[destIndex + 3] = data[srcIndex + 3]; // A
    }
  }
  return out;
};

/**
 * AES MixColumns Operation
 * ========================
 * Diffusion layer - ensures column mixing and wide diffusion.
 * Each column is transformed independently using matrix multiplication
 * in GF(2^8) to spread one byte's influence across the entire column.
 *
 * PURPOSE:
 * - High diffusion: changing one pixel affects adjacent pixels
 * - Combines linear transformation with GF(2^8) arithmetic
 * - Together with ShiftRows, ensures rapid diffusion across image
 *
 * SIMPLIFIED FOR VISUALIZATION:
 * - Full AES uses Galois field matrix: [[2,3,1,1], [1,2,3,1], [1,1,2,3], [3,1,1,2]]
 * - Visualization version uses simplified mixing: next_value XOR gmul3(next_x)
 *
 * @param {Uint8ClampedArray} data - Image data
 * @param {number} width - Image width in pixels
 * @param {number} height - Image height in pixels
 * @returns {Uint8ClampedArray} Data after column mixing
 */
export const applyMixColumns = (data, width, height) => {
  const out = new Uint8ClampedArray(data.length);
  const rowStride = width * 4;

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      // Get current and next pixel (wrapping at edges)
      const srcIndex = y * rowStride + x * 4;
      const nextX = (x + 1) % width;
      const nextIndex = y * rowStride + nextX * 4;

      // Apply mixing: current pixel affected by next pixel
      out[srcIndex] = xtime(data[srcIndex]) ^ gmul3(data[nextIndex]); // R
      out[srcIndex + 1] =
        xtime(data[srcIndex + 1]) ^ gmul3(data[nextIndex + 1]); // G
      out[srcIndex + 2] =
        xtime(data[srcIndex + 2]) ^ gmul3(data[nextIndex + 2]); // B
      out[srcIndex + 3] = data[srcIndex + 3]; // A
    }
  }
  return out;
};

/**
 * AES AddRoundKey Operation
 * =========================
 * Key mixing layer - combines round key with data via XOR.
 * Each byte of data is XORed with corresponding byte of round key.
 *
 * PURPOSE:
 * - Adds key-dependent diffusion
 * - Makes cipher dependent on both data and key
 * - Reversible operation (XOR is self-inverse)
 *
 * @param {Uint8ClampedArray} data - Image data
 * @param {Uint8Array} roundKey - Round key to mix in
 * @returns {Uint8ClampedArray} Data after key mixing
 */
export const applyAddRoundKey = (data, roundKey) => {
  const out = new Uint8ClampedArray(data.length);
  let keyIndex = 0;

  for (let i = 0; i < data.length; i++) {
    // Skip alpha channel (every 4th byte starting at index 3)
    if (i % 4 === 3) {
      out[i] = data[i];
      continue;
    }

    // XOR RGB channels with key material
    out[i] = data[i] ^ roundKey[keyIndex % roundKey.length];
    keyIndex++;
  }
  return out;
};

/**
 * Derives round keys from a base key.
 * Creates a sequence of keys, each derived from the previous using S-box
 * and round number as diversification.
 *
 * @param {Uint8Array} baseKeyBytes - Base encryption key
 * @param {number} rounds - Number of rounds to generate keys for
 * @returns {Array<Uint8Array>} Array of round keys
 */
export const deriveRoundKeys = (baseKeyBytes, rounds = 14) => {
  const keys = [];
  let prev =
    baseKeyBytes.length === 32
      ? new Uint8Array(baseKeyBytes)
      : new Uint8Array(32).fill(0, 0, Math.min(32, baseKeyBytes.length));

  for (let r = 1; r <= rounds; r++) {
    const next = new Uint8Array(prev.length);
    for (let i = 0; i < prev.length; i++) {
      // Simple key derivation: apply S-box and XOR with round number
      next[i] = AES_SBOX[prev[i]] ^ r;
    }
    keys.push(next);
    prev = next;
  }
  return keys;
};
