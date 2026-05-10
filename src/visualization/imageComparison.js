/**
 * IMAGE_COMPARISON.JS
 * ===================
 * Visual comparison of original vs. encrypted images.
 *
 * WHAT THIS DOES:
 * - Displays original image on left canvas
 * - Displays encrypted data as visual noise on right canvas
 * - Demonstrates diffusion property: no information leakage about original
 *
 * HOW NOISE IS GENERATED:
 * - Uses FNV-1a hash of ciphertext as PRNG seed
 * - Applies Xorshift32 PRNG to spread entropy across pixels
 * - Each pixel set independently based on ciphertext bytes
 * - Visual noise is completely random-looking, hiding image content
 */

import {
  FNV_OFFSET_BASIS,
  FNV_PRIME,
  NOISE_SEED_SAMPLE_SIZE,
  MAX_CANVAS_DIMENSION,
} from "../utils/constants.js";

/**
 * Clears the comparison panel.
 * Erases both canvases and hides the comparison card.
 *
 * @param {HTMLElement} comparisonCard - Container element for comparison
 * @param {HTMLElement} originalCanvas - Canvas for original image
 * @param {HTMLElement} encryptedCanvas - Canvas for encrypted noise
 */
export const clearComparison = ({
  comparisonCard,
  originalCanvas,
  encryptedCanvas,
}) => {
  if (comparisonCard) {
    comparisonCard.style.display = "none";
  }
  [originalCanvas, encryptedCanvas].forEach((canvas) => {
    if (canvas) {
      const ctx = canvas.getContext("2d");
      if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
  });
};

/**
 * Calculates appropriate canvas size to fit image within maximum dimension.
 * Maintains aspect ratio while respecting display limits.
 *
 * @param {ImageBitmap} bitmap - Image to measure
 * @returns {Object|null} { width, height } or null if bitmap invalid
 */
const computeCanvasSize = (bitmap) => {
  if (!bitmap || bitmap.width <= 0 || bitmap.height <= 0) {
    return null;
  }
  const scale = Math.min(
    1,
    MAX_CANVAS_DIMENSION / bitmap.width,
    MAX_CANVAS_DIMENSION / bitmap.height,
  );
  return {
    width: Math.max(1, Math.round(bitmap.width * scale)),
    height: Math.max(1, Math.round(bitmap.height * scale)),
  };
};

/**
 * Renders the original image to canvas.
 * Called when displaying the comparison panel.
 *
 * @param {HTMLElement} originalCanvas - Canvas to draw on
 * @param {ImageBitmap} bitmap - Original image
 * @param {number} targetWidth - Target canvas width
 * @param {number} targetHeight - Target canvas height
 */
const drawOriginalImage = (
  originalCanvas,
  bitmap,
  targetWidth,
  targetHeight,
) => {
  if (!originalCanvas) return;
  originalCanvas.width = targetWidth;
  originalCanvas.height = targetHeight;

  const ctx = originalCanvas.getContext("2d");
  if (!ctx) return;

  ctx.clearRect(0, 0, targetWidth, targetHeight);
  ctx.drawImage(bitmap, 0, 0, targetWidth, targetHeight);
};

/**
 * Renders encrypted data as visual noise.
 *
 * ALGORITHM:
 * 1. Sample ciphertext bytes to create hash seed
 * 2. Use FNV-1a hash to mix the bytes
 * 3. Use Xorshift32 PRNG to spread entropy across pixels
 * 4. Each pixel gets 3 bytes from ciphertext, full opacity
 *
 * WHY THIS WORKS:
 * - Ciphertext is random-looking by design
 * - FNV-1a hash spreads patterns across PRNG state
 * - Xorshift32 is fast and has good statistical properties
 * - Result: pixels appear completely random, revealing nothing
 *
 * @param {HTMLElement} encryptedCanvas - Canvas to draw on
 * @param {Uint8Array} bytes - Encrypted ciphertext bytes
 * @param {number} targetWidth - Target canvas width
 * @param {number} targetHeight - Target canvas height
 */
const drawEncryptedNoise = (
  encryptedCanvas,
  bytes,
  targetWidth,
  targetHeight,
) => {
  if (!encryptedCanvas || !bytes?.length) return;

  encryptedCanvas.width = targetWidth;
  encryptedCanvas.height = targetHeight;

  const ctx = encryptedCanvas.getContext("2d");
  if (!ctx) return;

  const imageData = ctx.createImageData(targetWidth, targetHeight);
  const data = imageData.data;
  const len = bytes.length;

  // Step 1: Create PRNG seed by hashing sample of ciphertext
  let state = FNV_OFFSET_BASIS;
  const actualSampleSize = Math.min(len, NOISE_SEED_SAMPLE_SIZE);
  const sampleStride = Math.max(1, Math.floor(len / actualSampleSize));

  let sampleIndex = 0;
  for (let sampled = 0; sampled < actualSampleSize; sampled++) {
    // FNV-1a hash
    state ^= bytes[sampleIndex];
    state = Math.imul(state, FNV_PRIME);
    sampleIndex = (sampleIndex + sampleStride) % len;
  }

  // Guard against zero state
  if (state === 0) state = FNV_OFFSET_BASIS;

  // Step 2: Fill pixels using PRNG
  for (let i = 0; i < data.length; i += 4) {
    // Xorshift32 PRNG step - spreads entropy
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;

    // Get pixel bytes from ciphertext using PRNG-derived index
    const startIndex = state % len;
    data[i] = bytes[startIndex]; // R
    data[i + 1] = bytes[(startIndex + 1) % len]; // G
    data[i + 2] = bytes[(startIndex + 2) % len]; // B
    data[i + 3] = 255; // A (opaque)
  }

  ctx.putImageData(imageData, 0, 0);
};

/**
 * Renders the comparison panel showing original and encrypted.
 * Main entry point for displaying the visual comparison.
 *
 * @param {File} file - Original file for display
 * @param {Uint8Array} ciphertextWithTagBytes - Encrypted data
 * @param {Object} canvasElements - { comparisonCard, originalCanvas, encryptedCanvas }
 */
export const renderComparisonPanel = async (
  file,
  ciphertextWithTagBytes,
  canvasElements,
) => {
  const { comparisonCard, originalCanvas, encryptedCanvas } = canvasElements;

  if (!comparisonCard || !file || !ciphertextWithTagBytes?.length) return;

  try {
    // Decode image from file
    const bitmap = await createImageBitmap(file);

    // Calculate appropriate canvas size
    const size = computeCanvasSize(bitmap);
    if (!size) {
      throw new Error("Unable to determine image dimensions for comparison.");
    }

    const { width, height } = size;

    // Render both images
    drawOriginalImage(originalCanvas, bitmap, width, height);
    drawEncryptedNoise(encryptedCanvas, ciphertextWithTagBytes, width, height);

    // Show comparison panel
    comparisonCard.style.display = "block";
  } catch (err) {
    console.warn("Comparison panel unavailable during rendering.", err);
    clearComparison(canvasElements);
  }
};
