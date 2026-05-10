/**
 * ROUND_VISUALIZER.JS
 * ===================
 * Visualization of AES-256-GCM round-by-round encryption process.
 *
 * WHAT THIS SHOWS:
 * - 15 states: original image + 14 AES encryption rounds
 * - How each operation (SubBytes, ShiftRows, MixColumns, AddRoundKey) changes the image
 * - Entropy progression: starts ordered, becomes completely random
 * - Histogram distribution: becomes uniform over 14 rounds
 *
 * KEY INSIGHT:
 * This visualizes the avalanche effect - how small changes rapidly spread
 * through the ciphertext, making it indistinguishable from random data.
 */

import {
  ROUND_STATES_TOTAL,
  VISUALIZER_MAX_DIMENSION,
  FILMSTRIP_THUMB_SIZE,
  ROUND_PLAY_INTERVAL_MS,
  ROUND_TITLES,
} from "../utils/constants.js";
import {
  applySubBytes,
  applyShiftRows,
  applyMixColumns,
  applyAddRoundKey,
  deriveRoundKeys,
} from "./aesAlgorithm.js";

const SUB_ROUND_TITLES = [
  "Start of Round 1",
  "Step 1: SubBytes",
  "Step 2: ShiftRows",
  "Step 3: MixColumns",
  "Step 4: AddRoundKey"
];

const SUB_ROUND_DESCRIPTIONS = [
  "This is the state after the initial Key Addition (Round 0). The image is already partially scrambled but patterns remain.",
  "<b>SubBytes (Confusion):</b> A non-linear substitution where each byte is replaced with another according to a lookup table (S-Box). This breaks the direct link between input and output values.",
  "<b>ShiftRows (Diffusion):</b> A transposition step where the rows of the data matrix are cyclically shifted. This spreads the influence of single bytes across the row.",
  "<b>MixColumns (Diffusion):</b> A mixing operation that operates on the columns of the state, combining the four bytes in each column. This further increases diffusion by linking all bytes in a column.",
  "<b>AddRoundKey:</b> The only step where the <b>Secret Key</b> is actually combined with the data (using a bitwise XOR). This finalizes the scrambling for this round."
];

/**
 * Computes histogram of image pixel values.
 * Used to analyze entropy progression across rounds.
 *
 * HISTOGRAM:
 * - Array of 256 bins (one for each byte value 0-255)
 * - Each bin counts how many times that value appears in RGB channels
 * - Alpha channel ignored (always 255)
 *
 * @param {ImageData} data - Image data to analyze
 * @returns {Object} { histogram: array, total: count }
 */
/**
 * Builds intermediate states for a single AES round (Deep Inspection).
 */
async function buildSubRoundStates(baseImageData, roundKeys, width, height) {
  const states = [];
  const entropies = [];
  const deviationPercentages = [];
  
  // Initial state for visualization is the result of Round 0 (AddRoundKey)
  let currentData = applyAddRoundKey(baseImageData.data, roundKeys[0] || new Uint8Array(32));
  const originalBuffer = currentData.slice();
  
  const captureState = (data) => {
    const imageData = new ImageData(new Uint8ClampedArray(data), width, height);
    states.push(imageData);
    entropies.push(calculateEntropy(data));
    deviationPercentages.push(computeRoundDifference(originalBuffer, data).changePercentage);
    return data;
  };
  
  // Step 0: Start of Round 1
  currentData = captureState(currentData);
  
  // Step 1: SubBytes (Confusion)
  currentData = applySubBytes(currentData);
  currentData = captureState(currentData);
  
  // Step 2: ShiftRows (Diffusion)
  currentData = applyShiftRows(currentData, width, height);
  currentData = captureState(currentData);
  
  // Step 3: MixColumns (Diffusion)
  currentData = applyMixColumns(currentData, width, height);
  currentData = captureState(currentData);
  
  // Step 4: AddRoundKey (Final Round 1 Result)
  currentData = applyAddRoundKey(currentData, roundKeys[1] || roundKeys[0]);
  currentData = captureState(currentData);
  
  return { states, entropies, deviationPercentages };
}

const histogramFromData = (data) => {
  const histogram = new Uint32Array(256);
  let total = 0;

  // Count occurrences of each byte value in RGB channels
  for (let i = 0; i < data.length; i += 4) {
    histogram[data[i]]++; // R
    histogram[data[i + 1]]++; // G
    histogram[data[i + 2]]++; // B
    total += 3; // Count 3 bytes per pixel
  }

  return { histogram, total };
};

/**
 * Calculates Shannon entropy from histogram.
 *
 * ENTROPY INTERPRETATION:
 * - 0: All pixels same value (completely ordered)
 * - 4-5: Some variation (entropy building)
 * - 8: Maximum entropy (perfectly random, uniform distribution)
 *
 * FORMULA: H = -Σ(p_i * log2(p_i)) for each bin
 * - p_i = probability of value i
 * - log2 gives bits of entropy
 *
 * @param {Object} histogram - Result from histogramFromData()
 * @returns {number} Entropy in bits (0-8)
 */
const entropyFromHistogram = ({ histogram, total }) => {
  if (!total) return 0;

  let entropy = 0;
  for (let i = 0; i < histogram.length; i++) {
    const count = histogram[i];
    if (!count) continue;

    const p = count / total;
    entropy -= p * Math.log2(p);
  }

  return entropy;
};

/**
 * High-level helper to calculate entropy directly from pixel data.
 */
const calculateEntropy = (data) => {
  return entropyFromHistogram(histogramFromData(data));
};

/**
 * Computes the visual and numerical difference between two image states.
 * 
 * @param {Uint8ClampedArray} original - Original image bytes (RGBA)
 * @param {Uint8ClampedArray} current - Current round bytes (RGBA)
 * @returns {Object} { diffData: Uint8ClampedArray, changePercentage: number }
 */
const computeRoundDifference = (original, current) => {
  const len = original.length;
  const diffData = new Uint8ClampedArray(len);
  let changedPixels = 0;

  for (let i = 0; i < len; i += 4) {
    // RGB Difference
    const dr = Math.abs(current[i] - original[i]);
    const dg = Math.abs(current[i + 1] - original[i + 1]);
    const db = Math.abs(current[i + 2] - original[i + 2]);

    diffData[i] = dr;
    diffData[i + 1] = dg;
    diffData[i + 2] = db;
    diffData[i + 3] = 255; // Keep difference map opaque

    // Count as changed if any color channel differs
    if (dr > 0 || dg > 0 || db > 0) {
      changedPixels++;
    }
  }

  const changePercentage = (changedPixels / (len / 4)) * 100;
  return { diffData, changePercentage };
};

/**
 * Builds all 15 round states by applying AES operations to image data.
 *
 * PROCESS:
 * 1. Start with original image as round 0
 * 2. For each round 1-14:
 *    - Apply SubBytes (substitution)
 *    - Apply ShiftRows (permutation)
 *    - Apply MixColumns (diffusion) - except for round 14
 *    - Apply AddRoundKey (key mixing)
 * 3. For each state, compute histogram and entropy
 * 4. Return all states with their statistics
 *
 * @param {ImageData} baseImageData - Original image
 * @param {Array<Uint8Array>} roundKeys - Derived round keys
 * @param {Function} onProgress - Callback with round number
 * @returns {Promise<Object>} { states, histograms, entropies }
 */
const buildRoundStates = async (baseImageData, roundKeys, onProgress) => {
  const states = [baseImageData];
  const hist0 = histogramFromData(baseImageData.data);
  const histograms = [hist0.histogram];
  const entropies = [entropyFromHistogram(hist0)];
  const diffs = [new Uint8ClampedArray(baseImageData.data.length)]; // Round 0 diff is zero
  const changePercentages = [0];
  let prevData = baseImageData.data;

  for (let r = 1; r <= ROUND_STATES_TOTAL; r++) {
    // Progress callback
    if (typeof onProgress === "function") {
      onProgress(r);
    }

    // Apply AES round operations
    let working = applySubBytes(prevData);
    working = applyShiftRows(
      working,
      baseImageData.width,
      baseImageData.height,
    );

    // MixColumns is skipped in final round (matches AES schedule)
    if (r !== ROUND_STATES_TOTAL) {
      working = applyMixColumns(
        working,
        baseImageData.width,
        baseImageData.height,
      );
    }

    working = applyAddRoundKey(working, roundKeys[r - 1]);

    // Create image data and compute statistics
    const imageData = new ImageData(
      working,
      baseImageData.width,
      baseImageData.height,
    );
    states.push(imageData);

    const hist = histogramFromData(imageData.data);
    histograms.push(hist.histogram);
    entropies.push(entropyFromHistogram(hist));

    // Compute difference from original (Round 0)
    const { diffData, changePercentage } = computeRoundDifference(
      baseImageData.data,
      working,
    );
    diffs.push(diffData);
    changePercentages.push(changePercentage);

    prevData = imageData.data;

    // Yield to browser to keep UI responsive
    await new Promise((resolve) => requestAnimationFrame(resolve));
  }

  return { states, histograms, entropies, diffs, changePercentages };
};

/**
 * Calculates visualizer canvas size maintaining aspect ratio.
 *
 * @param {ImageBitmap} bitmap - Source image
 * @returns {Object} { width, height }
 */
const computeVisualizerSize = (bitmap) => {
  const maxSide = Math.max(bitmap.width, bitmap.height);
  const scale = Math.min(1, VISUALIZER_MAX_DIMENSION / maxSide);
  return {
    width: Math.max(1, Math.round(bitmap.width * scale)),
    height: Math.max(1, Math.round(bitmap.height * scale)),
  };
};

/**
 * Draws ImageData to canvas.
 * Used to display both original and current round images.
 *
 * @param {HTMLElement} canvas - Canvas element
 * @param {ImageData} imageData - Image data to draw
 */
const drawImageDataToCanvas = (canvas, imageData) => {
  if (!canvas || !imageData) return;
  canvas.width = imageData.width;
  canvas.height = imageData.height;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.putImageData(imageData, 0, 0);
};

/**
 * Resets visualizer to initial state.
 * Used when starting new visualization or on errors.
 *
 * @param {Object} elements - Visualizer DOM elements
 * @param {string} message - Message to display during loading
 */
export const resetRoundVisualizer = (
  elements,
  message = "Awaiting encryption...",
) => {
  const {
    card,
    loading,
    loadingProgress,
    loadingText,
    visualizerBody,
    badges,
    filmstrip,
    histogramCurrentChart,
  } = elements;

  // Stop playback
  if (elements.playTimer) {
    clearInterval(elements.playTimer);
    elements.playTimer = null;
  }

  // Clear state
  elements.roundStates = [];
  elements.roundHistograms = [];
  elements.roundEntropies = [];
  elements.roundDiffs = [];
  elements.roundChangePercentages = [];
  elements.roundThumbRefs = [];

  // Clear charts
  histogramCurrentChart?.destroy?.();
  elements.histogramCurrentChart = null;

  // Update UI
  if (visualizerBody) visualizerBody.style.display = "none";
  if (loading) loading.style.display = "block";
  if (loadingText) loadingText.textContent = message;
  if (loadingProgress) loadingProgress.style.width = "0%";
  if (card) card.style.display = "none";
};

/**
 * Displays specific round state.
 * Updates all visualizer elements to show current round.
 *
 * @param {number} roundIndex - Round to display (0-14)
 * @param {Object} elements - All visualizer elements and state
 */
const setRoundDisplay = (roundIndex, elements) => {
  if (!elements.roundStates.length) return;

  const {
    roundStates,
    roundEntropies,
    numberEl,
    titleEl,
    entropyEl,
    pill,
    currentCanvasLabel,
    range,
    currentCanvas,
    originalCanvas,
    roundDiffCanvas,
    roundDeviationEl,
    badges,
    descriptionEl, // New element for educational text
  } = elements;

  elements.roundCurrentIndex = roundIndex;

  // Update display elements
  const padded = roundIndex.toString().padStart(2, "0");
  if (range) range.value = String(roundIndex);
  if (numberEl) numberEl.textContent = padded;
  
  // Use SUB_ROUND titles and descriptions
  if (titleEl) {
    titleEl.textContent = SUB_ROUND_TITLES[roundIndex] || `Step ${roundIndex}`;
  }
  if (pill) pill.textContent = `STEP ${roundIndex}`;
  if (currentCanvasLabel) {
    currentCanvasLabel.textContent = SUB_ROUND_TITLES[roundIndex] || `Step ${roundIndex}`;
  }
  if (descriptionEl) {
    descriptionEl.innerHTML = SUB_ROUND_DESCRIPTIONS[roundIndex] || "";
  }

  // Update entropy display
  if (entropyEl && roundEntropies[roundIndex] !== undefined) {
    entropyEl.textContent = `${roundEntropies[roundIndex].toFixed(2)} bits`;
  }

  // Update visual elements
  const ops = ["none", "subbytes", "shiftrows", "mixcolumns", "addroundkey"];
  const currentOp = ops[roundIndex];
  
  badges?.forEach(badge => {
    badge.classList.toggle("active", badge.dataset.op === currentOp);
  });
  
  drawImageDataToCanvas(currentCanvas, roundStates[roundIndex]);

  // Update Difference Canvas if available
  if (roundDiffCanvas && elements.roundDiffs[roundIndex]) {
    const diffImageData = new ImageData(
      elements.roundDiffs[roundIndex],
      roundStates[roundIndex].width,
      roundStates[roundIndex].height,
    );
    drawImageDataToCanvas(roundDiffCanvas, diffImageData);
  }

  // Update Deviation % if available
  if (roundDeviationEl && elements.roundChangePercentages[roundIndex] !== undefined) {
    roundDeviationEl.textContent = `${elements.roundChangePercentages[roundIndex].toFixed(2)}%`;
  }

  updateHistogramCharts(roundIndex, elements);
  highlightFilmstrip(roundIndex, elements.roundThumbRefs);
};

/**
 * Updates which operation badges are active for current round.
 * Shows which operations are applied in this round.
 *
 * @param {number} roundIndex - Current round
 * @param {NodeList} badges - Badge elements to update
 */
const updateRoundBadges = (roundIndex, badges) => {
  const ops = {
    subbytes: roundIndex > 0,
    shiftrows: roundIndex > 0,
    mixcolumns: roundIndex > 0 && roundIndex < ROUND_STATES_TOTAL,
    addroundkey: roundIndex > 0,
  };

  badges.forEach((badge) => {
    const op = badge?.dataset?.op;
    badge?.classList.toggle("active", Boolean(op && ops[op]));
  });
};

/**
 * Updates histogram charts showing byte distribution.
 * Compares original round 0 histogram with current round.
 *
 * Uses Chart.js library if available.
 *
 * @param {number} roundIndex - Current round
 * @param {Object} elements - Visualizer elements and state
 */
const updateHistogramCharts = (roundIndex, elements) => {
  const {
    roundHistograms,
    histogramOriginalCanvas,
    histogramCurrentCanvas,
    histogramCurrentChart,
  } = elements;

  if (!histogramOriginalCanvas || !histogramCurrentCanvas) return;
  if (typeof Chart === "undefined") return;

  const labels = Array.from({ length: 256 }, (_, i) => i);
  const primary = getPrimaryColor();

  // Initialize original histogram if needed
  if (!elements.histogramOriginalChart && roundHistograms[0]) {
    elements.histogramOriginalChart = new Chart(
      histogramOriginalCanvas.getContext("2d"),
      {
        type: "bar",
        data: {
          labels,
          datasets: [
            {
              label: "R0 Distribution",
              data: roundHistograms[0],
              backgroundColor: colorWithAlpha(primary, 0.45),
              borderColor: primary,
              borderWidth: 1,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: { x: { display: false }, y: { display: false } },
          plugins: { legend: { display: false } },
        },
      },
    );
  }

  // Update or create current histogram
  if (!histogramCurrentChart) {
    elements.histogramCurrentChart = new Chart(
      histogramCurrentCanvas.getContext("2d"),
      {
        type: "bar",
        data: {
          labels,
          datasets: [
            {
              label: "Current Round",
              data: roundHistograms[roundIndex] || [],
              backgroundColor: colorWithAlpha(primary, 0.35),
              borderColor: primary,
              borderWidth: 1,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: { x: { display: false }, y: { display: false } },
          plugins: { legend: { display: false } },
        },
      },
    );
  } else {
    elements.histogramCurrentChart.data.datasets[0].data =
      roundHistograms[roundIndex] || [];
    elements.histogramCurrentChart.update();
  }
};

/**
 * Highlights active thumbnail in filmstrip.
 *
 * @param {number} roundIndex - Active round
 * @param {Array<HTMLElement>} thumbRefs - Thumbnail canvas elements
 */
const highlightFilmstrip = (roundIndex, thumbRefs) => {
  thumbRefs.forEach((thumb, idx) => {
    thumb.classList.toggle("active", idx === roundIndex);
  });
};

/**
 * Builds filmstrip of thumbnail previews.
 * Allows quick navigation to any round.
 *
 * @param {Array<ImageData>} roundStates - All round states
 * @param {HTMLElement} filmstripContainer - Element to add thumbnails to
 * @param {Function} onThumbClick - Callback when thumbnail clicked
 * @param {number} activeIndex - Current active round
 * @returns {Array<HTMLElement>} Thumbnail canvas elements
 */
const buildFilmstrip = (
  roundStates,
  filmstripContainer,
  onThumbClick,
  activeIndex,
) => {
  if (!filmstripContainer) return [];

  filmstripContainer.innerHTML = "";
  const thumbRefs = [];

  roundStates.forEach((state, idx) => {
    // Create thumbnail canvas
    const thumb = document.createElement("canvas");
    thumb.className = "round-thumb";

    // Size: maintain aspect ratio, max FILMSTRIP_THUMB_SIZE
    const scale = Math.min(
      1,
      FILMSTRIP_THUMB_SIZE / Math.max(state.width, state.height),
    );
    thumb.width = Math.max(1, Math.round(state.width * scale));
    thumb.height = Math.max(1, Math.round(state.height * scale));

    // Draw scaled image data to thumbnail
    const ctx = thumb.getContext("2d");
    if (ctx) {
      const tempCanvas = document.createElement("canvas");
      tempCanvas.width = state.width;
      tempCanvas.height = state.height;
      const tempCtx = tempCanvas.getContext("2d");
      tempCtx?.putImageData(state, 0, 0);
      ctx.drawImage(tempCanvas, 0, 0, thumb.width, thumb.height);
    }

    // Click to jump to round
    thumb.addEventListener("click", () => onThumbClick(idx));
    filmstripContainer.appendChild(thumb);
    thumbRefs.push(thumb);
  });

  // Highlight active thumbnail
  highlightFilmstrip(activeIndex, thumbRefs);
  return thumbRefs;
};

/**
 * Starts automatic round playback.
 * Cycles through all rounds at fixed interval.
 *
 * @param {Object} elements - Visualizer elements and state
 */
const startRoundPlayback = (elements) => {
  if (elements.playTimer) {
    // Already playing - stop instead
    stopRoundPlayback(elements);
    return;
  }

  if (elements.playBtn) {
    elements.playBtn.textContent = "Pause";
  }

  elements.playTimer = setInterval(() => {
    const next = (elements.roundCurrentIndex + 1) % 5; // 5 steps total
    setRoundDisplay(next, elements);
  }, 1500); // Slower interval for sub-round visualization
};

/**
 * Stops automatic round playback.
 *
 * @param {Object} elements - Visualizer elements and state
 */
const stopRoundPlayback = (elements) => {
  if (elements.playTimer) {
    clearInterval(elements.playTimer);
    elements.playTimer = null;
  }
  if (elements.playBtn) {
    elements.playBtn.textContent = "Play";
  }
};

/**
 * Initializes round visualizer controls and event listeners.
 * Called once during page load.
 *
 * @param {Object} elements - Visualizer elements
 */
export const initializeRoundControls = (elements) => {
  if (elements.playHelper) {
    elements.playHelper.textContent = `Auto-advance every ${formatInterval(ROUND_PLAY_INTERVAL_MS)} when playing`;
  }

  elements.range?.addEventListener("input", (event) => {
    const value = Number(event.target?.value ?? 0);
    stopRoundPlayback(elements);
    setRoundDisplay(Math.min(Math.max(0, value), ROUND_STATES_TOTAL), elements);
  });

  elements.prevBtn?.addEventListener("click", () => {
    stopRoundPlayback(elements);
    const prev =
      elements.roundCurrentIndex === 0
        ? ROUND_STATES_TOTAL
        : elements.roundCurrentIndex - 1;
    setRoundDisplay(prev, elements);
  });

  elements.nextBtn?.addEventListener("click", () => {
    stopRoundPlayback(elements);
    const next = (elements.roundCurrentIndex + 1) % 5;
    setRoundDisplay(next, elements);
  });

  elements.playBtn?.addEventListener("click", () => {
    startRoundPlayback(elements);
  });
};

/**
 * Main entry point: starts the round visualization.
 * Decodes image, derives keys, builds round states, and displays visualizer.
 *
 * @param {File} file - Image file to visualize
 * @param {CryptoKey} key - Derived encryption key (optional, password required if null)
 * @param {string} password - Password for key derivation (if key not provided)
 * @param {Uint8Array} encryptionSalt - Salt used during encryption
 * @param {Object} elements - Visualizer DOM elements
 * @param {Function} deriveKeyFn - Function to derive key from password
 */
export const startRoundVisualizer = async (
  file,
  key,
  password,
  encryptionSalt,
  elements,
  deriveKeyFn,
) => {
  if (!file) return;

  resetRoundVisualizer(elements, "Computing rounds...");
  if (elements.card) {
    elements.card.style.display = "block";
  }

  const updateProgress = (round) => {
    const pct = Math.min(100, Math.round((round / ROUND_STATES_TOTAL) * 100));
    if (elements.loadingProgress) {
      elements.loadingProgress.style.width = `${pct}%`;
    }
    if (elements.loadingText) {
      elements.loadingText.textContent = `Computing round ${round} of ${ROUND_STATES_TOTAL}...`;
    }
  };

  try {
    // Decode image
    const bitmap = await createImageBitmap(file);

    // Prepare visualization canvas
    const { width, height } = computeVisualizerSize(bitmap);
    const tempCanvas = document.createElement("canvas");
    tempCanvas.width = width;
    tempCanvas.height = height;
    const ctx = tempCanvas.getContext("2d");
    if (!ctx) throw new Error("Canvas context unavailable.");

    ctx.drawImage(bitmap, 0, 0, width, height);
    const baseImageData = ctx.getImageData(0, 0, width, height);

    // Derive base key for round generation
    let baseKeyBytes;
    if (key) {
      const raw = await window.crypto.subtle.exportKey("raw", key);
      baseKeyBytes = new Uint8Array(raw);
    } else {
      const saltBytes =
        encryptionSalt || window.crypto.getRandomValues(new Uint8Array(16));
      const result = await deriveKeyFn(password || "", saltBytes);
      
      // Handle both raw CryptoKey and timing-wrapped object
      const derivedKey = result.key || result;
      
      const rawDerived = await window.crypto.subtle.exportKey(
        "raw",
        derivedKey,
      );
      baseKeyBytes = new Uint8Array(rawDerived);
    }

    // Generate round keys and build states
    const roundKeys = deriveRoundKeys(baseKeyBytes, 2); 
    const { states, entropies, deviationPercentages } = await buildSubRoundStates(
      baseImageData,
      roundKeys,
      baseImageData.width,
      baseImageData.height
    );

    // Store results
    elements.roundStates = states;
    elements.roundEntropies = entropies;
    elements.roundChangePercentages = deviationPercentages;

    // Render visualizer
    drawImageDataToCanvas(elements.originalCanvas, baseImageData);
    drawImageDataToCanvas(elements.currentCanvas, states[0]);

    elements.roundThumbRefs = buildFilmstrip(
      states,
      elements.filmstrip,
      (idx) => {
        stopRoundPlayback(elements);
        setRoundDisplay(idx, elements);
      },
      0
    );

    // Adjust range for 5 steps
    if (elements.range) {
      elements.range.max = "4";
    }

    setRoundDisplay(0, elements);

    // Show visualizer
    if (elements.loading) elements.loading.style.display = "none";
    if (elements.visualizerBody) elements.visualizerBody.style.display = "flex";
  } catch (err) {
    console.warn("Visualizer error:", err);
    resetRoundVisualizer(elements, "Visualizer unavailable.");
  }
};

// Helper functions
const getPrimaryColor = () => {
  return (
    getComputedStyle(document.documentElement)
      .getPropertyValue("--primary")
      .trim() || "#4f46e5"
  );
};

const colorWithAlpha = (color, alpha) => {
  const hexMatch = color.match(/^#?([a-fA-F0-9]{6})$/);
  if (hexMatch) {
    const hex = hexMatch[1];
    const r = parseInt(hex.slice(0, 2), 16);
    const g = parseInt(hex.slice(2, 4), 16);
    const b = parseInt(hex.slice(4, 6), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
  return `rgba(79, 70, 229, ${alpha})`;
};

const formatInterval = (ms) => {
  const useSeconds = ms >= 1000;
  const value = useSeconds ? (ms / 1000).toFixed(1) : ms;
  const unit = useSeconds ? "s" : "ms";
  return `${value}${unit}`;
};
