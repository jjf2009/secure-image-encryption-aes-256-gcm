/**
 * DOM_MANAGER.JS
 * ==============
 * Centralized DOM element caching and UI utility functions.
 *
 * WHY CACHING?
 * - Querying DOM repeatedly is slow. By caching on page load,
 *   we avoid repeated querySelector calls in hot loops.
 * - Easier to refactor: changing element IDs requires updating only here.
 * - Provides type safety through explicit object structure.
 */

/**
 * Cache all DOM elements used by the application.
 * This is called once during initialization to avoid repeated DOM queries.
 *
 * @returns {Object} Object containing references to all critical DOM elements
 */
export const cacheDOMElements = () => ({
  // ========== ENCRYPTION UI ==========
  encryption: {
    fileInput: document.getElementById("image-upload"),
    passwordInput: document.getElementById("encrypt-password"),
    button: document.getElementById("btn-encrypt"),
    status: document.getElementById("encrypt-status"),
    spinner: document.getElementById("encrypt-spinner"),
    downloadArea: document.getElementById("download-area"),
    downloadButton: document.getElementById("btn-download-txt"),
    ciphertextOutput: document.getElementById("ciphertext-output"),
  },

  // ========== DECRYPTION UI ==========
  decryption: {
    encryptedTextInput: document.getElementById("encrypted-text"),
    passwordInput: document.getElementById("decrypt-password"),
    button: document.getElementById("btn-decrypt"),
    status: document.getElementById("decrypt-status"),
    spinner: document.getElementById("decrypt-spinner"),
    previewImg: document.getElementById("decrypted-preview"),
    previewArea: document.getElementById("preview-area"),
    downloadButton: document.getElementById("btn-download-img"),
    fileUpload: document.getElementById("txt-upload"),
  },

  // ========== PASSWORD STRENGTH UI ==========
  passwordStrength: {
    strengthBar: document.getElementById("password-strength-bar"),
    strengthLabel: document.getElementById("password-strength-label"),
    strengthWarning: document.getElementById("password-strength-warning"),
    specialCharHelp: document.getElementById("criteria-special-help"),
    criteria: {
      minLength: document.getElementById("criteria-length"),
      longLength: document.getElementById("criteria-long"),
      upperLower: document.getElementById("criteria-case"),
      number: document.getElementById("criteria-number"),
      special: document.getElementById("criteria-special"),
      notCommon: document.getElementById("criteria-common"),
    },
  },

  // ========== STATISTICS PANEL ==========
  stats: {
    mode: document.getElementById("stat-mode"),
    pbkdf2: document.getElementById("stat-pbkdf2"),
    operation: document.getElementById("stat-operation"),
    fileSize: document.getElementById("stat-filesize"),
    throughput: document.getElementById("stat-throughput"),
    pbkdf2Warning: document.getElementById("pbkdf2-warning"),
  },

  // ========== IMAGE COMPARISON ==========
  comparison: {
    card: document.getElementById("comparison-card"),
    originalCanvas: document.getElementById("original-canvas"),
    encryptedCanvas: document.getElementById("encrypted-canvas"),
  },

  // ========== ROUND VISUALIZER ==========
  roundVisualizer: {
    card: document.getElementById("round-visualizer-card"),
    loading: document.getElementById("round-loading"),
    loadingProgress: document.getElementById("round-loading-progress"),
    loadingText: document.getElementById("round-loading-text"),
    body: document.getElementById("round-visualizer-body"),

    // Display elements
    numberEl: document.getElementById("round-number"),
    titleEl: document.getElementById("round-title"),
    entropyValue: document.getElementById("round-entropy-value"),
    pill: document.getElementById("round-pill"),
    currentCanvasLabel: document.getElementById("round-current-label"),

    // Canvas elements
    originalCanvas: document.getElementById("round-original-canvas"),
    currentCanvas: document.getElementById("round-current-canvas"),
    filmstrip: document.getElementById("round-filmstrip"),

    // Histogram canvases
    histogramOriginal: document.getElementById("histogram-original"),
    histogramCurrent: document.getElementById("histogram-current"),

    // Controls
    range: document.getElementById("round-range"),
    prevBtn: document.getElementById("round-prev"),
    nextBtn: document.getElementById("round-next"),
    playBtn: document.getElementById("round-play"),
    playHelper: document.getElementById("round-play-helper"),
    badges: document.querySelectorAll(".round-badge"),
  },

  // ========== ATTACK SIMULATOR ==========
  attackSimulator: {
    button: document.getElementById("btn-simulate-attack"),
    status: document.getElementById("attack-status"),
    tamperDisplay: document.getElementById("tamper-display"),
  },

  // ========== BENCHMARKING ==========
  benchmark: {
    button: document.getElementById("btn-benchmark"),
    status: document.getElementById("benchmark-status"),
    spinner: document.getElementById("benchmark-spinner"),
    canvas: document.getElementById("pbkdf2-chart"),
  },
});

/**
 * Displays a status message to the user.
 * Used for success/error feedback after operations.
 *
 * @param {HTMLElement} element - Status display element
 * @param {string} message - Message to display
 * @param {boolean} isSuccess - True for success (green), false for error (red)
 */
export const showStatus = (element, message, isSuccess) => {
  if (!element) return;
  element.textContent = isSuccess ? "Success: " + message : "Error: " + message;
  element.className = `status-box ${isSuccess ? "status-success" : "status-error"}`;
  element.style.display = "block";
};

/**
 * Toggles spinner visibility with optional display.
 * Used to indicate loading state during async operations.
 *
 * @param {HTMLElement} spinnerEl - Spinner element to toggle
 * @param {boolean} show - True to show, false to hide
 */
export const toggleSpinner = (spinnerEl, show) => {
  if (!spinnerEl) return;
  spinnerEl.style.display = show ? "inline-block" : "none";
};

/**
 * Escapes HTML special characters to prevent XSS attacks.
 * Used when displaying user-provided data or dynamic content.
 *
 * @param {string} str - String to escape
 * @returns {string} Escaped string safe for HTML display
 */
export const escapeHtml = (str) =>
  str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

/**
 * Formats time duration to human-readable format.
 * Automatically chooses between milliseconds and seconds based on value.
 *
 * @param {number} ms - Duration in milliseconds
 * @returns {string} Formatted string like "2.3s" or "150ms"
 */
export const formatInterval = (ms) => {
  const useSeconds = ms >= 1000;
  const value = useSeconds ? (ms / 1000).toFixed(1) : ms;
  const unit = useSeconds ? "s" : "ms";
  return `${value}${unit}`;
};
