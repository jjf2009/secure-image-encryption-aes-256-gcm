/**
 * APP.JS
 * ======
 * Main application orchestrator.
 * Brings together all modules and handles high-level application flow.
 *
 * ARCHITECTURE:
 * - Crypto module: Handles encryption/decryption operations
 * - UI modules: Manage user interface and DOM interactions
 * - Visualization modules: Display image comparisons and round states
 * - Utils: Provide helper functions and constants
 *
 * This file initializes the app and connects event handlers.
 */

// ============================================================================
// IMPORTS
// ============================================================================

// Crypto operations
import { deriveKey, deriveKeyWithTiming } from "./crypto/keyDerivation.js";
import { encryptFile, decryptFile } from "./crypto/encryption.js";

// UI Management
import {
  cacheDOMElements,
  showStatus,
  toggleSpinner,
  escapeHtml,
} from "./ui/domManager.js";
import { updatePasswordStrengthUI } from "./ui/passwordStrength.js";

// Visualization
import {
  renderComparisonPanel,
  clearComparison,
} from "./visualization/imageComparison.js";
import {
  startRoundVisualizer,
  resetRoundVisualizer,
  initializeRoundControls,
} from "./visualization/roundVisualizer.js";

// Utilities
import { sanitizeFileName, formatBytes } from "./utils/fileHandler.js";
import { arrayBufferToBase64 } from "./utils/encoding.js";
import { FIXED_SALT, METADATA_DELIMITER } from "./utils/constants.js";

// ============================================================================
// APPLICATION STATE
// ============================================================================

const appState = {
  // Encryption state
  encryptInProgress: false,
  lastEncryptedPayload: "",
  lastEncryptionPassword: "",
  encryptedBlobUrl: null,
  decryptedBlobUrl: null,
  lastStrengthLevel: "weak",

  // DOM elements (cached)
  dom: null,

  // Visualization state
  visualizerState: {},
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Timing wrapper for measuring async operations.
 * Used to track performance of crypto operations.
 *
 * @param {Function} operation - Async function to measure
 * @returns {Promise<Object>} { data: result, duration: milliseconds }
 */
const withTiming = async (operation) => {
  const start = performance.now();
  const data = await operation();
  return { data, duration: performance.now() - start };
};

/**
 * Updates statistics panel with operation timings and file size info.
 * Displayed to user for performance monitoring.
 *
 * @param {Object} stats - { mode, pbkdf2Ms, operationMs, fileSizeBytes }
 */
const updateStatsPanel = ({ mode, pbkdf2Ms, operationMs, fileSizeBytes }) => {
  const dom = appState.dom.stats;
  if (!dom.mode || !dom.pbkdf2 || !dom.operation || !dom.fileSize) return;

  const displayMode = mode || "Operation";
  dom.mode.textContent = `Last ${displayMode}`;
  dom.pbkdf2.textContent = `${pbkdf2Ms.toFixed(1)} ms`;
  dom.operation.textContent = `${operationMs.toFixed(1)} ms`;
  dom.fileSize.textContent = formatBytes(fileSizeBytes);

  // Calculate throughput
  const throughput = fileSizeBytes / 1048576 / (operationMs / 1000);
  dom.throughput.textContent =
    throughput > 0 ? `${throughput.toFixed(2)} MB/s` : "—";

  // Show warning if PBKDF2 too fast
  if (dom.pbkdf2Warning) {
    dom.pbkdf2Warning.style.display = pbkdf2Ms < 200 ? "block" : "none";
  }
};

/**
 * Computes throughput in MB/s for performance display.
 *
 * @param {number} bytes - Data size
 * @param {number} timeMs - Time taken
 * @returns {number} Throughput in MB/s
 */
const computeThroughputMBps = (bytes, timeMs) => {
  if (bytes <= 0 || timeMs <= 0) return 0;
  return bytes / 1048576 / (timeMs / 1000);
};

// ============================================================================
// ENCRYPTION HANDLER
// ============================================================================

/**
 * Handles encryption button click.
 *
 * FLOW:
 * 1. Validate inputs (file and password)
 * 2. Show progress spinner
 * 3. Encrypt file with metadata
 * 4. Display ciphertext and download options
 * 5. Render image comparison
 * 6. Start round visualizer
 */
const handleEncryption = async () => {
  const dom = appState.dom;
  const fileInput = dom.encryption.fileInput;
  const password = dom.encryption.passwordInput.value;
  const status = dom.encryption.status;
  const spinner = dom.encryption.spinner;
  const downloadArea = dom.encryption.downloadArea;

  // Validation
  if (fileInput.files.length === 0 || !password) {
    showStatus(status, "Please provide an image and password.", false);
    return;
  }

  try {
    resetRoundVisualizer(appState.visualizerState, "Preparing visualizer...");
    appState.encryptInProgress = true;
    dom.encryption.button.disabled = true;
    toggleSpinner(spinner, true);
    status.style.display = "none";
    downloadArea.style.display = "none";
    clearComparison(dom.comparison);

    // Perform encryption with our module
    const file = fileInput.files[0];
    const { ciphertext, ciphertextWithTag, metadata, salt, timingInfo } =
      await encryptFile(file, password, deriveKeyWithTiming, withTiming);

    // Display results
    dom.encryption.downloadButton.href = URL.createObjectURL(
      new Blob([ciphertext], { type: "text/plain" }),
    );
    dom.encryption.downloadButton.download = "encrypt.txt";

    if (appState.encryptedBlobUrl) {
      URL.revokeObjectURL(appState.encryptedBlobUrl);
    }
    appState.encryptedBlobUrl = URL.createObjectURL(
      new Blob([ciphertext], { type: "text/plain" }),
    );

    downloadArea.style.display = "block";
    showStatus(status, "Encryption complete.", true);
    updateStatsPanel({
      mode: "Encryption",
      pbkdf2Ms: timingInfo.pbkdf2Ms,
      operationMs: timingInfo.encryptionMs,
      fileSizeBytes: metadata.size,
    });

    // For UI features
    appState.lastEncryptedPayload = ciphertext;
    appState.lastEncryptionPassword = password;
    dom.encryption.ciphertextOutput.value = ciphertext;

    // Show visual comparisons
    await renderComparisonPanel(file, ciphertextWithTag, dom.comparison);

    // Start round visualizer
    await startRoundVisualizer(
      file,
      null, // key will be derived from password
      password,
      salt,
      appState.visualizerState,
      deriveKeyWithTiming,
    );
  } catch (e) {
    console.error(e);
    showStatus(status, e.message, false);
    appState.lastEncryptedPayload = "";
    appState.lastEncryptionPassword = "";
    clearComparison(dom.comparison);
    resetRoundVisualizer(appState.visualizerState, "Visualizer unavailable.");
  } finally {
    toggleSpinner(spinner, false);
    updatePasswordStrengthUI({
      passwordInput: dom.encryption.passwordInput,
      strengthBar: dom.passwordStrength.strengthBar,
      strengthLabel: dom.passwordStrength.strengthLabel,
      strengthWarning: dom.passwordStrength.strengthWarning,
      criteriaCheckboxes: dom.passwordStrength.criteria,
      encryptButton: dom.encryption.button,
      encryptInProgress: false,
    });
    appState.encryptInProgress = false;
  }
};

// ============================================================================
// DECRYPTION HANDLER
// ============================================================================

/**
 * Handles decryption button click.
 *
 * FLOW:
 * 1. Validate inputs (ciphertext and password)
 * 2. Parse ciphertext format
 * 3. Decrypt and verify authentication tag
 * 4. Extract and display metadata
 * 5. Show preview and download option
 */
const handleDecryption = async () => {
  const dom = appState.dom;
  const encryptedText = dom.decryption.encryptedTextInput.value;
  const password = dom.decryption.passwordInput.value;
  const status = dom.decryption.status;
  const spinner = dom.decryption.spinner;
  const previewImg = dom.decryption.previewImg;
  const previewArea = dom.decryption.previewArea;

  // Validation
  if (!encryptedText || !password) {
    showStatus(status, "Provide encrypted text and password.", false);
    return;
  }

  try {
    dom.decryption.button.disabled = true;
    toggleSpinner(spinner, true);
    status.style.display = "none";
    previewArea.style.display = "none";
    dom.decryption.downloadButton.style.display = "none";

    // Perform decryption with our module
    const { fileBytes, metadata, timingInfo } = await decryptFile(
      encryptedText,
      password,
      deriveKeyWithTiming,
      withTiming,
      FIXED_SALT,
    );

    // Sanitize filename
    const safeName = sanitizeFileName(metadata?.name);
    const normalizedMetadata = {
      name: safeName,
      type: metadata?.type || "application/octet-stream",
      size: fileBytes.length,
    };

    // Create download link
    const blob = new Blob([fileBytes], { type: normalizedMetadata.type });
    if (appState.decryptedBlobUrl) {
      URL.revokeObjectURL(appState.decryptedBlobUrl);
    }
    appState.decryptedBlobUrl = URL.createObjectURL(blob);

    dom.decryption.downloadButton.href = appState.decryptedBlobUrl;
    dom.decryption.downloadButton.download =
      "restored_" + normalizedMetadata.name;

    // Show preview
    previewImg.src = appState.decryptedBlobUrl;
    previewArea.style.display = "block";
    dom.decryption.downloadButton.style.display = "inline-flex";

    // Display success message
    showStatus(
      status,
      `Decryption complete. File: ${normalizedMetadata.name} (${normalizedMetadata.type}, ${formatBytes(normalizedMetadata.size)})`,
      true,
    );

    updateStatsPanel({
      mode: "Decryption",
      pbkdf2Ms: timingInfo.pbkdf2Ms,
      operationMs: timingInfo.decryptionMs,
      fileSizeBytes: normalizedMetadata.size,
    });
  } catch (e) {
    console.error(e);
    showStatus(status, "Decryption failed. Check password.", false);
  } finally {
    dom.decryption.button.disabled = false;
    toggleSpinner(spinner, false);
  }
};

// ============================================================================
// PASSWORD STRENGTH MONITORING
// ============================================================================

/**
 * Sets up real-time password strength indicator.
 * Called on every character typed into password field.
 */
const setupPasswordStrengthMonitoring = () => {
  const dom = appState.dom;
  const passwordInput = dom.encryption.passwordInput;

  if (!passwordInput) return;

  passwordInput.addEventListener("input", () => {
    const strength = updatePasswordStrengthUI({
      passwordInput: passwordInput,
      strengthBar: dom.passwordStrength.strengthBar,
      strengthLabel: dom.passwordStrength.strengthLabel,
      strengthWarning: dom.passwordStrength.strengthWarning,
      criteriaCheckboxes: dom.passwordStrength.criteria,
      encryptButton: dom.encryption.button,
      encryptInProgress: appState.encryptInProgress,
    });
    appState.lastStrengthLevel = strength.level;
  });
};

// ============================================================================
// FILE IMPORT HANDLER
// ============================================================================

/**
 * Handles encrypted text file import for decryption.
 * Reads uploaded .txt file and populates the decryption textarea.
 */
const setupFileImport = () => {
  const fileUpload = appState.dom.decryption.fileUpload;
  const encryptedTextInput = appState.dom.decryption.encryptedTextInput;

  if (!fileUpload) return;

  fileUpload.addEventListener("change", function (e) {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      encryptedTextInput.value = e.target.result;
    };
    reader.readAsText(file);
  });
};

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * Initialize the entire application.
 * Called on page load.
 */
export const initializeApp = async () => {
  console.log("🔐 SecureImage - Initializing...");

  // Cache DOM elements
  appState.dom = cacheDOMElements();
  const dom = appState.dom;

  // Initialize visualizer state
  appState.visualizerState = {
    card: dom.roundVisualizer.card,
    loading: dom.roundVisualizer.loading,
    loadingProgress: dom.roundVisualizer.loadingProgress,
    loadingText: dom.roundVisualizer.loadingText,
    visualizerBody: dom.roundVisualizer.body,
    numberEl: dom.roundVisualizer.numberEl,
    titleEl: dom.roundVisualizer.titleEl,
    entropyEl: dom.roundVisualizer.entropyValue,
    pill: dom.roundVisualizer.pill,
    currentCanvasLabel: dom.roundVisualizer.currentCanvasLabel,
    range: dom.roundVisualizer.range,
    prevBtn: dom.roundVisualizer.prevBtn,
    nextBtn: dom.roundVisualizer.nextBtn,
    playBtn: dom.roundVisualizer.playBtn,
    playHelper: dom.roundVisualizer.playHelper,
    originalCanvas: dom.roundVisualizer.originalCanvas,
    currentCanvas: dom.roundVisualizer.currentCanvas,
    filmstrip: dom.roundVisualizer.filmstrip,
    histogramOriginalCanvas: dom.roundVisualizer.histogramOriginal,
    histogramCurrentCanvas: dom.roundVisualizer.histogramCurrent,
    badges: dom.roundVisualizer.badges,
    // State arrays
    roundStates: [],
    roundHistograms: [],
    roundEntropies: [],
    roundThumbRefs: [],
    roundCurrentIndex: 0,
    playTimer: null,
    histogramCurrentChart: null,
    histogramOriginalChart: null,
  };

  // Setup event handlers
  if (dom.encryption.button) {
    dom.encryption.button.addEventListener("click", handleEncryption);
  }

  if (dom.decryption.button) {
    dom.decryption.button.addEventListener("click", handleDecryption);
  }

  // Setup UI features
  setupPasswordStrengthMonitoring();
  setupFileImport();
  initializeRoundControls(appState.visualizerState);

  // Set initial password strength display
  updatePasswordStrengthUI({
    passwordInput: dom.encryption.passwordInput,
    strengthBar: dom.passwordStrength.strengthBar,
    strengthLabel: dom.passwordStrength.strengthLabel,
    strengthWarning: dom.passwordStrength.strengthWarning,
    criteriaCheckboxes: dom.passwordStrength.criteria,
    encryptButton: dom.encryption.button,
    encryptInProgress: false,
  });

  // Set special character help text
  if (dom.passwordStrength.specialCharHelp) {
    const { SPECIAL_CHAR_HELP_TEXT } = await import("./utils/constants.js");
    dom.passwordStrength.specialCharHelp.textContent = SPECIAL_CHAR_HELP_TEXT;
  }

  console.log("✅ SecureImage - Ready for use");
};

// Initialize when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeApp);
} else {
  initializeApp();
}
