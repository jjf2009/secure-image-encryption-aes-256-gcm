/**
 * SecureImage - AES-256-GCM Image Encryption/Decryption
 */

// Key Derivation logic
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_WARNING_THRESHOLD_MS = 200;

const deriveKeyInternal = async (password, salt, iterations) => {
    const encoder = new TextEncoder();
    const passwordKey = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: iterations,
            hash: "SHA-256"
        },
        passwordKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
};

const deriveKey = (password, salt) => deriveKeyInternal(password, salt, PBKDF2_ITERATIONS);

const deriveKeyWithIterations = (password, salt, iterations = PBKDF2_ITERATIONS) =>
    deriveKeyInternal(password, salt, iterations);

// Base64 helpers
const arrayBufferToBase64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
};

const base64ToArrayBuffer = (base64) => {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
};

// UI Elements & State
const btnEncrypt = document.getElementById('btn-encrypt');
const btnDecrypt = document.getElementById('btn-decrypt');
const btnDownloadTxt = document.getElementById('btn-download-txt');
const btnDownloadImg = document.getElementById('btn-download-img');
const encryptPasswordInput = document.getElementById('encrypt-password');
const strengthBar = document.getElementById('password-strength-bar');
const strengthLabel = document.getElementById('password-strength-label');
const strengthWarning = document.getElementById('password-strength-warning');
const specialCharHelp = document.getElementById('criteria-special-help');
const criteriaCheckboxes = {
    minLength: document.getElementById('criteria-length'),
    longLength: document.getElementById('criteria-long'),
    upperLower: document.getElementById('criteria-case'),
    number: document.getElementById('criteria-number'),
    special: document.getElementById('criteria-special'),
    notCommon: document.getElementById('criteria-common')
};
const ciphertextOutput = document.getElementById('ciphertext-output');
const btnSimulateAttack = document.getElementById('btn-simulate-attack');
const attackStatus = document.getElementById('attack-status');
const tamperDisplay = document.getElementById('tamper-display');
const comparisonCard = document.getElementById('comparison-card');
const originalCanvas = document.getElementById('original-canvas');
const encryptedCanvas = document.getElementById('encrypted-canvas');
const statMode = document.getElementById('stat-mode');
const statPbkdf2 = document.getElementById('stat-pbkdf2');
const statOperation = document.getElementById('stat-operation');
const statFileSize = document.getElementById('stat-filesize');
const statThroughput = document.getElementById('stat-throughput');
const pbkdf2Warning = document.getElementById('pbkdf2-warning');
const roundCard = document.getElementById('round-visualizer-card');
const roundLoading = document.getElementById('round-loading');
const roundLoadingProgress = document.getElementById('round-loading-progress');
const roundLoadingText = document.getElementById('round-loading-text');
const roundVisualizerBody = document.getElementById('round-visualizer-body');
const roundNumberEl = document.getElementById('round-number');
const roundTitleEl = document.getElementById('round-title');
const roundEntropyEl = document.getElementById('round-entropy-value');
const roundRange = document.getElementById('round-range');
const roundPrevBtn = document.getElementById('round-prev');
const roundNextBtn = document.getElementById('round-next');
const roundPlayBtn = document.getElementById('round-play');
const roundPill = document.getElementById('round-pill');
const roundPlayHelper = document.getElementById('round-play-helper');
const roundCurrentCanvasLabel = document.getElementById('round-current-label');
const roundBadges = document.querySelectorAll('.round-badge');
const roundOriginalCanvas = document.getElementById('round-original-canvas');
const roundCurrentCanvas = document.getElementById('round-current-canvas');
const roundFilmstrip = document.getElementById('round-filmstrip');
const histogramOriginalCanvas = document.getElementById('histogram-original');
const histogramCurrentCanvas = document.getElementById('histogram-current');
const btnBenchmark = document.getElementById('btn-benchmark');
const benchmarkStatus = document.getElementById('benchmark-status');
const benchmarkSpinner = document.getElementById('benchmark-spinner');
const benchmarkChartCanvas = document.getElementById('pbkdf2-chart');
const MAX_CANVAS_DIMENSION = 420;
const NOISE_SEED_SAMPLE_SIZE = 1024;
const FNV_OFFSET_BASIS = 0x811c9dc5;
const FNV_PRIME = 0x01000193;
const VISUALIZER_MAX_DIMENSION = 280;
const ROUND_STATES_TOTAL = 14;
// 900ms provides time to observe diffusion changes while keeping playback engaging.
const ROUND_PLAY_INTERVAL_MS = 900;
const FILMSTRIP_THUMB_SIZE = 80;
const AES_SBOX = new Uint8Array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]);

let encryptedBlobUrl = null;
let decryptedBlobUrl = null;
let lastEncryptedPayload = "";
let lastEncryptionPassword = "";
let encryptInProgress = false;
let lastStrengthLevel = "weak";
let roundStates = [];
let roundHistograms = [];
let roundEntropies = [];
let roundThumbRefs = [];
let roundPlayTimer = null;
let roundCurrentIndex = 0;
let histogramOriginalChart = null;
let histogramCurrentChart = null;

const METADATA_DELIMITER = "::SECUREIMAGE_METADATA::";
const DEFAULT_FILE_NAME = "file.bin";
const MAX_FILENAME_LENGTH = 200;
const MAX_METADATA_SIZE = 10 * 1024; // 10 KB
const MAX_FILESIZE_BYTES = 200 * 1024 * 1024; // 200 MB ceiling
const RESERVED_FILENAMES = new Set([
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
]);
const FIXED_SALT = new TextEncoder().encode("SECUREIMAGE_SALT_PBKDF2");
const SALT_BYTE_LENGTH = 16;
const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
let pbkdf2Chart = null;
let primaryColorCache = null;
// Benchmark range includes a low iteration count for comparative timing only (not a security recommendation).
const BENCHMARK_ITERATIONS = [10000, 50000, 100000, 200000, 500000];
const COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "111111", "qwerty", "abc123", "password1", "123123",
    "iloveyou", "1q2w3e4r", "000000", "letmein", "dragon",
    "sunshine", "princess", "monkey", "login", "password123"
];
const MIN_PASSWORD_LENGTH = 8;
const STRONG_PASSWORD_LENGTH = 12;
// Set of allowed special characters kept as an explicit list to avoid escape ambiguity.
const SPECIAL_CHARACTERS = [
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '-', '=', '[',
    ']', '{', '}', ';', ':', "'", '"', ',', '.', '<', '>', '/', '?', '\\', '|', '~', '`'
];
const SPECIAL_CHAR_SET = SPECIAL_CHARACTERS.join('');
const SPECIAL_CHAR_DISPLAY = SPECIAL_CHARACTERS.join(', ');
/**
 * Escapes characters with special meaning inside regex character classes.
 * Ensures the provided string can be embedded safely in a RegExp like /[...]/.
 * Escapes backslash (escape), square brackets (class delimiters), caret (negation),
 * and hyphen (range definition) which are the special tokens within [].
 */
const escapeForCharClass = (chars) => chars.replace(/[\\\[\]^-]/g, '\\$&');
const SPECIAL_CHAR_PATTERN = new RegExp(`[${escapeForCharClass(SPECIAL_CHAR_SET)}]`);
const STRENGTH_SCORE_MAX = {
    weak: 2,
    fair: 4,
    strong: 5
};
const STRENGTH_PERCENTAGES = {
    weak: 25,
    fair: 50,
    strong: 75,
    veryStrong: 100
};
const STRENGTH_CLASSES = {
    weak: "strength-weak",
    fair: "strength-fair",
    strong: "strength-strong",
    veryStrong: "strength-very-strong"
};
const SPECIAL_CHAR_HELP_TEXT = `Special characters include: ${SPECIAL_CHAR_DISPLAY}`;
const ROUND_TITLES = [
    "Round 0 — Original Image",
    "Round 1 — Initial Confusion",
    "Round 2 — S-Box Cascade",
    "Round 3 — Shifted Strata",
    "Round 4 — Heavy Diffusion",
    "Round 5 — Avalanche Builds",
    "Round 6 — Deep Mixing",
    "Round 7 — Randomness Rising",
    "Round 8 — Column Scramble",
    "Round 9 — Cross-Byte Shuffle",
    "Round 10 — Key Weave",
    "Round 11 — Entropy Surge",
    "Round 12 — Near-Uniform",
    "Round 13 — Final Diffusion",
    "Round 14 — Final Key Infusion"
];

if (specialCharHelp) {
    specialCharHelp.textContent = SPECIAL_CHAR_HELP_TEXT;
}

const getPrimaryColor = () => {
    if (primaryColorCache) return primaryColorCache;
    primaryColorCache = (getComputedStyle(document.documentElement).getPropertyValue('--primary').trim() || '#4f46e5');
    return primaryColorCache;
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

const showStatus = (el, msg, isSuccess) => {
    el.textContent = isSuccess ? "Success: " + msg : "Error: " + msg;
    el.className = `status-box ${isSuccess ? 'status-success' : 'status-error'}`;
    el.style.display = "block";
};

const toggleSpinner = (spinnerEl, show) => {
    if (!spinnerEl) return;
    spinnerEl.style.display = show ? "inline-block" : "none";
};

const evaluatePasswordCriteria = (password) => {
    const lower = password.toLowerCase();
    return {
        minLength: password.length >= MIN_PASSWORD_LENGTH,
        longLength: password.length >= STRONG_PASSWORD_LENGTH,
        upperLower: /[a-z]/.test(password) && /[A-Z]/.test(password),
        number: /\d/.test(password),
        special: SPECIAL_CHAR_PATTERN.test(password),
        notCommon: password.length > 0 && !COMMON_PASSWORDS.includes(lower)
    };
};

const determineStrength = (criteria) => {
    const metCriteriaCount = Object.values(criteria).filter(Boolean).length;
    if (!criteria.minLength) return { level: "weak", label: "Weak", percentage: STRENGTH_PERCENTAGES.weak };
    if (metCriteriaCount <= STRENGTH_SCORE_MAX.weak) return { level: "weak", label: "Weak", percentage: STRENGTH_PERCENTAGES.weak };
    if (metCriteriaCount <= STRENGTH_SCORE_MAX.fair) return { level: "fair", label: "Fair", percentage: STRENGTH_PERCENTAGES.fair };
    if (metCriteriaCount <= STRENGTH_SCORE_MAX.strong) return { level: "strong", label: "Strong", percentage: STRENGTH_PERCENTAGES.strong };
    return { level: "veryStrong", label: "Very Strong", percentage: STRENGTH_PERCENTAGES.veryStrong };
};

const updatePasswordStrengthUI = () => {
    if (!encryptPasswordInput || !strengthBar || !strengthLabel) return;
    const password = encryptPasswordInput.value || "";
    const criteria = evaluatePasswordCriteria(password);
    const { level, label, percentage } = determineStrength(criteria);
    const labelClass = STRENGTH_CLASSES[level];

    if (level !== lastStrengthLevel) {
        strengthLabel.textContent = label;
        strengthLabel.className = `strength-text ${labelClass}`;
    }

    strengthBar.style.width = `${percentage}%`;
    strengthBar.className = `strength-bar ${labelClass}`;

    if (strengthWarning) {
        strengthWarning.style.display = criteria.minLength ? "none" : "inline";
        strengthWarning.textContent = criteria.minLength ? "" : `Minimum ${MIN_PASSWORD_LENGTH} characters required.`;
    }

    Object.entries(criteriaCheckboxes).forEach(([key, checkbox]) => {
        if (!checkbox) return;
        const met = Boolean(criteria[key]);
        checkbox.checked = met;
        const item = checkbox.closest('.criteria-item');
        if (item) {
            item.classList.toggle('met', met);
        }
    });

    if (btnEncrypt) {
        btnEncrypt.disabled = encryptInProgress || level === "weak";
    }
    lastStrengthLevel = level;
};

encryptPasswordInput?.addEventListener('input', updatePasswordStrengthUI);

const formatBytes = (bytes) => {
    if (bytes === 0) return "0 B";
    const kb = bytes / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    return `${(kb / 1024).toFixed(2)} MB`;
};

const computeThroughputMBps = (bytes, timeMs) => {
    if (bytes <= 0 || timeMs <= 0) return 0;
    return (bytes / 1048576) / (timeMs / 1000);
};

const sanitizeFileName = (name) => {
    const originalName = name || DEFAULT_FILE_NAME;
    if (/[\\/]/.test(originalName)) {
        console.warn("Embedded filename contained path separators; using last segment.");
    }
    const base = originalName.split(/[\\/]/).pop();
    const withoutControl = base.replace(/[\x00-\x1F\x80-\x9F]/g, "");
    const cleaned = withoutControl.replace(/[<>:"/\\|?*]/g, "_").trim();
    const stripped = cleaned.replace(/^\.+/, "").replace(/\.+$/, "");
    const dotIndex = stripped.lastIndexOf(".");
    const nameRoot = dotIndex === -1 ? (stripped || "file") : stripped.slice(0, dotIndex);
    const extension = dotIndex === -1 ? "" : stripped.slice(dotIndex);
    const baseRoot = (nameRoot.split(".")[0] || "file").toUpperCase();
    const needsAdjust = RESERVED_FILENAMES.has(baseRoot);
    const adjustedRoot = needsAdjust ? `${nameRoot}_file` : nameRoot;
    const candidate = `${adjustedRoot}${extension}`.replace(/^\.+/, "") || DEFAULT_FILE_NAME;
    if (candidate.length <= MAX_FILENAME_LENGTH) return candidate;
    const lastDot = candidate.lastIndexOf(".");
    const ext = lastDot >= 0 ? candidate.slice(lastDot) : "";
    const baseTruncated = lastDot >= 0 ? candidate.slice(0, lastDot) : candidate;
    const trimmedBase = baseTruncated.slice(0, Math.max(1, MAX_FILENAME_LENGTH - ext.length));
    return `${trimmedBase}${ext}`;
};

const updateStatsPanel = ({ mode, pbkdf2Ms, operationMs, fileSizeBytes }) => {
    if (!statMode || !statPbkdf2 || !statOperation || !statFileSize || !statThroughput) return;
    const displayMode = mode || "Operation";
    statMode.textContent = `Last ${displayMode}`;
    statPbkdf2.textContent = `${pbkdf2Ms.toFixed(1)} ms`;
    statOperation.textContent = `${operationMs.toFixed(1)} ms`;
    statFileSize.textContent = formatBytes(fileSizeBytes);
    const throughput = computeThroughputMBps(fileSizeBytes, operationMs);
    statThroughput.textContent = throughput > 0 ? `${throughput.toFixed(2)} MB/s` : "—";
    if (pbkdf2Warning) {
        pbkdf2Warning.style.display = pbkdf2Ms < PBKDF2_WARNING_THRESHOLD_MS ? "block" : "none";
    }
};

const withTiming = async (operation) => {
    const start = performance.now();
    const data = await operation();
    return { data, duration: performance.now() - start };
};

const deriveKeyWithTiming = async (password, salt, iterations = PBKDF2_ITERATIONS) => {
    const { data, duration } = await withTiming(() => deriveKeyWithIterations(password, salt, iterations));
    return { key: data, duration };
};

const encryptWithTiming = async (key, iv, dataBuffer) =>
    withTiming(() => window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, dataBuffer));

const decryptWithTiming = async (key, iv, ciphertextWithTag) =>
    withTiming(() => window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertextWithTag));

const resetAttackPanel = () => {
    if (attackStatus) {
        attackStatus.style.display = "none";
        attackStatus.textContent = "";
    }
    if (tamperDisplay) {
        tamperDisplay.innerHTML = "";
    }
    if (btnSimulateAttack) {
        btnSimulateAttack.disabled = true;
    }
};

const escapeHtml = (str) => str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const renderTamperDisplay = (parts, tamperedSegment, tamperedIndex = parts.length - 1) => {
    if (!tamperDisplay) return;
    const labels = parts.length === 4
        ? ["Salt", "IV", "Tag", "Ciphertext"]
        : ["IV", "Tag", "Ciphertext"];

    const segmentsHtml = parts.map((segment, idx) => {
        const isTampered = idx === tamperedIndex;
        const content = escapeHtml(isTampered ? tamperedSegment : segment);
        const label = labels[idx] || "Segment";
        return `
            <div class="segments">
                <span class="segment-label">${label}</span>
                <span class="tamper-chip ${isTampered ? 'tampered' : ''}">${content}</span>
            </div>
        `;
    }).join('<span style="color: var(--text-muted);">:</span>');

    tamperDisplay.innerHTML = segmentsHtml;
};

const clearComparison = () => {
    if (comparisonCard) {
        comparisonCard.style.display = "none";
    }
    [originalCanvas, encryptedCanvas].forEach((canvas) => {
        if (canvas) {
            const ctx = canvas.getContext('2d');
            if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height);
        }
    });
};

const computeCanvasSize = (bitmap) => {
    if (!bitmap || bitmap.width <= 0 || bitmap.height <= 0) {
        return null;
    }
    const scale = Math.min(1, MAX_CANVAS_DIMENSION / bitmap.width, MAX_CANVAS_DIMENSION / bitmap.height);
    return {
        width: Math.max(1, Math.round(bitmap.width * scale)),
        height: Math.max(1, Math.round(bitmap.height * scale))
    };
};

const drawOriginalImage = (bitmap, targetWidth, targetHeight) => {
    if (!originalCanvas) return;
    originalCanvas.width = targetWidth;
    originalCanvas.height = targetHeight;
    const ctx = originalCanvas.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, targetWidth, targetHeight);
    ctx.drawImage(bitmap, 0, 0, targetWidth, targetHeight);
};

const drawEncryptedNoise = (bytes, targetWidth, targetHeight) => {
    if (!encryptedCanvas || !bytes?.length) return;
    encryptedCanvas.width = targetWidth;
    encryptedCanvas.height = targetHeight;
    const ctx = encryptedCanvas.getContext('2d');
    if (!ctx) return;

    const imageData = ctx.createImageData(targetWidth, targetHeight);
    const data = imageData.data;
    const len = bytes.length;
    let state = FNV_OFFSET_BASIS;
    const actualSampleSize = Math.min(len, NOISE_SEED_SAMPLE_SIZE);
    const sampleStride = Math.max(1, Math.floor(len / actualSampleSize));
    let sampleIndex = 0;
    for (let sampled = 0; sampled < actualSampleSize; sampled++) {
        state ^= bytes[sampleIndex];
        state = Math.imul(state, FNV_PRIME);
        sampleIndex = (sampleIndex + sampleStride) % len;
    }
    // Guard against a zero state after hashing the ciphertext sample (bytes is non-empty due to guard above).
    if (state === 0) state = FNV_OFFSET_BASIS;

    for (let i = 0; i < data.length; i += 4) {
        // Xorshift32 PRNG step to spread ciphertext-derived entropy across pixels
        state ^= state << 13;
        state ^= state >>> 17;
        state ^= state << 5;
        state >>>= 0;
        const startIndex = state % len;
        data[i] = bytes[startIndex];
        data[i + 1] = bytes[(startIndex + 1) % len];
        data[i + 2] = bytes[(startIndex + 2) % len];
        data[i + 3] = 255;
    }

    ctx.putImageData(imageData, 0, 0);
};

const clampKeyBytes = (bytes) => {
    if (!bytes) return new Uint8Array(32);
    if (bytes.length === 32) return new Uint8Array(bytes);
    if (bytes.length > 32) return new Uint8Array(bytes.slice(0, 32));
    const padded = new Uint8Array(32);
    padded.set(bytes);
    return padded;
};

const deriveRoundKeys = (baseKeyBytes, rounds = ROUND_STATES_TOTAL) => {
    const keys = [];
    let prev = clampKeyBytes(baseKeyBytes);
    for (let r = 1; r <= rounds; r++) {
        const next = new Uint8Array(prev.length);
        for (let i = 0; i < prev.length; i++) {
            next[i] = AES_SBOX[prev[i]] ^ r;
        }
        keys.push(next);
        prev = next;
    }
    return keys;
};

const xtime = (b) => {
    const shifted = (b << 1) & 0xff;
    return (b & 0x80) ? (shifted ^ 0x1b) : shifted;
};

const gmul3 = (b) => xtime(b) ^ b;

const applySubBytes = (data) => {
    const out = new Uint8ClampedArray(data.length);
    for (let i = 0; i < data.length; i += 4) {
        out[i] = AES_SBOX[data[i]];
        out[i + 1] = AES_SBOX[data[i + 1]];
        out[i + 2] = AES_SBOX[data[i + 2]];
        out[i + 3] = data[i + 3];
    }
    return out;
};

const applyShiftRows = (data, width, height) => {
    const out = new Uint8ClampedArray(data.length);
    const rowStride = width * 4;
    for (let y = 0; y < height; y++) {
        const shift = y % 4;
        for (let x = 0; x < width; x++) {
            const destX = (x - shift + width) % width;
            const srcIndex = (y * rowStride) + (x * 4);
            const destIndex = (y * rowStride) + (destX * 4);
            out[destIndex] = data[srcIndex];
            out[destIndex + 1] = data[srcIndex + 1];
            out[destIndex + 2] = data[srcIndex + 2];
            out[destIndex + 3] = data[srcIndex + 3];
        }
    }
    return out;
};

const applyMixColumns = (data, width, height) => {
    const out = new Uint8ClampedArray(data.length);
    const rowStride = width * 4;
    for (let y = 0; y < height; y++) {
        for (let x = 0; x < width; x++) {
            const srcIndex = (y * rowStride) + (x * 4);
            const nextX = (x + 1) % width;
            const nextIndex = (y * rowStride) + (nextX * 4);
            out[srcIndex] = xtime(data[srcIndex]) ^ gmul3(data[nextIndex]);
            out[srcIndex + 1] = xtime(data[srcIndex + 1]) ^ gmul3(data[nextIndex + 1]);
            out[srcIndex + 2] = xtime(data[srcIndex + 2]) ^ gmul3(data[nextIndex + 2]);
            out[srcIndex + 3] = data[srcIndex + 3];
        }
    }
    return out;
};

const applyAddRoundKey = (data, roundKey) => {
    const out = new Uint8ClampedArray(data.length);
    let keyIndex = 0;
    for (let i = 0; i < data.length; i++) {
        if ((i % 4) === 3) {
            out[i] = data[i];
            continue;
        }
        out[i] = data[i] ^ roundKey[keyIndex % roundKey.length];
        keyIndex++;
    }
    return out;
};

const histogramFromData = (data) => {
    const histogram = new Uint32Array(256);
    let total = 0;
    for (let i = 0; i < data.length; i += 4) {
        histogram[data[i]]++;
        histogram[data[i + 1]]++;
        histogram[data[i + 2]]++;
        total += 3;
    }
    return { histogram: Array.from(histogram), total };
};

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

const buildRoundStates = async (baseImageData, roundKeys, onProgress) => {
    const states = [baseImageData];
    const hist0 = histogramFromData(baseImageData.data);
    const histograms = [hist0.histogram];
    const entropies = [entropyFromHistogram(hist0)];
    let prevData = baseImageData.data;

    for (let r = 1; r <= ROUND_STATES_TOTAL; r++) {
        if (typeof onProgress === "function") {
            onProgress(r);
        }
        let working = applySubBytes(prevData);
        working = applyShiftRows(working, baseImageData.width, baseImageData.height);
        // Apply MixColumns for rounds 1–13 to mirror the AES round schedule for visualization; round 14 (final) omits it.
        if (r !== ROUND_STATES_TOTAL) {
            working = applyMixColumns(working, baseImageData.width, baseImageData.height);
        }
        working = applyAddRoundKey(working, roundKeys[r - 1]);
        const imageData = new ImageData(working, baseImageData.width, baseImageData.height);
        states.push(imageData);
        const hist = histogramFromData(imageData.data);
        histograms.push(hist.histogram);
        entropies.push(entropyFromHistogram(hist));
        prevData = imageData.data;
        await new Promise((resolve) => requestAnimationFrame(resolve));
    }

    return { states, histograms, entropies };
};

const computeVisualizerSize = (bitmap) => {
    const maxSide = Math.max(bitmap.width, bitmap.height);
    const scale = Math.min(1, VISUALIZER_MAX_DIMENSION / maxSide);
    const width = Math.max(1, Math.round(bitmap.width * scale));
    const height = Math.max(1, Math.round(bitmap.height * scale));
    return { width, height };
};

const drawImageDataToCanvas = (canvas, imageData) => {
    if (!canvas || !imageData) return;
    canvas.width = imageData.width;
    canvas.height = imageData.height;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.putImageData(imageData, 0, 0);
};

const setRoundBadges = (roundIndex) => {
    const ops = {
        subbytes: roundIndex > 0,
        shiftrows: roundIndex > 0,
        mixcolumns: roundIndex > 0 && roundIndex < ROUND_STATES_TOTAL,
        addroundkey: roundIndex > 0
    };
    roundBadges.forEach((badge) => {
        const op = badge?.dataset?.op;
        badge?.classList.toggle('active', Boolean(op && ops[op]));
    });
};

const updateHistogramCharts = (roundIndex) => {
    if (!histogramOriginalCanvas || !histogramCurrentCanvas) return;
    const labels = Array.from({ length: 256 }, (_, i) => i);
    const primary = getPrimaryColor();
    if (typeof Chart === "undefined") return;

    if (!histogramOriginalChart) {
        histogramOriginalChart = new Chart(histogramOriginalCanvas.getContext('2d'), {
            type: "bar",
            data: {
                labels,
                datasets: [{
                    label: "R0 Distribution",
                    data: roundHistograms[0] || [],
                    backgroundColor: colorWithAlpha(primary, 0.45),
                    borderColor: primary,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { x: { display: false }, y: { display: false } },
                plugins: { legend: { display: false } }
            }
        });
    }

    if (!histogramCurrentChart) {
        histogramCurrentChart = new Chart(histogramCurrentCanvas.getContext('2d'), {
            type: "bar",
            data: {
                labels,
                datasets: [{
                    label: "Current Round",
                    data: roundHistograms[roundIndex] || [],
                    backgroundColor: colorWithAlpha(primary, 0.35),
                    borderColor: primary,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { x: { display: false }, y: { display: false } },
                plugins: { legend: { display: false } }
            }
        });
    } else {
        histogramCurrentChart.data.datasets[0].data = roundHistograms[roundIndex] || [];
        histogramCurrentChart.update();
    }
};

const highlightFilmstrip = (roundIndex) => {
    roundThumbRefs.forEach((thumb, idx) => {
        thumb.classList.toggle('active', idx === roundIndex);
    });
};

const setRoundDisplay = (roundIndex) => {
    if (!roundStates.length) return;
    roundCurrentIndex = roundIndex;
    const padded = roundIndex.toString().padStart(2, '0');
    if (roundRange) roundRange.value = String(roundIndex);
    if (roundNumberEl) roundNumberEl.textContent = padded;
    if (roundTitleEl) roundTitleEl.textContent = ROUND_TITLES[roundIndex] || `Round ${roundIndex}`;
    if (roundPill) roundPill.textContent = `R${padded}`;
    if (roundCurrentCanvasLabel) roundCurrentCanvasLabel.textContent = `R${padded} — Current`;
    if (roundEntropyEl && roundEntropies[roundIndex] !== undefined) {
        roundEntropyEl.textContent = `${roundEntropies[roundIndex].toFixed(3)} bits`;
    }

    setRoundBadges(roundIndex);
    drawImageDataToCanvas(roundCurrentCanvas, roundStates[roundIndex]);
    updateHistogramCharts(roundIndex);
    highlightFilmstrip(roundIndex);
};

const stopRoundPlayback = () => {
    if (roundPlayTimer) {
        clearInterval(roundPlayTimer);
        roundPlayTimer = null;
    }
    if (roundPlayBtn) roundPlayBtn.textContent = "Play";
};

const buildFilmstrip = () => {
    if (!roundFilmstrip) return;
    roundFilmstrip.innerHTML = "";
    roundThumbRefs = [];
    roundStates.forEach((state, idx) => {
        const thumb = document.createElement('canvas');
        thumb.className = 'round-thumb';
        const scale = Math.min(1, FILMSTRIP_THUMB_SIZE / Math.max(state.width, state.height));
        thumb.width = Math.max(1, Math.round(state.width * scale));
        thumb.height = Math.max(1, Math.round(state.height * scale));
        const ctx = thumb.getContext('2d');
        if (ctx) {
            const tempCanvas = document.createElement('canvas');
            tempCanvas.width = state.width;
            tempCanvas.height = state.height;
            const tempCtx = tempCanvas.getContext('2d');
            tempCtx?.putImageData(state, 0, 0);
            ctx.drawImage(tempCanvas, 0, 0, thumb.width, thumb.height);
        }
        thumb.addEventListener('click', () => {
            stopRoundPlayback();
            setRoundDisplay(idx);
        });
        roundFilmstrip.appendChild(thumb);
        roundThumbRefs.push(thumb);
    });
    highlightFilmstrip(roundCurrentIndex);
};

const resetRoundVisualizer = (message = "Awaiting encryption...") => {
    stopRoundPlayback();
    roundStates = [];
    roundHistograms = [];
    roundEntropies = [];
    roundThumbRefs = [];
    histogramOriginalChart?.destroy?.();
    histogramCurrentChart?.destroy?.();
    histogramOriginalChart = null;
    histogramCurrentChart = null;
    if (roundVisualizerBody) roundVisualizerBody.style.display = "none";
    if (roundLoading) roundLoading.style.display = "block";
    if (roundLoadingText) roundLoadingText.textContent = message;
    if (roundLoadingProgress) roundLoadingProgress.style.width = "0%";
    if (roundCard) roundCard.style.display = "none";
};

const startRoundPlayback = () => {
    if (roundPlayTimer) {
        stopRoundPlayback();
        return;
    }
    if (roundPlayBtn) roundPlayBtn.textContent = "Pause";
    roundPlayTimer = setInterval(() => {
        const next = (roundCurrentIndex + 1) % (ROUND_STATES_TOTAL + 1);
        setRoundDisplay(next);
    }, ROUND_PLAY_INTERVAL_MS);
};

const handleRoundRangeChange = (event) => {
    const value = Number(event.target?.value ?? 0);
    stopRoundPlayback();
    setRoundDisplay(Math.min(Math.max(0, value), ROUND_STATES_TOTAL));
};

const initializeRoundControls = () => {
    if (roundPlayHelper) {
        roundPlayHelper.textContent = `Auto-advance every ${formatInterval(ROUND_PLAY_INTERVAL_MS)} when playing`;
    }
    roundRange?.addEventListener('input', handleRoundRangeChange);
    roundPrevBtn?.addEventListener('click', () => {
        stopRoundPlayback();
        const prev = roundCurrentIndex === 0 ? ROUND_STATES_TOTAL : roundCurrentIndex - 1;
        setRoundDisplay(prev);
    });
    roundNextBtn?.addEventListener('click', () => {
        stopRoundPlayback();
        const next = (roundCurrentIndex + 1) % (ROUND_STATES_TOTAL + 1);
        setRoundDisplay(next);
    });
    roundPlayBtn?.addEventListener('click', startRoundPlayback);
};

initializeRoundControls();

const startRoundVisualizer = async (file, key, password, encryptionSalt) => {
    if (!file || !roundCard) return;
    resetRoundVisualizer("Computing rounds...");
    roundCard.style.display = "block";

    const updateProgress = (round) => {
        const pct = Math.min(100, Math.round((round / ROUND_STATES_TOTAL) * 100));
        if (roundLoadingProgress) roundLoadingProgress.style.width = `${pct}%`;
        if (roundLoadingText) roundLoadingText.textContent = `Computing round ${round} of ${ROUND_STATES_TOTAL}...`;
    };

    let bitmap;
    try {
        bitmap = await createImageBitmap(file);
    } catch (err) {
        console.warn("Visualizer image decode failed.", err);
        resetRoundVisualizer("Image decode failed for visualizer.");
        return;
    }

    const { width, height } = computeVisualizerSize(bitmap);
    const tempCanvas = document.createElement('canvas');
    tempCanvas.width = width;
    tempCanvas.height = height;
    const ctx = tempCanvas.getContext('2d');
    if (!ctx) {
        resetRoundVisualizer("Canvas context unavailable.");
        return;
    }
    ctx.drawImage(bitmap, 0, 0, width, height);
    const baseImageData = ctx.getImageData(0, 0, width, height);

    let baseKeyBytes;
    try {
        if (key) {
            const raw = await window.crypto.subtle.exportKey('raw', key);
            baseKeyBytes = new Uint8Array(raw);
        } else {
            const saltBytes = encryptionSalt ? new Uint8Array(encryptionSalt) : window.crypto.getRandomValues(new Uint8Array(SALT_BYTE_LENGTH));
            // Visualization-only derivation mirrors PBKDF2 flow.
            // Use the encryption salt when available, or a fresh random salt — avoiding any hardcoded fixed salt.
            // Non-deterministic previews are acceptable for this educational visualization.
            const derivedKey = await deriveKeyWithIterations(password || "", saltBytes);
            const rawDerived = await window.crypto.subtle.exportKey('raw', derivedKey);
            baseKeyBytes = new Uint8Array(rawDerived);
        }
    } catch (err) {
        console.warn("Visualizer key derivation failed.", err);
        baseKeyBytes = new Uint8Array(32);
    }

    const roundKeys = deriveRoundKeys(baseKeyBytes, ROUND_STATES_TOTAL);
    const { states, histograms, entropies } = await buildRoundStates(baseImageData, roundKeys, updateProgress);

    roundStates = states;
    roundHistograms = histograms;
    roundEntropies = entropies;

    drawImageDataToCanvas(roundOriginalCanvas, states[0]);
    drawImageDataToCanvas(roundCurrentCanvas, states[0]);
    buildFilmstrip();
    setRoundDisplay(0);

    if (roundLoading) roundLoading.style.display = "none";
    if (roundVisualizerBody) roundVisualizerBody.style.display = "flex";
};

const renderComparisonPanel = async (file, ciphertextWithTagBytes) => {
    if (!comparisonCard || !file || !ciphertextWithTagBytes?.length) return;

    let bitmap;
    try {
        bitmap = await createImageBitmap(file);
    } catch (err) {
        console.warn("Comparison panel unavailable: image decoding failed.", err);
        clearComparison();
        return;
    }

    try {
        const size = computeCanvasSize(bitmap);
        if (!size) {
            throw new Error("Unable to determine image dimensions for comparison.");
        }
        const { width, height } = size;
        drawOriginalImage(bitmap, width, height);
        drawEncryptedNoise(ciphertextWithTagBytes, width, height);
        comparisonCard.style.display = "block";
    } catch (err) {
        console.warn("Comparison panel unavailable during canvas rendering.", err);
        clearComparison();
    }
};

updatePasswordStrengthUI();

// ENCRYPTION
btnEncrypt.addEventListener('click', async () => {
    const fileInput = document.getElementById('image-upload');
    const password = document.getElementById('encrypt-password').value;
    const status = document.getElementById('encrypt-status');
    const spinner = document.getElementById('encrypt-spinner');
    const downloadArea = document.getElementById('download-area');

    if (fileInput.files.length === 0 || !password) {
        showStatus(status, "Please provide an image and password.", false);
        return;
    }

    try {
        resetRoundVisualizer("Preparing visualizer...");
        encryptInProgress = true;
        btnEncrypt.disabled = true;
        spinner.style.display = "inline-block";
        status.style.display = "none";
        downloadArea.style.display = "none";
        clearComparison();

        const file = fileInput.files[0];
        const arrayBuffer = await file.arrayBuffer();
        const encoder = new TextEncoder();
        const metadata = {
            name: file.name || "file.bin",
            type: file.type || "application/octet-stream",
            size: file.size
        };
        const metadataBytes = encoder.encode(JSON.stringify(metadata));
        const delimiterBytes = encoder.encode(METADATA_DELIMITER);
        const metadataLengthBytes = new Uint8Array(4);
        new DataView(metadataLengthBytes.buffer).setUint32(0, metadataBytes.length, true);
        const fileBytes = new Uint8Array(arrayBuffer);
        const payload = new Uint8Array(metadataLengthBytes.length + metadataBytes.length + delimiterBytes.length + fileBytes.length);
        payload.set(metadataLengthBytes, 0);
        payload.set(metadataBytes, metadataLengthBytes.length);
        payload.set(delimiterBytes, metadataLengthBytes.length + metadataBytes.length);
        payload.set(fileBytes, metadataLengthBytes.length + metadataBytes.length + delimiterBytes.length);

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const salt = window.crypto.getRandomValues(new Uint8Array(SALT_BYTE_LENGTH));
        const { key, duration: pbkdf2Ms } = await deriveKeyWithTiming(password, salt);

        const { data: encryptedData, duration: encryptionMs } = await encryptWithTiming(
            key,
            iv,
            payload
        );

        const tagSize = 16;
        const ciphertextWithTag = new Uint8Array(encryptedData);
        const ciphertext = ciphertextWithTag.slice(0, ciphertextWithTag.length - tagSize);
        const tag = ciphertextWithTag.slice(ciphertextWithTag.length - tagSize);

        const saltB64 = arrayBufferToBase64(salt);
        const ivB64 = arrayBufferToBase64(iv);
        const tagB64 = arrayBufferToBase64(tag);
        const dataB64 = arrayBufferToBase64(ciphertext);

        const outputText = `${saltB64}:${ivB64}:${tagB64}:${dataB64}`;

        const blob = new Blob([outputText], { type: 'text/plain' });
        if (encryptedBlobUrl) URL.revokeObjectURL(encryptedBlobUrl);
        encryptedBlobUrl = URL.createObjectURL(blob);

        // Set attributes for native download link
        btnDownloadTxt.href = encryptedBlobUrl;
        btnDownloadTxt.download = "encrypt.txt";
        
        downloadArea.style.display = "block";
        showStatus(status, "Encryption complete.", true);
        updateStatsPanel({
            mode: "Encryption",
            pbkdf2Ms,
            operationMs: encryptionMs,
            fileSizeBytes: metadata.size
        });

        // Attack simulator priming
        lastEncryptedPayload = outputText;
        lastEncryptionPassword = password;
        resetAttackPanel();
        if (ciphertextOutput) {
            ciphertextOutput.value = outputText;
        }
        if (btnSimulateAttack) {
            btnSimulateAttack.disabled = false;
        }

        await renderComparisonPanel(file, ciphertextWithTag);
        await startRoundVisualizer(file, key, password, salt);

    } catch (e) {
        console.error(e);
        showStatus(status, e.message, false);
        resetAttackPanel();
        lastEncryptedPayload = "";
        lastEncryptionPassword = "";
        if (ciphertextOutput) {
            ciphertextOutput.value = "";
        }
        clearComparison();
        resetRoundVisualizer("Visualizer unavailable.");
    } finally {
        spinner.style.display = "none";
        updatePasswordStrengthUI();
        encryptInProgress = false;
        updatePasswordStrengthUI();
    }
});

// DECRYPTION
btnDecrypt.addEventListener('click', async () => {
    const encryptedText = document.getElementById('encrypted-text').value;
    const password = document.getElementById('decrypt-password').value;
    const status = document.getElementById('decrypt-status');
    const spinner = document.getElementById('decrypt-spinner');
    const previewImg = document.getElementById('decrypted-preview');
    const previewArea = document.getElementById('preview-area');

    if (!encryptedText || !password) {
        showStatus(status, "Provide encrypted text and password.", false);
        return;
    }

    try {
        btnDecrypt.disabled = true;
        spinner.style.display = "inline-block";
        status.style.display = "none";
        previewArea.style.display = "none";
        btnDownloadImg.style.display = "none";

        const parts = encryptedText.split(':');
        if (parts.length !== 4 && parts.length !== 3) throw new Error("Invalid format.");

        let salt;
        let iv;
        let tag;
        let ciphertext;

        if (parts.length === 4) {
            salt = new Uint8Array(base64ToArrayBuffer(parts[0]));
            iv = new Uint8Array(base64ToArrayBuffer(parts[1]));
            tag = new Uint8Array(base64ToArrayBuffer(parts[2]));
            ciphertext = new Uint8Array(base64ToArrayBuffer(parts[3]));
        } else {
            // Backward compatibility with older format (iv:tag:ciphertext) using fixed salt
            salt = FIXED_SALT;
            iv = new Uint8Array(base64ToArrayBuffer(parts[0]));
            tag = new Uint8Array(base64ToArrayBuffer(parts[1]));
            ciphertext = new Uint8Array(base64ToArrayBuffer(parts[2]));
        }

        const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
        ciphertextWithTag.set(ciphertext);
        ciphertextWithTag.set(tag, ciphertext.length);

        const { key, duration: pbkdf2Ms } = await deriveKeyWithTiming(password, salt);

        const { data: decryptedBuffer, duration: decryptionMs } = await decryptWithTiming(
            key,
            iv,
            ciphertextWithTag
        );

        const decryptedBytes = new Uint8Array(decryptedBuffer);
        const delimiterBytes = new TextEncoder().encode(METADATA_DELIMITER);
        const headerSize = 4;
        if (decryptedBytes.length < headerSize + delimiterBytes.length) {
            throw new Error("Metadata header missing or corrupted.");
        }

        const metadataLength = new DataView(decryptedBytes.buffer, decryptedBytes.byteOffset, headerSize).getUint32(0, true);
        const metadataStart = headerSize;
        const metadataEnd = metadataStart + metadataLength;
        const delimiterStart = metadataEnd;
        const delimiterEnd = delimiterStart + delimiterBytes.length;

        if (metadataLength < 0 || metadataLength > MAX_METADATA_SIZE || delimiterEnd > decryptedBytes.length) {
            throw new Error("Invalid metadata length.");
        }

        const delimiterSegment = decryptedBytes.subarray(delimiterStart, delimiterEnd);
        const delimiterValid = delimiterSegment.length === delimiterBytes.length &&
            delimiterBytes.every((byte, idx) => delimiterSegment[idx] === byte);
        if (!delimiterValid) {
            throw new Error("Metadata delimiter not found in decrypted payload.");
        }

        const metadataBytes = decryptedBytes.slice(metadataStart, metadataEnd);
        const fileBytes = decryptedBytes.slice(delimiterEnd);
        const decoder = new TextDecoder();

        let metadata;
        try {
            metadata = JSON.parse(decoder.decode(metadataBytes));
        } catch (err) {
            throw new Error("Failed to parse embedded metadata.");
        }

        const safeName = sanitizeFileName(metadata?.name);
        const actualSize = fileBytes.length;
        const parsedSize = Number(metadata?.size);
        const reportedSize = (Number.isFinite(parsedSize) && Number.isInteger(parsedSize) && parsedSize >= 0 && parsedSize <= MAX_FILESIZE_BYTES)
            ? parsedSize
            : null;
        if (reportedSize !== null && reportedSize !== actualSize) {
            console.warn(`Embedded metadata size (${reportedSize}) did not match decrypted content size (${actualSize}). Using actual size.`);
        }
        const normalizedSize = reportedSize !== null && reportedSize === actualSize ? reportedSize : actualSize;
        const normalizedMetadata = {
            name: safeName,
            type: metadata?.type || "application/octet-stream",
            size: normalizedSize
        };

        const blob = new Blob([fileBytes], { type: normalizedMetadata.type });
        if (decryptedBlobUrl) URL.revokeObjectURL(decryptedBlobUrl);
        decryptedBlobUrl = URL.createObjectURL(blob);

        // Set attributes for native download link
        btnDownloadImg.href = decryptedBlobUrl;
        btnDownloadImg.download = "restored_" + normalizedMetadata.name;

        previewImg.src = decryptedBlobUrl;
        previewArea.style.display = "block";
        btnDownloadImg.style.display = "inline-flex";
        showStatus(
            status,
            `Decryption complete. File: ${normalizedMetadata.name} (${normalizedMetadata.type}, ${formatBytes(normalizedMetadata.size)})`,
            true
        );
        updateStatsPanel({
            mode: "Decryption",
            pbkdf2Ms,
            operationMs: decryptionMs,
            fileSizeBytes: normalizedMetadata.size
        });

    } catch (e) {
        console.error(e);
        showStatus(status, "Decryption failed. Check password.", false);
    } finally {
        btnDecrypt.disabled = false;
        spinner.style.display = "none";
    }
});

// File Import
document.getElementById('txt-upload').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        document.getElementById('encrypted-text').value = e.target.result;
    };
    reader.readAsText(file);
});

// Attack Simulator
btnSimulateAttack.addEventListener('click', async () => {
    if (!lastEncryptedPayload || !lastEncryptionPassword) {
        attackStatus.textContent = "Encrypt an image first to generate ciphertext.";
        attackStatus.className = "status-box status-error";
        attackStatus.style.display = "block";
        return;
    }

    attackStatus.style.display = "none";
    const parts = lastEncryptedPayload.split(':');
    if (parts.length < 3) {
        attackStatus.textContent = "Ciphertext format invalid for simulation.";
        attackStatus.className = "status-box status-error";
        attackStatus.style.display = "block";
        return;
    }

    const cipherIndex = parts.length - 1;
    const originalCipherSegment = parts[cipherIndex];
    if (!originalCipherSegment) {
        attackStatus.textContent = "Ciphertext segment missing; cannot simulate tampering.";
        attackStatus.className = "status-box status-error";
        attackStatus.style.display = "block";
        return;
    }
    const flipIndex = Math.floor(Math.random() * Math.max(1, originalCipherSegment.length));
    const currentChar = originalCipherSegment[flipIndex];
    const currentIndex = BASE64_CHARS.indexOf(currentChar);
    let replacementChar = "A";
    if (currentIndex >= 0) {
        replacementChar = BASE64_CHARS[(currentIndex + 1) % BASE64_CHARS.length];
        if (replacementChar === currentChar) {
            replacementChar = BASE64_CHARS[(currentIndex + 2) % BASE64_CHARS.length];
        }
    } else {
        replacementChar = currentChar === "A" ? "B" : "A";
    }
    const tamperedSegment = `${originalCipherSegment.substring(0, flipIndex)}${replacementChar}${originalCipherSegment.substring(flipIndex + 1)}`;

    const tamperedParts = [...parts];
    tamperedParts[cipherIndex] = tamperedSegment;
    const tamperedPayload = tamperedParts.join(':');

    renderTamperDisplay(tamperedParts, tamperedSegment, cipherIndex);
    if (ciphertextOutput) {
        ciphertextOutput.value = tamperedPayload;
    }

    try {
        let salt, iv, tag, ciphertext;
        if (tamperedParts.length === 4) {
            salt = new Uint8Array(base64ToArrayBuffer(tamperedParts[0]));
            iv = new Uint8Array(base64ToArrayBuffer(tamperedParts[1]));
            tag = new Uint8Array(base64ToArrayBuffer(tamperedParts[2]));
            ciphertext = new Uint8Array(base64ToArrayBuffer(tamperedParts[3]));
        } else {
            salt = FIXED_SALT;
            iv = new Uint8Array(base64ToArrayBuffer(tamperedParts[0]));
            tag = new Uint8Array(base64ToArrayBuffer(tamperedParts[1]));
            ciphertext = new Uint8Array(base64ToArrayBuffer(tamperedParts[2]));
        }

        const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
        ciphertextWithTag.set(ciphertext);
        ciphertextWithTag.set(tag, ciphertext.length);

        const key = await deriveKey(lastEncryptionPassword, salt);
        await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertextWithTag
        );

        attackStatus.textContent = "Tampering went undetected (unexpected).";
        attackStatus.className = "status-box status-error";
        attackStatus.style.display = "block";
    } catch (e) {
        console.warn("Tampering detected during simulated decrypt.");
        attackStatus.textContent = "⚠️ Tampering Detected — Authentication tag mismatch. GCM integrity check failed.";
        attackStatus.className = "status-box status-error";
        attackStatus.style.display = "block";
    }
});

btnBenchmark?.addEventListener('click', async () => {
    if (!benchmarkChartCanvas) return;
    if (typeof Chart === "undefined") {
        showStatus(benchmarkStatus, "Chart.js library not available. Please check your internet connection or verify the CDN URL in index.html.", false);
        return;
    }

    btnBenchmark.disabled = true;
    toggleSpinner(benchmarkSpinner, true);
    if (benchmarkStatus) benchmarkStatus.style.display = "none";

    const durations = [];

    try {
        for (const iterationCount of BENCHMARK_ITERATIONS) {
            const salt = window.crypto.getRandomValues(new Uint8Array(SALT_BYTE_LENGTH));
            const { duration } = await deriveKeyWithTiming("benchmark-password", salt, iterationCount);
            durations.push(duration);
        }

        const context = benchmarkChartCanvas.getContext('2d');
        if (pbkdf2Chart) {
            pbkdf2Chart.destroy();
        }
        pbkdf2Chart = new Chart(context, {
            type: "line",
            data: {
                labels: BENCHMARK_ITERATIONS.map((val) => val.toLocaleString()),
                datasets: [
                    {
                        label: "PBKDF2 derivation time (ms)",
                        data: durations.map((v) => Number(v.toFixed(1))),
                        borderColor: getPrimaryColor(),
                        backgroundColor: colorWithAlpha(getPrimaryColor(), 0.1),
                        tension: 0.25,
                        fill: true,
                        pointRadius: 4,
                        pointHoverRadius: 5
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: "PBKDF2 iteration benchmark (ms)"
                    },
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: (ctx) => `${ctx.parsed.y.toFixed(1)} ms`
                        }
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: "Iterations"
                        }
                    },
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: "Milliseconds"
                        }
                    }
                }
            }
        });

        showStatus(benchmarkStatus, "Benchmark complete.", true);
    } catch (err) {
        console.error(err);
        showStatus(benchmarkStatus, "Benchmark failed. Try again.", false);
    } finally {
        btnBenchmark.disabled = false;
        toggleSpinner(benchmarkSpinner, false);
    }
});
