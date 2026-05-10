/**
 * CONSTANTS.JS
 * ============
 * Centralized configuration and constants for the SecureImage application.
 * All magic numbers, limits, and configuration values are defined here
 * to make the codebase more maintainable and easier to adjust.
 */

// ============================================================================
// CRYPTOGRAPHY CONSTANTS
// ============================================================================

/** PBKDF2 iteration count for key derivation - higher is more secure but slower */
export const PBKDF2_ITERATIONS = 100000;

/** Warning threshold for PBKDF2 derivation time (milliseconds) */
export const PBKDF2_WARNING_THRESHOLD_MS = 200;

/** Salt size in bytes - standard for cryptographic operations */
export const SALT_BYTE_LENGTH = 16;

/** Fixed salt used for backward compatibility with older encrypted files */
export const FIXED_SALT = new TextEncoder().encode("SECUREIMAGE_SALT_PBKDF2");

// ============================================================================
// AES & CRYPTOGRAPHIC PARAMETERS
// ============================================================================

/** AES S-Box: Substitution table used in AES SubBytes operation */
export const AES_SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
  0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
  0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
  0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
  0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
  0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
  0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
  0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
  0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
  0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
  0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
  0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
  0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
  0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
  0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
  0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

// ============================================================================
// FILE HANDLING CONSTANTS
// ============================================================================

/** Delimiter used to separate metadata from actual file data */
export const METADATA_DELIMITER = "::SECUREIMAGE_METADATA::";

/** Default filename when metadata is missing */
export const DEFAULT_FILE_NAME = "file.bin";

/** Maximum filename length after sanitization */
export const MAX_FILENAME_LENGTH = 200;

/** Maximum metadata size in bytes (10 KB) - prevents abuse */
export const MAX_METADATA_SIZE = 10 * 1024;

/** Maximum file size ceiling (200 MB) - browser limitation */
export const MAX_FILESIZE_BYTES = 200 * 1024 * 1024;

/** Reserved Windows filenames that cannot be used */
export const RESERVED_FILENAMES = new Set([
  "CON",
  "PRN",
  "AUX",
  "NUL",
  "COM1",
  "COM2",
  "COM3",
  "COM4",
  "COM5",
  "COM6",
  "COM7",
  "COM8",
  "COM9",
  "LPT1",
  "LPT2",
  "LPT3",
  "LPT4",
  "LPT5",
  "LPT6",
  "LPT7",
  "LPT8",
  "LPT9",
]);

// ============================================================================
// PASSWORD STRENGTH CONSTANTS
// ============================================================================

/** Minimum password length requirement */
export const MIN_PASSWORD_LENGTH = 8;

/** Recommended strong password length */
export const STRONG_PASSWORD_LENGTH = 12;

/** Common weak passwords to check against */
export const COMMON_PASSWORDS = [
  "123456",
  "password",
  "123456789",
  "12345678",
  "12345",
  "111111",
  "qwerty",
  "abc123",
  "password1",
  "123123",
  "iloveyou",
  "1q2w3e4r",
  "000000",
  "letmein",
  "dragon",
  "sunshine",
  "princess",
  "monkey",
  "login",
  "password123",
];

/** Allowed special characters for password validation */
export const SPECIAL_CHARACTERS = [
  "!",
  "@",
  "#",
  "$",
  "%",
  "^",
  "&",
  "*",
  "(",
  ")",
  "_",
  "+",
  "-",
  "=",
  "[",
  "]",
  "{",
  "}",
  ";",
  ":",
  "'",
  '"',
  ",",
  ".",
  "<",
  ">",
  "/",
  "?",
  "\\",
  "|",
  "~",
  "`",
];

export const SPECIAL_CHAR_SET = SPECIAL_CHARACTERS.join("");
export const SPECIAL_CHAR_DISPLAY = SPECIAL_CHARACTERS.join(", ");
export const SPECIAL_CHAR_HELP_TEXT = `Special characters include: ${SPECIAL_CHAR_DISPLAY}`;

// Escaped pattern for RegExp character class usage
const escapeForCharClass = (chars) => chars.replace(/[\\\[\]^-]/g, "\\$&");
export const SPECIAL_CHAR_PATTERN = new RegExp(
  `[${escapeForCharClass(SPECIAL_CHAR_SET)}]`,
);

/** Password strength scoring thresholds */
export const STRENGTH_SCORE_MAX = {
  weak: 2,
  fair: 4,
  strong: 5,
};

/** Password strength visual percentages (0-100%) */
export const STRENGTH_PERCENTAGES = {
  weak: 25,
  fair: 50,
  strong: 75,
  veryStrong: 100,
};

/** CSS classes for password strength display */
export const STRENGTH_CLASSES = {
  weak: "strength-weak",
  fair: "strength-fair",
  strong: "strength-strong",
  veryStrong: "strength-very-strong",
};

// ============================================================================
// VISUALIZATION CONSTANTS
// ============================================================================

/** Maximum canvas dimension for rendering images */
export const MAX_CANVAS_DIMENSION = 420;

/** Sample size for entropy calculation from ciphertext */
export const NOISE_SEED_SAMPLE_SIZE = 1024;

/** Total number of AES rounds to visualize (0-14 = 15 states) */
export const ROUND_STATES_TOTAL = 14;

/** Interval between automatic round advances during playback (ms) */
export const ROUND_PLAY_INTERVAL_MS = 900;

/** Thumbnail size for filmstrip display (pixels) */
export const FILMSTRIP_THUMB_SIZE = 80;

/** Maximum dimension for the round visualizer display */
export const VISUALIZER_MAX_DIMENSION = 280;

/** Descriptive titles for each AES round during visualization */
export const ROUND_TITLES = [
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
  "Round 14 — Final Key Infusion",
];

// ============================================================================
// BENCHMARKING CONSTANTS
// ============================================================================

/** Iteration counts for PBKDF2 benchmarking */
export const BENCHMARK_ITERATIONS = [10000, 50000, 100000, 200000, 500000];

// ============================================================================
// BASE64 ENCODING CONSTANTS
// ============================================================================

/** Base64 character set for encoding/decoding operations */
export const BASE64_CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

// ============================================================================
// PRNG CONSTANTS (for encrypted noise visualization)
// ============================================================================

/** FNV-1a hash offset basis for hashing */
export const FNV_OFFSET_BASIS = 0x811c9dc5;

/** FNV-1a prime multiplier */
export const FNV_PRIME = 0x01000193;
