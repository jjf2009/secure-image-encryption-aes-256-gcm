/**
 * FILE_HANDLER.JS
 * ===============
 * Utilities for file metadata management and filename sanitization.
 * Ensures filenames are safe across different operating systems
 * and protects against file system vulnerabilities.
 */

import {
  DEFAULT_FILE_NAME,
  MAX_FILENAME_LENGTH,
  RESERVED_FILENAMES,
} from "./constants.js";

/**
 * Sanitizes and validates a filename for safe download.
 *
 * SECURITY CONSIDERATIONS:
 * - Removes path separators to prevent directory traversal attacks
 * - Strips control characters (invisible characters that could cause issues)
 * - Removes reserved Windows filenames (CON, PRN, AUX, etc.)
 * - Removes invalid filesystem characters (<>:"/\|?*)
 * - Truncates to maximum filename length
 * - Preserves file extension
 *
 * @param {string} name - The original filename from file metadata
 * @returns {string} A safe, filesystem-compatible filename
 */
export const sanitizeFileName = (name) => {
  // Use provided name or default if empty
  const originalName = name || DEFAULT_FILE_NAME;

  // Step 1: Handle path separators - extract only the filename
  if (/[\\/]/.test(originalName)) {
    console.warn(
      "Embedded filename contained path separators; using last segment.",
    );
  }
  const base = originalName.split(/[\\/]/).pop();

  // Step 2: Remove control characters (ASCII 0-31 and 128-159)
  // These can cause issues or be used for attacks
  const withoutControl = base.replace(/[\x00-\x1F\x80-\x9F]/g, "");

  // Step 3: Replace invalid filesystem characters with underscore
  const cleaned = withoutControl.replace(/[<>:"/\\|?*]/g, "_").trim();

  // Step 4: Remove leading/trailing dots (can cause issues on Windows)
  const stripped = cleaned.replace(/^\.+/, "").replace(/\.+$/, "");

  // Step 5: Check for and handle reserved Windows filenames
  const dotIndex = stripped.lastIndexOf(".");
  const nameRoot =
    dotIndex === -1 ? stripped || "file" : stripped.slice(0, dotIndex);
  const extension = dotIndex === -1 ? "" : stripped.slice(dotIndex);
  const baseRoot = (nameRoot.split(".")[0] || "file").toUpperCase();

  const needsAdjust = RESERVED_FILENAMES.has(baseRoot);
  const adjustedRoot = needsAdjust ? `${nameRoot}_file` : nameRoot;

  // Step 6: Combine adjusted name with extension
  const candidate =
    `${adjustedRoot}${extension}`.replace(/^\.+/, "") || DEFAULT_FILE_NAME;

  // Step 7: Truncate if exceeds maximum length while preserving extension
  if (candidate.length <= MAX_FILENAME_LENGTH) return candidate;

  const lastDot = candidate.lastIndexOf(".");
  const ext = lastDot >= 0 ? candidate.slice(lastDot) : "";
  const baseTruncated = lastDot >= 0 ? candidate.slice(0, lastDot) : candidate;
  const trimmedBase = baseTruncated.slice(
    0,
    Math.max(1, MAX_FILENAME_LENGTH - ext.length),
  );

  return `${trimmedBase}${ext}`;
};

/**
 * Creates metadata object for a file to be encrypted.
 * This metadata is embedded in the encrypted payload and used
 * to restore the file with its original properties.
 *
 * @param {File} file - The File object from input
 * @returns {Object} Metadata object with name, type, and size
 */
export const createFileMetadata = (file) => ({
  name: file.name || DEFAULT_FILE_NAME,
  type: file.type || "application/octet-stream",
  size: file.size,
});

/**
 * Formats byte size to human-readable format (B, KB, MB).
 * Used throughout the UI to display file sizes clearly.
 *
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted string like "1.5 MB"
 */
export const formatBytes = (bytes) => {
  if (bytes === 0) return "0 B";
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(2)} MB`;
};
