/**
 * ENCRYPTION.JS
 * =============
 * AES-256-GCM encryption and decryption operations.
 *
 * WHY AES-256-GCM?
 * - AES: Industry standard symmetric encryption, 256-bit key = 2^256 possible keys
 * - GCM mode: Galois/Counter Mode provides both confidentiality AND authenticity
 * - Authentication tag prevents tampering - any bit flip is detected
 * - Nonce (IV) prevents replay attacks when used correctly
 *
 * OUTPUT FORMAT:
 * During encryption, we combine:
 * - Salt: Random value for PBKDF2 (16 bytes)
 * - IV: Random initialization vector for AES-GCM (12 bytes)
 * - Tag: Authentication tag from GCM (16 bytes)
 * - Ciphertext: Encrypted data
 *
 * Format: Base64(salt):Base64(IV):Base64(tag):Base64(ciphertext)
 */

import { arrayBufferToBase64, base64ToArrayBuffer } from "../utils/encoding.js";
import { compressData, decompressData } from "../utils/compression.js";
import { METADATA_DELIMITER } from "../utils/constants.js";

/**
 * Encrypts data using AES-256-GCM.
 *
 * PROCESS:
 * 1. Create metadata JSON with file info (name, type, size)
 * 2. Create random IV (initialization vector) for AES-GCM
 * 3. Create random salt for PBKDF2
 * 4. Derive encryption key from password using salt
 * 5. Encrypt metadata + delimiter + file data
 * 6. Extract authentication tag from encrypted output
 * 7. Encode all components as Base64
 * 8. Combine into text format
 *
 * @param {File} file - File to encrypt
 * @param {string} password - Password for key derivation
 * @param {Function} deriveKeyFn - Function to derive key from password
 * @param {Function} timingWrapper - Function to measure operation time
 * @returns {Promise<Object>} { ciphertext: string, metadata: object, timingInfo: object }
 */
export const encryptFile = async (
  file,
  password,
  deriveKeyFn,
  timingWrapper,
) => {
  // Step 1: Prepare file metadata
  const encoder = new TextEncoder();
  const metadata = {
    name: file.name || "file.bin",
    type: file.type || "application/octet-stream",
    size: file.size,
    compressed: true,
  };

  // Step 2: Build payload: [metadata_length][metadata][delimiter][file_data]
  const metadataBytes = encoder.encode(JSON.stringify(metadata));
  const delimiterBytes = encoder.encode(METADATA_DELIMITER);
  
  // Compress file data before encryption
  const rawFileBytes = new Uint8Array(await file.arrayBuffer());
  const { data: fileBytes, duration: compressionMs } = await timingWrapper(
    () => compressData(rawFileBytes)
  );

  // Create header: 4-byte length field (little-endian) for metadata
  const metadataLengthBytes = new Uint8Array(4);
  new DataView(metadataLengthBytes.buffer).setUint32(
    0,
    metadataBytes.length,
    true,
  );

  // Combine all parts into single payload
  const payload = new Uint8Array(
    metadataLengthBytes.length +
      metadataBytes.length +
      delimiterBytes.length +
      fileBytes.length,
  );

  let offset = 0;
  payload.set(metadataLengthBytes, offset);
  offset += metadataLengthBytes.length;
  payload.set(metadataBytes, offset);
  offset += metadataBytes.length;
  payload.set(delimiterBytes, offset);
  offset += delimiterBytes.length;
  payload.set(fileBytes, offset);

  // Step 3: Generate random IV and salt
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const salt = window.crypto.getRandomValues(new Uint8Array(16));

  // Step 4: Derive key with timing information
  const { key, duration: pbkdf2Ms } = await deriveKeyFn(password, salt);

  // Step 5: Encrypt payload and measure time
  const { data: encryptedData, duration: encryptionMs } = await timingWrapper(
    () =>
      window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, payload),
  );

  // Step 6: Extract tag from encrypted data
  // GCM produces: [ciphertext || authentication_tag]
  // Tag is last 16 bytes
  const tagSize = 16;
  const fullCiphertext = new Uint8Array(encryptedData);
  const ciphertext = fullCiphertext.slice(0, fullCiphertext.length - tagSize);
  const tag = fullCiphertext.slice(fullCiphertext.length - tagSize);

  // Step 7: Encode all components as Base64
  const saltB64 = arrayBufferToBase64(salt);
  const ivB64 = arrayBufferToBase64(iv);
  const tagB64 = arrayBufferToBase64(tag);
  const dataB64 = arrayBufferToBase64(ciphertext);

  // Step 8: Create final output format
  const ciphertextOutput = `${saltB64}:${ivB64}:${tagB64}:${dataB64}`;

  return {
    ciphertext: ciphertextOutput,
    ciphertextWithTag: fullCiphertext, // For visualization
    metadata: metadata,
    salt: salt, // For round visualizer
    timingInfo: {
      pbkdf2Ms,
      compressionMs,
      encryptionMs,
      fileSizeBytes: metadata.size,
    },
  };
};

/**
 * Decrypts data using AES-256-GCM.
 *
 * PROCESS:
 * 1. Parse the Base64-encoded ciphertext format
 * 2. Handle both new format (with salt) and old format (without salt)
 * 3. Reconstruct ciphertext with authentication tag
 * 4. Derive key from password and salt
 * 5. Decrypt and verify authentication tag
 * 6. Extract and parse metadata
 * 7. Validate and extract actual file data
 *
 * @param {string} encryptedText - Base64-encoded encrypted data
 * @param {string} password - Password for key derivation
 * @param {Function} deriveKeyFn - Function to derive key from password
 * @param {Function} timingWrapper - Function to measure operation time
 * @param {Uint8Array} fixedSalt - Fallback salt for backward compatibility
 * @returns {Promise<Object>} { fileBytes: Uint8Array, metadata: object, timingInfo: object }
 */
export const decryptFile = async (
  encryptedText,
  password,
  deriveKeyFn,
  timingWrapper,
  fixedSalt,
) => {
  // Step 1: Parse format - handle both old and new formats
  const parts = encryptedText.split(":");
  if (parts.length !== 4 && parts.length !== 3) {
    throw new Error(
      "Invalid ciphertext format. Expected salt:iv:tag:data or iv:tag:data.",
    );
  }

  let salt, iv, tag, ciphertext;

  if (parts.length === 4) {
    // New format: salt:iv:tag:ciphertext
    salt = new Uint8Array(base64ToArrayBuffer(parts[0]));
    iv = new Uint8Array(base64ToArrayBuffer(parts[1]));
    tag = new Uint8Array(base64ToArrayBuffer(parts[2]));
    ciphertext = new Uint8Array(base64ToArrayBuffer(parts[3]));
  } else {
    // Old format: iv:tag:ciphertext (use fixed salt for backward compatibility)
    salt = fixedSalt;
    iv = new Uint8Array(base64ToArrayBuffer(parts[0]));
    tag = new Uint8Array(base64ToArrayBuffer(parts[1]));
    ciphertext = new Uint8Array(base64ToArrayBuffer(parts[2]));
  }

  // Step 2: Reconstruct ciphertext with tag (GCM expects ciphertext || tag)
  const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
  ciphertextWithTag.set(ciphertext);
  ciphertextWithTag.set(tag, ciphertext.length);

  // Step 3: Derive key with timing
  const { key, duration: pbkdf2Ms } = await deriveKeyFn(password, salt);

  // Step 4: Decrypt and verify tag
  // If tag is invalid, this will throw an error
  const { data: decryptedBuffer, duration: decryptionMs } = await timingWrapper(
    () =>
      window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ciphertextWithTag,
      ),
  );

  // Step 5: Parse metadata from decrypted payload
  const decryptedBytes = new Uint8Array(decryptedBuffer);
  const delimiterBytes = encoder.encode(METADATA_DELIMITER);
  const headerSize = 4;

  if (decryptedBytes.length < headerSize + delimiterBytes.length) {
    throw new Error("Metadata header missing or corrupted.");
  }

  // Read metadata length from first 4 bytes
  const metadataLength = new DataView(
    decryptedBytes.buffer,
    decryptedBytes.byteOffset,
    headerSize,
  ).getUint32(0, true);

  const metadataStart = headerSize;
  const metadataEnd = metadataStart + metadataLength;
  const delimiterStart = metadataEnd;
  const delimiterEnd = delimiterStart + delimiterBytes.length;

  if (
    metadataLength < 0 ||
    metadataLength > 10240 ||
    delimiterEnd > decryptedBytes.length
  ) {
    throw new Error("Invalid metadata length or corrupt data.");
  }

  // Verify delimiter is present
  const delimiterSegment = decryptedBytes.subarray(
    delimiterStart,
    delimiterEnd,
  );
  const delimiterValid =
    delimiterSegment.length === delimiterBytes.length &&
    delimiterBytes.every((byte, idx) => delimiterSegment[idx] === byte);

  if (!delimiterValid) {
    throw new Error(
      "Metadata delimiter not found - decryption may have failed.",
    );
  }

  // Step 6: Extract metadata and file data
  const metadataBytes = decryptedBytes.slice(metadataStart, metadataEnd);
  const fileBytes = decryptedBytes.slice(delimiterEnd);
  const decoder = new TextDecoder();

  let metadata;
  try {
    metadata = JSON.parse(decoder.decode(metadataBytes));
  } catch (err) {
    throw new Error("Failed to parse embedded metadata.");
  }

  // Step 7: Decompress if necessary
  let finalFileBytes = fileBytes;
  let decompressionMs = 0;

  if (metadata.compressed) {
    const decompressed = await timingWrapper(() => decompressData(fileBytes));
    finalFileBytes = decompressed.data;
    decompressionMs = decompressed.duration;
  }

  return {
    fileBytes: finalFileBytes,
    metadata: metadata,
    timingInfo: {
      pbkdf2Ms,
      decryptionMs,
      decompressionMs,
      fileSizeBytes: finalFileBytes.length,
    },
  };
};

// Helper for encoding - reuse in decryption
const encoder = new TextEncoder();
