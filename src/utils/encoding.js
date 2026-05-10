/**
 * ENCODING.JS
 * ===========
 * Base64 and binary encoding utilities for cryptographic operations.
 * Handles conversion between ArrayBuffers, Uint8Arrays, and Base64 strings.
 */

/**
 * Converts an ArrayBuffer to a Base64 string.
 * Used for serializing binary cryptographic data (salt, IV, tag, ciphertext)
 * for transmission or storage as text.
 *
 * @param {ArrayBuffer} buffer - The binary data to encode
 * @returns {string} Base64-encoded string
 */
export const arrayBufferToBase64 = (buffer) => {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  // Convert bytes to binary string - each byte becomes a character
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // Use browser's native btoa to encode binary string to Base64
  return window.btoa(binary);
};

/**
 * Converts a Base64 string to an ArrayBuffer.
 * Reverses the encoding process - used during decryption to retrieve
 * binary cryptographic components from the text format.
 *
 * @param {string} base64 - The Base64-encoded string
 * @returns {ArrayBuffer} The decoded binary data
 */
export const base64ToArrayBuffer = (base64) => {
  // Use browser's native atob to decode Base64 to binary string
  const binaryString = window.atob(base64);
  // Convert binary string back to bytes
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
};
