# Technical Implementation Details: SecureImage (AES-256-GCM)

This project implements a professional-grade, browser-native encryption system for image data. It utilizes the **Web Crypto API** (`window.crypto.subtle`) to ensure high-performance, secure operations without external dependencies. 

## 1. Cryptographic Standard: AES-GCM
We use **AES-256-GCM** (Advanced Encryption Standard - Galois/Counter Mode).

### Why GCM?
Unlike older modes like CBC, **GCM is an Authenticated Encryption** mode. It not only ensures that the data is secret (confidentiality) but also provides an **Authentication Tag** (integrity). If even ONE bit of the ciphertext or the tag is modified, the decryption will fail.

### Components:
*   **IV (Initialization Vector)**: A unique, random 12-byte value for every encryption session. It ensures that the same image encrypted with the same password twice results in completely different ciphertext.
*   **Tag (Authentication Tag)**: A 16-byte value generated during encryption that verifies the integrity of the data during decryption.
*   **Ciphertext**: The actual encrypted binary data.

---

## 2. Key Derivation: PBKDF2
Since users provide simple password strings, we cannot use them directly as 256-bit encryption keys. We use **PBKDF2 (Password-Based Key Derivation Function 2)** to "stretch" the password into a cryptographically strong key.

*   **Hashing Algorithm**: SHA-256.
*   **Iterations**: 100,000. High iterations protect against brute-force and rainbow table attacks by making each password attempt computationally expensive.
*   **Salt**: A unique value that ensures the same password results in different keys on different systems (or if the salt is changed).

---

## 3. Implementation Workflow (JavaScript)

### A. Encryption Process
1.  **File Reading**: The image is read into an `ArrayBuffer` using `file.arrayBuffer()`.
2.  **Key Generation**: 
    ```javascript
    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false, 
        ["encrypt"]
    );
    ```
3.  **Core Encryption**: 
    ```javascript
    const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        originalArrayBuffer
    );
    ```
4.  **Formatting**: The `encryptedData` contains both the ciphertext and the tag. We split them and encode everything into **Base64** strings to allow saving as a portable text file (`IV:Tag:Ciphertext`).

### B. Decryption Process
1.  **Parsing**: The `encrypt.txt` content is split into its 3 Base64 parts (IV, Tag, Ciphertext) and converted back to `Uint8Array`.
2.  **Reconstruction**: The Ciphertext and Tag are concatenated back into a single buffer because `crypto.subtle.decrypt` expects the tag to be at the end of the data.
3.  **Decryption**: Using the same password and salt, the key is re-derived, and the data is transformed back into the original image `ArrayBuffer`.
4.  **Display**: The buffer is world-wrapped in a `Blob` and converted into a `URL.createObjectURL` for the browser to render as an image.

---

## 4. Key Security Advantages:
*   **Zero-Server Exposure**: All encryption happens on the client side. Your password and raw image never touch a server.
*   **Immutable Blobs**: Decrypted data is held in browser memory as a private blob URL and is revoked (cleared) between sessions to prevent memory leaks or data exposure.
*   **Native Performance**: Uses the browser's optimized C++ crypto backends, providing near-instant encryption even for large high-resolution photos.
