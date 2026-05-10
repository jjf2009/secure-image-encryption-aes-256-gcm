# SecureImage — Modular Architecture Documentation

## Overview

This document explains the refactored modular architecture of SecureImage, transforming ~3000 lines of monolithic code into maintainable, testable modules organized by concern.

---

## Project Structure

```
secure-image-encryption-aes-256-gcm/
├── src/
│   ├── app.js                          # Main orchestrator - brings everything together
│   ├── crypto/
│   │   ├── keyDerivation.js           # PBKDF2 key derivation logic
│   │   └── encryption.js              # AES-256-GCM encrypt/decrypt operations
│   ├── ui/
│   │   ├── domManager.js              # DOM caching & UI utilities
│   │   └── passwordStrength.js        # Password validation & strength indicator
│   ├── visualization/
│   │   ├── aesAlgorithm.js           # AES round operations (SubBytes, ShiftRows, MixColumns, AddRoundKey)
│   │   ├── imageComparison.js        # Visual comparison: original vs encrypted noise
│   │   └── roundVisualizer.js        # Round-by-round AES diffusion visualization
│   └── utils/
│       ├── constants.js               # All constants & configuration
│       ├── encoding.js                # Base64 encoding/decoding utilities
│       └── fileHandler.js             # File metadata & filename sanitization
├── index.html                         # HTML interface
├── style.css                          # Styling
└── README.md                          # User documentation
```

---

## Module Descriptions

### 1. **Constants** (`src/utils/constants.js`)

**Purpose:** Centralized configuration storage.

**Key Content:**

- PBKDF2 parameters (100,000 iterations, warning threshold)
- AES S-box lookup table for visualization
- File handling limits (200 MB max, 10 KB metadata)
- Password requirements (min 8 chars, special character set)
- Visualization parameters (14 AES rounds, filmstrip size)
- All magic numbers in one place for easy maintenance

**Why This Matters:**

- No magic numbers scattered through code
- One place to adjust security parameters
- Easy to experiment with iteration counts or file limits

---

### 2. **Encoding** (`src/utils/encoding.js`)

**Purpose:** Convert between binary and text formats.

**Functions:**

- `arrayBufferToBase64()` - Binary → Base64 (for storage/transmission)
- `base64ToArrayBuffer()` - Base64 → Binary (for decryption)

**Example Flow:**

```
Salt (16 bytes) → arrayBufferToBase64() → "mD3k..." (Base64)
                                           ↓
Format: salt:iv:tag:ciphertext (text file)
                                           ↓
base64ToArrayBuffer() → Salt (16 bytes) [during decryption]
```

---

### 3. **File Handler** (`src/utils/fileHandler.js`)

**Purpose:** Safe file management and metadata handling.

**Functions:**

- `sanitizeFileName()` - Prevents directory traversal attacks, removes control characters, handles reserved Windows names
- `createFileMetadata()` - Creates metadata object from File
- `formatBytes()` - Converts bytes to human-readable format (KB, MB)

**Security Considerations:**

- Removes path separators (prevents `../` attacks)
- Strips control characters (could cause issues on some filesystems)
- Replaces invalid characters with underscore
- Checks against Windows reserved names (CON, PRN, AUX, etc.)

---

### 4. **DOM Manager** (`src/ui/domManager.js`)

**Purpose:** Centralized DOM element caching and UI helpers.

**Key Functions:**

- `cacheDOMElements()` - Called once at startup, caches all DOM references
- `showStatus()` - Displays success/error messages
- `toggleSpinner()` - Shows/hides loading spinner
- `escapeHtml()` - Prevents XSS attacks when displaying dynamic content
- `formatInterval()` - Shows durations as "2.3s" or "150ms"

**Why Caching?**

```javascript
// BEFORE (bad - queries DOM every time)
document.getElementById('btn-encrypt').addEventListener('click', ...);
document.getElementById('btn-encrypt').disabled = true;  // DOM query again!

// AFTER (good - query once, reuse)
const encryptBtn = document.getElementById('btn-encrypt');
encryptBtn.addEventListener('click', ...);
encryptBtn.disabled = true;  // No query needed
```

---

### 5. **Password Strength** (`src/ui/passwordStrength.js`)

**Purpose:** Real-time password validation and strength feedback.

**Flow:**

```
User types password
    ↓
evaluatePasswordCriteria() → Check 6 criteria
    ↓
determineStrength() → Assign level (weak/fair/strong/veryStrong)
    ↓
updatePasswordStrengthUI() → Update bar, checkmarks, button state
```

**Criteria Checked:**

1. Minimum length (8 chars)
2. Strong length (12+ chars)
3. Mixed case (upper + lower)
4. Numbers (0-9)
5. Special characters (!@#$%...)
6. Not in common passwords list

**Real-Time Updates:**

- Visual strength bar fills as password improves
- Green checkmarks appear for met criteria
- Encrypt button disabled until password is "strong" or better

---

### 6. **Key Derivation** (`src/crypto/keyDerivation.js`)

**Purpose:** Convert password to cryptographic key using PBKDF2-SHA256.

**Why PBKDF2?**

- Slows down brute-force attacks (100,000 iterations = ~1.2 seconds per guess)
- Standard algorithm (RFC 2898)
- Built into Web Crypto API

**Functions:**

- `deriveKey()` - Standard derivation with default iterations
- `deriveKeyWithIterations()` - Custom iteration count (for benchmarking)
- `deriveKeyWithTiming()` - Measures derivation time for performance monitoring

**Security Details:**

```
Password + Salt → PBKDF2-SHA256 → 256-bit AES key
(100,000 iterations)    (1.2 seconds on typical device)

Each encryption gets random salt → prevents rainbow tables
```

---

### 7. **Encryption** (`src/crypto/encryption.js`)

**Purpose:** AES-256-GCM encryption and decryption with metadata.

**Encryption Flow:**

```
File + Password
    ↓
Create metadata: { name, type, size }
    ↓
Build payload: [length][metadata][delimiter][file]
    ↓
Generate random: IV (12 bytes) + Salt (16 bytes)
    ↓
Derive key: PBKDF2(password, salt, 100000 iterations)
    ↓
Encrypt: AES-256-GCM(payload, key, IV)
    ↓
Extract tag: GCM produces [ciphertext || tag]
    ↓
Encode: Base64(salt:iv:tag:ciphertext)
    ↓
Output: Text file with encrypted data
```

**Decryption Flow:**

```
Encrypted text + Password
    ↓
Parse format: Extract salt, iv, tag, ciphertext
    ↓
Reconstruct: Combine ciphertext + tag
    ↓
Derive key: PBKDF2(password, salt, 100000 iterations)
    ↓
Decrypt: AES-256-GCM with tag verification
    ↓
If tag invalid: Throw error (tampering detected)
    ↓
Extract metadata: Read first 4 bytes for length
    ↓
Validate delimiter: Confirm metadata separator
    ↓
Extract file: Everything after delimiter
    ↓
Return: File bytes + metadata
```

**Key Security Properties:**

- **Authentication Tag**: Prevents tampering - any bit flip detected
- **Random IV**: Different ciphertext for same plaintext/password
- **Random Salt**: Prevents rainbow tables
- **Backward Compatibility**: Can decrypt old format (without salt) using fixed salt

---

### 8. **AES Algorithm** (`src/visualization/aesAlgorithm.js`)

**Purpose:** Educational visualization of AES-256 round operations.

**Important:** NOT used for actual encryption (Web Crypto API does that).

**Four Operations per Round:**

#### 1. **SubBytes** - Confusion (byte-level substitution)

```
Each RGB byte → AES S-box lookup → New byte
Example: 0x53 → AES_SBOX[0x53] → 0xED
- Introduces non-linearity
- Makes patterns hard to find
```

#### 2. **ShiftRows** - Permutation (position-level diffusion)

```
Row 0: [0, 1, 2, 3] → [0, 1, 2, 3]  (no shift)
Row 1: [4, 5, 6, 7] → [5, 6, 7, 4]  (shift left 1)
Row 2: [8, 9,10,11] → [10,11, 8, 9] (shift left 2)
Row 3: [12,13,14,15] → [15,12,13,14] (shift left 3)
- Creates position-dependent diffusion
- Works with MixColumns for rapid spreading
```

#### 3. **MixColumns** - Diffusion (column-level mixing)

```
Uses Galois Field (2^8) polynomial multiplication:
new_value = xtime(current) XOR gmul3(next_column)
- High diffusion: one byte affects multiple pixels
- Linear transformation spreads entropy
- Skipped in final round (optimization)
```

#### 4. **AddRoundKey** - Key mixing (XOR with round key)

```
RGB bytes XOR with derived round key bytes
Alpha channel unchanged (always 255)
- Adds key-dependent diffusion
- Makes cipher dependent on both data and key
- Reversible operation (XOR is self-inverse)
```

**Result After 14 Rounds:**

- Original: Recognizable image
- After Round 1-3: Some confusion visible
- After Round 4-7: Heavy distortion
- After Round 8-14: Complete randomness (entropy ≈ 8 bits)

---

### 9. **Image Comparison** (`src/visualization/imageComparison.js`)

**Purpose:** Display side-by-side visual comparison of original vs encrypted.

**How Noise Generation Works:**

```
Ciphertext bytes
    ↓
FNV-1a hash (sample ciphertext → seed PRNG)
    ↓
Xorshift32 PRNG (spread entropy across pixels)
    ↓
Each pixel gets 3 bytes from ciphertext
    ↓
Result: Completely random-looking noise
    ↓
Security guarantee: No information about original image leaked
```

**Why This Works:**

- Ciphertext is random by AES-GCM design
- FNV-1a hash spreads patterns
- Xorshift32 PRNG has good statistical properties
- Visual proves: perfect secrecy of encrypted data

---

### 10. **Round Visualizer** (`src/visualization/roundVisualizer.js`)

**Purpose:** Show AES diffusion progression across 15 states (R0 original + R1-R14 encrypted rounds).

**Key Metrics Tracked:**

- **Entropy**: Increases from ~0 (ordered) to ~8 (random)
- **Histogram**: Distribution of pixel values (becomes uniform)
- **Diffusion**: How quickly changes spread

**Visualizer Features:**

- Original image canvas
- Current round canvas
- Filmstrip: Thumbnails of all 15 rounds (click to jump)
- Histogram charts: Compare R0 vs current round
- Playback controls: Auto-advance through rounds
- Operation badges: Shows which ops applied in this round

**Filmstrip Navigation:**

- Hover/click thumbnail to jump to that round
- Active round highlighted
- Quick visual reference of entire encryption process

---

## Data Flow

### Encryption Example

```
┌─────────────────────────────────────────────────────────────┐
│ USER: Selects image + enters password                       │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ app.js: handleEncryption()                                  │
│ - Validates input                                            │
│ - Clears previous state                                      │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ encryption.js: encryptFile()                                │
│ - Creates metadata JSON                                      │
│ - Builds payload (length + metadata + delimiter + file)     │
│ - Generates random IV (12B) + Salt (16B)                    │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ keyDerivation.js: deriveKeyWithTiming()                      │
│ - PBKDF2-SHA256 (100,000 iterations)                         │
│ - Measures time (performance monitoring)                     │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ Web Crypto API: encrypt()                                   │
│ - AES-256-GCM (uses IV + key)                               │
│ - Produces: ciphertext + authentication tag                 │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ encoding.js: arrayBufferToBase64()                           │
│ - Convert salt, IV, tag, ciphertext to Base64               │
│ - Format: salt:iv:tag:ciphertext (text)                     │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ app.js: Display results                                      │
│ - Show ciphertext in textarea                                │
│ - Enable download button                                     │
│ - Update stats (timing, throughput)                          │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ Visualizations                                               │
│ - imageComparison.js: Show original vs noise                │
│ - roundVisualizer.js: Show AES round progression            │
└─────────────────────────────────────────────────────────────┘
```

---

## Testing & Debugging

### How to Debug Individual Modules

**Example: Debugging encryption**

```javascript
// In browser console
import { encryptFile } from './src/crypto/encryption.js';

// Test encrypt
const testFile = new File(['test'], 'test.txt', {type: 'text/plain'});
const result = await encryptFile(testFile, 'mypassword', ...);
console.log('Ciphertext:', result.ciphertext);
```

**Testing Key Derivation**

```javascript
import { deriveKeyWithTiming } from "./src/crypto/keyDerivation.js";

const salt = new Uint8Array(16);
const { key, duration } = await deriveKeyWithTiming("password", salt);
console.log("Derivation took:", duration, "ms");
```

### Module Isolation Benefits

- Test one module without others
- Mock dependencies for unit testing
- Easy to identify which module has issues
- Can profile individual modules

---

## Performance Considerations

### Bottlenecks

1. **PBKDF2** (~1.2 seconds): Most time-intensive, intentional for security
2. **AES Encryption**: Typically <100ms for typical files
3. **Visualization**: Can lag on very large images

### Optimization Strategies

- PBKDF2 runs in worker thread? (Future enhancement)
- Limit visualizer resolution (already done: 280px max)
- Cancel pending visualizations if new encryption starts
- Use requestAnimationFrame for smooth progress updates

---

## Security Properties

### Encryption

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Size**: 256-bit
- **Key Derivation**: PBKDF2-SHA256 (100,000 iterations)
- **IV**: 12 random bytes per operation (prevents replay)
- **Authentication**: 16-byte GCM tag (detects tampering)

### Authentication Tag

```
// If user tampers with encrypted file:
// (even changes 1 bit in ciphertext)

Original: "salt:iv:tag:ciphertext"
Tampered: "salt:iv:tag:cipher7ext"  ← one char changed
                    ↓
During decryption, tag verification FAILS
Application throws error: "Decryption failed"
↓
Tampering is detected! ✓
```

### Metadata Embedding

- File name, type, size stored inside encrypted payload
- Metadata delimiter ensures integrity
- If delimiter missing: corruption detected

---

## Future Enhancement Ideas

1. **Worker Thread for PBKDF2**
   - Keep UI responsive during key derivation
   - `new Worker('./crypto/keyDerivation.js')`

2. **Streaming Encryption**
   - For files >200 MB
   - Process in chunks

3. **Archive Support**
   - Encrypt multiple files
   - ZIP → Encrypt

4. **Password Quality Meter**
   - NIST guidelines compliance check
   - Crack time estimation

5. **Offline Mode**
   - Service Worker caching
   - Works completely offline

6. **Dark Mode**
   - CSS variables already in place
   - Toggle theme button

7. **Batch Operations**
   - Encrypt/decrypt multiple files
   - Progress tracking

---

## File Size Reference

**Before Refactoring:**

- `script.js`: ~3000 lines, monolithic

**After Refactoring:**

- `app.js`: ~300 lines (orchestration)
- `src/crypto/`: ~200 lines (encryption logic)
- `src/ui/`: ~200 lines (UI management)
- `src/visualization/`: ~600 lines (visualizer)
- `src/utils/`: ~150 lines (helpers)
- **Total**: ~1500 lines of application code (+ better structure)

**Lines are fewer BUT MORE ORGANIZED:**

- Easy to find code by module
- Each module has single responsibility
- No need to search through 3000 lines
- Clear dependencies between modules

---

## Troubleshooting

### Common Issues

**Q: "Module not found" error in browser**

- A: Check that relative import paths match file locations
- Example: `import { func } from './crypto/encryption.js'` (note `./`)

**Q: Visualizer shows "Visualizer unavailable"**

- A: Could be image too large, canvas context issue, or memory
- Check browser console for error details

**Q: Decryption says "Check password"**

- A: Either password is wrong OR file was corrupted
- GCM authentication tag detects both cases

**Q: Encryption slower than expected**

- A: PBKDF2 takes ~1.2 seconds by design (security tradeoff)
- On slower devices, might be 2-3 seconds

---

## Module Development Guide

### Adding a New Feature

**Example: Add file size limit validation**

1. Add constant in `src/utils/constants.js`

   ```javascript
   export const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500 MB
   ```

2. Use in `src/utils/fileHandler.js`

   ```javascript
   export const validateFileSize = (file) => {
     return file.size <= MAX_FILE_SIZE;
   };
   ```

3. Import in `src/app.js`

   ```javascript
   import { validateFileSize } from "./utils/fileHandler.js";

   if (!validateFileSize(file)) {
     showStatus(status, "File too large", false);
     return;
   }
   ```

### Adding a New Module

1. Create file in appropriate folder (`src/crypto/`, `src/ui/`, etc.)
2. Add detailed JSDoc comments
3. Export functions clearly
4. Import in `app.js` or relevant module
5. Test in browser console

---

## Conclusion

This modular architecture provides:

- **Maintainability**: Find code quickly, understand relationships
- **Testability**: Test individual modules in isolation
- **Scalability**: Add features without modifying existing code
- **Clarity**: Documentation explains each module's purpose
- **Security**: Focused review of cryptographic operations

Each module has single responsibility, making the codebase significantly easier to debug, maintain, and extend compared to the original 3000-line monolithic script.
