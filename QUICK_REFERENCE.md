# SecureImage — Quick Reference Guide

## File Organization Quick Map

### 🔐 Cryptography (`src/crypto/`)

| File               | Purpose                             | Key Functions                          |
| ------------------ | ----------------------------------- | -------------------------------------- |
| `keyDerivation.js` | PBKDF2 key generation from password | `deriveKey()`, `deriveKeyWithTiming()` |
| `encryption.js`    | AES-256-GCM encrypt/decrypt         | `encryptFile()`, `decryptFile()`       |

### 🎨 UI Management (`src/ui/`)

| File                  | Purpose                        | Key Functions                                              |
| --------------------- | ------------------------------ | ---------------------------------------------------------- |
| `domManager.js`       | DOM element caching & helpers  | `cacheDOMElements()`, `showStatus()`                       |
| `passwordStrength.js` | Password validation & feedback | `evaluatePasswordCriteria()`, `updatePasswordStrengthUI()` |

### 👁️ Visualization (`src/visualization/`)

| File                 | Purpose                              | Key Functions                                         |
| -------------------- | ------------------------------------ | ----------------------------------------------------- |
| `aesAlgorithm.js`    | AES round operations (educational)   | `applySubBytes()`, `applyShiftRows()`, etc.           |
| `imageComparison.js` | Original vs encrypted display        | `renderComparisonPanel()`, `clearComparison()`        |
| `roundVisualizer.js` | AES diffusion progress visualization | `startRoundVisualizer()`, `initializeRoundControls()` |

### 🛠️ Utilities (`src/utils/`)

| File             | Purpose                           | Key Functions                                    |
| ---------------- | --------------------------------- | ------------------------------------------------ |
| `constants.js`   | All configuration & magic numbers | (Exports 50+ constants)                          |
| `encoding.js`    | Base64 conversion                 | `arrayBufferToBase64()`, `base64ToArrayBuffer()` |
| `fileHandler.js` | File metadata & sanitization      | `sanitizeFileName()`, `formatBytes()`            |

### 📋 Main App

| File         | Purpose                                  |
| ------------ | ---------------------------------------- |
| `src/app.js` | Application orchestrator, event handlers |

---

## Common Tasks

### ✏️ Adding a New Constant

```javascript
// 1. Edit src/utils/constants.js
export const MY_NEW_CONSTANT = 42;

// 2. Import where needed
import { MY_NEW_CONSTANT } from "../utils/constants.js";
```

### 🔧 Modifying Password Requirements

```javascript
// Edit src/utils/constants.js
export const MIN_PASSWORD_LENGTH = 10; // Changed from 8
export const STRONG_PASSWORD_LENGTH = 15; // Changed from 12
```

### 🎯 Changing PBKDF2 Iterations (⚠️ Security!)

```javascript
// Edit src/utils/constants.js
export const PBKDF2_ITERATIONS = 500000; // More secure but slower

// Note: Higher iterations = more resistant to brute force
// But users wait longer during encryption/decryption
```

### 🎨 Adding a New UI Element

```javascript
// 1. Add to HTML (index.html)
<div id="my-new-element">...</div>;

// 2. Cache it (src/ui/domManager.js)
export const cacheDOMElements = () => ({
  // ... existing elements ...
  myNewElement: document.getElementById("my-new-element"),
});

// 3. Use in app (src/app.js)
const myElement = appState.dom.myNewElement;
```

### 🐛 Debugging Encryption

```javascript
// In browser console
import { encryptFile } from "./src/crypto/encryption.js";
import { deriveKeyWithTiming } from "./src/crypto/keyDerivation.js";

// Create test file
const file = new File(["test"], "test.txt", { type: "text/plain" });

// Encrypt and inspect
const result = await encryptFile(
  file,
  "password",
  deriveKeyWithTiming,
  withTiming,
);
console.log("Result:", result);
console.log("Ciphertext:", result.ciphertext);
console.log("Timing:", result.timingInfo);
```

---

## Data Flow Cheatsheet

### Encryption Flow

```
File + Password
    ↓ [app.js]
handleEncryption()
    ↓ [encryption.js]
encryptFile() → generates salt, IV
    ↓ [keyDerivation.js]
deriveKeyWithTiming() → PBKDF2 (100k iterations)
    ↓ [Web Crypto API]
AES-256-GCM.encrypt()
    ↓ [encoding.js]
arrayBufferToBase64()
    ↓
Text output: "salt:iv:tag:ciphertext"
```

### Decryption Flow

```
Encrypted text + Password
    ↓ [app.js]
handleDecryption()
    ↓ [encryption.js]
decryptFile() → parse format
    ↓ [keyDerivation.js]
deriveKeyWithTiming() → PBKDF2 (same salt)
    ↓ [Web Crypto API]
AES-256-GCM.decrypt() with tag verification
    ↓ [fileHandler.js]
sanitizeFileName()
    ↓
File download
```

### Visualization Flow

```
After encryption:
    ↓ [imageComparison.js]
renderComparisonPanel()
    ↓
Shows original image vs noise
    ↓ [roundVisualizer.js]
startRoundVisualizer()
    ↓
Builds 15 round states via [aesAlgorithm.js]
    ↓
Shows diffusion progression R0 → R14
```

---

## Module Dependency Graph

```
                  app.js
                    │
        ┌───────────┼───────────┐
        │           │           │
    crypto/      ui/        visualization/
        │           │           │
    ├─────────┬─────────────────────┐
    │         │                     │
keyDer.  encryption   imageComp.  aesAlgo.  roundVis.
    │         │                     │           │
    └─────────┴─────────────────────┴───────────┘
              │
          utils/
         ├─────┬───────┬────────┐
         │     │       │        │
     const  encoding fileHdlr  domMgr  pwdStr
```

**Direction:** Lower modules used by higher modules

- `utils/*` used by everyone
- `crypto/*`, `ui/*` used by `app.js`
- `visualization/*` provides optional features
- **No circular dependencies** ✓

---

## Key Security Decisions Explained

| Decision                   | Reason                                                   |
| -------------------------- | -------------------------------------------------------- |
| PBKDF2 100k iterations     | ~1.2 sec/guess makes brute force impractical             |
| Random salt per encryption | Prevents rainbow table attacks                           |
| Random IV per encryption   | Different ciphertext for same plaintext+password         |
| AES-256-GCM (not just AES) | GCM mode provides authentication tag (detects tampering) |
| Metadata inside ciphertext | User can't spoof filename/type                           |
| Client-side only           | Password never sent to server                            |

---

## Performance Notes

| Operation                      | Typical Time                     |
| ------------------------------ | -------------------------------- |
| PBKDF2 key derivation          | 1.0-1.5 seconds                  |
| AES-256-GCM encrypt (1 MB)     | 20-50 ms                         |
| Base64 encoding                | <10 ms                           |
| Visualization (round building) | 5-10 seconds (displays progress) |

---

## Environment Requirements

- **Browser**: Modern browser with Web Crypto API
- **HTTPS**: Required for secure context
- **JavaScript**: ES6 modules support
- **Chart.js**: For visualization (loaded from CDN)

---

## Useful Browser Commands

### Test encryption/decryption

```javascript
// Get reference to app state
const state = window.appState;

// Check if encryption in progress
console.log("Encrypting:", state.encryptInProgress);

// View last encrypted payload
console.log("Payload:", state.lastEncryptedPayload);

// Check cached DOM elements
console.log("DOM:", state.dom);
```

### View module imports

```javascript
// In developer tools → Sources tab → Network
// Each module file should load without errors
```

### Performance profiling

```javascript
// Measure PBKDF2 performance
performance.mark("pbkdf2-start");
// ... do encryption ...
performance.mark("pbkdf2-end");
performance.measure("pbkdf2", "pbkdf2-start", "pbkdf2-end");
const measure = performance.getEntriesByName("pbkdf2")[0];
console.log("PBKDF2 took:", measure.duration, "ms");
```

---

## Troubleshooting Checklist

- [ ] All files in `/src/` folder created?
- [ ] HTML modified to load `src/app.js` instead of `script.js`?
- [ ] Module imports use relative paths (`./`, `../`)?
- [ ] No circular imports between modules?
- [ ] Browser supports ES6 modules?
- [ ] HTTPS enabled (required for Web Crypto)?
- [ ] Chart.js CDN accessible?
- [ ] No console errors about missing modules?

---

## Next Steps

1. **Read ARCHITECTURE.md** for detailed module descriptions
2. **Inspect individual files** in `/src/` for implementation details
3. **Test in browser console** to understand data flow
4. **Modify constants** to experiment with different parameters
5. **Extend modules** to add new features

---

## Support

For issues or questions:

1. Check browser console for errors (F12)
2. Check ARCHITECTURE.md for detailed explanations
3. Review specific module files for implementation details
4. Test individual functions in browser console
