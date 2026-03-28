# SecureImage — AES-256-GCM Client-Side Image Encryption
*Zero-backend image encryption with authenticated integrity and cryptographic visual analytics.*

![Vanilla JS](https://img.shields.io/badge/Vanilla%20JS-ES2020-F7DF1E?style=flat-square&logo=javascript&logoColor=000000)
![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-Authenticated%20Encryption-0f766e?style=flat-square)
![Zero Backend](https://img.shields.io/badge/Zero%20Backend-Client%20Only-1f2937?style=flat-square)
![Client-Side](https://img.shields.io/badge/Client--Side-Web%20Crypto-2563eb?style=flat-square)

SecureImage is a fully client-side AES-256-GCM encryption system for images that never transmits data or keys to a server. It derives strong keys from user passphrases using PBKDF2 (SHA-256, 100,000 iterations) and produces a portable Base64 payload that embeds both ciphertext and metadata. Beyond encryption, it provides attack simulation, diffusion/entropy visualizations, and performance analytics to demonstrate cryptographic principles with measurable evidence.

## Live Demo
[Live Demo (TODO: replace with deployment URL)](#)  
*Note: This placeholder link should be updated once the project is hosted.*

## Feature Matrix

| Feature | Description | Status ✅ |
| --- | --- | --- |
| AES-256-GCM encryption/decryption | Authenticated encryption providing confidentiality and integrity | ✅ |
| PBKDF2 key derivation (SHA-256, 100k) | Stretches passphrases into 256-bit keys with brute-force resistance | ✅ |
| Random 16-byte salt | Unique salt per encryption, embedded in payload | ✅ |
| Random 12-byte IV | Ensures semantic security (same input ≠ same output) | ✅ |
| Authentication tag validation | Detects tampering during decryption | ✅ |
| Client-side only | Zero backend; no upload, no data leakage | ✅ |
| Payload format | `Base64(SALT):Base64(IV):Base64(TAG):Base64(CIPHERTEXT)` | ✅ |
| Embedded metadata | Original filename, MIME type, and size bundled inside ciphertext | ✅ |
| Attack Simulation Panel | Bit-flip tampering demo with GCM integrity failure | ✅ |
| Password strength validator | Real-time 4-level meter that blocks weak keys | ✅ |
| Round-by-Round diffusion visualizer | Captures initial state (R0) plus rounds 1–14 with S-box/ShiftRows/MixColumns/AddRoundKey | ✅ |
| Entropy visualization panel | Original vs ciphertext noise + pixel histograms | ✅ |
| Performance benchmarking | PBKDF2 time, encryption time, throughput, iteration sweep | ✅ |

## How It Works

### Encryption Flow
```
Image → Binary → Salt+IV Gen → PBKDF2(key,salt) → AES-GCM → Base64 Encode → .txt File
```

### Decryption Flow
```
.txt File → Base64 Decode → Parse Salt+IV+Tag → PBKDF2(key,salt) → AES-GCM Verify+Decrypt → Reconstruct Image
```

### Payload Format
```
Base64(SALT):Base64(IV):Base64(TAG):Base64(CIPHERTEXT)
```

## Security Architecture (Why Each Layer Exists)

- **AES-GCM over CBC**: GCM is an AEAD mode, delivering confidentiality and integrity in one pass. Any bit-flip in ciphertext or tag causes decryption to fail, making tampering detectable.
- **Random Salt (16 bytes)**: Prevents rainbow-table attacks and ensures identical passwords yield different keys across encryptions.
- **PBKDF2 @ 100,000 Iterations**: Increases the cost of brute-force attempts by making each guess computationally expensive.
- **Random IV (12 bytes)**: Provides semantic security so repeated encryption of the same image does not produce the same ciphertext.
- **Embedded Metadata**: Stores filename, MIME type, and size inside the encrypted payload so restoration is self-contained and deterministic.

## Visualization Features (What They Prove)

- **Round-by-Round Diffusion Visualizer**  
  Implements the real AES S-box, ShiftRows, MixColumns (GF(2^8)), and AddRoundKey to show how diffusion increases across AES-256’s 14 rounds, with an explicit R0 snapshot of the initial state. The entropy score rises and histograms converge toward uniformity, evidencing the avalanche effect rather than mere visual obfuscation.

- **Entropy Visualization Panel**  
  Renders ciphertext bytes as pixel noise side-by-side with the original image and plots per-channel histograms. This visually demonstrates loss of structure and near-uniform distribution expected from secure ciphertext.

- **Performance Benchmarking Dashboard**  
  Measures PBKDF2 derivation time, encryption/decryption time, and throughput (MB/s). The iteration sweep (10k→500k) makes the security–performance tradeoff explicit rather than assumed.

## Tech Stack

| Technology | Purpose | Why Chosen |
| --- | --- | --- |
| Web Crypto API | PBKDF2 + AES-GCM | Native, audited browser crypto with hardware acceleration |
| Vanilla JavaScript | Core logic + UI flow | Full control, zero framework overhead |
| HTML5/CSS3 | UI and layout | Clean, static deployment |
| Canvas API | Image + round visualization | Direct pixel-level rendering |
| Chart.js | Histograms + benchmark charts | Reliable charting without backend dependencies |

## Project Structure

```
secure-image-encryption-aes-256-gcm/
├── index.html
├── script.js
├── style.css
├── explanation.md
├── README.md
└── LICENSE
```

## Getting Started

1. Clone or download the repository.
2. Open `index.html` in any modern browser (Chrome, Edge, Firefox).
3. Encrypt an image to generate the portable `.txt` payload, then decrypt it to restore the original file.

> This project is static—no build step, no server, and no dependencies beyond a browser.

## Concepts Demonstrated

- Authenticated encryption (AEAD) and integrity validation
- Key derivation using PBKDF2 with salt and iteration cost
- Semantic security via random IVs
- Secure payload serialization (Base64 with structured fields)
- Metadata encapsulation inside ciphertext
- Diffusion and confusion across AES rounds
- Shannon entropy measurement and histogram analysis
- Security–performance tradeoffs in KDF parameters

## Known Limitations & Future Scope

**Limitations**
- Security depends on passphrase strength; weak passwords are blocked but not recoverable.
- Large files are processed in memory (no streaming/chunked encryption).
- Browser-only execution; no secure key storage beyond the current session.

**Future Scope**
- Streaming encryption/decryption for multi-GB files.
- Versioned payload headers for long-term format evolution.
- Optional hardware-backed key storage (WebAuthn / Web Crypto keys).
- Exportable audit logs for benchmarking runs.

## License

MIT License — see [LICENSE](LICENSE).
