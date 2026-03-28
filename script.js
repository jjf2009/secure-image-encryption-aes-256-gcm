/**
 * SecureImage - AES-256-GCM Image Encryption/Decryption
 */

// Key Derivation logic
const deriveKey = async (password, salt, iterations = 100000) => {
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
const btnBenchmark = document.getElementById('btn-benchmark');
const benchmarkStatus = document.getElementById('benchmark-status');
const benchmarkSpinner = document.getElementById('benchmark-spinner');
const benchmarkChartCanvas = document.getElementById('pbkdf2-chart');
const MAX_CANVAS_DIMENSION = 420;
const NOISE_SEED_SAMPLE_SIZE = 1024;
const FNV_OFFSET_BASIS = 0x811c9dc5;
const FNV_PRIME = 0x01000193;

let encryptedBlobUrl = null;
let decryptedBlobUrl = null;
let originalFileName = "image.png";
let lastEncryptedPayload = "";
let lastEncryptionPassword = "";

const FIXED_SALT = new TextEncoder().encode("SECUREIMAGE_SALT_PBKDF2");
const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
let pbkdf2Chart = null;

const showStatus = (el, msg, isSuccess) => {
    el.textContent = isSuccess ? "Success: " + msg : "Error: " + msg;
    el.className = `status-box ${isSuccess ? 'status-success' : 'status-error'}`;
    el.style.display = "block";
};

const toggleSpinner = (spinnerEl, show) => {
    if (!spinnerEl) return;
    spinnerEl.style.display = show ? "inline-block" : "none";
};

const formatBytes = (bytes) => {
    if (!bytes || bytes <= 0) return "0 KB";
    const kb = bytes / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    return `${(kb / 1024).toFixed(2)} MB`;
};

const computeThroughputMBps = (bytes, timeMs) => {
    if (!bytes || timeMs <= 0) return 0;
    return (bytes / 1048576) / (timeMs / 1000);
};

const updateStatsPanel = ({ mode, pbkdf2Ms, operationMs, fileSizeBytes }) => {
    if (!statMode || !statPbkdf2 || !statOperation || !statFileSize || !statThroughput) return;
    statMode.textContent = `Last ${mode}`;
    statPbkdf2.textContent = `${pbkdf2Ms.toFixed(1)} ms`;
    statOperation.textContent = `${operationMs.toFixed(1)} ms`;
    statFileSize.textContent = formatBytes(fileSizeBytes);
    const throughput = computeThroughputMBps(fileSizeBytes, operationMs);
    statThroughput.textContent = throughput ? `${throughput.toFixed(2)} MB/s` : "—";
    if (pbkdf2Warning) {
        pbkdf2Warning.style.display = pbkdf2Ms < 200 ? "block" : "none";
    }
};

const deriveKeyWithTiming = async (password, salt, iterations = 100000) => {
    const start = performance.now();
    const key = await deriveKey(password, salt, iterations);
    const duration = performance.now() - start;
    return { key, duration };
};

const encryptWithTiming = async (key, iv, dataBuffer) => {
    const start = performance.now();
    const encryptedData = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        dataBuffer
    );
    return { encryptedData, duration: performance.now() - start };
};

const decryptWithTiming = async (key, iv, ciphertextWithTag) => {
    const start = performance.now();
    const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ciphertextWithTag
    );
    return { decryptedBuffer, duration: performance.now() - start };
};

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
        btnEncrypt.disabled = true;
        spinner.style.display = "inline-block";
        status.style.display = "none";
        downloadArea.style.display = "none";
        clearComparison();

        const file = fileInput.files[0];
        originalFileName = file.name;
        const arrayBuffer = await file.arrayBuffer();

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const { key, duration: pbkdf2Ms } = await deriveKeyWithTiming(password, salt);

        const { encryptedData, duration: encryptionMs } = await encryptWithTiming(
            key,
            iv,
            arrayBuffer
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
            fileSizeBytes: arrayBuffer.byteLength
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
    } finally {
        btnEncrypt.disabled = false;
        spinner.style.display = "none";
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

        const { decryptedBuffer, duration: decryptionMs } = await decryptWithTiming(
            key,
            iv,
            ciphertextWithTag
        );

        const blob = new Blob([decryptedBuffer]);
        if (decryptedBlobUrl) URL.revokeObjectURL(decryptedBlobUrl);
        decryptedBlobUrl = URL.createObjectURL(blob);

        // Set attributes for native download link
        const fileName = originalFileName.includes('.') ? originalFileName : "image.png";
        btnDownloadImg.href = decryptedBlobUrl;
        btnDownloadImg.download = "restored_" + fileName;

        previewImg.src = decryptedBlobUrl;
        previewArea.style.display = "block";
        btnDownloadImg.style.display = "inline-flex";
        showStatus(status, "Decryption complete.", true);
        updateStatsPanel({
            mode: "Decryption",
            pbkdf2Ms,
            operationMs: decryptionMs,
            fileSizeBytes: decryptedBuffer.byteLength
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
        showStatus(benchmarkStatus, "Chart.js failed to load.", false);
        return;
    }

    btnBenchmark.disabled = true;
    toggleSpinner(benchmarkSpinner, true);
    if (benchmarkStatus) benchmarkStatus.style.display = "none";

    const iterationSet = [10000, 50000, 100000, 200000, 500000];
    const durations = [];

    try {
        for (const iterationCount of iterationSet) {
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
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
                labels: iterationSet.map((val) => val.toLocaleString()),
                datasets: [
                    {
                        label: "PBKDF2 derivation time (ms)",
                        data: durations.map((v) => Number(v.toFixed(1))),
                        borderColor: getComputedStyle(document.documentElement).getPropertyValue('--primary') || '#4f46e5',
                        backgroundColor: 'rgba(79, 70, 229, 0.1)',
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
                        text: "Higher iterations = slower brute force attacks but slower for legitimate users — this is the security/performance tradeoff."
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
