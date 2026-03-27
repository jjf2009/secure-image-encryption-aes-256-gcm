/**
 * SecureImage - AES-256-GCM Image Encryption/Decryption
 */

// Key Derivation logic
const deriveKey = async (password, salt) => {
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
            iterations: 100000,
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

let encryptedBlobUrl = null;
let decryptedBlobUrl = null;
let originalFileName = "image.png";
let lastEncryptedPayload = "";
let lastEncryptionPassword = "";

const FIXED_SALT = new TextEncoder().encode("SECUREIMAGE_SALT_PBKDF2");

const showStatus = (el, msg, isSuccess) => {
    el.textContent = isSuccess ? "Success: " + msg : "Error: " + msg;
    el.className = `status-box ${isSuccess ? 'status-success' : 'status-error'}`;
    el.style.display = "block";
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
    .replace(/>/g, "&gt;");

const renderTamperDisplay = (parts, tamperedSegment) => {
    if (!tamperDisplay) return;
    const labels = parts.length === 4
        ? ["Salt", "IV", "Tag", "Ciphertext"]
        : ["IV", "Tag", "Ciphertext"];

    const segmentsHtml = parts.map((segment, idx) => {
        const isTampered = idx === parts.length - 1;
        const content = escapeHtml(idx === parts.length - 1 ? tamperedSegment : segment);
        const label = labels[idx] || "Segment";
        return `
            <div class="segments">
                <span class="segment-label">${label}</span>
                <span class="tamper-chip ${isTampered ? 'tampered' : ''}">${content}</span>
            </div>
        `;
    }).join('<span style="color:#9ca3af;">:</span>');

    tamperDisplay.innerHTML = segmentsHtml;
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

        const file = fileInput.files[0];
        originalFileName = file.name;
        const arrayBuffer = await file.arrayBuffer();

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const key = await deriveKey(password, salt);

        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
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

    } catch (e) {
        console.error(e);
        showStatus(status, e.message, false);
        resetAttackPanel();
        lastEncryptedPayload = "";
        lastEncryptionPassword = "";
        if (ciphertextOutput) {
            ciphertextOutput.value = "";
        }
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

        const key = await deriveKey(password, salt);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
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
    const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    const flipIndex = Math.max(0, Math.floor(originalCipherSegment.length / 2));
    const currentChar = originalCipherSegment[flipIndex];
    const currentIndex = base64Chars.indexOf(currentChar);
    let replacementChar = "A";
    if (currentIndex >= 0) {
        replacementChar = base64Chars[(currentIndex + 1) % base64Chars.length];
        if (replacementChar === currentChar) {
            replacementChar = base64Chars[(currentIndex + 2) % base64Chars.length];
        }
    } else {
        replacementChar = currentChar === "A" ? "B" : "A";
    }
    const tamperedSegment = originalCipherSegment.substring(0, flipIndex) + replacementChar + originalCipherSegment.substring(flipIndex + 1);

    const tamperedParts = [...parts];
    tamperedParts[cipherIndex] = tamperedSegment;
    const tamperedPayload = tamperedParts.join(':');

    renderTamperDisplay(tamperedParts, tamperedSegment);
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
        attackStatus.className = "status-box status-success";
        attackStatus.style.display = "block";
    } catch (e) {
        console.warn("Tampering detected:", e);
        attackStatus.textContent = "⚠️ Tampering Detected — Authentication tag mismatch. GCM integrity check failed.";
        attackStatus.className = "status-box status-error";
        attackStatus.style.display = "block";
    }
});
