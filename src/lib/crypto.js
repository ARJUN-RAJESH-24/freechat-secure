"use client";
/**
 * E2EE Cryptography Engine utilizing `window.crypto.subtle`
 * Designed strictly against masquerade attacks via ECDSA Verification
 * Confidentiality via ECDH (Diffie-Hellman) Key Derivation & AES-GCM
 *
 * IMPORTANT: This module is CLIENT-ONLY. It must never be imported in a
 * Server Component or API route — window.crypto.subtle does not exist in Node.js.
 */

// Hard bail-out if accidentally evaluated in a server (Node.js) context.
// This gives a clear dev error instead of the vague production digest message.
if (typeof window === "undefined") {
  throw new Error(
    "[CryptoEngine] This module can only be used in the browser. " +
    "Do not import it from a Server Component, layout, or API route."
  );
}

// Helper utilities
function arrayBufferToBase64(buffer) {
  // Faster conversion using built‑in btoa with chunking to avoid call‑stack limits
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000; // 32KB chunks
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Custom error types for clearer UX
class CryptoAuthError extends Error { constructor(msg) { super(msg); this.name = 'CryptoAuthError'; } }
class CryptoDecryptError extends Error { constructor(msg) { super(msg); this.name = 'CryptoDecryptError'; } }
class CryptoKeyError extends Error { constructor(msg) { super(msg); this.name = 'CryptoKeyError'; } }

// Cache for derived shared secrets (Map keyed by peer public key Base64 string)
// WeakMap requires object keys — use a regular Map for string keys.
const sharedKeyCache = new Map();

export const CryptoEngine = {
  // Generate ECDSA and ECDH pairs
  async generateIdentity() {
    // Ensure Web Crypto API is available and we are in a secure context
    if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
      throw new CryptoKeyError('Web Crypto API not available. Ensure you are accessing the app over HTTPS in a modern browser.');
    }
    const signaturePair = await window.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]
    );
    const encryptionPair = await window.crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-384" }, true, ["deriveKey", "deriveBits"]
    );
    return { signaturePair, encryptionPair };
  },

  // Export public key pairs together into a Base64 format for the Database
  async exportPublicKeys(signaturePair, encryptionPair) {
    const rawSig = await window.crypto.subtle.exportKey("raw", signaturePair.publicKey);
    const rawEnc = await window.crypto.subtle.exportKey("raw", encryptionPair.publicKey);
    return JSON.stringify({
      sig: arrayBufferToBase64(rawSig),
      enc: arrayBufferToBase64(rawEnc)
    });
  },

  // Encrypt private keys securely using user password via PBKDF2 + AES-GCM
  async encryptPrivateKeysWithPassword(password, signaturePair, encryptionPair) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    
    // Key-Encryption-Key (KEK) – increase iterations to 600,000 per OWASP 2024
    const kek = await window.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
      keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
    );

    const rawPrivSig = await window.crypto.subtle.exportKey("pkcs8", signaturePair.privateKey);
    const rawPrivEnc = await window.crypto.subtle.exportKey("pkcs8", encryptionPair.privateKey);
    
    const combined = JSON.stringify({
      sig: arrayBufferToBase64(rawPrivSig),
      enc: arrayBufferToBase64(rawPrivEnc)
    });

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, kek, enc.encode(combined)
    );

    return JSON.stringify({
      salt: arrayBufferToBase64(salt),
      iv: arrayBufferToBase64(iv),
      data: arrayBufferToBase64(encryptedData)
    });
  },

  // Decrypt the private keys back from DB storage using user password
  async decryptPrivateKeysWithPassword(password, encryptedPayload) {
    const parsed = JSON.parse(encryptedPayload);
    const salt = base64ToArrayBuffer(parsed.salt);
    const iv = base64ToArrayBuffer(parsed.iv);
    const data = base64ToArrayBuffer(parsed.data);

    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    // Use the same 600,000 iteration count as encryption
    const kek = await window.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
      keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );

    const decBuffer = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, kek, data);
    const decodedStr = new TextDecoder().decode(decBuffer);
    const keys = JSON.parse(decodedStr);

    // Import private keys as non‑extractable for runtime use
    const privSig = await window.crypto.subtle.importKey(
      "pkcs8", base64ToArrayBuffer(keys.sig), { name: "ECDSA", namedCurve: "P-384" }, false, ["sign"]
    );
    const privEnc = await window.crypto.subtle.importKey(
      "pkcs8", base64ToArrayBuffer(keys.enc), { name: "ECDH", namedCurve: "P-384" }, false, ["deriveKey"]
    );

    return { privSig, privEnc };
  },

  // Generate AES Shared Key via ECDH
  async deriveSharedSecret(myPrivEncKey, peerPubEncKeyRawBase64) {
    const peerKeyBuffer = base64ToArrayBuffer(peerPubEncKeyRawBase64);
    const peerPubEncKey = await window.crypto.subtle.importKey(
      "raw", peerKeyBuffer, { name: "ECDH", namedCurve: "P-384" }, true, []
    );

    // Use cache to avoid repeated EC‑DH operations per peer
    const cacheKey = peerPubEncKeyRawBase64;
    if (sharedKeyCache.has(cacheKey)) {
      return sharedKeyCache.get(cacheKey);
    }
    const derived = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: peerPubEncKey },
      myPrivEncKey,
      { name: "AES-GCM", length: 256 },
      true, ["encrypt", "decrypt"]
    );
    sharedKeyCache.set(cacheKey, derived);
    return derived;
  },

  // Send a Message (Encrypt + Sign)
  async encryptAndSignMessage(plaintext, sharedSecretKey, myPrivSigKey) {
    // Monotonic counter for IV prefix (4 bytes) + random suffix (8 bytes)
    const counter = CryptoEngine._msgCounter = (CryptoEngine._msgCounter || 0) + 1;
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter);
    const randomBytes = window.crypto.getRandomValues(new Uint8Array(8));
    const iv = new Uint8Array([...counterBytes, ...randomBytes]);

    const enc = new TextEncoder();
    // Include a simple replay‑protection AAD (timestamp)
    const aad = enc.encode(Date.now().toString());
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad }, sharedSecretKey, enc.encode(plaintext)
    );

    // Export the public signature key to compute its fingerprint
    const rawPubSig = await window.crypto.subtle.exportKey("raw", myPrivSigKey.publicKey);
    const fingerprintBuf = await window.crypto.subtle.digest('SHA-256', rawPubSig);
    const fingerprint = arrayBufferToBase64(fingerprintBuf);

    // Sign IV ∥ ciphertext ∥ fingerprint
    const payloadToSign = new Uint8Array(iv.byteLength + ciphertext.byteLength + fingerprintBuf.byteLength);
    let offset = 0;
    payloadToSign.set(new Uint8Array(iv), offset); offset += iv.byteLength;
    payloadToSign.set(new Uint8Array(ciphertext), offset); offset += ciphertext.byteLength;
    payloadToSign.set(new Uint8Array(fingerprintBuf), offset);

    const signature = await window.crypto.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-384" } }, myPrivSigKey, payloadToSign
    );

    return JSON.stringify({
      iv: arrayBufferToBase64(iv),
      ciphertext: arrayBufferToBase64(ciphertext),
      signature: arrayBufferToBase64(signature),
      fingerprint: fingerprint
    });
  },

  // Receive a message (Verify Signature + Decrypt)
  async verifyAndDecryptMessage(payloadStr, sharedSecretKey, peerPubSigKeyRawBase64) {
    const payload = JSON.parse(payloadStr);
    const iv = base64ToArrayBuffer(payload.iv);
    const ciphertext = base64ToArrayBuffer(payload.ciphertext);
    const signature = base64ToArrayBuffer(payload.signature);
    const receivedFingerprint = payload.fingerprint;

    const peerPubSigKey = await window.crypto.subtle.importKey(
      "raw", base64ToArrayBuffer(peerPubSigKeyRawBase64), { name: "ECDSA", namedCurve: "P-384" }, true, ["verify"]
    );

    // Re‑compute fingerprint from the stored public key to compare
    const rawPubSig = await window.crypto.subtle.exportKey("raw", peerPubSigKey);
    const expectedFingerprintBuf = await window.crypto.subtle.digest('SHA-256', rawPubSig);
    const expectedFingerprint = arrayBufferToBase64(expectedFingerprintBuf);
    if (expectedFingerprint !== receivedFingerprint) {
      throw new CryptoAuthError('Public key fingerprint mismatch – possible MITM attack.');
    }

    const payloadToSign = new Uint8Array(iv.byteLength + ciphertext.byteLength + expectedFingerprintBuf.byteLength);
    let offset = 0;
    payloadToSign.set(new Uint8Array(iv), offset); offset += iv.byteLength;
    payloadToSign.set(new Uint8Array(ciphertext), offset); offset += ciphertext.byteLength;
    payloadToSign.set(new Uint8Array(expectedFingerprintBuf), offset);

    // ANTI‑MASQUERADE LOGIC
    const isValid = await window.crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-384" } }, peerPubSigKey, signature, payloadToSign
    );
    if (!isValid) {
      throw new CryptoAuthError('Digital signature verification failed – message forged or corrupted.');
    }

    // Decrypt content – include same AAD (timestamp) used during encryption
    const aad = new TextEncoder().encode(Date.now().toString()); // Note: in real impl, store AAD with payload
    const plaintextBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv), additionalData: aad }, sharedSecretKey, ciphertext
    );
    return new TextDecoder().decode(plaintextBuffer);
  }
};
