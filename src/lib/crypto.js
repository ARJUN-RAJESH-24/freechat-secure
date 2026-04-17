/**
 * E2EE Cryptography Engine utilizing `window.crypto.subtle`
 * Designed strictly against masquerade attacks via ECDSA Verification
 * Confidentiality via ECDH (Diffie-Hellman) Key Derivation & AES-GCM
 */

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

export const CryptoEngine = {
  // Generate ECDSA and ECDH pairs
  async generateIdentity() {
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
    
    // Key-Encryption-Key (KEK)
    const kek = await window.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
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
    const kek = await window.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
      keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );

    const decBuffer = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, kek, data);
    const decodedStr = new TextDecoder().decode(decBuffer);
    const keys = JSON.parse(decodedStr);

    const privSig = await window.crypto.subtle.importKey(
      "pkcs8", base64ToArrayBuffer(keys.sig), { name: "ECDSA", namedCurve: "P-384" }, true, ["sign"]
    );
    const privEnc = await window.crypto.subtle.importKey(
      "pkcs8", base64ToArrayBuffer(keys.enc), { name: "ECDH", namedCurve: "P-384" }, true, ["deriveKey"]
    );

    return { privSig, privEnc };
  },

  // Generate AES Shared Key via ECDH
  async deriveSharedSecret(myPrivEncKey, peerPubEncKeyRawBase64) {
    const peerKeyBuffer = base64ToArrayBuffer(peerPubEncKeyRawBase64);
    const peerPubEncKey = await window.crypto.subtle.importKey(
      "raw", peerKeyBuffer, { name: "ECDH", namedCurve: "P-384" }, true, []
    );

    return await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: peerPubEncKey },
      myPrivEncKey,
      { name: "AES-GCM", length: 256 },
      true, ["encrypt", "decrypt"]
    );
  },

  // Send a Message (Encrypt + Sign)
  async encryptAndSignMessage(plaintext, sharedSecretKey, myPrivSigKey) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    
    // Encrypt Identity-Stripped Message
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, sharedSecretKey, enc.encode(plaintext)
    );

    // Sign the Ciphertext+IV so masquerading is impossible
    const payloadToSign = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    payloadToSign.set(new Uint8Array(iv), 0);
    payloadToSign.set(new Uint8Array(ciphertext), iv.byteLength);

    const signature = await window.crypto.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-384" } }, myPrivSigKey, payloadToSign
    );

    return JSON.stringify({
      iv: arrayBufferToBase64(iv),
      ciphertext: arrayBufferToBase64(ciphertext),
      signature: arrayBufferToBase64(signature)
    });
  },

  // Receive a message (Verify Signature + Decrypt)
  async verifyAndDecryptMessage(payloadStr, sharedSecretKey, peerPubSigKeyRawBase64) {
    const payload = JSON.parse(payloadStr);
    const iv = base64ToArrayBuffer(payload.iv);
    const ciphertext = base64ToArrayBuffer(payload.ciphertext);
    const signature = base64ToArrayBuffer(payload.signature);

    const peerPubSigKey = await window.crypto.subtle.importKey(
      "raw", base64ToArrayBuffer(peerPubSigKeyRawBase64), { name: "ECDSA", namedCurve: "P-384" }, true, ["verify"]
    );

    const payloadToSign = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    payloadToSign.set(new Uint8Array(iv), 0);
    payloadToSign.set(new Uint8Array(ciphertext), iv.byteLength);

    // ANTI-MASQUERADE LOGIC
    const isValid = await window.crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-384" } }, peerPubSigKey, signature, payloadToSign
    );

    if (!isValid) throw new Error("CRITICAL SEC: Digital Signature failed verification. Message forged/masquerading detected.");

    // Decrypt content
    const plaintextBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) }, sharedSecretKey, ciphertext
    );

    return new TextDecoder().decode(plaintextBuffer);
  }
};
