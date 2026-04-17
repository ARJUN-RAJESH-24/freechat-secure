"use client";

import { useState, useEffect } from "react";
import { registerUser } from "@/app/actions/auth";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { CryptoEngine } from "@/lib/crypto";

export default function RegisterForm() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [status, setStatus] = useState("idle"); // idle | generating | submitting | success

  // Proactive Secure Context Check
  useEffect(() => {
    if (typeof window !== "undefined") {
      if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
        setError("CRITICAL: Secure Context Required. The cryptographic engine is disabled over insecure connections (HTTP). Please ensure you are accessing FreeChat via HTTPS.");
      }
    }
  }, []);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setStatus("generating");

    try {
      const formData = new FormData(e.target);
      const password = formData.get("password");
      const confirmPassword = formData.get("confirmPassword");

      if (password !== confirmPassword) {
        setError("Passphrase mismatch. Both fields must be identical.");
        setStatus("idle");
        return;
      }

      if (password.length < 12) {
        setError("Passphrase must be at least 12 characters.");
        setStatus("idle");
        return;
      }

      // E2EE Identity Generation
      const { signaturePair, encryptionPair } = await CryptoEngine.generateIdentity();

      setStatus("submitting");

      const publicKeyPayload = await CryptoEngine.exportPublicKeys(signaturePair, encryptionPair);
      const encryptedPrivateKeyPayload = await CryptoEngine.encryptPrivateKeysWithPassword(
        password, signaturePair, encryptionPair
      );

      formData.append("publicKey", publicKeyPayload);
      formData.append("encryptedPrivateKey", encryptedPrivateKeyPayload);

      const res = await registerUser(formData);

      if (res.error) {
        setError(res.error);
        setStatus("idle");
      } else {
        setStatus("success");
        setTimeout(() => {
          router.push("/login?registered=true");
        }, 2000);
      }
    } catch (err) {
      console.error("[CryptoEngine] Fatal error:", err);
      setError(`Cryptographic engine failure: ${err?.message || err?.name || "Unknown error"}. Ensure you are on HTTPS and using a modern browser.`);
      setStatus("idle");
    }
  }

  return (
    <form onSubmit={handleSubmit} className="glass-panel" style={{ padding: "3rem", width: "100%", maxWidth: "450px", display: "flex", flexDirection: "column", gap: "1.5rem" }}>

      <h2 className="animate-brand" style={{ textAlign: "center", fontSize: "3rem", color: "#ffffff", fontWeight: "900", letterSpacing: "2px", margin: "0" }}>FREECHAT</h2>
      <p style={{ textAlign: "center", fontSize: "0.875rem", color: "var(--accent-cyan)", marginTop: "-1rem", letterSpacing: "4px" }}>NODE INITIALIZATION</p>

      {error && (
        <div style={{ color: "#ff4d4d", fontSize: "0.875rem", border: "1px solid rgba(255, 77, 77, 0.3)", padding: "0.75rem", borderRadius: "4px", background: "rgba(255, 0, 0, 0.1)" }}>
          {error}
        </div>
      )}

      {status === "success" && (
        <div style={{ color: "#00e5ff", fontSize: "0.875rem", border: "1px solid rgba(0, 229, 255, 0.3)", padding: "0.75rem", borderRadius: "4px", background: "rgba(0, 229, 255, 0.1)" }}>
          Identity successfully initialized. Keypair generated. Redirecting to authentication...
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <label htmlFor="username" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", letterSpacing: "1px" }}>USERNAME</label>
        <input type="text" id="username" name="username" required autoComplete="off" disabled={status !== "idle"} minLength={4} />
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <label htmlFor="password" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", letterSpacing: "1px" }}>SECURE PASSPHRASE (min 12 chars)</label>
        <input type="password" id="password" name="password" required autoComplete="new-password" disabled={status !== "idle"} minLength={12} />
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <label htmlFor="confirmPassword" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", letterSpacing: "1px" }}>CONFIRM PASSPHRASE</label>
        <input type="password" id="confirmPassword" name="confirmPassword" required autoComplete="new-password" disabled={status !== "idle"} minLength={12} />
      </div>

      <button type="submit" disabled={status !== "idle"} style={{ marginTop: "1rem", opacity: status !== "idle" ? 0.5 : 1 }}>
        {status === "idle" && "INITIALIZE IDENTITY"}
        {status === "generating" && "GENERATING KEYPAIR..."}
        {status === "submitting" && "ENCRYPTING AND STORING..."}
        {status === "success" && "IDENTITY CREATED"}
      </button>

      <p style={{ textAlign: "center", fontSize: "0.875rem", color: "var(--text-secondary)" }}>
        Already have credentials? <Link href="/login" style={{ color: "var(--accent-cyan)" }}>Authenticate</Link>
      </p>

      <p style={{ textAlign: "center", fontSize: "0.65rem", color: "rgba(255,255,255,0.2)" }}>SECURE-GEN v1.3</p>

    </form>
  );
}
