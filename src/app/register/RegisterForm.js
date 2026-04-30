"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { CryptoEngine } from "@/lib/crypto";

export default function RegisterForm() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [status, setStatus] = useState("idle"); // idle | generating | submitting | success
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

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

      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_\-+=\[\]{}|\\:;"'<>,./~`])[A-Za-z\d@$!%*?&#^()_\-+=\[\]{}|\\:;"'<>,./~`]{12,}$/;
      if (!passwordRegex.test(password)) {
        setError("Passphrase must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character.");
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

      // Use a stable REST API endpoint instead of a Server Action.
      // Server Action IDs change with every deployment, causing stale-ID errors.
      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: formData.get("username"),
          password: formData.get("password"),
          publicKey: publicKeyPayload,
          encryptedPrivateKey: encryptedPrivateKeyPayload,
        }),
      });

      const data = await res.json();

      if (!res.ok || data.error) {
        setError(data.error || "Registration failed.");
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
    <div style={{ position: "relative", width: "100%", maxWidth: "450px" }}>
      <Link href="/" style={{ position: "absolute", top: "-40px", left: "0", color: "var(--text-secondary)", fontSize: "0.875rem", display: "flex", alignItems: "center", gap: "8px", textDecoration: "none", transition: "color 0.2s" }} onMouseEnter={(e) => e.target.style.color = "#fff"} onMouseLeave={(e) => e.target.style.color = "var(--text-secondary)"}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
        RETURN TO PROTOCOL
      </Link>
      <form onSubmit={handleSubmit} className="glass-panel fade-in" style={{ padding: "3rem", width: "100%", display: "flex", flexDirection: "column", gap: "1.5rem" }}>

      <h2 className="animate-brand" style={{ textAlign: "center", fontSize: "3rem", color: "#ffffff", fontWeight: "900", letterSpacing: "2px", margin: "0" }}>FREECHAT</h2>
      <p style={{ textAlign: "center", fontSize: "0.875rem", color: "var(--accent-cyan)", marginTop: "-1rem", letterSpacing: "4px" }}>NODE INITIALIZATION</p>

      {error && (
        <div className="msg-enter" style={{ color: "#ff4d4d", fontSize: "0.875rem", border: "1px solid rgba(255, 77, 77, 0.3)", padding: "0.75rem", borderRadius: "8px", background: "rgba(255, 0, 0, 0.1)" }}>
          {error}
        </div>
      )}

      {status === "success" && (
        <div className="msg-enter" style={{ color: "#00e5ff", fontSize: "0.875rem", border: "1px solid rgba(0, 229, 255, 0.3)", padding: "0.75rem", borderRadius: "8px", background: "rgba(0, 229, 255, 0.1)" }}>
          Identity successfully initialized. Keypair generated. Redirecting to authentication...
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <label htmlFor="username" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", letterSpacing: "1px" }}>USERNAME</label>
        <input type="text" id="username" name="username" required autoComplete="off" disabled={status !== "idle"} minLength={4} autoFocus />
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <label htmlFor="password" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", letterSpacing: "1px" }}>SECURE PASSPHRASE (min 12 chars)</label>
        <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
          <input type={showPassword ? "text" : "password"} id="password" name="password" required autoComplete="new-password" disabled={status !== "idle"} minLength={12} style={{ width: "100%", paddingRight: "40px" }} />
          <button type="button" onClick={() => setShowPassword(!showPassword)} style={{ position: "absolute", right: "8px", background: "transparent", border: "none", padding: "4px", color: "var(--text-secondary)", cursor: "pointer", display: "flex" }}>
            {showPassword ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22"></path></svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            )}
          </button>
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <label htmlFor="confirmPassword" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", letterSpacing: "1px" }}>CONFIRM PASSPHRASE</label>
        <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
          <input type={showConfirmPassword ? "text" : "password"} id="confirmPassword" name="confirmPassword" required autoComplete="new-password" disabled={status !== "idle"} minLength={12} style={{ width: "100%", paddingRight: "40px" }} />
          <button type="button" onClick={() => setShowConfirmPassword(!showConfirmPassword)} style={{ position: "absolute", right: "8px", background: "transparent", border: "none", padding: "4px", color: "var(--text-secondary)", cursor: "pointer", display: "flex" }}>
            {showConfirmPassword ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22"></path></svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            )}
          </button>
        </div>
      </div>

      <button type="submit" disabled={status !== "idle"} style={{ marginTop: "1rem" }}>
        {status === "idle" && "INITIALIZE IDENTITY"}
        {(status === "generating" || status === "submitting") && (
          <>
            <svg width="20" height="20" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" stroke="currentColor">
              <style>
                {`.spinner_V8m1{transform-origin:center;animation:spinner_zKoa 2s linear infinite}.spinner_V8m1 circle{stroke-linecap:round;animation:spinner_YpZS 1.5s ease-in-out infinite}@keyframes spinner_zKoa{100%{transform:rotate(360deg)}}@keyframes spinner_YpZS{0%{stroke-dasharray:0 150;stroke-dashoffset:0}47.5%{stroke-dasharray:42 150;stroke-dashoffset:-16}95%,100%{stroke-dasharray:42 150;stroke-dashoffset:-59}}`}
              </style>
              <g className="spinner_V8m1"><circle cx="12" cy="12" r="9.5" fill="none" strokeWidth="3"></circle></g>
            </svg>
            {status === "generating" ? "GENERATING KEYPAIR..." : "ENCRYPTING..."}
          </>
        )}
        {status === "success" && "IDENTITY CREATED"}
      </button>

      <p style={{ textAlign: "center", fontSize: "0.875rem", color: "var(--text-secondary)" }}>
        Already have credentials? <Link href="/login" style={{ color: "var(--accent-cyan)", textDecoration: "underline" }}>Authenticate</Link>
      </p>

      <p className="mono-text" style={{ textAlign: "center", fontSize: "0.65rem", color: "rgba(255,255,255,0.2)" }}>SECURE-GEN v1.3</p>

      </form>
    </div>
  );
}
