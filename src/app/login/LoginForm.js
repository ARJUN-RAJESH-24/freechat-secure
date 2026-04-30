"use client";

import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState, useEffect } from "react";
import Link from "next/link";

export default function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const registered = searchParams.get("registered");
  const [error, setError] = useState("");
  const [status, setStatus] = useState("idle"); // idle | authenticating | success
  const [showPassword, setShowPassword] = useState(false);

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
    setStatus("authenticating");

    const username = e.target.username.value;
    const password = e.target.password.value;

    const res = await signIn("credentials", {
      username,
      password,
      redirect: false,
    });

    if (res?.error) {
      setError("Authentication failed. Invalid credentials or unregistered node.");
      setStatus("idle");
    } else {
      setStatus("success");
      setTimeout(() => {
        router.push("/chat");
        router.refresh();
      }, 1500);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="glass-panel fade-in" style={{ padding: "3rem", width: "100%", maxWidth: "450px", display: "flex", flexDirection: "column", gap: "1.5rem" }}>

      <h2 className="animate-brand" style={{ textAlign: "center", fontSize: "3rem", color: "#ffffff", fontWeight: "900", letterSpacing: "2px", margin: "0" }}>FREECHAT</h2>
      <p style={{ textAlign: "center", fontSize: "0.875rem", color: "var(--accent-cyan)", marginTop: "-1rem", letterSpacing: "4px" }}>SECURE LOGIN</p>

      {registered && (
        <div className="msg-enter" style={{ color: "#00e5ff", fontSize: "0.875rem", border: "1px solid rgba(0, 229, 255, 0.3)", padding: "0.75rem", borderRadius: "8px", background: "rgba(0, 229, 255, 0.1)" }}>
          Identity initialized successfully. You may now authenticate.
        </div>
      )}

      {status === "success" && (
        <div className="msg-enter" style={{ color: "#00e5ff", fontSize: "0.875rem", border: "1px solid rgba(0, 229, 255, 0.3)", padding: "0.75rem", borderRadius: "8px", background: "rgba(0, 229, 255, 0.1)" }}>
          Authentication verified. Establishing encrypted session...
        </div>
      )}

      {error && (
        <div className="msg-enter" style={{ color: "#ff4d4d", fontSize: "0.875rem", border: "1px solid rgba(255, 77, 77, 0.3)", padding: "0.75rem", borderRadius: "8px", background: "rgba(255, 0, 0, 0.1)" }}>
          {error}
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <label htmlFor="username" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", letterSpacing: "1px" }}>USERNAME</label>
        <input type="text" id="username" name="username" required autoComplete="username" disabled={status !== "idle"} />
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <label htmlFor="password" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", letterSpacing: "1px" }}>PASSPHRASE</label>
        <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
          <input type={showPassword ? "text" : "password"} id="password" name="password" required autoComplete="current-password" disabled={status !== "idle"} style={{ width: "100%", paddingRight: "40px" }} />
          <button type="button" onClick={() => setShowPassword(!showPassword)} style={{ position: "absolute", right: "8px", background: "transparent", border: "none", padding: "4px", color: "var(--text-secondary)", cursor: "pointer", display: "flex" }}>
            {showPassword ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22"></path></svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            )}
          </button>
        </div>
      </div>

      <button type="submit" disabled={status !== "idle"} style={{ marginTop: "1rem" }}>
        {status === "idle" && "VERIFY IDENTITY"}
        {status === "authenticating" && (
          <>
            <svg width="20" height="20" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" stroke="currentColor">
              <style>
                {`.spinner_V8m1{transform-origin:center;animation:spinner_zKoa 2s linear infinite}.spinner_V8m1 circle{stroke-linecap:round;animation:spinner_YpZS 1.5s ease-in-out infinite}@keyframes spinner_zKoa{100%{transform:rotate(360deg)}}@keyframes spinner_YpZS{0%{stroke-dasharray:0 150;stroke-dashoffset:0}47.5%{stroke-dasharray:42 150;stroke-dashoffset:-16}95%,100%{stroke-dasharray:42 150;stroke-dashoffset:-59}}`}
              </style>
              <g className="spinner_V8m1"><circle cx="12" cy="12" r="9.5" fill="none" strokeWidth="3"></circle></g>
            </svg>
            VERIFYING...
          </>
        )}
        {status === "success" && "SESSION ESTABLISHED"}
      </button>

      <p style={{ textAlign: "center", fontSize: "0.875rem", color: "var(--text-secondary)" }}>
        Unregistered node? <Link href="/register" style={{ color: "var(--accent-cyan)", textDecoration: "underline" }}>Initialize Here</Link>
      </p>
      <p className="mono-text" style={{ textAlign: "center", fontSize: "0.65rem", color: "rgba(255,255,255,0.2)" }}>SECURE-GEN v1.3</p>

    </form>
  );
}
