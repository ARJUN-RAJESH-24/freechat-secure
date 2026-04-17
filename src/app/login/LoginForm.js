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
    <form onSubmit={handleSubmit} className="glass-panel" style={{ padding: "3rem", width: "100%", maxWidth: "450px", display: "flex", flexDirection: "column", gap: "1.5rem" }}>

      <h2 className="animate-brand" style={{ textAlign: "center", fontSize: "3rem", color: "#ffffff", fontWeight: "900", letterSpacing: "2px", margin: "0" }}>FREECHAT</h2>
      <p style={{ textAlign: "center", fontSize: "0.875rem", color: "var(--accent-cyan)", marginTop: "-1rem", letterSpacing: "4px" }}>SECURE LOGIN</p>

      {registered && (
        <div style={{ color: "#00e5ff", fontSize: "0.875rem", border: "1px solid rgba(0, 229, 255, 0.3)", padding: "0.75rem", borderRadius: "4px", background: "rgba(0, 229, 255, 0.1)" }}>
          Identity initialized successfully. You may now authenticate.
        </div>
      )}

      {status === "success" && (
        <div style={{ color: "#00e5ff", fontSize: "0.875rem", border: "1px solid rgba(0, 229, 255, 0.3)", padding: "0.75rem", borderRadius: "4px", background: "rgba(0, 229, 255, 0.1)" }}>
          Authentication verified. Establishing encrypted session...
        </div>
      )}

      {error && (
        <div style={{ color: "#ff4d4d", fontSize: "0.875rem", border: "1px solid rgba(255, 77, 77, 0.3)", padding: "0.75rem", borderRadius: "4px", background: "rgba(255, 0, 0, 0.1)" }}>
          {error}
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <label htmlFor="username" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", letterSpacing: "1px" }}>USERNAME</label>
        <input type="text" id="username" name="username" required autoComplete="username" disabled={status !== "idle"} />
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <label htmlFor="password" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", letterSpacing: "1px" }}>PASSPHRASE</label>
        <input type="password" id="password" name="password" required autoComplete="current-password" disabled={status !== "idle"} />
      </div>

      <button type="submit" disabled={status !== "idle"} style={{ marginTop: "1rem", opacity: status !== "idle" ? 0.5 : 1 }}>
        {status === "idle" && "VERIFY IDENTITY"}
        {status === "authenticating" && "VERIFYING CREDENTIALS..."}
        {status === "success" && "SESSION ESTABLISHED"}
      </button>

      <p style={{ textAlign: "center", fontSize: "0.875rem", color: "var(--text-secondary)" }}>
        Unregistered node? <Link href="/register" style={{ color: "var(--accent-cyan)" }}>Initialize Here</Link>
      </p>
      <p style={{ textAlign: "center", fontSize: "0.65rem", color: "rgba(255,255,255,0.2)" }}>SECURE-GEN v1.3</p>

    </form>
  );
}
