import Link from "next/link";

export default function Home() {
  return (
    <main style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem" }}>
      <div className="glass-panel" style={{ padding: "4rem 3rem", width: "100%", maxWidth: "600px", textAlign: "center" }}>
        
        <h1 className="animate-brand" style={{ marginBottom: "1.5rem", fontSize: "4rem", letterSpacing: "4px", color: "#ffffff", fontWeight: "900", textTransform: "uppercase" }}>
          FREECHAT
        </h1>
        
        <p style={{ color: "var(--text-secondary)", marginBottom: "3.5rem", lineHeight: "1.6", fontSize: "1.1rem" }}>
          End-to-End Encrypted Real-Time Architecture. Protocol initialized.
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "1rem", alignItems: "center" }}>
          <p style={{ fontSize: "0.875rem", textTransform: "uppercase", letterSpacing: "2px", color: "var(--accent-cyan)" }}>
            Awaiting Authentication
          </p>
          <div style={{ display: "flex", gap: "1.5rem", marginTop: "1.5rem", width: "100%", justifyContent: "center" }}>
            <Link href="/login" style={{ flex: "1", maxWidth: "200px" }}>
              <button style={{ width: "100%", padding: "1rem" }}>AUTHENTICATE</button>
            </Link>
            <Link href="/register" style={{ flex: "1", maxWidth: "200px" }}>
              <button style={{ width: "100%", padding: "1rem", background: "rgba(0, 229, 255, 0.15)" }}>INITIALIZE NODE</button>
            </Link>
          </div>
        </div>
        
      </div>
    </main>
  );
}
