// Server Component wrapper — force-dynamic prevents stale Server Action IDs
// being baked into static HTML at build time.
export const dynamic = 'force-dynamic';

import { Suspense } from "react";
import LoginForm from "./LoginForm";

export default function LoginPage() {
  return (
    <main style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem" }}>
      <Suspense fallback={<div className="glass-panel" style={{ padding: "2rem" }}>Initializing Protocol...</div>}>
        <LoginForm />
      </Suspense>
    </main>
  );
}
