// Server Component wrapper — force-dynamic ensures Next.js NEVER statically renders
// this page. Without this, action IDs baked into the HTML become stale after redeploy
// causing: "Server Action was not found on the server".
export const dynamic = 'force-dynamic';

import RegisterForm from "./RegisterForm";

export default function RegisterPage() {
  return (
    <main style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem" }}>
      <RegisterForm />
    </main>
  );
}
