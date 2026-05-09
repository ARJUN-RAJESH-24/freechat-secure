# Resilience Demonstration

This section shows how the **main application** (the one you built) is protected against the attacks that worked in the lab.

## 1. Login Bypass Resilience
Try the same bypass payload on the real authentication endpoint.

**Target**: `/api/auth/callback/credentials` (NextAuth)
**Payload**: `' OR '1'='1`

```bash
curl -X POST http://localhost:3000/api/auth/callback/credentials \
-H "Content-Type: application/json" \
-d '{"username": "admin", "password": "'\'' OR '\''1'\''='\''1", "csrfToken": "dummy"}'
```

**Why it fails**:
- **Zod Validation**: The application uses Zod to validate input. A payload with special characters like `'` or `=` would be rejected by the validation schema before it even hits the database.
- **Parameterized Queries**: Even if it passed validation, NextAuth and Prisma use prepared statements. The database treats the injection string as a literal piece of text to search for, not as a command.

## 2. UNION Injection Resilience
Try to leak data through the registration or chat endpoints.

**Target**: `/api/register`
**Payload**: `' UNION SELECT ...`

```bash
curl -X POST http://localhost:3000/api/register \
-H "Content-Type: application/json" \
-d '{"username": "'\'' UNION SELECT NULL,NULL,NULL,NULL--", "password": "password123456", "publicKey": "dummy-key-long-enough", "encryptedPrivateKey": "dummy-key-long-enough"}'
```

**Why it fails**:
- **Strict Schema**: The `registerSchema` enforces a minimum and maximum length.
- **ORM Protection**: Prisma's `findUnique` method explicitly maps the `username` field to a single parameter. It is impossible to "break out" of the query to add a `UNION` statement.

## 3. Blind SQL Injection Resilience
Try to use time-based or boolean-based probes on user-facing endpoints.

**Why it fails**:
- **Error Masking**: The application returns generic error messages instead of raw database errors.
- **Input Sanitization**: All inputs are strictly typed as strings by Prisma, preventing the execution of sub-queries inside the `WHERE` clause.
