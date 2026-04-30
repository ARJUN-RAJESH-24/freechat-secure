#!/bin/bash
# =============================================================================
# FreeChat MySQL/MariaDB Setup Script
# Run with: sudo bash scripts/setup-db.sh
# =============================================================================

set -e

echo "╔══════════════════════════════════════════════════╗"
echo "║      FreeChat Database Setup (MariaDB)           ║"
echo "╚══════════════════════════════════════════════════╝"

# Start MariaDB if not running
echo "[1/4] Ensuring MariaDB is running..."
systemctl start mariadb 2>/dev/null || echo "MariaDB already running"
systemctl enable mariadb 2>/dev/null || true

# Create database and user
echo "[2/4] Creating database 'freechat_db'..."
mariadb -u root -e "
  CREATE DATABASE IF NOT EXISTS freechat_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;
"

echo "[3/4] Creating user 'freechat'@'localhost'..."
mariadb -u root -e "
  CREATE USER IF NOT EXISTS 'freechat'@'localhost' IDENTIFIED BY 'FreeChat2026!';
  GRANT ALL PRIVILEGES ON freechat_db.* TO 'freechat'@'localhost';
  FLUSH PRIVILEGES;
"

echo "[4/4] Verifying connection..."
mariadb -u freechat -p'FreeChat2026!' freechat_db -e "SELECT 'Connection successful!' AS status;"

echo ""
echo "✅ Database setup complete!"
echo ""
echo "Connection string for .env:"
echo "  DATABASE_URL=\"mysql://freechat:FreeChat2026!@localhost:3306/freechat_db\""
echo ""
