#!/usr/bin/env bash

set -euo pipefail

AUTH_LOG="${1:-/var/log/auth.log}"
WEB_LOG="${2:-/var/log/nginx/access.log}"

echo "Appending safe demo events..."
echo "Auth log target: $AUTH_LOG"
echo "Web log target: $WEB_LOG"
echo "Run this after clicking 'Start Monitoring' in the dashboard."

if [ -w "$AUTH_LOG" ]; then
  echo "Apr 03 17:00:00 ids-host sshd[2201]: Failed password for invalid user admin from 198.51.100.24 port 44322 ssh2" | sudo tee -a "$AUTH_LOG" >/dev/null
  echo "Apr 03 17:00:20 ids-host sshd[2202]: Failed password for invalid user admin from 198.51.100.24 port 44323 ssh2" | sudo tee -a "$AUTH_LOG" >/dev/null
  echo "Apr 03 17:00:40 ids-host sshd[2203]: Failed password for invalid user admin from 198.51.100.24 port 44324 ssh2" | sudo tee -a "$AUTH_LOG" >/dev/null
  echo "Apr 03 17:01:00 ids-host sshd[2204]: Failed password for invalid user admin from 198.51.100.24 port 44325 ssh2" | sudo tee -a "$AUTH_LOG" >/dev/null
  echo "Apr 03 17:01:10 ids-host sshd[2205]: Failed password for invalid user admin from 198.51.100.24 port 44326 ssh2" | sudo tee -a "$AUTH_LOG" >/dev/null
  echo "Apr 03 17:01:40 ids-host sshd[2206]: Accepted password for user admin from 198.51.100.24 port 44328 ssh2" | sudo tee -a "$AUTH_LOG" >/dev/null
else
  echo "Skipping auth log writes because the file is not writable: $AUTH_LOG"
fi

if [ -w "$WEB_LOG" ]; then
  echo '203.0.113.50 - - [03/Apr/2026:17:02:10 +0000] "GET /product?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 612 "-" "Mozilla/5.0"' | sudo tee -a "$WEB_LOG" >/dev/null
  echo '203.0.113.50 - - [03/Apr/2026:17:02:15 +0000] "GET /admin HTTP/1.1" 403 221 "-" "Mozilla/5.0"' | sudo tee -a "$WEB_LOG" >/dev/null
  echo '203.0.113.50 - - [03/Apr/2026:17:03:00 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 403 221 "-" "Mozilla/5.0"' | sudo tee -a "$WEB_LOG" >/dev/null
else
  echo "Skipping web log writes because the file is not writable: $WEB_LOG"
fi

echo "Demo events appended. Check the dashboard alerts and timeline."
