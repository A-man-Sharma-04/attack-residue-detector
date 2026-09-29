#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# bootstrap_target.sh - provision the monitored target host.
#
# Idempotent: safe to re-run. Installs the telemetry stack and web target that
# the project definition requires (Ubuntu 24.04+ , Wazuh dropped as over-scope).
#
# THIS SCRIPT IS THE REPLACEMENT FOR AD-HOC SETUP. The target must be
# reproducible from git, not from shell history.
#
# Usage:  sudo ./deploy/bootstrap_target.sh [--app-port 8081]
#
# Safety: touches only /var/www/college, /etc/nginx/sites-*, and
#         /etc/audit/rules.d/residue.rules. Never modifies /usr/bin/python3,
#         docker, or any pre-existing service.
# ---------------------------------------------------------------------------
set -euo pipefail

APP_PORT="${APP_PORT:-8081}"
WATCHED_RULES="/etc/audit/rules.d/residue.rules"

log() { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }

log "target host : $(hostname)"
log "os          : $(. /etc/os-release && echo "$PRETTY_NAME")"
log "python3     : $(python3 --version 2>&1 || echo 'absent')  (must stay as-is)"

# ---------------------------------------------------------------------------
log "1/5 installing packages: auditd, nginx, php-fpm"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq auditd nginx php-fpm

# ---------------------------------------------------------------------------
log "2/5 detecting the real php-fpm socket and starting it"
PHP_SOCK="$(sudo find /run/php -maxdepth 1 -name '*.sock' 2>/dev/null | head -1 || true)"
if [ -z "$PHP_SOCK" ]; then
    PHP_SOCK="$(sudo ls /run/php/*.sock 2>/dev/null | head -1 || true)"
fi
if [ -n "$PHP_SOCK" ]; then
    sudo systemctl enable "$(basename "$PHP_SOCK" .sock)-fpm" >/dev/null 2>&1 || true
    sudo systemctl start "$(basename "$PHP_SOCK" .sock)-fpm" >/dev/null 2>&1 || true
    log "php-fpm socket: $PHP_SOCK"
else
    warn "no php-fpm socket found - the demo app will be served as static text"
    PHP_SOCK=""
fi

# ---------------------------------------------------------------------------
log "3/5 writing the college portal vhost (loopback only, never public)"
sudo mkdir -p /var/www/college
sudo tee /etc/nginx/sites-available/college >/dev/null <<NGINX
# Demo target web application.
# Bound to LOOPBACK ON PURPOSE: the host is internet-reachable and a
# deliberately-compromised demo app must not be world-scannable.
# Demo traffic is local curl, so nothing is lost.
server {
    listen 127.0.0.1:${APP_PORT};
    server_name localhost;

    root /var/www/college;
    index index.php index.html;

    access_log /var/log/nginx/college.access.log;
    error_log  /var/log/nginx/college.error.log;

    location / {
        try_files \$uri \$uri/ =404;
    }
NGINX
if [ -n "$PHP_SOCK" ]; then
sudo tee -a /etc/nginx/sites-available/college >/dev/null <<NGINX

    location ~ \\.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${PHP_SOCK};
    }
NGINX
fi
sudo tee -a /etc/nginx/sites-available/college >/dev/null <<'NGINX'
}
NGINX

sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/college /etc/nginx/sites-enabled/college
sudo nginx -t
sudo systemctl enable nginx >/dev/null 2>&1 || true
sudo systemctl reload nginx
log "nginx listening on 127.0.0.1:${APP_PORT}"

# ---------------------------------------------------------------------------
log "4/5 installing audit rules (the evidence source)"
sudo tee "$WATCHED_RULES" >/dev/null <<'RULES'
## Attack Residue Detection - evidence rules
## Keys map 1:1 onto residue types in residue_system/residue/classifiers.py

# Identity -> new_user / permission_change
-w /etc/passwd -p wa -k identity_changes
-w /etc/group -p wa -k identity_changes
-w /etc/shadow -p wa -k authentication_changes
-w /etc/sudoers -p wa -k privilege_changes
-w /etc/sudoers.d/ -p wa -k privilege_changes

# SSH persistence -> new_ssh_key
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/ -p wa -k ssh_keys

# Service persistence -> new_service  (catches update-service.service)
-w /etc/systemd/system/ -p wa -k service_changes
-w /lib/systemd/system/ -p wa -k service_changes
-w /etc/init.d/ -p wa -k service_changes

# Web content -> file_modified / file_created  (catches index.php)
-w /var/www/ -p wa -k web_changes

# Staging area -> new_executable  (catches /opt/.cache/update)
-w /opt/ -p wa -k opt_changes

# Scheduled tasks -> new_scheduled_task
-w /etc/cron.d/ -p wa -k cron_changes
-w /etc/crontab -p wa -k cron_changes
-w /var/spool/cron/ -p wa -k cron_changes

# Tampering -> log_tampering
-w /var/log/ -p wa -k log_changes

# Process execution -> process_execution (needed for the attack-path stage)
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution
RULES

sudo systemctl enable auditd >/dev/null 2>&1 || true
sudo systemctl restart auditd 2>/dev/null || true
sleep 2
log "auditd active : $(systemctl is-active auditd)"
log "audit rules   : $(sudo auditctl -l 2>/dev/null | wc -l) active"
sudo auditctl -s 2>/dev/null | head -1

# ---------------------------------------------------------------------------
log "5/5 verifying pre-existing production services are untouched"
for svc in telegram-bot n8n-sandbox docker ssh; do
    if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1; then
        log "  ${svc}: active=$(systemctl is-active "$svc" 2>/dev/null || echo n/a) pid=$(systemctl show -p MainPID --value "$svc" 2>/dev/null)"
    fi
done

cat <<'DONE'

[bootstrap] target provisioned.

  web app   : http://127.0.0.1:PORT/index.php   (populated by deploy/seed_app.sh)
  audit log : /var/log/audit/audit.log
  web log   : /var/log/nginx/college.access.log

Next:  ./deploy/seed_app.sh    # clean app BEFORE baseline
       ./deploy/deploy.sh      # push code
       python3 residue_system/cli.py baseline create
DONE
