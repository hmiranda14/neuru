<?php
// NetMon server-specific paths — filled in by install.sh

define('VENV_PYTHON',  '__VENV_PYTHON__');   // e.g. /opt/netmon-venv/bin/python3
define('SCRIPTS_DIR',  '__SCRIPTS_DIR__');   // e.g. /var/www/html/netmon/scripts
define('LOG_DIR',      '__LOG_DIR__');        // e.g. /var/www/html/netmon/logs
define('APP_ROOT',     '__APP_ROOT__');       // e.g. /var/www/html/netmon

// n8n integration (set via Configuration tab or edit here)
define('N8N_BASE_URL', '__N8N_BASE_URL__');  // e.g. http://n8n:5678
define('N8N_API_KEY',  '__N8N_API_KEY__');   // shared secret header value
