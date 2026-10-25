#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this helper as root (for example, with sudo)" >&2
    exit 1
fi

if [ ! -x /usr/sbin/setfmac ]; then
    echo "error: /usr/sbin/setfmac is not available" >&2
    exit 127
fi

# ==============================================================================
# Helper Function: Apply Label
# Usage: apply_label "label_name" "file_path"
# ==============================================================================
apply_label() {
    label_name="$1"
    file_path="$2"

    if [ -e "$file_path" ]; then
        echo "Setting casper/${label_name} on ${file_path}"
        /usr/sbin/setfmac "casper/${label_name}" "$file_path"
    else
        echo "Skipping ${file_path} (file not found)"
    fi
}

# ==============================================================================
# File Mapping Configuration
# Mirrored from: obj_file_map[] and cas_obj_label_map[]
# Format: apply_label  "STRING_NAME_FROM_MAP"  "FILE_PATH"
# ==============================================================================

# --- NSS Config ---
apply_label "nss_config"    "/etc/nsswitch.conf"

# --- DNS Service ---
apply_label "net_resolve"   "/etc/hosts"
apply_label "net_resolve"   "/etc/resolv.conf"

# --- NETDB Service (Services) ---
apply_label "net_services"  "/etc/services"

# --- GRP Service ---
apply_label "group_db"      "/etc/group"
apply_label "group_db"      "/var/db/cache/group.cache"

# --- NETDB Service (Protocols) ---
apply_label "net_protocols" "/etc/protocols"

# --- PWD Public Info ---
apply_label "pwd_public"    "/etc/pwd.db"
# Note: You might want to add /etc/passwd here if your module supports it
# apply_label "pwd_public"    "/etc/passwd"

# --- PWD Shadow (Sensitive!) ---
apply_label "pwd_shadow"    "/etc/spwd.db"
# Note: You might want to add /etc/master.passwd here
# apply_label "pwd_shadow"    "/etc/master.passwd"

# --- SYSLOG / Time ---
apply_label "sys_time"      "/etc/localtime"
apply_label "sys_log"       "/var/run/log"
apply_label "sys_log"       "/dev/console"
apply_label "sys_log"       "/var/run/logpriv"

echo "Done."
