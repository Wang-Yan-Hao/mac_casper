#!/bin/sh

# ==============================================================================
# Helper Function: Apply Label
# Usage: apply_label "label_name" "file_path"
# ==============================================================================
apply_label() {
    LABEL_NAME="$1"
    FILE_PATH="$2"

    if [ -e "$FILE_PATH" ]; then
        echo "Setting casper/${LABEL_NAME} on ${FILE_PATH}"
        /usr/sbin/setfmac "casper/${LABEL_NAME}" "$FILE_PATH"
    else
        echo "Skipping ${FILE_PATH} (File not found)"
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

echo "Done."
