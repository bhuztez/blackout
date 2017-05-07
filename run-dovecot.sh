#!/usr/bin/env bash

mkdir -p "$2"

cat > "$2/dovecot.conf" << EOF
base_dir="$2/dovecot"
default_internal_user=$(whoami)
default_login_user=$(whoami)
protocols = pop3 lmtp
log_path = $2/log
info_log_path = $2/info
debug_log_path = $2/debug

mail_location = maildir:~
ssl = no
disable_plaintext_auth = no
userdb {
  driver = static
  args = uid=$(whoami) gid=$(whoami) home=$2/users/%n
}

passdb {
  driver = static
  args = password=secret
}

service anvil {
  chroot =
}

service pop3-login {
  chroot =

  inet_listener pop3 {
    address = *
    port = "$1"
  }
}
EOF

dovecot -F -c "$2/dovecot.conf"
