#!/bin/bash
# Force the Chromium setuid sandbox helper into the correct state.
#
# electron-builder's default install script tests user namespaces while
# running as root. On Ubuntu 23.10+/24.04 that test always succeeds (root is
# exempt from the AppArmor userns restriction), so it leaves chrome-sandbox
# non-setuid — and then the app aborts for unprivileged users at launch.
# The setuid helper is the canonical Chromium setup (same as the distro
# chromium package), so set it unconditionally.
set -e

HELPER=/opt/SysGuard/chrome-sandbox
if [ -f "$HELPER" ]; then
  chown root:root "$HELPER" 2>/dev/null || true
  chmod 4755 "$HELPER" 2>/dev/null || true
fi

exit 0
