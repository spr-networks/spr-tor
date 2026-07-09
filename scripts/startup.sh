#!/bin/bash
set -a
. /configs/base/config.sh
if [ -f /configs/spr-tor/config.sh ]; then
    . /configs/spr-tor/config.sh
fi
set +a

# Tor drops privileges to debian-tor (torrc `User`); its data dir must be
# owned by that user and kept private. The control socket + auth cookie live
# in /run/tor (container-local tmpfs-ish path, never on a host mount).
mkdir -p /state/plugins/spr-tor/tor /run/tor
chown -R debian-tor:debian-tor /state/plugins/spr-tor/tor /run/tor
chmod 700 /state/plugins/spr-tor/tor /run/tor

# The plugin binary generates torrc from the validated config and
# supervises the tor daemon as a child process.
exec /tor_plugin
