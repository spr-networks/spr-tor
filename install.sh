#!/bin/bash
# Command line install alternative to the UI
echo "Please enter your SPR path (/home/spr/super/)"
read -r SUPERDIR

if [ -z "$SUPERDIR" ]; then
    SUPERDIR="/home/spr/super/"
fi

export SUPERDIR

echo "Please enter your SPR API token:"
read -r SPR_API_TOKEN

if [ -z "$SPR_API_TOKEN" ]; then
  echo "need api token, generate one on the auth keys page"
  exit 1
fi

mkdir -p "$SUPERDIR/configs/plugins/spr-tor"

# the backend does not call the SPR API in the MVP; the token is only used
# below to register the plugin's bridge interface with the SPR firewall.
printf '%s' "$SPR_API_TOKEN" > "$SUPERDIR/configs/plugins/spr-tor/api-token"
chmod 600 "$SUPERDIR/configs/plugins/spr-tor/api-token"

# default config: SOCKS only, no TransPort/DNSPort, no bridges
if [ ! -f "$SUPERDIR/configs/plugins/spr-tor/config.json" ]; then
  echo '{}' > "$SUPERDIR/configs/plugins/spr-tor/config.json"
  chmod 600 "$SUPERDIR/configs/plugins/spr-tor/config.json"
fi

docker compose build
docker compose up -d
CONTAINER_IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "spr-tor")
API=127.0.0.1

# outbound-only tor client: wan for reaching the tor network, dns for
# hostname-based bridges/PTs. Devices in the `tor` group may reach the
# container's SocksPort (and TransPort/DNSPort when enabled).
curl "http://${API}/firewall/custom_interface" \
-H "Authorization: Bearer ${SPR_API_TOKEN}" \
-X 'PUT' \
--data-raw "{\"SrcIP\":\"${CONTAINER_IP}\",\"Interface\":\"spr-tor\",\"Policies\":[\"wan\",\"dns\"],\"Groups\":[\"tor\"]}"

docker compose restart
