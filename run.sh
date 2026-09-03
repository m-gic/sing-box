#!/bin/bash

export CLOUDFLARE_TUNNEL_TOKEN="${1:-your cloudflare tunnel token}"
export CLOUDFLARE_TUNNEL_HOSTNAME="${2:-your cloudflare tunnel hostname}"
export UUID="${3:-your uuid}"
export FILE_PATH="${4:-.}"
export CLOUDFLARE_IP="${5:-chinese.com}"

# Auto-detect architecture: one-liner
export ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')

# Create working directory
mkdir -p "$FILE_PATH"
cd "$FILE_PATH"

# Port config (override via env, unset to skip protocol)
export VLESS_PORT="${VLESS_PORT:-}"
export VMESS_PORT="${VMESS_PORT:-}"
export SS_PORT="${SS_PORT:-}"
export TROJAN_PORT="${TROJAN_PORT:-}"
export HYSTERIA2_PORT="${HYSTERIA2_PORT:-}"
export WG_PORT="${WG_PORT:-}"
export S5_PORT="${S5_PORT:-}"
export HTTP_PORT="${HTTP_PORT:-}"
export TUIC_PORT="${TUIC_PORT:-}"

curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}" -o ./cloudflared
chmod +x cloudflared
./cloudflared --version
nohup ./cloudflared --no-autoupdate tunnel run --token "$CLOUDFLARE_TUNNEL_TOKEN" > cloudflared.log 2>&1 &

export SB_VERSION=$(curl -sI https://github.com/SagerNet/sing-box/releases/latest | grep -i location | sed 's|.*/tag/v||;s/[^0-9.].*//')
export SB_DIR="sing-box-${SB_VERSION}-linux-${ARCH}"
curl -O -L "https://github.com/SagerNet/sing-box/releases/download/v${SB_VERSION}/${SB_DIR}.tar.gz"
tar -zxf "${SB_DIR}.tar.gz"

"${SB_DIR}/sing-box" version

export WG_PRIVKEY=$(wg genkey 2>/dev/null || echo 'REPLACE_WITH_WG_PRIVKEY')
export WG_PUBKEY=$(echo "$WG_PRIVKEY" | wg pubkey 2>/dev/null || echo 'REPLACE_WITH_WG_PUBKEY')

# Build inbounds array: only add protocols with configured ports
INBOUNDS="["
[[ -n "$VLESS_PORT" ]] && INBOUNDS+='{"type":"vless","tag":"vless-in","listen":"::","listen_port":'$VLESS_PORT',"users":[{"name":"user","uuid":"'$UUID'","flow":""}],"transport":{"type":"ws","path":"/misaka","headers":{},"max_early_data":0,"early_data_header_name":""},"multiplex":{"enabled":true,"padding":false}},'
[[ -n "$VMESS_PORT" ]] && INBOUNDS+='{"type":"vmess","tag":"vmess-in","listen":"::","listen_port":'$VMESS_PORT',"users":[{"name":"user","uuid":"'$UUID'","alterId":0}],"transport":{"type":"ws","path":"/vmess","headers":{},"max_early_data":0,"early_data_header_name":""},"multiplex":{"enabled":true,"padding":false}},'
[[ -n "$SS_PORT" ]] && INBOUNDS+='{"type":"shadowsocks","tag":"ss-in","listen":"::","listen_port":'$SS_PORT',"method":"aes-256-gcm","password":"'$UUID'","multiplex":{"enabled":true,"padding":false}},'
[[ -n "$TROJAN_PORT" ]] && INBOUNDS+='{"type":"trojan","tag":"trojan-in","listen":"::","listen_port":'$TROJAN_PORT',"users":[{"name":"user","password":"'$UUID'"}],"transport":{"type":"ws","path":"/trojan","headers":{},"max_early_data":0,"early_data_header_name":""},"multiplex":{"enabled":true,"padding":false}},'
[[ -n "$HYSTERIA2_PORT" ]] && INBOUNDS+='{"type":"hysteria2","tag":"hysteria2-in","listen":"::","listen_port":'$HYSTERIA2_PORT',"users":[{"name":"user","password":"'$UUID'"}],"tls":{"enabled":true,"server_name":"'$CLOUDFLARE_TUNNEL_HOSTNAME'","acme":{"domain":"'$CLOUDFLARE_TUNNEL_HOSTNAME'","email":"admin@example.com"}}},'
[[ -n "$WG_PORT" ]] && INBOUNDS+='{"type":"wireguard","tag":"wg-in","listen":"::","listen_port":'$WG_PORT',"private_key":"'$WG_PRIVKEY'","peers":[{"public_key":"'$WG_PUBKEY'","allowed_ips":["0.0.0.0/0","::/0"]}],"interface_name":"wg0","address":["10.0.0.1/24"]},'
[[ -n "$S5_PORT" ]] && INBOUNDS+='{"type":"socks","tag":"socks-in","listen":"::","listen_port":'$S5_PORT',"users":[{"username":"user","password":"'$UUID'"}]},'
[[ -n "$HTTP_PORT" ]] && INBOUNDS+='{"type":"http","tag":"http-in","listen":"::","listen_port":'$HTTP_PORT',"users":[{"username":"user","password":"'$UUID'"}]},'
[[ -n "$TUIC_PORT" ]] && INBOUNDS+='{"type":"tuic","tag":"tuic-in","listen":"::","listen_port":'$TUIC_PORT',"users":[{"name":"user","uuid":"'$UUID'","password":"'$UUID'"}],"congestion_control":"bbr","tls":{"enabled":true,"server_name":"'$CLOUDFLARE_TUNNEL_HOSTNAME'","acme":{"domain":"'$CLOUDFLARE_TUNNEL_HOSTNAME'","email":"admin@example.com"}}},'
INBOUNDS=${INBOUNDS%,}"]" # Remove trailing comma

cat <<EOF > "${SB_DIR}/config.json"
{"log":{"disabled":false,"level":"info","timestamp":true},"dns":{"servers":[{"tag":"cloudflare","address":"https://1.1.1.1/dns-query","strategy":"ipv4_only","detour":"direct"},{"tag":"block","address":"rcode://success"}],"rules":[{"rule_set":["geosite-cn","geosite-category-ads-all"],"server":"block"}],"final":"cloudflare","strategy":"","disable_cache":false,"disable_expire":false},"inbounds":$INBOUNDS,"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"},{"type":"dns","tag":"dns-out"}],"route":{"rules":[{"protocol":"dns","outbound":"dns-out"},{"ip_is_private":true,"outbound":"direct"},{"rule_set":["geoip-cn","geosite-cn","geosite-category-ads-all"],"outbound":"block"}],"rule_set":[{"tag":"geoip-cn","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs","download_detour":"direct"},{"tag":"geosite-cn","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs","download_detour":"direct"},{"tag":"geosite-category-ads-all","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs","download_detour":"direct"}],"auto_detect_interface":true,"final":"direct"},"experimental":{"cache_file":{"enabled":true,"path":"cache.db","cache_id":"mycacheid","store_fakeip":true}}}
EOF

[[ -n "$VLESS_PORT" ]] && echo "vless://$UUID@$CLOUDFLARE_IP:443?encryption=none&flow=none&security=tls&sni=$CLOUDFLARE_TUNNEL_HOSTNAME&alpn=h2%2Chttp%2F1.1&fp=chrome&type=ws&host=$CLOUDFLARE_TUNNEL_HOSTNAME&path=%2Fmisaka#vless"
[[ -n "$VMESS_PORT" ]] && echo "vmess://$(echo -n "{\"v\":\"2\",\"ps\":\"vmess\",\"add\":\"$CLOUDFLARE_IP\",\"port\":\"443\",\"id\":\"$UUID\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"$CLOUDFLARE_TUNNEL_HOSTNAME\"}" | base64 -w0)"
[[ -n "$SS_PORT" ]] && echo "ss://$(echo -n "aes-256-gcm:$UUID@$CLOUDFLARE_IP:$SS_PORT" | base64 -w0)#shadowsocks"
[[ -n "$TROJAN_PORT" ]] && echo "trojan://$UUID@$CLOUDFLARE_IP:443?security=tls&sni=$CLOUDFLARE_TUNNEL_HOSTNAME&type=ws&host=$CLOUDFLARE_TUNNEL_HOSTNAME&path=%2Ftrojan#trojan"
[[ -n "$HYSTERIA2_PORT" ]] && echo "hy2://$UUID@$CLOUDFLARE_IP:$HYSTERIA2_PORT?sni=$CLOUDFLARE_TUNNEL_HOSTNAME#hysteria2"
[[ -n "$WG_PORT" ]] && echo "wireguard privkey=$WG_PRIVKEY pubkey=$WG_PUBKEY endpoint=$CLOUDFLARE_IP:$WG_PORT"
[[ -n "$S5_PORT" ]] && echo "socks5://user:$UUID@$CLOUDFLARE_IP:$S5_PORT#socks5"
[[ -n "$HTTP_PORT" ]] && echo "http://user:$UUID@$CLOUDFLARE_IP:$HTTP_PORT#http"
[[ -n "$TUIC_PORT" ]] && echo "tuic://$UUID:$UUID@$CLOUDFLARE_IP:$TUIC_PORT?sni=$CLOUDFLARE_TUNNEL_HOSTNAME#tuic"
"${SB_DIR}/sing-box" run -c "${SB_DIR}/config.json"
