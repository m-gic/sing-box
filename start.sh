#!/bin/bash

# ========== 用户配置 ==========
NAME=${NAME:-''}
UUID=${UUID:-$(cat /proc/sys/kernel/random/uuid)}
CLOUDFLARE_TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN:-''}
CLOUDFLARE_IP=${CLOUDFLARE_IP:-''}
PORT=${PORT:-''}
# 各协议的 *_MODE 支持逗号分隔多个模式：ws / cloudflare / try / 端口 / 回落协议名，例如 VLESS_MODE="ws,8443"
VLESS_MODE=${VLESS_MODE:-''}
VMESS_MODE=${VMESS_MODE:-''}
TROJAN_MODE=${TROJAN_MODE:-''}
SHADOWSOCKS_MODE=${SHADOWSOCKS_MODE:-''}
HYSTERIA2_MODE=${HYSTERIA2_MODE:-''}
MIXED_MODE=${MIXED_MODE:-''}
WIREGUARD_MODE=${WIREGUARD_MODE:-''}
CERT_HOST=${CERT_HOST:-''}
KOMARI_ENDPOINT=${KOMARI_ENDPOINT:-''}
KOMARI_TOKEN=${KOMARI_TOKEN:-''}

# 把当前 UUID 写回脚本本身：下次运行直接沿用
sed -i "s|^UUID=.*|UUID=\${UUID:-'$UUID'}|" "${BASH_SOURCE[0]}"

# ========== 基础环境 ==========
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$BASE_DIR" || exit 1
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 XARCH=64 ;;
  aarch64|arm64) ARCH=arm64 XARCH=arm64-v8a ;;
  *) echo "[ARCH] Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

# ========== 通用函数 ==========
b64() { base64 | tr -d '\n'; }
b64url() { b64 | tr '+/' '-_' | tr -d '='; }
b64url_dec() { local input; input=$(tr '_-' '/+'); case $(( ${#input} % 4 )) in 2) input+="==" ;; 3) input+="=" ;; esac; printf '%s' "$input" | base64 -d; }
mode_error() { echo "[MODE] $*" >&2; exit 1; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
in_array() { local needle="$1" item; shift; for item in "$@"; do [[ "$item" == "$needle" ]] && return 0; done; return 1; }
urlencode() {   # 按字节编码，中文、空格、引号都安全
  local LC_ALL=C text="$1" index char encoded=""
  for (( index = 0; index < ${#text}; index++ )); do
    char="${text:index:1}"
    case "$char" in [a-zA-Z0-9.~_-]) encoded+="$char" ;; *) printf -v char '%%%02X' "'$char"; encoded+="$char" ;; esac
  done
  printf '%s' "$encoded"
}
json_escape() { local text="$1"; text="${text//\\/\\\\}"; text="${text//\"/\\\"}"; text="${text//$'\n'/\\n}"; text="${text//$'\r'/\\r}"; printf '%s' "${text//$'\t'/\\t}"; }
dl() {   # dl <输出文件> <URL>：先写 .part 再改名
  curl -fsSL --retry 3 --connect-timeout 10 -o "$1.part" "$2" && mv -f "$1.part" "$1" && return 0
  rm -f "$1.part"; echo "[DL] Download failed: $2" >&2; return 1
}
# x25519_pub <私钥 base64>：固定 PKCS8 DER 头 + 原始私钥，交给 openssl 推导公钥(标准 base64)
x25519_pub() {
  { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'; printf '%s' "$1" | b64url_dec; } \
    | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | tail -c 32 | b64
}
gen_key() { [[ -s "$1" ]] || ( umask 077; openssl rand 32 | "$2" > "$1" ); }   # 首次生成并落盘复用

NAME_ENC=$(urlencode "$NAME")

# ========== 协议与模式 ==========
PROTOS=(vless vmess trojan shadowsocks)
# 内部入口全用抽象 unix socket(@名字)；Shadowsocks 入站不支持 unix socket，链内用 127.0.0.1:40004，ws 入口用 127.0.0.1:40014
declare -A WS_PATH=([vless]=/$UUID-vless [vmess]=/$UUID-vmess [trojan]=/$UUID-trojan [shadowsocks]=/$UUID-ss)
SS_IPORT=40004; WSPORT_SS=40014
ws_sock() { echo "@$UUID-ws-$1"; }
chain_dest() { if [[ "$1" == shadowsocks ]]; then echo "$SS_IPORT"; else echo "\"@$UUID-in-$1\""; fi; }
# NPORT 协议->端口  FB 协议->回落到的协议  PARENT 反向回落  SMODE 协议->ws 类模式  RMODE Reality 角色
# CHAIN 链头->整条链  HPORT 链头->端口  RPORT 链上协议->对外端口
declare -A NPORT FB PARENT SMODE RMODE CHAIN HPORT RPORT
ENABLED=() SHARED=() HEADS=()
ACTIVE_MODE="" TRY_TUNNEL="" FRONT_ON="" SHARE_FRONT=""
DEFAULT_FRONT_PORT=8000

# 回落网站：PORT 和 CERT_HOST 都填了才启用
WEB_DEST=""
if [[ -n "$PORT" && -n "$CERT_HOST" ]]; then
  WEB_DEST="$CERT_HOST:80"
  [[ "$WEB_DEST" =~ ^[A-Za-z0-9.-]+:[0-9]{1,5}$ ]] || mode_error "CERT_HOST='$CERT_HOST' is invalid (expected a domain or an IPv4 address)"
  echo "[WEB] Non-ws requests on the front port fall back to $WEB_DEST"
elif [[ -n "$PORT" ]]; then
  echo "[WEB] PORT is set but CERT_HOST is empty, fallback disabled (PORT only changes the listening port)" >&2
fi

# Hysteria2(UDP) / Mixed(TCP，账号密码都是 UUID) / WireGuard(UDP)：只接受数字端口，不参与回落链
WG_CLIENT_ADDR="10.0.0.2/32"
for spec in HYSTERIA2:HY2_PORT:udp MIXED:MIXED_PORT:tcp WIREGUARD:WG_PORT:udp; do
  IFS=: read -r prefix port_variable network <<< "$spec"; mode_variable="${prefix}_MODE"
  [[ -n "${!mode_variable}" ]] || continue
  valid_port "${!mode_variable}" || mode_error "$mode_variable='${!mode_variable}' is invalid (expected a port number 1-65535, or empty to disable)"
  printf -v "$port_variable" %s $((10#${!mode_variable})); echo "[MODE] port ${!port_variable}/$network: ${prefix,,}"
done

parse_modes() {
  local proto mode_variable mode_value token tokens
  for proto in "${PROTOS[@]}"; do
    mode_variable="${proto^^}_MODE"; mode_value="${!mode_variable}"
    [[ -n "$mode_value" ]] || continue
    IFS=',' read -ra tokens <<< "${mode_value// /}"
    for token in "${tokens[@]}"; do
      [[ -n "$token" ]] || continue
      if [[ "$token" == ws || "$token" == cloudflare || "$token" == try ]]; then
        [[ -z "${SMODE[$proto]}" ]] || mode_error "$mode_variable='$mode_value': only one of ws / cloudflare / try is allowed per protocol"
        [[ -z "$ACTIVE_MODE" || "$ACTIVE_MODE" == "$token" ]] || mode_error "ws / cloudflare / try share one port (PORT), so they must use the same mode (got: $ACTIVE_MODE $token)"
        SHARED+=("$proto"); ACTIVE_MODE="$token"; SMODE[$proto]="$token"; continue
      fi
      [[ -z "${RMODE[$proto]}" ]] || mode_error "$mode_variable='$mode_value': only one Reality role (a port or a fallback protocol) is allowed per protocol"
      if [[ "$token" =~ ^[0-9]+$ ]]; then
        valid_port "$token" || mode_error "$mode_variable='$mode_value': port must be 1-65535"
        NPORT[$proto]=$((10#$token))
      elif [[ "$token" =~ ^[a-z]+$ ]]; then
        in_array "$token" "${PROTOS[@]}" || mode_error "$mode_variable='$mode_value': '$token' is not valid (expected ws / cloudflare / try / a port, or a fallback protocol: ${PROTOS[*]})"
        [[ "$token" != "$proto" ]] || mode_error "$mode_variable='$mode_value': a protocol cannot fall back to itself"
        [[ "$proto" == vless || "$proto" == trojan ]] || mode_error "$mode_variable='$mode_value': only VLESS and TROJAN can choose a fallback"
        FB[$proto]="$token"
      else
        mode_error "$mode_variable='$mode_value' is invalid (comma-separated list of: ws / cloudflare / try / a port / a protocol name)"
      fi
      RMODE[$proto]="$token"
    done
  done
  # try = 不用 Token 的 Cloudflare 临时隧道，其余与 cloudflare 相同
  [[ "$ACTIVE_MODE" == try ]] && { ACTIVE_MODE=cloudflare; TRY_TUNNEL=1; }
}

# 把回落关系整理成 Reality 链：得到 ENABLED / HEADS / CHAIN / HPORT / RPORT
build_chains() {
  local proto target head chain_tail
  for proto in "${!FB[@]}"; do
    target="${FB[$proto]}"
    [[ -z "${PARENT[$target]}" ]] || mode_error "${target^^} is the fallback of both ${PARENT[$target]^^} and ${proto^^}, it can only have one"
    PARENT[$target]="$proto"
  done
  for proto in "${PROTOS[@]}"; do
    [[ -n "${SMODE[$proto]}${RMODE[$proto]}${PARENT[$proto]}" ]] && ENABLED+=("$proto")
    [[ -n "${RMODE[$proto]}" && -z "${PARENT[$proto]}" ]] && HEADS+=("$proto")
  done
  for head in "${HEADS[@]}"; do
    chain_tail="$head"; CHAIN[$head]="$head"
    while [[ -n "${FB[$chain_tail]}" ]]; do chain_tail="${FB[$chain_tail]}"; CHAIN[$head]+=" $chain_tail"; done
    [[ -n "${NPORT[$chain_tail]}" ]] || mode_error "The chain from ${head^^} ends at ${chain_tail^^}, which needs a port: set ${chain_tail^^}_MODE to a port number"
    HPORT[$head]="${NPORT[$chain_tail]}"
    for proto in ${CHAIN[$head]}; do RPORT[$proto]="${HPORT[$head]}"; done
  done
  XRAY_ON=""   # 没有启用任何协议时不报错：只跑 Komari 探针
  [[ ${#ENABLED[@]} -gt 0 || -n "$HY2_PORT$MIXED_PORT$WG_PORT" ]] && XRAY_ON=1
  for proto in "${ENABLED[@]}"; do
    [[ -n "${RMODE[$proto]}${PARENT[$proto]}" && -z "${RPORT[$proto]}" ]] && mode_error "${proto^^} is part of a fallback loop: the chain needs a head that no protocol falls back to"
  done
}

# 前置入口：是否需要、监听哪个端口、是否与某条 Reality 链共用
plan_front() {
  local proto
  [[ -n "$ACTIVE_MODE$WEB_DEST" ]] || return 0
  FRONT_ON=1
  # cloudflare 先用 8000(之后从 cloudflared 日志读到回源端口再覆盖)；其它用 PORT，留空 8000
  if [[ "$ACTIVE_MODE" == cloudflare ]]; then FRONT_PORT="$DEFAULT_FRONT_PORT"; else FRONT_PORT="${PORT:-$DEFAULT_FRONT_PORT}"; fi
  valid_port "$FRONT_PORT" || mode_error "PORT='$PORT' is not a valid port"
  FRONT_PORT=$((10#$FRONT_PORT))
  [[ -n "$PORT" && "$ACTIVE_MODE" != cloudflare ]] || return 0
  for proto in "${HEADS[@]}"; do
    [[ "${HPORT[$proto]}" == "$FRONT_PORT" ]] || continue
    [[ "$ACTIVE_MODE" == ws ]] && SHARE_FRONT=1 || mode_error "PORT=$PORT is also the Reality port of ${proto^^}: sharing a port needs ws mode"
  done
}

# 各监听端口互不重复，且不占用内部保留端口
check_ports() {
  local proto port dup ports=()
  for proto in "${HEADS[@]}"; do ports+=("${HPORT[$proto]}"); done
  [[ -n "$FRONT_ON" && -z "$SHARE_FRONT" ]] && ports+=("$FRONT_PORT")
  [[ -n "$MIXED_PORT" ]] && ports+=("$MIXED_PORT")
  dup=$(printf '%s\n' "${ports[@]}" | sort | uniq -d | head -1)
  [[ -z "$dup" ]] || mode_error "Port $dup is used more than once: every Reality chain, the ws / cloudflare group (PORT) and MIXED_MODE need different TCP ports"
  for port in "${ports[@]}"; do
    in_array "$port" "$SS_IPORT" "$WSPORT_SS" && mode_error "Port $port conflicts with the internal ports $SS_IPORT / $WSPORT_SS"
  done
}

parse_modes; build_chains; plan_front; check_ports

[[ ${#ENABLED[@]} -gt 0 ]] && echo "[MODE] enabled=${ENABLED[*]}"
[[ -n "$ACTIVE_MODE" ]] && echo "[MODE] port $FRONT_PORT: $ACTIVE_MODE (${SHARED[*]})${SHARE_FRONT:+ shared with reality}"
for proto in "${HEADS[@]}"; do echo "[MODE] port ${HPORT[$proto]}: reality (${CHAIN[$proto]// / -> })"; done

# 流控 xtls-rprx-vision：仅 VLESS 作为 Reality 链头时启用
VLESS_FLOW=''; in_array vless "${HEADS[@]}" && VLESS_FLOW='xtls-rprx-vision'

# ========== Komari Agent ==========
KM_ON=""; [[ -n "$KOMARI_ENDPOINT" && -n "$KOMARI_TOKEN" ]] && KM_ON=1
[[ -n "$XRAY_ON$KM_ON" ]] || mode_error "Nothing to run: set a protocol *_MODE / HYSTERIA2_MODE / MIXED_MODE / WIREGUARD_MODE, or KOMARI_ENDPOINT + KOMARI_TOKEN"

if [[ -n "$KM_ON" ]]; then
  KM_BIN="$BASE_DIR/komari-agent"
  pkill -x komari-agent && { echo "[KOMARI] Stopped previous agent"; sleep 1; }
  dl "$KM_BIN" "https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-$ARCH" || exit 1
  chmod +x "$KM_BIN"
  export AGENT_ENDPOINT="$KOMARI_ENDPOINT" AGENT_TOKEN="$KOMARI_TOKEN"   # 走环境变量，ps 看不到
  if [[ -z "$XRAY_ON" ]]; then
    echo "[KOMARI] No proxy protocol enabled, running the agent only, reporting to $KOMARI_ENDPOINT"
    exec "$KM_BIN"
  fi
  nohup "$KM_BIN" > "$BASE_DIR/komari-agent.log" 2>&1 &
  unset AGENT_ENDPOINT AGENT_TOKEN
  echo "[KOMARI] Agent started, reporting to $KOMARI_ENDPOINT"
fi

# ========== 密钥 ==========
if [[ ${#HEADS[@]} -gt 0 ]]; then
  gen_key "$BASE_DIR/.reality_key" b64url
  REALITY_PRIVATE_KEY=$(<"$BASE_DIR/.reality_key")
  REALITY_PUBLIC_KEY=$(x25519_pub "$REALITY_PRIVATE_KEY" | tr '+/' '-_' | tr -d '=')
  [[ -n "$REALITY_PUBLIC_KEY" ]] || { echo "[REALITY] Failed to derive public key, check openssl and $BASE_DIR/.reality_key" >&2; exit 1; }
  echo "[REALITY] Private key: $REALITY_PRIVATE_KEY"; echo "[REALITY] Public key: $REALITY_PUBLIC_KEY"
fi
if [[ -n "$WG_PORT" ]]; then
  gen_key "$BASE_DIR/.wg_server_key" b64; gen_key "$BASE_DIR/.wg_client_key" b64
  WG_SERVER_PRIVATE=$(<"$BASE_DIR/.wg_server_key"); WG_CLIENT_PRIVATE=$(<"$BASE_DIR/.wg_client_key")
  WG_SERVER_PUBLIC=$(x25519_pub "$WG_SERVER_PRIVATE"); WG_CLIENT_PUBLIC=$(x25519_pub "$WG_CLIENT_PRIVATE")
  [[ -n "$WG_SERVER_PUBLIC" && -n "$WG_CLIENT_PUBLIC" ]] || { echo "[WG] Failed to derive public key, check openssl and $BASE_DIR/.wg_*_key" >&2; exit 1; }
fi
SS_USERINFO=$(printf 'aes-256-gcm:%s' "$UUID" | b64url)

# ========== 链接里的连接地址(PUBLIC_IP) ==========
# CERT_HOST 填 IP 就直接用；填域名则探测公网 IPv4，域名解析结果包含它时改用域名
IP_RE='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
TRACE_URL='https://one.one.one.one/cdn-cgi/trace'
if [[ "$ACTIVE_MODE" != cloudflare || ${#HEADS[@]} -gt 0 || -n "$HY2_PORT$MIXED_PORT$WG_PORT" ]]; then
  if [[ "$CERT_HOST" =~ $IP_RE ]]; then
    PUBLIC_IP="$CERT_HOST"
  else
    PUBLIC_IP=$(curl -4 -s -m 5 "$TRACE_URL" | sed -n 's/^ip=//p')
    if [[ -n "$CERT_HOST" && -n "$PUBLIC_IP" ]] && getent ahostsv4 "$CERT_HOST" 2>/dev/null | awk '{print $1}' | grep -qxF "$PUBLIC_IP"; then
      echo "[NET] $CERT_HOST points to this server, using it instead of the IP"; PUBLIC_IP="$CERT_HOST"
    fi
  fi
  [[ -n "$PUBLIC_IP" ]] || echo "[NET] Cannot determine the public address, links will be invalid (set CERT_HOST)" >&2
  echo "[NET] Address in links: $PUBLIC_IP"
fi

# ========== IPv6 出口检查 ==========
IPV6_RULE=',{"type": "field", "ip": ["::/0"], "outboundTag": "block"}'
if curl -6 -s -m 5 -o /dev/null "$TRACE_URL"; then
  IPV6_RULE=''; echo "[NET] IPv6 egress: available"
else
  echo "[NET] IPv6 egress: unavailable, blocking IPv6 destinations"
fi

# ========== TLS 证书(供 ws / Hysteria2 使用) ==========
# 脚本不申请证书。CERT_HOST 是域名且目录下有可信的 $CERT_HOST.crt / .key 就直接使用，否则用自签证书(链接里用 pcs 固定哈希)
generate_self_signed_cert() {   # 已有且 30 天内不过期就复用，否则每次重启哈希都变
  local common_name="$1" dir="$BASE_DIR/.selfsigned" error_output
  mkdir -p "$dir"; chmod 700 "$dir"
  CERT_FILE="$dir/$common_name.crt"; KEY_FILE="$dir/$common_name.key"
  [[ -s "$CERT_FILE" && -s "$KEY_FILE" ]] && openssl x509 -in "$CERT_FILE" -noout -checkend 2592000 >/dev/null 2>&1 && return
  error_output=$(openssl req -x509 -nodes -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 3650 \
    -config <(printf '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=%s\n[v3]\nsubjectAltName=DNS:%s,DNS:localhost\n' "$common_name" "$common_name") \
    -extensions v3 2>&1)
  [[ -s "$CERT_FILE" && -s "$KEY_FILE" ]] || { echo "[TLS] Failed to generate self-signed certificate (is openssl installed?):" >&2; echo "$error_output" >&2; exit 1; }
  chmod 600 "$KEY_FILE"
}

trusted_cert_for_host() {
  local host="$1" cert_path="$BASE_DIR/$1.crt" key_path="$BASE_DIR/$1.key" verify_output
  [[ -s "$cert_path" && -s "$key_path" ]] || return 1
  [[ "$(openssl x509 -in "$cert_path" -noout -pubkey 2>/dev/null)" == "$(openssl pkey -in "$key_path" -pubout 2>/dev/null)" ]] \
    || { echo "[TLS] $cert_path and $key_path do not match" >&2; return 1; }
  verify_output=$(openssl verify -verify_hostname "$host" -untrusted "$cert_path" "$cert_path" 2>&1)
  [[ "$verify_output" == *": OK" && "$verify_output" != *error* ]] || { echo "[TLS] $cert_path is not a trusted certificate for $host:" >&2; echo "$verify_output" >&2; return 1; }
  CERT_FILE="$cert_path"; KEY_FILE="$key_path"
}

setup_tls() {
  TLS_PCS=""; TLS_SERVER_NAME="${CERT_HOST:-www.nazhumi.com}"
  if [[ -n "$CERT_HOST" && ! "$CERT_HOST" =~ $IP_RE ]] && trusted_cert_for_host "$CERT_HOST"; then
    TLS_INSECURE=0
  else
    TLS_INSECURE=1
    echo "[TLS] No trusted certificate available (put one at $BASE_DIR/<CERT_HOST>.crt and .key), using self-signed certificate" >&2
    generate_self_signed_cert "$TLS_SERVER_NAME"
    TLS_PCS=$(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
  fi
  echo "[TLS] Server name: $TLS_SERVER_NAME, insecure: $TLS_INSECURE, cert: $CERT_FILE, key: $KEY_FILE"
}

[[ "$ACTIVE_MODE" == ws || -n "$HY2_PORT" ]] && setup_tls

# ========== cloudflared ==========
# cloudflare：Token 固定隧道；try：无需 Token 的临时隧道。隧道域名从 cloudflared 日志里取
CLOUDFLARE_TUNNEL_HOSTNAME=""
if [[ "$ACTIVE_MODE" == cloudflare && ( -n "$CLOUDFLARE_TUNNEL_TOKEN" || -n "$TRY_TUNNEL" ) ]]; then
  CF_BIN="$BASE_DIR/cloudflared"; CF_LOG="$BASE_DIR/cloudflared.log"
  pkill -x cloudflared && { echo "[CF] Stopped previous cloudflared"; sleep 1; }
  dl "$CF_BIN" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$ARCH" || exit 1
  chmod +x "$CF_BIN"; "$CF_BIN" --version
  if [[ -n "$TRY_TUNNEL" ]]; then
    nohup "$CF_BIN" --no-autoupdate tunnel --url "http://localhost:$FRONT_PORT" > "$CF_LOG" 2>&1 &
    for _ in {1..30}; do
      CLOUDFLARE_TUNNEL_HOSTNAME=$(grep -aoE 'https://[a-z0-9-]+\.trycloudflare\.com' "$CF_LOG" | grep -v '^https://api\.' | head -1 | sed 's|https://||')
      [[ -n "$CLOUDFLARE_TUNNEL_HOSTNAME" ]] && break; sleep 1
    done
    if [[ -n "$CLOUDFLARE_TUNNEL_HOSTNAME" ]]; then echo "[CF] Quick tunnel hostname from log: $CLOUDFLARE_TUNNEL_HOSTNAME (service port=$FRONT_PORT)"
    else echo "[CF] Cannot find the trycloudflare.com hostname in $CF_LOG" >&2; fi
  else
    TUNNEL_TOKEN="$CLOUDFLARE_TUNNEL_TOKEN" nohup "$CF_BIN" --no-autoupdate tunnel run > "$CF_LOG" 2>&1 &
    # 日志会打印下发的 ingress 配置：取第一条有具体域名(不含 *)、Service 为 http://localhost|127.0.0.1:端口 的规则(日志引号带反斜杠，先还原)
    for _ in {1..30}; do
      tunnel_config=$(grep -a 'Updated to new configuration' "$CF_LOG" | tail -1)
      [[ -n "$tunnel_config" ]] && break; sleep 1
    done
    tunnel_config="${tunnel_config//\\\"/\"}"
    tunnel_rule=$(grep -oE '\{[^{}]*\}' <<< "$tunnel_config" | grep -E '"hostname":"[^"*]+"' | grep -E '"service":"http://(localhost|127\.0\.0\.1):[0-9]+"' | head -1)
    CLOUDFLARE_TUNNEL_HOSTNAME=$(grep -oE '"hostname":"[^"]+"' <<< "$tunnel_rule" | cut -d'"' -f4)
    tunnel_port=$(grep -oE '"service":"http://[^"]+"' <<< "$tunnel_rule" | grep -oE '[0-9]+"$' | tr -d '"')
    if [[ -n "$CLOUDFLARE_TUNNEL_HOSTNAME" && -n "$tunnel_port" ]]; then
      valid_port "$tunnel_port" || mode_error "Tunnel service port '$tunnel_port' read from the cloudflared log is not valid"
      FRONT_PORT=$((10#$tunnel_port)); check_ports
      echo "[CF] From cloudflared log: hostname=$CLOUDFLARE_TUNNEL_HOSTNAME, tunnel service port=$FRONT_PORT"
    else
      CLOUDFLARE_TUNNEL_HOSTNAME=""
      echo "[CF] Cannot read hostname / port from $CF_LOG (the tunnel needs a Public hostname without * and a Service like http://localhost:PORT)" >&2
    fi
  fi
fi

# ========== Xray ==========
XRAY_DIR="$BASE_DIR/xray"; XRAY_BIN="$XRAY_DIR/xray"; XRAY_CONF="$XRAY_DIR/config.json"
mkdir -p "$XRAY_DIR"
dl "$BASE_DIR/xray.zip" "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$XARCH.zip" || exit 1
if command -v unzip >/dev/null 2>&1; then   # 没有 unzip(精简容器)就用 node 自带 zlib 解压
  unzip -oq "$BASE_DIR/xray.zip" -d "$XRAY_DIR"
else
  node - "$BASE_DIR/xray.zip" "$XRAY_DIR" <<'JS'
const fs = require('fs'), zlib = require('zlib'), path = require('path');
const [zip, dir] = process.argv.slice(-2);
const buffer = fs.readFileSync(zip), root = path.resolve(dir);
let eocdOffset = buffer.length - 22;
while (eocdOffset >= 0 && buffer.readUInt32LE(eocdOffset) !== 0x06054b50) eocdOffset--;
if (eocdOffset < 0) { console.error('not a zip file'); process.exit(1); }
let pos = buffer.readUInt32LE(eocdOffset + 16);
for (let remaining = buffer.readUInt16LE(eocdOffset + 10); remaining > 0; remaining--) {
  const method = buffer.readUInt16LE(pos + 10), csize = buffer.readUInt32LE(pos + 20);
  const nlen = buffer.readUInt16LE(pos + 28), xlen = buffer.readUInt16LE(pos + 30), clen = buffer.readUInt16LE(pos + 32);
  const off = buffer.readUInt32LE(pos + 42), name = buffer.toString('utf8', pos + 46, pos + 46 + nlen);
  pos += 46 + nlen + xlen + clen;
  if (name.endsWith('/')) continue;
  const ds = off + 30 + buffer.readUInt16LE(off + 26) + buffer.readUInt16LE(off + 28);
  const data = buffer.subarray(ds, ds + csize);
  const outPath = path.resolve(root, name);
  if (!outPath.startsWith(root + path.sep)) continue;
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, method === 0 ? data : zlib.inflateRawSync(data));
}
JS
fi
rm -f "$BASE_DIR/xray.zip"; chmod +x "$XRAY_BIN" 2>/dev/null
[[ -x "$XRAY_BIN" ]] || { echo "[XRAY] Binary not found after extraction: $XRAY_BIN" >&2; exit 1; }
export XRAY_LOCATION_ASSET="$XRAY_DIR"
"$XRAY_BIN" version

# 每个 inbound 共用的嗅探配置：只用于路由匹配，不改写目标地址
SNIFFING='"sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}'

# ---- stream 片段 ----
stream_tcp_plain() { echo '{"network": "tcp", "security": "none"}'; }
stream_ws() { echo "{\"network\": \"ws\", \"security\": \"none\", \"wsSettings\": {\"path\": \"$1\"}}"; }
# stream_reality [dest] [serverName]：默认伪装 www.iij.ad.jp；与 ws 共用端口时 dest 指向本机前置入口
stream_reality() {
  local dest="${1:-www.iij.ad.jp:443}" sni="${2:-www.iij.ad.jp}"
  echo "{\"network\": \"tcp\", \"security\": \"reality\", \"realitySettings\": {\"show\": false, \"dest\": \"$dest\", \"xver\": 0, \"serverNames\": [\"$sni\"], \"privateKey\": \"$REALITY_PRIVATE_KEY\", \"shortIds\": [\"cdcf853c\"]}}"
}
# tls_stream <network> <alpn> [额外字段]：ws 前置入口和 Hysteria2 共用
tls_stream() {
  echo "{\"network\": \"$1\", \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"$TLS_SERVER_NAME\", \"alpn\": [\"$2\"], \"certificates\": [{\"certificateFile\": \"$CERT_FILE\", \"keyFile\": \"$KEY_FILE\"}]}$3}"
}

# proto_settings <proto> [fallbacks JSON 数组] [flow]
proto_settings() {
  local fallbacks="${2:+, \"fallbacks\": $2}" flow="${3:+, \"flow\": \"$3\"}"
  case "$1" in
    vless)  echo "{\"clients\": [{\"id\": \"$UUID\", \"email\": \"$UUID\"$flow}], \"decryption\": \"none\"$fallbacks}" ;;
    vmess)  echo "{\"clients\": [{\"id\": \"$UUID\", \"email\": \"$UUID\"}]}" ;;
    trojan) echo "{\"clients\": [{\"password\": \"$UUID\", \"email\": \"$UUID\"}]$fallbacks}" ;;
    shadowsocks) echo "{\"method\": \"aes-256-gcm\", \"password\": \"$UUID\", \"network\": \"tcp\"}" ;;
  esac
}

# inbound_json <tag> <listen> <port，unix socket 时留空> <protocol> <settings> <stream>
inbound_json() {
  echo "{\"tag\": \"$1\", \"listen\": \"$2\", ${3:+\"port\": $3, }\"protocol\": \"$4\", \"settings\": $5, \"streamSettings\": $6, $SNIFFING}"
}

# 前置入口(ws / cloudflare / 只回落)：监听 FRONT_PORT，按 HTTP 路径把 ws 流量回落给各内部 ws 入口，其余回落给 WEB_DEST。
# ws 带 TLS；其余明文。与 Reality 共用端口时只听本机，由 Reality 转进来
inbounds_front() {
  local proto fallbacks=() stream front_listen="::" front_port="$FRONT_PORT" ws_listen ws_listen_port ws_dest
  for proto in "${SHARED[@]}"; do
    if [[ "$proto" == shadowsocks ]]; then ws_listen=127.0.0.1; ws_listen_port="$WSPORT_SS"; ws_dest="$WSPORT_SS"; else ws_listen="$(ws_sock "$proto")"; ws_listen_port=""; ws_dest="\"$ws_listen\""; fi
    fallbacks+=("{\"path\": \"${WS_PATH[$proto]}\", \"dest\": $ws_dest, \"xver\": 0}")
    INB+=("$(inbound_json "$proto-ws-in" "$ws_listen" "$ws_listen_port" "$proto" "$(proto_settings "$proto")" "$(stream_ws "${WS_PATH[$proto]}")")")
  done
  [[ -n "$WEB_DEST" ]] && fallbacks+=("{\"dest\": \"$WEB_DEST\", \"xver\": 0}")
  if [[ "$ACTIVE_MODE" == ws ]]; then stream=$(tls_stream tcp http/1.1); else stream=$(stream_tcp_plain); fi
  [[ -n "$SHARE_FRONT" ]] && { front_listen="@$UUID-front"; front_port=""; }
  INB+=("$(inbound_json front-in "$front_listen" "$front_port" vless "$(proto_settings vless "[$(IFS=,; echo "${fallbacks[*]}")]")" "$stream")")
}

# Reality 链：链头监听自己的端口并套 Reality；被回落到的协议依次监听内部 unix socket
inbounds_chains() {
  local head proto fallbacks flow listen port stream
  for head in "${HEADS[@]}"; do
    for proto in ${CHAIN[$head]}; do
      fallbacks=""; flow=""
      [[ -n "${FB[$proto]}" ]] && fallbacks="[{\"dest\": $(chain_dest "${FB[$proto]}"), \"xver\": 0}]"
      if [[ "$proto" != "$head" ]]; then
        if [[ "$proto" == shadowsocks ]]; then listen=127.0.0.1; port="$SS_IPORT"; else listen="@$UUID-in-$proto"; port=""; fi
        stream=$(stream_tcp_plain)
      else
        listen="::"; port="${HPORT[$head]}"
        if [[ -n "$SHARE_FRONT" && "$port" == "$FRONT_PORT" ]]; then stream=$(stream_reality "@$UUID-front" "$TLS_SERVER_NAME"); else stream=$(stream_reality); fi
        [[ "$proto" == vless ]] && flow="$VLESS_FLOW"
      fi
      INB+=("$(inbound_json "$proto-in" "$listen" "$port" "$proto" "$(proto_settings "$proto" "$fallbacks" "$flow")" "$stream")")
    done
  done
}

collect_inbounds() {
  INB=()
  [[ -n "$FRONT_ON" ]] && inbounds_front
  inbounds_chains
  [[ -n "$HY2_PORT" ]] && INB+=("$(inbound_json hysteria2-in :: "$HY2_PORT" hysteria "{\"version\": 2, \"clients\": [{\"auth\": \"$UUID\", \"email\": \"$UUID\"}]}" "$(tls_stream hysteria h3 ', "hysteriaSettings": {"version": 2}')")")
  [[ -n "$MIXED_PORT" ]] && INB+=("$(inbound_json mixed-in :: "$MIXED_PORT" socks "{\"auth\": \"password\", \"accounts\": [{\"user\": \"$UUID\", \"pass\": \"$UUID\"}], \"udp\": false}" "$(stream_tcp_plain)")")
  [[ -n "$WG_PORT" ]] && INB+=("$(inbound_json wireguard-in :: "$WG_PORT" wireguard "{\"secretKey\": \"$WG_SERVER_PRIVATE\", \"peers\": [{\"publicKey\": \"$WG_CLIENT_PUBLIC\", \"allowedIPs\": [\"$WG_CLIENT_ADDR\"]}], \"mtu\": 1420}" null)")
  ( IFS=,; printf '%s\n' "${INB[*]}" )
}

# ========== 订阅链接 ==========
reality_link() {   # <proto> <port>：VMess / SS 也用 URI 格式，客户端要能当作 Reality 节点导入
  local sni=www.iij.ad.jp reality_query
  [[ -n "$SHARE_FRONT" && "$2" == "$FRONT_PORT" ]] && sni="$TLS_SERVER_NAME"
  reality_query="security=reality&sni=$sni&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=tcp&sid=cdcf853c"
  case "$1" in
    vless)  echo "vless://$UUID@$PUBLIC_IP:$2?encryption=none${VLESS_FLOW:+&flow=$VLESS_FLOW}&$reality_query#$NAME_ENC" ;;
    vmess)  echo "vmess://$UUID@$PUBLIC_IP:$2?encryption=auto&$reality_query#$NAME_ENC" ;;
    trojan) echo "trojan://$UUID@$PUBLIC_IP:$2?$reality_query#$NAME_ENC" ;;
    shadowsocks) echo "ss://$SS_USERINFO@$PUBLIC_IP:$2?$reality_query#$NAME_ENC" ;;
  esac
}

hy2_link() { echo "hysteria2://$UUID@$PUBLIC_IP:$HY2_PORT/?sni=$TLS_SERVER_NAME$([[ $TLS_INSECURE == 1 ]] && echo '&insecure=1')#$NAME_ENC"; }

mixed_links() {   # SOCKS5 和 HTTP 各一条(同端口同账号密码，明文传输)
  echo "socks5://$UUID:$UUID@$PUBLIC_IP:$MIXED_PORT#$NAME_ENC"
  echo "http://$UUID:$UUID@$PUBLIC_IP:$MIXED_PORT#$NAME_ENC"
}

wg_link() {
  echo "wireguard://$(urlencode "$WG_CLIENT_PRIVATE")@$PUBLIC_IP:$WG_PORT?publickey=$(urlencode "$WG_SERVER_PUBLIC")&address=$(urlencode "$WG_CLIENT_ADDR")&mtu=1420#$NAME_ENC"
}
wg_conf() {
  printf '[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n' \
    "$WG_CLIENT_PRIVATE" "$WG_CLIENT_ADDR" "$WG_SERVER_PUBLIC" "$PUBLIC_IP" "$WG_PORT"
}

# SIP003 v2ray-plugin 参数(固定 tls)：ss_plugin_param <host> <path>
ss_plugin_param() {
  local param="v2ray-plugin;tls;host=$1;path=$2;mux=0"
  param="${param//;/%3B}"; param="${param//=/%3D}"; echo "${param//\//%2F}"
}

# ws / cloudflare 链接的共同参数
#   cloudflare：连 CLOUDFLARE_IP:443(没设置就连探测到的隧道域名)；ws：连 PUBLIC_IP:FRONT_PORT，自签证书用 pcs 固定
init_ws_params() {
  WS_IQ=""; WS_VM_INSECURE=0; WS_VM_EXTRA=""; WS_VM_PCS=""
  if [[ "$ACTIVE_MODE" == cloudflare ]]; then
    WS_ADDR="${CLOUDFLARE_IP:-$CLOUDFLARE_TUNNEL_HOSTNAME}"; WS_PORT=443; WS_HOST="$CLOUDFLARE_TUNNEL_HOSTNAME"
  else
    WS_ADDR="$PUBLIC_IP"; WS_PORT="$FRONT_PORT"; WS_HOST="$TLS_SERVER_NAME"
    WS_VM_INSECURE="$TLS_INSECURE"; WS_VM_PCS="$TLS_PCS"
    WS_VM_EXTRA=",\"allowInsecure\":$TLS_INSECURE,\"verify_cert\":$([[ "$TLS_INSECURE" == 1 ]] && echo false || echo true)"
    [[ "$TLS_INSECURE" == 1 ]] && WS_IQ="&allowInsecure=1&pcs=$TLS_PCS"
  fi
}

generate_ws_node() {
  local proto="$1" path="${WS_PATH[$1]}" early_data="" encoded_path="${WS_PATH[$1]//\//%2F}"
  if [[ "$ACTIVE_MODE" == cloudflare ]]; then
    if [[ -z "$CLOUDFLARE_TUNNEL_HOSTNAME" || ( -z "$TRY_TUNNEL" && -z "$CLOUDFLARE_TUNNEL_TOKEN" ) ]]; then
      echo "[MODE] cloudflare mode needs CLOUDFLARE_TUNNEL_TOKEN (not needed in try mode) and a tunnel hostname found in the cloudflared log, no $proto link generated" >&2
      return
    fi
    [[ "$proto" == vmess ]] && early_data="?ed=2560"   # 0-RTT early data
  fi
  case "$proto" in
    vless)  echo "vless://$UUID@$WS_ADDR:$WS_PORT?encryption=none&security=tls&sni=$WS_HOST&fp=chrome&type=ws&host=$WS_HOST&path=$encoded_path$WS_IQ#$NAME_ENC" ;;
    vmess)  printf 'vmess://%s\n' "$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"none","net":"ws","type":"none","host":"%s","path":"%s","tls":"tls","sni":"%s","alpn":"","fp":"","insecure":"%s"%s,"vcn":"","pcs":"%s"}' \
              "$(json_escape "$NAME")" "$WS_ADDR" "$WS_PORT" "$UUID" "$WS_HOST" "$path$early_data" "$WS_HOST" "$WS_VM_INSECURE" "$WS_VM_EXTRA" "$WS_VM_PCS" | b64)" ;;
    trojan) echo "trojan://$UUID@$WS_ADDR:$WS_PORT?security=tls&sni=$WS_HOST&fp=chrome&type=ws&host=$WS_HOST&path=$encoded_path$WS_IQ#$NAME_ENC" ;;
    shadowsocks)   # v2ray-plugin 无法跳过证书校验，自签证书下该节点连不上，不输出
      if [[ "$ACTIVE_MODE" == ws && "$TLS_INSECURE" == 1 ]]; then
        echo "[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, put one at $BASE_DIR/<CERT_HOST>.crt and .key. No SS link generated" >&2
        return
      fi
      echo "ss://$SS_USERINFO@$WS_ADDR:$WS_PORT/?plugin=$(ss_plugin_param "$WS_HOST" "$path")#$NAME_ENC" ;;
  esac
}

# 一个协议的全部链接：Reality 链上输出 Reality 链接，用了 ws / cloudflare 再输出 ws 链接
generate_node() {
  [[ -n "${RPORT[$1]}" ]] && reality_link "$1" "${RPORT[$1]}"
  in_array "$1" "${SHARED[@]}" && generate_ws_node "$1"
}

# ========== 生成 config.json ==========
# 里面有 UUID 和 Reality 私钥，先收紧权限再写入
( umask 077; cat > "$XRAY_CONF" <<EOF
{
  "log": {"loglevel": "warning"},
  "dns": {"servers": ["https+local://1.1.1.1/dns-query"], "queryStrategy": "UseIPv4"},
  "inbounds": [
$(collect_inbounds)
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}${IPV6_RULE}
    ]
  }
}
EOF
)
chmod 600 "$XRAY_CONF"
"$XRAY_BIN" run -test -c "$XRAY_CONF" || { echo "[XRAY] Config test failed, aborting" >&2; exit 1; }

# ========== 输出订阅 ==========
[[ -n "$ACTIVE_MODE" ]] && init_ws_params
ALL_NODES=""
emit() { [[ -n "$1" ]] || return 0; echo "$1"; ALL_NODES+="$1"$'\n'; }
for proto in "${ENABLED[@]}"; do emit "$(generate_node "$proto")"; done
[[ -n "$HY2_PORT" ]] && emit "$(hy2_link)"
[[ -n "$MIXED_PORT" ]] && emit "$(mixed_links)"
[[ -n "$WG_PORT" ]] && emit "$(wg_link)"

echo; echo "=== Nodes ==="; echo -n "$ALL_NODES"
echo; echo "=== Subscription (base64) ==="; echo -n "$ALL_NODES" | b64; echo
[[ -n "$WG_PORT" ]] && { echo; echo "=== WireGuard config (wg-quick) ==="; wg_conf; }

exec "$XRAY_BIN" run -c "$XRAY_CONF"
