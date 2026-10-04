#!/bin/bash

# ========== 用户配置 ==========
NAME=${NAME:-''}
UUID=${UUID:-$(cat /proc/sys/kernel/random/uuid)}
CLOUDFLARE_TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN:-''}
CLOUDFLARE_IP=${CLOUDFLARE_IP:-''}
PORT=${PORT:-''}
FALLBACK_SITE=${FALLBACK_SITE:-''}
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
CF_TOKEN=${CF_TOKEN:-''}

# 把当前 UUID 写回脚本本身：下次运行直接沿用，不做任何检测
sed -i "s|^UUID=.*|UUID=\${UUID:-'$UUID'}|" "${BASH_SOURCE[0]}"

# ========== 基础环境 ==========
# 所有下载物和数据目录都放在脚本所在目录
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR" || exit 1

# ARCH 同时用于 cloudflared / lego 的文件名；Xray 的命名不同(64 / arm64-v8a)，下载处单独换算
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "[ARCH] Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

# ========== 通用函数 ==========
b64() { base64 | tr -d '\n'; }
b64url() { b64 | tr '+/' '-_' | tr -d '='; }
b64url_dec() {
  local s; s=$(tr '_-' '/+')
  case $(( ${#s} % 4 )) in 2) s+="==" ;; 3) s+="=" ;; esac
  printf '%s' "$s" | base64 -d
}
mode_error() { echo "[MODE] $*" >&2; exit 1; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# in_array <item> <array elements...>
in_array() {
  local x="$1" i; shift
  for i in "$@"; do [[ "$i" == "$x" ]] && return 0; done
  return 1
}

# URL 片段 / 查询值编码(按字节处理，中文、空格、引号都安全)
urlencode() {
  local LC_ALL=C s="$1" i c out=""
  for (( i = 0; i < ${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) printf -v c '%%%02X' "'$c"; out+="$c" ;;
    esac
  done
  printf '%s' "$out"
}

# JSON 字符串转义(不含外层引号)
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

# dl <输出文件> <URL>：先写 .part 再改名，失败(含 HTTP 错误)返回 1，不留半截文件
dl() {
  curl -fsSL --retry 3 --connect-timeout 10 -o "$1.part" "$2" && mv -f "$1.part" "$1" && return 0
  rm -f "$1.part"; echo "[DL] Download failed: $2" >&2; return 1
}

NAME_ENC=$(urlencode "$NAME")

# ========== 协议与模式 ==========
PROTOS=(vless vmess trojan shadowsocks)
# 各协议的 ws 路径，以及回落用的内部端口(仅监听 127.0.0.1；不用 unix socket，因为 Xray 的 Shadowsocks 入站不支持)
# 内部端口 40001-40005 不能被 PORT 或 *_MODE 里的端口占用
declare -A WS_PATH=([vless]=/misaka-vless [vmess]=/misaka-vmess [trojan]=/misaka-trojan [shadowsocks]=/misaka-ss)
declare -A IPORT=([vless]=40001 [vmess]=40002 [trojan]=40003 [shadowsocks]=40004)
declare -A NPORT   # 协议 -> 它的 *_MODE 里写的数字端口
declare -A FB      # 协议 -> 它回落到的协议
declare -A PARENT  # 协议 -> 回落到它的协议
declare -A CHAIN   # Reality 链头 -> 整条链上的协议(空格分隔，如 "vless trojan vmess")
declare -A HPORT   # Reality 链头 -> 监听端口
declare -A RPORT   # Reality 链上的每个协议 -> 对外端口(即链头端口)，生成链接用
ENABLED=()         # 所有启用的协议(含被回落到而自动启用的)，订阅链接按此顺序输出
SHARED=()          # 采用 ws / cloudflare 的协议
HEADS=()           # Reality 链头(独占端口的单个协议也算)
ACTIVE_MODE=""     # SHARED 统一的模式：ws / cloudflare / 空
FRONT_ON=""        # 是否需要前置入口(ws / cloudflare，或只回落)
SHARE_FRONT=""     # 前置入口是否与某条 Reality 链共用端口
DEFAULT_FRONT_PORT=8000   # ws 模式 PORT 留空时用它；cloudflare 模式先用它，读到隧道日志里的端口后会覆盖
FRONT_IPORT=40005         # 与 Reality 共用端口时，ws 前置入口改监听 127.0.0.1 的这个端口

# 回落网站：PORT 和 FALLBACK_SITE 都填了才启用；host 或 host:port，不写端口默认 80
WEB_DEST=""
if [[ -n "$PORT" && -n "$FALLBACK_SITE" ]]; then
  WEB_DEST="$FALLBACK_SITE"
  [[ "$WEB_DEST" == *:* ]] || WEB_DEST+=":80"
  [[ "$WEB_DEST" =~ ^[A-Za-z0-9.-]+:[0-9]{1,5}$ ]] || mode_error "FALLBACK_SITE='$FALLBACK_SITE' is invalid (expected host or host:port)"
  [[ "${WEB_DEST##*:}" != 443 ]] || echo "[WEB] Warning: fallback sends plain HTTP, port 443 will usually reject it; use the site's HTTP port (80)" >&2
  echo "[WEB] Non-ws requests on the front port fall back to $WEB_DEST"
elif [[ -n "$PORT" ]]; then
  echo "[WEB] PORT is set but FALLBACK_SITE is empty, fallback disabled (PORT only changes the listening port)" >&2
elif [[ -n "$FALLBACK_SITE" ]]; then
  echo "[WEB] FALLBACK_SITE is set but PORT is empty, fallback disabled" >&2
fi

# Hysteria2：只接受数字端口(UDP)，不参与回落链，也不占用 TCP 端口
HY2_PORT=""
if [[ -n "$HYSTERIA2_MODE" ]]; then
  valid_port "$HYSTERIA2_MODE" || mode_error "HYSTERIA2_MODE='$HYSTERIA2_MODE' is invalid (expected a port number 1-65535, or empty to disable)"
  HY2_PORT=$((10#$HYSTERIA2_MODE))
  echo "[MODE] port $HY2_PORT/udp: hysteria2"
fi

# Mixed(同一个端口同时支持 SOCKS5 和 HTTP 代理，TCP)：数字端口，账号 misaka、密码 UUID，不参与回落链
MIXED_PORT=""
if [[ -n "$MIXED_MODE" ]]; then
  valid_port "$MIXED_MODE" || mode_error "MIXED_MODE='$MIXED_MODE' is invalid (expected a port number 1-65535, or empty to disable)"
  MIXED_PORT=$((10#$MIXED_MODE))
  echo "[MODE] port $MIXED_PORT/tcp: mixed (socks5 + http)"
fi

# WireGuard(Xray 用户态实现，UDP)：数字端口，不参与回落链，也不占用 TCP 端口
WG_PORT=""
WG_CLIENT_ADDR="10.0.0.2/32"   # 客户端在隧道里的内网地址
if [[ -n "$WIREGUARD_MODE" ]]; then
  valid_port "$WIREGUARD_MODE" || mode_error "WIREGUARD_MODE='$WIREGUARD_MODE' is invalid (expected a port number 1-65535, or empty to disable)"
  WG_PORT=$((10#$WIREGUARD_MODE))
  echo "[MODE] port $WG_PORT/udp: wireguard"
fi

mode_of() { local v="${1^^}_MODE"; printf '%s' "${!v}"; }

# 1. 解析各协议的 *_MODE：ws / cloudflare、数字端口、协议名(回落)
parse_modes() {
  local p v m t
  for p in "${PROTOS[@]}"; do
    m="$(mode_of "$p")"; v="${p^^}_MODE"
    [[ -n "$m" ]] || continue
    if [[ "$m" == ws || "$m" == cloudflare ]]; then
      [[ -z "$ACTIVE_MODE" || "$ACTIVE_MODE" == "$m" ]] || mode_error "Protocols using ws / cloudflare share one port (PORT), so they must use the same mode (got: $ACTIVE_MODE $m)"
      SHARED+=("$p"); ACTIVE_MODE="$m"
    elif [[ "$m" =~ ^[0-9]+$ ]]; then
      valid_port "$m" || mode_error "$v='$m': port must be 1-65535"
      NPORT[$p]=$((10#$m))
    elif [[ "$m" =~ ^[a-z]+$ ]]; then
      t="$m"
      in_array "$t" "${PROTOS[@]}" || mode_error "$v='$m': '$t' is not valid (expected ws / cloudflare / a port, or a fallback protocol: ${PROTOS[*]})"
      [[ "$t" != "$p" ]] || mode_error "$v='$m': a protocol cannot fall back to itself"
      [[ "$p" == vless || "$p" == trojan ]] || mode_error "$v='$m': ${p^^} has no fallback ability, only VLESS and TROJAN can choose a fallback"
      FB[$p]="$t"
    else
      mode_error "$v='$m' is invalid (expected: ws / cloudflare / a port / a protocol name, or empty to disable)"
    fi
  done
}

# 2. 把回落关系整理成 Reality 链：得到 ENABLED / HEADS / CHAIN / HPORT / RPORT
build_chains() {
  local p t h q
  # 每个协议只能被一个协议回落到；被回落到的协议不能用 ws / cloudflare
  for p in "${!FB[@]}"; do
    t="${FB[$p]}"
    [[ -z "${PARENT[$t]}" ]] || mode_error "${t^^} is the fallback of both ${PARENT[$t]^^} and ${p^^}, it can only have one"
    PARENT[$t]="$p"
    in_array "$t" "${SHARED[@]}" && mode_error "${t^^} is already the fallback of ${p^^}: ${t^^}_MODE cannot be ws / cloudflare (leave it empty; if it ends the chain, set a port; if it keeps falling back, use a protocol name)"
  done
  # 链头 = 设了 Reality 相关模式(数字 / 协议名)且没被别人回落到的协议；顺着回落走到链尾，端口取链尾的数字
  for p in "${PROTOS[@]}"; do
    [[ -n "$(mode_of "$p")" || -n "${PARENT[$p]}" ]] && ENABLED+=("$p")
    [[ -n "$(mode_of "$p")" && -z "${PARENT[$p]}" ]] && ! in_array "$p" "${SHARED[@]}" && HEADS+=("$p")
  done
  for h in "${HEADS[@]}"; do
    q="$h"; CHAIN[$h]="$h"
    while [[ -n "${FB[$q]}" ]]; do q="${FB[$q]}"; CHAIN[$h]+=" $q"; done
    [[ -n "${NPORT[$q]}" ]] || mode_error "The chain from ${h^^} ends at ${q^^}, which needs a port: set ${q^^}_MODE to a port number"
    HPORT[$h]="${NPORT[$q]}"
    for p in ${CHAIN[$h]}; do RPORT[$p]="${HPORT[$h]}"; done
  done
  # 没有启用任何协议时不报错：只跑 Komari 探针(见下面的 Komari Agent 段)
  XRAY_ON=""
  [[ ${#ENABLED[@]} -gt 0 || -n "$HY2_PORT" || -n "$MIXED_PORT" || -n "$WG_PORT" ]] && XRAY_ON=1
  for p in "${ENABLED[@]}"; do   # 既不在 ws / cloudflare 组、也没挂到任何 Reality 链上 = 回落成环
    in_array "$p" "${SHARED[@]}" || [[ -n "${RPORT[$p]}" ]] || mode_error "${p^^} is part of a fallback loop: the chain needs a head that no protocol falls back to"
  done
}

# 3. 前置入口：是否需要、监听哪个端口、是否与某条 Reality 链共用
plan_front() {
  local p
  [[ -n "$ACTIVE_MODE$WEB_DEST" ]] || return 0
  FRONT_ON=1
  # cloudflare 先用 8000(之后从 cloudflared 日志读到隧道的回源端口再覆盖)；其它(ws / 只回落)用 PORT，留空 8000
  if [[ "$ACTIVE_MODE" == cloudflare ]]; then FRONT_PORT="$DEFAULT_FRONT_PORT"; else FRONT_PORT="${PORT:-$DEFAULT_FRONT_PORT}"; fi
  valid_port "$FRONT_PORT" || mode_error "PORT='$PORT' is not a valid port"
  FRONT_PORT=$((10#$FRONT_PORT))
  # PORT 与某条 Reality 链端口相同：ws 模式下共用端口，其它情况不能共用
  [[ -n "$PORT" && "$ACTIVE_MODE" != cloudflare ]] || return 0
  for p in "${HEADS[@]}"; do
    [[ "${HPORT[$p]}" == "$FRONT_PORT" ]] || continue
    [[ "$ACTIVE_MODE" == ws ]] && SHARE_FRONT=1 || mode_error "PORT=$PORT is also the Reality port of ${p^^}: sharing a port needs ws mode (cloudflare / fallback-only cannot share it with Reality)"
  done
}

# 4. 端口检查：各监听端口(Reality 链头 + 前置入口)互不重复，且不占用内部保留端口 40001-40005
check_ports() {
  local p q dup ports=()
  for p in "${HEADS[@]}"; do ports+=("${HPORT[$p]}"); done
  [[ -n "$FRONT_ON" && -z "$SHARE_FRONT" ]] && ports+=("$FRONT_PORT")
  [[ -n "$MIXED_PORT" ]] && ports+=("$MIXED_PORT")
  dup=$(printf '%s\n' "${ports[@]}" | sort | uniq -d | head -1)
  [[ -z "$dup" ]] || mode_error "Port $dup is used more than once: every Reality chain, the ws / cloudflare group (PORT) and MIXED_MODE need different TCP ports"
  for q in "${ports[@]}"; do
    in_array "$q" "${IPORT[@]}" "$FRONT_IPORT" && mode_error "Port $q conflicts with the internal fallback ports 40001-40005"
  done
}

parse_modes
build_chains
plan_front
check_ports

[[ ${#ENABLED[@]} -gt 0 ]] && echo "[MODE] enabled=${ENABLED[*]}"
[[ -n "$ACTIVE_MODE" ]] && echo "[MODE] port $FRONT_PORT: $ACTIVE_MODE (${SHARED[*]})${SHARE_FRONT:+ shared with reality}"
for p in "${HEADS[@]}"; do echo "[MODE] port ${HPORT[$p]}: reality (${CHAIN[$p]// / -> })"; done

# 流控 xtls-rprx-vision：仅 VLESS 作为 Reality 链头(tcp + reality)时启用；
# VLESS 作为被回落的内部入口(明文 tcp)或走 ws 时不支持 Vision
VLESS_FLOW=''
in_array vless "${HEADS[@]}" && VLESS_FLOW='xtls-rprx-vision'

# ========== Komari Agent ==========
# 探针：KOMARI_ENDPOINT 和 KOMARI_TOKEN 都填了才启用，向 Komari 面板上报本机状态
#   有代理协议：agent 后台运行，脚本继续启动 Xray
#   没有代理协议：脚本只作为 Komari 启动脚本，agent 前台运行(脚本不退出)
KM_ON=""
[[ -n "$KOMARI_ENDPOINT" && -n "$KOMARI_TOKEN" ]] && KM_ON=1
[[ -n "$XRAY_ON" || -n "$KM_ON" ]] || mode_error "Nothing to run: set a protocol *_MODE / HYSTERIA2_MODE / MIXED_MODE / WIREGUARD_MODE, or KOMARI_ENDPOINT + KOMARI_TOKEN"

if [[ -n "$KM_ON" ]]; then
  KM_BIN="$BASE_DIR/komari-agent"

  # 脚本被重启时，按进程名先停掉上一次留下的探针，避免出现两个探针进程
  pkill -x komari-agent && { echo "[KOMARI] Stopped previous agent"; sleep 1; }

  dl "$KM_BIN" "https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-$ARCH" || exit 1
  chmod +x "$KM_BIN"
  # Endpoint / Token 通过环境变量只传给这一个进程，不出现在命令行(ps 看不到)
  export AGENT_ENDPOINT="$KOMARI_ENDPOINT" AGENT_TOKEN="$KOMARI_TOKEN"
  if [[ -z "$XRAY_ON" ]]; then
    echo "[KOMARI] No proxy protocol enabled, running the agent only, reporting to $KOMARI_ENDPOINT"
    exec "$KM_BIN"
  fi
  nohup "$KM_BIN" > "$BASE_DIR/komari-agent.log" 2>&1 &
  unset AGENT_ENDPOINT AGENT_TOKEN
  echo "[KOMARI] Agent started, reporting to $KOMARI_ENDPOINT"
fi

# ========== REALITY 密钥 ==========
# 私钥首次随机生成并落盘复用(不由 UUID 派生)；公钥由私钥推导，结果写入 REALITY_PRIVATE_KEY / REALITY_PUBLIC_KEY
REALITY_KEY_FILE="$BASE_DIR/.reality_key"

load_reality_keypair() {
  [[ -s "$REALITY_KEY_FILE" ]] || ( umask 077; openssl rand 32 | b64url > "$REALITY_KEY_FILE" )
  REALITY_PRIVATE_KEY=$(<"$REALITY_KEY_FILE")
  # 固定的 PKCS8 DER 头(X25519 专用) + raw private key，交给 openssl 推导出配对的 public key
  REALITY_PUBLIC_KEY=$({ printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'
                         printf '%s' "$REALITY_PRIVATE_KEY" | b64url_dec; } \
    | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | tail -c 32 | b64url)
  [[ -n "$REALITY_PUBLIC_KEY" ]] || { echo "[REALITY] Failed to derive public key, check that openssl is installed and $REALITY_KEY_FILE is valid" >&2; exit 1; }
}

if [[ ${#HEADS[@]} -gt 0 ]]; then
  load_reality_keypair
  echo "[REALITY] Private key: $REALITY_PRIVATE_KEY"
  echo "[REALITY] Public key: $REALITY_PUBLIC_KEY"
fi

# ========== WireGuard 密钥 ==========
# 服务端、客户端各一把私钥，首次随机生成并落盘复用(订阅不会因重启失效)；公钥由私钥推导(标准 base64)
wg_pub() {
  { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'
    printf '%s' "$1" | base64 -d; } | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | tail -c 32 | b64
}

load_wg_keys() {
  local f
  for f in .wg_server_key .wg_client_key; do
    [[ -s "$BASE_DIR/$f" ]] || ( umask 077; openssl rand 32 | b64 > "$BASE_DIR/$f" )
  done
  WG_SERVER_PRIVATE=$(<"$BASE_DIR/.wg_server_key"); WG_CLIENT_PRIVATE=$(<"$BASE_DIR/.wg_client_key")
  WG_SERVER_PUBLIC=$(wg_pub "$WG_SERVER_PRIVATE"); WG_CLIENT_PUBLIC=$(wg_pub "$WG_CLIENT_PRIVATE")
  [[ -n "$WG_SERVER_PUBLIC" && -n "$WG_CLIENT_PUBLIC" ]] || { echo "[WG] Failed to derive public key, check that openssl is installed and $BASE_DIR/.wg_*_key are valid" >&2; exit 1; }
}

[[ -n "$WG_PORT" ]] && load_wg_keys
SS_USERINFO=$(printf 'aes-256-gcm:%s' "$UUID" | b64url)

# ========== 链接里的连接地址(PUBLIC_IP) ==========
# 全部是 cloudflare 模式时链接用 CLOUDFLARE_IP，不需要本机地址；其余情况：
#   CERT_HOST 填 IP    -> 直接当作公网 IP，不再探测
#   CERT_HOST 填域名   -> 探测公网 IP；域名解析结果包含它(域名指向本服务器)时改用域名
#                         (域名走了 Cloudflare 代理等、解析不到本机 IP 时，仍用 IP)
IP_RE='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'

resolve_public_addr() {
  local ips
  if [[ "$CERT_HOST" =~ $IP_RE ]]; then
    PUBLIC_IP="$CERT_HOST"
  else
    # 只取 IPv4：IPv6 地址直接拼进 host:port 会让链接失效
    PUBLIC_IP=$(curl -4 -s -m 5 'https://one.one.one.one/cdn-cgi/trace' | sed -n 's/^ip=//p')
    if [[ -n "$CERT_HOST" && -n "$PUBLIC_IP" ]]; then
      ips="$(getent ahostsv4 "$CERT_HOST" 2>/dev/null | awk '{print $1}')"
      if grep -qxF "$PUBLIC_IP" <<< "$ips"; then
        echo "[NET] $CERT_HOST points to this server, using it instead of the IP"
        PUBLIC_IP="$CERT_HOST"
      fi
    fi
  fi
  [[ -n "$PUBLIC_IP" ]] || echo "[NET] Cannot determine the public address, links will be invalid (set CERT_HOST)" >&2
  echo "[NET] Address in links: $PUBLIC_IP"
}

if [[ "$ACTIVE_MODE" != "cloudflare" || ${#HEADS[@]} -gt 0 || -n "$HY2_PORT" || -n "$MIXED_PORT" || -n "$WG_PORT" ]]; then
  resolve_public_addr
fi

# ========== IPv6 egress check ==========
# 无 IPv6 出口时拒绝 IPv6 目标，让客户端立即回退 IPv4，而不是等拨号超时
IPV6_RULE='{"type": "field", "ip": ["::/0"], "outboundTag": "block"},'
if curl -6 -s -m 5 -o /dev/null 'https://one.one.one.one/cdn-cgi/trace'; then
  IPV6_RULE=''
  echo "[NET] IPv6 egress: available"
else
  echo "[NET] IPv6 egress: unavailable, blocking IPv6 destinations"
fi

# ========== TLS 证书(供 ws / Hysteria2 使用) ==========
# 证书获取方式(仅 DNS-01，通过 lego + Cloudflare API)：
#   CERT_HOST 为域名且填了 CF_TOKEN -> 申请可信证书；其余情况(留空 / 填 IP / 无 Token / 申请失败) -> 自签证书兜底
# 产出：CERT_FILE / KEY_FILE(证书与私钥路径)、TLS_SERVER_NAME(SNI)、
#   TLS_INSECURE(1=自签，订阅链接需跳过校验；0=可信)、TLS_PCS(自签证书的 SHA256 哈希，hex，链接里的 pcs；可信时为空)

# 生成自签证书：私钥用随机 RSA；已有且 30 天内不过期就复用，否则每次重启证书哈希都变，已导入的订阅会失效
# 用 -config 写 SAN，兼容不支持 -addext 的老版本 openssl
generate_self_signed_cert() {
  local cn="$1" dir="$BASE_DIR/.selfsigned" err
  mkdir -p "$dir"; chmod 700 "$dir"
  CERT_FILE="$dir/$cn.crt"; KEY_FILE="$dir/$cn.key"
  [[ -s "$CERT_FILE" && -s "$KEY_FILE" ]] && openssl x509 -in "$CERT_FILE" -noout -checkend 2592000 >/dev/null 2>&1 && return
  err=$(openssl req -x509 -nodes -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 3650 \
    -config <(printf '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=%s\n[v3]\nsubjectAltName=DNS:%s,DNS:localhost\n' "$cn" "$cn") \
    -extensions v3 2>&1)
  if [[ ! -s "$CERT_FILE" || ! -s "$KEY_FILE" ]]; then
    echo "[TLS] Failed to generate self-signed certificate, openssl output:" >&2
    echo "$err" >&2
    echo "[TLS] Check that openssl is installed. Aborting: xray cannot start without a certificate" >&2
    exit 1
  fi
  chmod 600 "$KEY_FILE"
}

# 用 lego 通过 DNS-01(Cloudflare)申请证书，成功返回 0 并写入 CERT_FILE / KEY_FILE；不占用任何端口
# 已有证书走 renew(剩余有效期 >30 天时 lego 自动跳过)，没有则走 run
issue_cert_for_host() {
  local host="$1" sub_cmd="run" out email ver
  local lego="$BASE_DIR/lego" lego_dir="$BASE_DIR/.lego"

  if [[ ! -x "$lego" ]]; then
    # /releases/latest 会 302 到 /releases/tag/vX.Y.Z，从最终 URL 取版本号(不走 API，无限流)
    ver=$(curl -fsSL -m 10 -o /dev/null -w '%{url_effective}' 'https://github.com/go-acme/lego/releases/latest' | sed -n 's|.*/tag/v\([0-9.]*\)$|\1|p')
    [[ -n "$ver" ]] || { echo "[TLS] Cannot detect latest lego version" >&2; return 1; }
    dl "$BASE_DIR/lego.tar.gz" "https://github.com/go-acme/lego/releases/download/v${ver}/lego_v${ver}_linux_${ARCH}.tar.gz" || return 1
    tar -zxf "$BASE_DIR/lego.tar.gz" -C "$BASE_DIR" lego
    rm -f "$BASE_DIR/lego.tar.gz"
    chmod +x "$lego" 2>/dev/null
    [[ -x "$lego" ]] || { echo "[TLS] Failed to extract lego" >&2; return 1; }
  fi
  mkdir -p "$lego_dir"; chmod 700 "$lego_dir"
  [[ -s "$lego_dir/certificates/$host.crt" ]] && sub_cmd="renew"

  # ACME 注册邮箱会发给 CA，用 UUID 的哈希片段，不泄露 UUID 本身
  email="cert-$(printf '%s' "$UUID" | sha256sum | cut -c1-12)@$host"
  # Token 只传给 lego 这一个进程，不进入脚本环境
  out=$(CF_DNS_API_TOKEN="$CF_TOKEN" "$lego" --path "$lego_dir" --email "$email" \
        --dns cloudflare --domains "$host" --accept-tos "$sub_cmd" 2>&1) || {
    echo "[TLS] DNS-01 (Cloudflare) certificate request failed, lego output:" >&2
    echo "$out" >&2
    return 1
  }
  CERT_FILE="$lego_dir/certificates/$host.crt"; KEY_FILE="$lego_dir/certificates/$host.key"
  [[ -s "$CERT_FILE" && -s "$KEY_FILE" ]]
}

setup_tls() {
  TLS_PCS=""
  TLS_SERVER_NAME="${CERT_HOST:-www.nazhumi.com}"
  if [[ -n "$CERT_HOST" && ! "$CERT_HOST" =~ $IP_RE && -n "$CF_TOKEN" ]] && issue_cert_for_host "$CERT_HOST"; then
    TLS_INSECURE=0
  else
    TLS_INSECURE=1
    echo "[TLS] No trusted certificate available, using self-signed certificate" >&2
    generate_self_signed_cert "$TLS_SERVER_NAME"
    # 新版 Xray 客户端已移除 allowInsecure，自签证书改用证书哈希固定(链接里的 pcs)
    TLS_PCS=$(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
  fi
  echo "[TLS] Server name: $TLS_SERVER_NAME, insecure: $TLS_INSECURE, cert: $CERT_FILE, key: $KEY_FILE"
}

[[ "$ACTIVE_MODE" == "ws" || -n "$HY2_PORT" ]] && setup_tls

# ========== cloudflared ==========
CLOUDFLARE_TUNNEL_HOSTNAME=""   # 隧道域名：不用填，启动 cloudflared 后从它的日志里取
if [[ "$ACTIVE_MODE" == "cloudflare" && -n "$CLOUDFLARE_TUNNEL_TOKEN" ]]; then
  CF_BIN="$BASE_DIR/cloudflared"

  # 脚本被重启时，按进程名先停掉上一次留下的 cloudflared，避免出现两个隧道进程
  pkill -x cloudflared && { echo "[CF] Stopped previous cloudflared"; sleep 1; }

  dl "$CF_BIN" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$ARCH" || exit 1
  chmod +x "$CF_BIN"
  "$CF_BIN" --version
  # Token 通过环境变量只传给这一个进程，不出现在命令行(ps 看不到)
  TUNNEL_TOKEN="$CLOUDFLARE_TUNNEL_TOKEN" nohup "$CF_BIN" --no-autoupdate tunnel run > "$BASE_DIR/cloudflared.log" 2>&1 &

  # 从日志取隧道的域名和回源端口：等隧道连上后，cloudflared 会打印一行后台下发的配置(ingress 规则)，
  # 取第一条「有具体域名(不含通配符 *)、Service 是 http://localhost:端口 或 http://127.0.0.1:端口」的规则
  # (日志里的引号带反斜杠，先还原)
  for _ in {1..30}; do
    cf_cfg=$(grep -a 'Updated to new configuration' "$BASE_DIR/cloudflared.log" | tail -1)
    [[ -n "$cf_cfg" ]] && break
    sleep 1
  done
  cf_cfg="${cf_cfg//\\\"/\"}"
  cf_rule=$(grep -oE '\{[^{}]*\}' <<< "$cf_cfg" | grep -E '"hostname":"[^"*]+"' | grep -E '"service":"http://(localhost|127\.0\.0\.1):[0-9]+"' | head -1)
  CLOUDFLARE_TUNNEL_HOSTNAME=$(grep -oE '"hostname":"[^"]+"' <<< "$cf_rule" | cut -d'"' -f4)
  cf_port=$(grep -oE '"service":"http://[^"]+"' <<< "$cf_rule" | grep -oE '[0-9]+"$' | tr -d '"')
  if [[ -n "$CLOUDFLARE_TUNNEL_HOSTNAME" && -n "$cf_port" ]]; then
    valid_port "$cf_port" || mode_error "Tunnel service port '$cf_port' read from the cloudflared log is not a valid port"
    FRONT_PORT=$((10#$cf_port))
    check_ports   # 端口变了，重新检查是否与 Reality 端口 / 内部保留端口冲突
    echo "[CF] From cloudflared log: hostname=$CLOUDFLARE_TUNNEL_HOSTNAME, tunnel service port=$FRONT_PORT"
  else
    CLOUDFLARE_TUNNEL_HOSTNAME=""
    echo "[CF] Cannot read hostname / port from $BASE_DIR/cloudflared.log (the tunnel needs a Public hostname without * and a Service like http://localhost:PORT)" >&2
  fi
fi

# ========== Xray ==========
XRAY_DIR="$BASE_DIR/xray"
XRAY_BIN="$XRAY_DIR/xray"
XRAY_CONF="$XRAY_DIR/config.json"
mkdir -p "$XRAY_DIR"

dl "$BASE_DIR/xray.zip" "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$([[ $ARCH == amd64 ]] && echo 64 || echo arm64-v8a).zip" || exit 1
# 解压：有 unzip 就用 unzip；没有(如精简容器)就用 node 自带的 zlib 解压，不依赖任何额外软件
if command -v unzip >/dev/null 2>&1; then
  unzip -oq "$BASE_DIR/xray.zip" -d "$XRAY_DIR"
else
  node - "$BASE_DIR/xray.zip" "$XRAY_DIR" <<'JS'
const fs = require('fs'), zlib = require('zlib'), path = require('path');
const [zip, dir] = process.argv.slice(-2);
const b = fs.readFileSync(zip), root = path.resolve(dir);
let e = b.length - 22;
while (e >= 0 && b.readUInt32LE(e) !== 0x06054b50) e--;
if (e < 0) { console.error('not a zip file'); process.exit(1); }
const n = b.readUInt16LE(e + 10);
let p = b.readUInt32LE(e + 16);
for (let i = 0; i < n; i++) {
  const method = b.readUInt16LE(p + 10), csize = b.readUInt32LE(p + 20);
  const nlen = b.readUInt16LE(p + 28), xlen = b.readUInt16LE(p + 30), clen = b.readUInt16LE(p + 32);
  const off = b.readUInt32LE(p + 42), name = b.toString('utf8', p + 46, p + 46 + nlen);
  p += 46 + nlen + xlen + clen;
  if (name.endsWith('/')) continue;
  const ds = off + 30 + b.readUInt16LE(off + 26) + b.readUInt16LE(off + 28);
  const data = b.subarray(ds, ds + csize);
  const out = method === 0 ? data : zlib.inflateRawSync(data);
  const f = path.resolve(root, name);
  if (!f.startsWith(root + path.sep)) continue;
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, out);
}
JS
fi
rm -f "$BASE_DIR/xray.zip"
chmod +x "$XRAY_BIN" 2>/dev/null
[[ -x "$XRAY_BIN" ]] || { echo "[XRAY] Binary not found after extraction: $XRAY_BIN" >&2; exit 1; }
# geoip.dat / geosite.dat 随 Xray 发行包一起解压在同一目录
export XRAY_LOCATION_ASSET="$XRAY_DIR"
"$XRAY_BIN" version

# 每个 inbound 共用的嗅探配置：只用于路由匹配，不改写目标地址
SNIFFING='"sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}'

# ---- stream 片段 ----
stream_tcp_plain() { echo '{"network": "tcp", "security": "none"}'; }
stream_ws() { echo "{\"network\": \"ws\", \"security\": \"none\", \"wsSettings\": {\"path\": \"$1\"}}"; }
# stream_reality [dest] [serverName]：默认伪装 www.iij.ad.jp；与 ws 共用端口时 dest 指向本机 ws 入口
stream_reality() {
  local dest="${1:-www.iij.ad.jp:443}" sni="${2:-www.iij.ad.jp}"
  echo "{\"network\": \"tcp\", \"security\": \"reality\", \"realitySettings\": {\"show\": false, \"dest\": \"$dest\", \"xver\": 0, \"serverNames\": [\"$sni\"], \"privateKey\": \"$REALITY_PRIVATE_KEY\", \"shortIds\": [\"cdcf853c\"]}}"
}
# tls_stream <network> <alpn> [额外字段]：ws 前置入口(tcp + http/1.1)和 Hysteria2(hysteria + h3)共用
tls_stream() {
  echo "{\"network\": \"$1\", \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"$TLS_SERVER_NAME\", \"alpn\": [\"$2\"], \"certificates\": [{\"certificateFile\": \"$CERT_FILE\", \"keyFile\": \"$KEY_FILE\"}]}$3}"
}

# ---- settings 片段：proto_settings <proto> [fallbacks JSON 数组] [flow] ----
proto_settings() {
  local fb="" flow=""
  [[ -n "$2" ]] && fb=", \"fallbacks\": $2"
  [[ -n "$3" ]] && flow=", \"flow\": \"$3\""
  case "$1" in
    vless)  echo "{\"clients\": [{\"id\": \"$UUID\", \"email\": \"misaka\"$flow}], \"decryption\": \"none\"$fb}" ;;
    vmess)  echo "{\"clients\": [{\"id\": \"$UUID\", \"email\": \"misaka\"}]}" ;;
    trojan) echo "{\"clients\": [{\"password\": \"$UUID\", \"email\": \"misaka\"}]$fb}" ;;
    shadowsocks) echo "{\"method\": \"aes-256-gcm\", \"password\": \"$UUID\", \"network\": \"tcp\"}" ;;
  esac
}

# inbound_json <tag> <listen> <port> <protocol> <settings> <stream>
inbound_json() {
  cat <<EOF
    {
      "tag": "$1",
      "listen": "$2",
      "port": $3,
      "protocol": "$4",
      "settings": $5,
      "streamSettings": $6,
      $SNIFFING
    }
EOF
}

# 前置入口(ws / cloudflare / 只回落)：监听 FRONT_PORT，按 HTTP 路径把 ws 流量回落给各内部 ws 入口，
# 其余请求回落给 FALLBACK_SITE(如果启用)。ws 带 TLS；cloudflare 和只回落是明文(cloudflare 的 TLS 由隧道终结)
# 与 Reality 共用端口时只听本机，由 Reality 转进来。前置入口本身也是一个 VLESS 入口，直接用 UUID
inbounds_front() {
  local p fb=() stream flisten="::" fport="$FRONT_PORT"
  for p in "${SHARED[@]}"; do
    fb+=("{\"path\": \"${WS_PATH[$p]}\", \"dest\": ${IPORT[$p]}, \"xver\": 0}")
    INB+=("$(inbound_json "$p-in" 127.0.0.1 "${IPORT[$p]}" "$p" "$(proto_settings "$p")" "$(stream_ws "${WS_PATH[$p]}")")")
  done
  [[ -n "$WEB_DEST" ]] && fb+=("{\"dest\": \"$WEB_DEST\", \"xver\": 0}")
  if [[ "$ACTIVE_MODE" == "ws" ]]; then stream=$(tls_stream tcp http/1.1); else stream=$(stream_tcp_plain); fi
  [[ -n "$SHARE_FRONT" ]] && { flisten=127.0.0.1; fport="$FRONT_IPORT"; }
  INB+=("$(inbound_json front-in "$flisten" "$fport" vless "$(proto_settings vless "[$(IFS=,; echo "${fb[*]}")]")" "$stream")")
}

# Reality 链：链头监听自己的端口并套 Reality；被回落到的协议依次监听 127.0.0.1 内部端口，由上一级回落过来
inbounds_chains() {
  local h p fb flow listen port stream
  for h in "${HEADS[@]}"; do
    for p in ${CHAIN[$h]}; do
      fb=""; flow=""
      [[ -n "${FB[$p]}" ]] && fb="[{\"dest\": ${IPORT[${FB[$p]}]}, \"xver\": 0}]"
      if [[ "$p" != "$h" ]]; then
        listen="127.0.0.1"; port="${IPORT[$p]}"; stream=$(stream_tcp_plain)
      else
        listen="::"; port="${HPORT[$h]}"
        if [[ -n "$SHARE_FRONT" && "$port" == "$FRONT_PORT" ]]; then
          stream=$(stream_reality "127.0.0.1:$FRONT_IPORT" "$TLS_SERVER_NAME")
        else
          stream=$(stream_reality)
        fi
        [[ "$p" == vless ]] && flow="$VLESS_FLOW"
      fi
      INB+=("$(inbound_json "$p-in" "$listen" "$port" "$p" "$(proto_settings "$p" "$fb" "$flow")" "$stream")")
    done
  done
}

# 收集所有 inbounds，以逗号分隔
collect_inbounds() {
  INB=()
  [[ -n "$FRONT_ON" ]] && inbounds_front
  inbounds_chains
  [[ -n "$HY2_PORT" ]] && INB+=("$(inbound_json hysteria2-in :: "$HY2_PORT" hysteria "{\"version\": 2, \"clients\": [{\"auth\": \"$UUID\", \"email\": \"misaka\"}]}" "$(tls_stream hysteria h3 ', "hysteriaSettings": {"version": 2}')")")
  [[ -n "$MIXED_PORT" ]] && INB+=("$(inbound_json mixed-in :: "$MIXED_PORT" socks "{\"auth\": \"password\", \"accounts\": [{\"user\": \"misaka\", \"pass\": \"$UUID\"}], \"udp\": false}" "$(stream_tcp_plain)")")
  [[ -n "$WG_PORT" ]] && INB+=("$(inbound_json wireguard-in :: "$WG_PORT" wireguard "{\"secretKey\": \"$WG_SERVER_PRIVATE\", \"peers\": [{\"publicKey\": \"$WG_CLIENT_PUBLIC\", \"allowedIPs\": [\"$WG_CLIENT_ADDR\"]}], \"mtu\": 1420}" null)")
  ( IFS=,; printf '%s\n' "${INB[*]}" )
}

# SIP003 v2ray-plugin 参数：ss_plugin_param <host> <path>(固定 tls)
ss_plugin_param() {
  local s="v2ray-plugin;tls;host=$1;path=$2;mux=0"
  s="${s//;/%3B}"; s="${s//=/%3D}"; s="${s//\//%2F}"
  echo "$s"
}

# reality 链接：reality_link <proto> <port>(VMess / SS 也用 URI 格式，客户端要能当作 Reality 节点导入)
reality_link() {
  local sni=www.iij.ad.jp rq
  [[ -n "$SHARE_FRONT" && "$2" == "$FRONT_PORT" ]] && sni="$TLS_SERVER_NAME"
  rq="security=reality&sni=$sni&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=tcp&sid=cdcf853c"
  case "$1" in
    vless)  echo "vless://$UUID@$PUBLIC_IP:$2?encryption=none${VLESS_FLOW:+&flow=$VLESS_FLOW}&$rq#$NAME_ENC-VLESS" ;;
    vmess)  echo "vmess://$UUID@$PUBLIC_IP:$2?encryption=auto&$rq#$NAME_ENC-VMESS" ;;
    trojan) echo "trojan://$UUID@$PUBLIC_IP:$2?$rq#$NAME_ENC-TROJAN" ;;
    shadowsocks) echo "ss://$SS_USERINFO@$PUBLIC_IP:$2?$rq#$NAME_ENC-SS" ;;
  esac
}

# Hysteria2 链接：自签证书时带 insecure=1(跳过证书校验，不再固定证书哈希)
hy2_link() {
  local q="sni=$TLS_SERVER_NAME"
  [[ "$TLS_INSECURE" == 1 ]] && q+="&insecure=1"
  echo "hysteria2://$UUID@$PUBLIC_IP:$HY2_PORT/?$q#$NAME_ENC-HY2"
}

# Mixed 链接：SOCKS5 和 HTTP 各一条(同一个端口、同一组账号密码)；明文传输，不加密
mixed_links() {
  echo "socks5://misaka:$UUID@$PUBLIC_IP:$MIXED_PORT#$NAME_ENC-SOCKS5"
  echo "http://misaka:$UUID@$PUBLIC_IP:$MIXED_PORT#$NAME_ENC-HTTP"
}

# WireGuard 链接(v2rayN / NekoBox / sing-box 等客户端可导入)
wg_link() {
  echo "wireguard://$(urlencode "$WG_CLIENT_PRIVATE")@$PUBLIC_IP:$WG_PORT?publickey=$(urlencode "$WG_SERVER_PUBLIC")&address=$(urlencode "$WG_CLIENT_ADDR")&mtu=1420#$NAME_ENC-WG"
}

# 标准 WireGuard 配置文件(wg-quick / WireGuard 官方客户端用)
wg_conf() {
  printf '[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n' \
    "$WG_CLIENT_PRIVATE" "$WG_CLIENT_ADDR" "$WG_SERVER_PUBLIC" "$PUBLIC_IP" "$WG_PORT"
}

# ws / cloudflare 链接的共同参数(连接地址、端口、host、名称后缀、证书校验)，按模式确定一次
#   cloudflare：连 CLOUDFLARE_IP:443(没设置 CLOUDFLARE_IP 就连从 cloudflared 日志探测到的隧道域名)，隧道的 Service 指向的本机端口从 cloudflared 日志里读取
#   ws：连 PUBLIC_IP:FRONT_PORT；自签证书用 pcs(证书哈希)固定，allowInsecure 保留给旧客户端
init_ws_params() {
  WS_IQ=""; WS_VM_INSECURE=0; WS_VM_EXTRA=""; WS_VM_PCS=""
  if [[ "$ACTIVE_MODE" == cloudflare ]]; then
    WS_ADDR="${CLOUDFLARE_IP:-$CLOUDFLARE_TUNNEL_HOSTNAME}"; WS_PORT=443; WS_HOST="$CLOUDFLARE_TUNNEL_HOSTNAME"; WS_SFX=CF
  else
    WS_ADDR="$PUBLIC_IP"; WS_PORT="$FRONT_PORT"; WS_HOST="$TLS_SERVER_NAME"; WS_SFX=WS
    WS_VM_INSECURE="$TLS_INSECURE"; WS_VM_PCS="$TLS_PCS"
    WS_VM_EXTRA=",\"allowInsecure\":$TLS_INSECURE,\"verify_cert\":$([[ "$TLS_INSECURE" == 1 ]] && echo false || echo true)"
    [[ "$TLS_INSECURE" == 1 ]] && WS_IQ="&allowInsecure=1&pcs=$TLS_PCS"
  fi
}

# 生成单个订阅节点链接
generate_node() {
  local proto="$1" path="${WS_PATH[$1]}" ed=""
  local enc="${path//\//%2F}"

  # Reality 链上的协议(链头或被回落到的)：都走链头的端口
  if [[ -n "${RPORT[$proto]}" ]]; then
    reality_link "$proto" "${RPORT[$proto]}"
    return
  fi

  if [[ "$ACTIVE_MODE" == cloudflare ]]; then
    if [[ -z "$CLOUDFLARE_TUNNEL_TOKEN" || -z "$CLOUDFLARE_TUNNEL_HOSTNAME" ]]; then
      echo "[MODE] cloudflare mode needs CLOUDFLARE_TUNNEL_TOKEN and a tunnel hostname found in the cloudflared log, no $proto link generated" >&2
      return
    fi
    # VMess 链接里的 ?ed=2560 为 0-RTT early data，Xray 服务端自动识别
    [[ "$proto" == vmess ]] && ed="?ed=2560"
  fi

  case "$proto" in
    vless)
      echo "vless://$UUID@$WS_ADDR:$WS_PORT?encryption=none&security=tls&sni=$WS_HOST&fp=chrome&type=ws&host=$WS_HOST&path=$enc$WS_IQ#$NAME_ENC-VLESS-$WS_SFX" ;;
    vmess)
      printf 'vmess://%s\n' "$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"none","net":"ws","type":"none","host":"%s","path":"%s","tls":"tls","sni":"%s","alpn":"","fp":"","insecure":"%s"%s,"vcn":"","pcs":"%s"}' \
        "$(json_escape "$NAME-VMESS-$WS_SFX")" "$WS_ADDR" "$WS_PORT" "$UUID" "$WS_HOST" "$path$ed" "$WS_HOST" "$WS_VM_INSECURE" "$WS_VM_EXTRA" "$WS_VM_PCS" | b64)" ;;
    trojan)
      echo "trojan://$UUID@$WS_ADDR:$WS_PORT?security=tls&sni=$WS_HOST&fp=chrome&type=ws&host=$WS_HOST&path=$enc$WS_IQ#$NAME_ENC-TROJAN-$WS_SFX" ;;
    shadowsocks)
      # v2ray-plugin 无法跳过证书校验，自签证书下该节点连不上，不输出
      if [[ "$ACTIVE_MODE" == ws && "$TLS_INSECURE" == 1 ]]; then
        echo "[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, set CERT_HOST + CF_TOKEN. No SS link generated" >&2
        return
      fi
      echo "ss://$SS_USERINFO@$WS_ADDR:$WS_PORT/?plugin=$(ss_plugin_param "$WS_HOST" "$path")#$NAME_ENC-SS-$WS_SFX" ;;
  esac
}

# ========== 生成 config.json ==========
# 先建空文件并收紧权限，再写入(里面有 UUID 和 Reality 私钥)
: > "$XRAY_CONF"
chmod 600 "$XRAY_CONF"
{
  cat <<'JSONEOF'
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": ["https+local://1.1.1.1/dns-query"],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
JSONEOF
  collect_inbounds
  cat <<JSONEOF
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
      ${IPV6_RULE}
      {"type": "field", "domain": ["geosite:cn", "geosite:category-ads-all"], "outboundTag": "block"},
      {"type": "field", "ip": ["geoip:cn"], "outboundTag": "block"}
    ]
  }
}
JSONEOF
} >> "$XRAY_CONF"

# 启动前校验配置
"$XRAY_BIN" run -test -c "$XRAY_CONF" || { echo "[XRAY] Config test failed, aborting" >&2; exit 1; }

# ========== 输出订阅 ==========
# 每行一个原始链接方便单条复制，末尾再给一份合并后的 base64 订阅，方便整段导入
[[ -n "$ACTIVE_MODE" ]] && init_ws_params
ALL_NODES=""
emit() { [[ -n "$1" ]] || return 0; echo "$1"; ALL_NODES+="$1"$'\n'; }
for proto in "${ENABLED[@]}"; do emit "$(generate_node "$proto")"; done
[[ -n "$HY2_PORT" ]] && emit "$(hy2_link)"
[[ -n "$MIXED_PORT" ]] && emit "$(mixed_links)"
[[ -n "$WG_PORT" ]] && emit "$(wg_link)"

echo ""
echo "=== Nodes ==="
echo -n "$ALL_NODES"
echo ""
echo "=== Subscription (base64) ==="
echo -n "$ALL_NODES" | b64
echo ""
if [[ -n "$WG_PORT" ]]; then
  echo ""
  echo "=== WireGuard config (wg-quick) ==="
  wg_conf
fi

# ========== 运行 ==========
# 证书在每次启动时 renew(剩余 >30 天会自动跳过)，长期不重启的话请定期重启本脚本
exec "$XRAY_BIN" run -c "$XRAY_CONF"
