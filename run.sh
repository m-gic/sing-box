#!/bin/bash

# ========== 用户配置 ==========
# *_MODE：留空 = 不启用，可选：
#   ws          TLS + WebSocket(CERT_HOST + CF_TOKEN 可得到可信证书，否则自签)，共用 PORT(PORT 留空时用默认端口 8000)
#   cloudflare  Cloudflare 隧道(明文 WS)，固定监听 8000，隧道的 Service 指向 http://localhost:8000，不受 PORT 影响
#   数字(端口)  Reality，四个协议都支持，端口写在“链尾”协议上：
#               没有被别的协议回落到 -> 独占该端口(raw reality)
#               被别的协议回落到(是链尾) -> 整条回落链对外监听这个端口
#   协议名      仅 VLESS、TROJAN：选择回落到哪个协议(vless / vmess / trojan / shadowsocks)
#               只写协议名，不写端口；链头、链中都这样写
#               被回落到的协议自动启用；链尾协议的 *_MODE 必须写端口
#               例：VLESS_MODE='trojan'  TROJAN_MODE='vmess'  VMESS_MODE='443'
#                   =>  VLESS -> Trojan -> VMess，对外监听 443
# ws / cloudflare 这一组必须是同一种模式，共用一个端口，不能与任何 Reality 端口重复
# 多条 Reality 链各自在链尾写不同端口，互不影响
# PORT：填了 -> ws 的前置入口改用此端口；留空 -> 用默认端口 8000(cloudflare 模式固定 8000，不看 PORT)
# FALLBACK_SITE：host 或 host:port，不写端口默认 80；PORT 和 FALLBACK_SITE 都填了就启用回落，与 ws / cloudflare 无关：
#       前置入口上不匹配 ws 路径的请求，原样转给该站点；没启用 ws / cloudflare 时，PORT 上只做回落(明文入口)
#       cloudflare 模式下 PORT 只是开关，回落挂在固定的 8000 上
#       转发的是解密后的明文 HTTP，所以要填对方的 HTTP 端口(通常是 80)，不能填 443
#       只填其中一个、或两个都留空 -> 不回落
# PORT 与某条 Reality 链的端口相同(需 ws 模式)：该端口上 Reality 和 ws 共用，也共用回落
#       Reality 认不出的流量转给本机 ws 入口，Reality 的 dest / serverNames 改用 CERT_HOST(留空为 www.nazhumi.com)
#       证书是自签时，探测者能看到证书和域名不符
# HYSTERIA2_MODE：数字(端口) = 启用 Hysteria2(UDP / QUIC)，留空 = 不启用
#       证书同 ws(可信或自签；自签时链接里带 insecure=1 和 pinSHA256)
#       走 UDP，和上面所有 TCP 端口互不冲突，可以和 Reality / ws 用同一个端口号
NAME=''
UUID=''
CLOUDFLARE_TUNNEL_TOKEN=''
CLOUDFLARE_TUNNEL_HOSTNAME=''
CLOUDFLARE_IP=''
PORT=''
FALLBACK_SITE=''
VLESS_MODE='trojan'
VMESS_MODE=''
TROJAN_MODE='vmess'
SHADOWSOCKS_MODE=''
HYSTERIA2_MODE=''
CERT_HOST=''   # 链接里的连接地址(填 IP 或域名)，同时是 ws / Hysteria2 证书的域名(SNI)；留空自动探测公网 IP
CF_TOKEN=''    # Cloudflare API Token(Zone:Read + DNS:Edit)：CERT_HOST 是域名且填了它，就用 DNS-01 申请可信证书(域名无需指向本机)；否则用自签证书

# ========== 基础环境 ==========
# 所有下载物和数据目录都放在脚本所在目录；通过管道 / 进程替换运行时退回当前目录
if [[ -f "${BASH_SOURCE[0]}" ]]; then BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; else BASE_DIR="$(pwd)"; fi
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
DEFAULT_FRONT_PORT=8000   # cloudflare 模式固定用它；ws 模式 PORT 留空时也用它
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
  [[ ${#ENABLED[@]} -gt 0 || -n "$HY2_PORT" ]] || mode_error "No protocol enabled: set at least one of VLESS_MODE / VMESS_MODE / TROJAN_MODE / SHADOWSOCKS_MODE / HYSTERIA2_MODE"
  for p in "${ENABLED[@]}"; do   # 既不在 ws / cloudflare 组、也没挂到任何 Reality 链上 = 回落成环
    in_array "$p" "${SHARED[@]}" || [[ -n "${RPORT[$p]}" ]] || mode_error "${p^^} is part of a fallback loop: the chain needs a head that no protocol falls back to"
  done
}

# 3. 前置入口：是否需要、监听哪个端口、是否与某条 Reality 链共用
plan_front() {
  local p
  [[ -n "$ACTIVE_MODE$WEB_DEST" ]] || return 0
  FRONT_ON=1
  # cloudflare 固定 8000；其它(ws / 只回落)用 PORT，留空 8000
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
  dup=$(printf '%s\n' "${ports[@]}" | sort | uniq -d | head -1)
  [[ -z "$dup" ]] || mode_error "Port $dup is used more than once: every Reality chain and the ws / cloudflare group (PORT) need different ports"
  for q in "${ports[@]}"; do
    in_array "$q" "${IPORT[@]}" "$FRONT_IPORT" && mode_error "Port $q conflicts with the internal fallback ports 40001-40005"
  done
}

parse_modes
build_chains
plan_front
check_ports

echo "[MODE] enabled=${ENABLED[*]}"
[[ -n "$ACTIVE_MODE" ]] && echo "[MODE] port $FRONT_PORT: $ACTIVE_MODE (${SHARED[*]})${SHARE_FRONT:+ shared with reality}"
for p in "${HEADS[@]}"; do echo "[MODE] port ${HPORT[$p]}: reality (${CHAIN[$p]// / -> })"; done

# 流控 xtls-rprx-vision：仅 VLESS 作为 Reality 链头(tcp + reality)时启用；
# VLESS 作为被回落的内部入口(明文 tcp)或走 ws 时不支持 Vision
VLESS_FLOW=''
in_array vless "${HEADS[@]}" && VLESS_FLOW='xtls-rprx-vision'

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
    [[ -n "$PUBLIC_IP" ]] || PUBLIC_IP="$CLOUDFLARE_IP"
    if [[ -n "$CERT_HOST" && -n "$PUBLIC_IP" ]]; then
      # 先用本机解析；没匹配上再用 DoH 兜底(避免本机 DNS 缓存或缺少 getent 导致误判)
      ips="$(getent ahostsv4 "$CERT_HOST" 2>/dev/null | awk '{print $1}')"
      grep -qxF "$PUBLIC_IP" <<< "$ips" || \
        ips="$(curl -s -m 5 -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$CERT_HOST&type=A" 2>/dev/null \
               | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+')"
      if grep -qxF "$PUBLIC_IP" <<< "$ips"; then
        echo "[NET] $CERT_HOST points to this server, using it instead of the IP"
        PUBLIC_IP="$CERT_HOST"
      fi
    fi
  fi
  [[ -n "$PUBLIC_IP" ]] || echo "[NET] Cannot determine the public address, links will be invalid (set CERT_HOST or CLOUDFLARE_IP)" >&2
  echo "[NET] Address in links: $PUBLIC_IP"
}

if [[ "$ACTIVE_MODE" != "cloudflare" || ${#HEADS[@]} -gt 0 || -n "$HY2_PORT" ]]; then
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
#   TLS_INSECURE(1=自签，订阅链接需跳过校验；0=可信)、TLS_PCS(自签证书的 SHA256 哈希，hex，链接里的 pcs / pinSHA256；可信时为空)

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
    [[ -n "$ver" ]] || { ver="4.35.2"; echo "[TLS] Cannot detect latest lego version, using $ver" >&2; }
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
if [[ "$ACTIVE_MODE" == "cloudflare" && -n "$CLOUDFLARE_TUNNEL_TOKEN" && -n "$CLOUDFLARE_TUNNEL_HOSTNAME" ]]; then
  CF_BIN="$BASE_DIR/cloudflared"
  CF_PID_FILE="$BASE_DIR/cloudflared.pid"

  # 脚本被重启时，先停掉上一次留下的 cloudflared，避免出现两个隧道进程
  if [[ -s "$CF_PID_FILE" ]]; then
    old_pid=$(<"$CF_PID_FILE")
    if kill -0 "$old_pid" 2>/dev/null && grep -q cloudflared "/proc/$old_pid/cmdline" 2>/dev/null; then
      echo "[CF] Stopping previous cloudflared (pid $old_pid)"
      kill "$old_pid"
      sleep 1
    fi
  fi

  dl "$CF_BIN" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$ARCH" || exit 1
  chmod +x "$CF_BIN"
  "$CF_BIN" --version
  # Token 通过环境变量只传给这一个进程，不出现在命令行(ps 看不到)
  TUNNEL_TOKEN="$CLOUDFLARE_TUNNEL_TOKEN" nohup "$CF_BIN" --no-autoupdate tunnel run > "$BASE_DIR/cloudflared.log" 2>&1 &
  echo $! > "$CF_PID_FILE"
fi

# ========== Xray ==========
XRAY_DIR="$BASE_DIR/xray"
XRAY_BIN="$XRAY_DIR/xray"
XRAY_CONF="$XRAY_DIR/config.json"
mkdir -p "$XRAY_DIR"

dl "$BASE_DIR/xray.zip" "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$([[ $ARCH == amd64 ]] && echo 64 || echo arm64-v8a).zip" || exit 1
if command -v unzip >/dev/null 2>&1; then
  unzip -oq "$BASE_DIR/xray.zip" -d "$XRAY_DIR"
else
  python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$BASE_DIR/xray.zip" "$XRAY_DIR"
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

# Hysteria2 链接：自签证书时带 insecure=1 和 pinSHA256(证书哈希，hex)
hy2_link() {
  local q="sni=$TLS_SERVER_NAME"
  [[ "$TLS_INSECURE" == 1 ]] && q+="&insecure=1&pinSHA256=$TLS_PCS"
  echo "hysteria2://$UUID@$PUBLIC_IP:$HY2_PORT/?$q#$NAME_ENC-HY2"
}

# ws / cloudflare 链接的共同参数(连接地址、端口、host、名称后缀、证书校验)，按模式确定一次
#   cloudflare：连 CLOUDFLARE_IP:443，隧道的 Service 要指向 http://localhost:8000
#   ws：连 PUBLIC_IP:FRONT_PORT；自签证书用 pcs(证书哈希)固定，allowInsecure 保留给旧客户端
init_ws_params() {
  WS_IQ=""; WS_VM_INSECURE=0; WS_VM_EXTRA=""; WS_VM_PCS=""
  if [[ "$ACTIVE_MODE" == cloudflare ]]; then
    WS_ADDR="$CLOUDFLARE_IP"; WS_PORT=443; WS_HOST="$CLOUDFLARE_TUNNEL_HOSTNAME"; WS_SFX=CF
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
      echo "[MODE] cloudflare mode needs CLOUDFLARE_TUNNEL_TOKEN and CLOUDFLARE_TUNNEL_HOSTNAME, no $proto link generated" >&2
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

echo ""
echo "=== Nodes ==="
echo -n "$ALL_NODES"
echo ""
echo "=== Subscription (base64) ==="
echo -n "$ALL_NODES" | b64
echo ""

# ========== 运行 ==========
# 证书在每次启动时 renew(剩余 >30 天会自动跳过)，长期不重启的话请定期重启本脚本
exec "$XRAY_BIN" run -c "$XRAY_CONF"
