#!/bin/bash

# ========== 用户配置 ==========
# *_MODE：留空 = 不启用，可选：
#   ws          TLS + WebSocket(需域名证书)，共用 PORT
#   cloudflare  Cloudflare 隧道(明文 WS)，共用 PORT
#   数字(端口)  Reality，独占该端口(raw reality)，四个协议都支持
#   协议名      仅 VLESS、TROJAN：选择回落到哪个协议(vless / vmess / trojan / shadowsocks)
#               只写协议名：Reality 监听 PORT(和 cloudflare 一样用 PORT)，认不出的流量回落给该协议
#               端口:协议名：想单独指定端口时用，如 VLESS_MODE='443:trojan'
#               被回落到的协议自动启用，不用再填它的 *_MODE；它自己如果也要继续回落，只写协议名即可
#               例：VLESS_MODE='trojan'  TROJAN_MODE='vmess'  =>  VLESS -> Trojan -> VMess，都在 PORT 上
# PORT 同一时间只能给一处用：ws / cloudflare 这一组(必须是同一种模式)，或一条只写协议名的 Reality 链
# 其余 Reality 链用 端口 或 端口:协议名 各自独立，互不影响
NAME=''
UUID=''
CLOUDFLARE_TUNNEL_TOKEN=''
CLOUDFLARE_TUNNEL_HOSTNAME=''
CLOUDFLARE_IP=''
PORT=8000
VLESS_MODE=''
VMESS_MODE=''
TROJAN_MODE=''
SHADOWSOCKS_MODE=''
CERT_HOST=''
CF_TOKEN=''

# ========== 基础环境 ==========
# 所有下载物和数据目录都放在脚本所在目录；通过管道 / 进程替换运行时退回当前目录
if [[ -f "${BASH_SOURCE[0]}" ]]; then
  BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  BASE_DIR="$(pwd)"
fi
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

# dl <输出文件> <URL>：失败(含 HTTP 错误)返回 1，先写 .part 再改名，避免留下半截文件
dl() {
  if curl -fsSL --retry 3 --connect-timeout 10 -o "$1.part" "$2" && mv -f "$1.part" "$1"; then
    return 0
  fi
  rm -f "$1.part"
  echo "[DL] Download failed: $2" >&2
  return 1
}

NAME_ENC=$(urlencode "$NAME")

# ========== 协议与模式 ==========
PROTOS=(vless vmess trojan shadowsocks)
# 各协议的 ws 路径，以及回落用的内部端口(仅监听 127.0.0.1；不用 unix socket，因为 Xray 的 Shadowsocks 入站不支持)
# 内部端口 40001-40004 不能被 PORT 或 *_MODE 里的端口占用
declare -A WS_PATH=([vless]=/misaka-vless [vmess]=/misaka-vmess [trojan]=/misaka-trojan [shadowsocks]=/misaka-ss)
declare -A IPORT=([vless]=40001 [vmess]=40002 [trojan]=40003 [shadowsocks]=40004)
declare -A HPORT   # Reality 链头 -> 监听端口
declare -A FB      # 协议 -> 它回落到的协议
declare -A RPORT   # Reality 链上的每个协议 -> 对外端口(即链头端口)，生成链接用

# 校验各协议的模式，得到：
#   ENABLED        所有启用的协议(含被回落到而自动启用的)，订阅链接按此顺序输出
#   SHARED         采用 ws / cloudflare 的协议，ACTIVE_MODE 为它们统一的模式(可能为空)，共用 PORT
#   HEADS          Reality 链头；HPORT 是各自的监听端口，FB 是回落关系，RPORT 是各协议的对外端口
prepare_protocols() {
  ENABLED=(); SHARED=(); HEADS=(); ACTIVE_MODE=""; HPORT=(); FB=(); RPORT=()
  local -A PARENT=() EXPLICIT=()
  local port_re='^([0-9]+)(:([a-z]+))?$'
  local p v m t q port modes=() bare_heads=() ports=() dup chain

  # 1. 解析每个协议的 MODE
  for p in "${PROTOS[@]}"; do
    v="${p^^}_MODE"; m="${!v}"; t=""
    [[ -n "$m" ]] || continue
    EXPLICIT[$p]=1

    if [[ "$m" == ws || "$m" == cloudflare ]]; then
      SHARED+=("$p")
      in_array "$m" "${modes[@]}" || modes+=("$m")
      continue
    elif [[ "$m" =~ $port_re ]]; then
      port=$((10#${BASH_REMATCH[1]})); t="${BASH_REMATCH[3]}"
      (( port >= 1 && port <= 65535 )) || mode_error "$v='$m': port must be 1-65535"
      HPORT[$p]=$port
    elif [[ "$m" =~ ^[a-z]+$ ]]; then
      t="$m"
    else
      mode_error "$v='$m' is invalid (expected: ws / cloudflare / a port / port:protocol / a protocol name, or empty to disable)"
    fi

    [[ -n "$t" ]] || continue
    in_array "$t" "${PROTOS[@]}" || mode_error "$v='$m': '$t' is not valid (expected ws / cloudflare / a port, or a fallback protocol: ${PROTOS[*]})"
    [[ "$t" != "$p" ]] || mode_error "$v='$m': a protocol cannot fall back to itself"
    [[ "$p" == vless || "$p" == trojan ]] || mode_error "$v='$m': ${p^^} has no fallback ability, only VLESS and TROJAN can choose a fallback"
    FB[$p]="$t"
  done

  # 2. 回落关系：每个协议只能被一个协议回落到；被回落到的协议不能再有自己的端口 / ws / cloudflare
  for p in "${!FB[@]}"; do
    t="${FB[$p]}"
    [[ -z "${PARENT[$t]}" ]] || mode_error "${t^^} is the fallback of both ${PARENT[$t]^^} and ${p^^}, it can only have one"
    PARENT[$t]="$p"
    if [[ -n "${EXPLICIT[$t]}" && ( -z "${FB[$t]}" || -n "${HPORT[$t]}" ) ]]; then
      mode_error "${t^^} is already the fallback of ${p^^}: clear ${t^^}_MODE (or, to keep falling back further, make it just a protocol name)"
    fi
  done

  # 3. 链头：填了端口的；以及只写协议名、且没有被别人回落到的(监听 PORT)。再顺着回落关系记下链上每个协议的对外端口
  for p in "${PROTOS[@]}"; do
    [[ -n "${EXPLICIT[$p]}" || -n "${PARENT[$p]}" ]] && ENABLED+=("$p")
    [[ -n "${EXPLICIT[$p]}" ]] || continue
    if [[ -z "${HPORT[$p]}" && -n "${FB[$p]}" && -z "${PARENT[$p]}" ]]; then
      HPORT[$p]="$PORT"; bare_heads+=("$p")
    fi
    [[ -n "${HPORT[$p]}" ]] && HEADS+=("$p")
  done
  for p in "${HEADS[@]}"; do
    q="$p"
    while [[ -n "$q" ]]; do RPORT[$q]="${HPORT[$p]}"; q="${FB[$q]}"; done
  done

  [[ ${#ENABLED[@]} -gt 0 ]] || mode_error "No protocol enabled: set at least one of VLESS_MODE / VMESS_MODE / TROJAN_MODE / SHADOWSOCKS_MODE"
  [[ ${#modes[@]} -le 1 ]] || mode_error "Protocols using ws / cloudflare share PORT, so they must use the same mode (got: ${modes[*]})"
  ACTIVE_MODE="${modes[0]}"
  for p in "${ENABLED[@]}"; do   # 既不在 ws / cloudflare 组、也没挂到任何 Reality 链上 = 回落成环
    in_array "$p" "${SHARED[@]}" || [[ -n "${RPORT[$p]}" ]] || mode_error "${p^^} is part of a fallback loop: some protocol in it must be the chain head (give it a port)"
  done

  # 4. 端口检查：PORT 有效；各 Reality 监听端口与 PORT(ws / cloudflare 用到时)互不重复；不占用内部回落端口
  if [[ -n "$ACTIVE_MODE" || ${#bare_heads[@]} -gt 0 ]]; then
    [[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || mode_error "PORT='$PORT' is not a valid port"
  fi
  for p in "${HEADS[@]}"; do ports+=("${HPORT[$p]}"); done
  [[ -n "$ACTIVE_MODE" ]] && ports+=("$PORT")
  dup=$(printf '%s\n' "${ports[@]}" | sort | uniq -d | head -1)
  [[ -z "$dup" ]] || mode_error "Port $dup is used more than once: every Reality chain and the ws / cloudflare group need different ports (a protocol that only names a fallback uses PORT; give it a port instead, e.g. '443:trojan')"
  if [[ -n "$ACTIVE_MODE" || ${#PARENT[@]} -gt 0 ]]; then
    for q in "${ports[@]}"; do
      in_array "$q" "${IPORT[@]}" && mode_error "Port $q conflicts with the internal fallback ports 40001-40004"
    done
  fi

  echo "[MODE] enabled=${ENABLED[*]}"
  [[ -n "$ACTIVE_MODE" ]] && echo "[MODE] port $PORT: $ACTIVE_MODE (${SHARED[*]})"
  for p in "${HEADS[@]}"; do
    chain="$p"; q="$p"
    while [[ -n "${FB[$q]}" ]]; do q="${FB[$q]}"; chain+=" -> $q"; done
    echo "[MODE] port ${HPORT[$p]}: reality ($chain)"
  done
}

prepare_protocols

# ========== REALITY 密钥 ==========
# 私钥首次随机生成并落盘复用(不再由 UUID 派生，知道 UUID 的人无法推出私钥)；公钥由私钥推导
# 结果写入 REALITY_PRIVATE_KEY / REALITY_PUBLIC_KEY
REALITY_KEY_FILE="$BASE_DIR/.reality_key"

load_reality_keypair() {
  if [[ ! -s "$REALITY_KEY_FILE" ]]; then
    ( umask 077; openssl rand 32 | b64url > "$REALITY_KEY_FILE" )
  fi
  REALITY_PRIVATE_KEY=$(<"$REALITY_KEY_FILE")
  # 固定的 PKCS8 DER 头(X25519 专用) + raw private key，交给 openssl 推导出配对的 public key
  REALITY_PUBLIC_KEY=$({ printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'
                         printf '%s' "$REALITY_PRIVATE_KEY" | b64url_dec; } \
    | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | tail -c 32 | b64url)
  if [[ -z "$REALITY_PUBLIC_KEY" ]]; then
    echo "[REALITY] Failed to derive public key, check that openssl is installed and $REALITY_KEY_FILE is valid" >&2
    exit 1
  fi
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

if [[ "$ACTIVE_MODE" != "cloudflare" || ${#HEADS[@]} -gt 0 ]]; then
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

# ========== TLS 证书(供 ws 模式使用) ==========
# 证书获取方式(仅 DNS-01，通过 lego + Cloudflare API)：
#   CERT_HOST 为域名且 CF_TOKEN 有效 -> DNS-01 申请正式证书(域名无需指向本机)
#   其余情况(留空/填IP/无Token/申请失败) -> 自签证书兜底
# 最终产出：
#   CERT_FILE / KEY_FILE  证书与私钥路径
#   TLS_SERVER_NAME       TLS server_name / SNI
#   TLS_INSECURE          1=自签证书(订阅链接需跳过校验)，0=可信证书
#   TLS_PCS               自签证书的 SHA256 哈希(hex)，用于链接里的 pcs；可信证书时为空

# 生成自签证书。私钥用随机 RSA，不像 REALITY 早期那样由 UUID 派生，否则任何拿到 UUID 的人都能算出同一把私钥。
# 用 -config 写 SAN，兼容不支持 -addext 的老版本 openssl。
generate_self_signed_cert() {
  local cn="$1" dir="$BASE_DIR/.selfsigned" err
  mkdir -p "$dir"
  chmod 700 "$dir"
  CERT_FILE="$dir/$cn.crt"
  KEY_FILE="$dir/$cn.key"

  # 已有且 30 天内不过期就复用：链接里的 pcs 是证书哈希，每次重启都换证书会让已导入的订阅失效
  if [[ -s "$CERT_FILE" && -s "$KEY_FILE" ]] && openssl x509 -in "$CERT_FILE" -noout -checkend 2592000 >/dev/null 2>&1; then
    return
  fi

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

# 用 lego 通过 DNS-01(Cloudflare)申请证书，成功返回 0 并写入 CERT_FILE / KEY_FILE
# 不占用任何端口；Token 需同时有 Zone:Read + DNS:Edit 权限。
# 已有证书走 renew(剩余有效期 >30 天时 lego 自动跳过)，没有则走 run。
issue_cert_for_host() {
  local host="$1" sub_cmd="run" out email
  local lego="$BASE_DIR/lego" lego_dir="$BASE_DIR/.lego"

  if [[ ! -x "$lego" ]]; then
    local ver
    # /releases/latest 会 302 到 /releases/tag/vX.Y.Z，从最终 URL 取版本号(不走 API，无限流)
    ver=$(curl -fsSL -m 10 -o /dev/null -w '%{url_effective}' 'https://github.com/go-acme/lego/releases/latest' | sed -n 's|.*/tag/v\([0-9.]*\)$|\1|p')
    [[ -n "$ver" ]] || { ver="4.35.2"; echo "[TLS] Cannot detect latest lego version, using $ver" >&2; }
    dl "$BASE_DIR/lego.tar.gz" "https://github.com/go-acme/lego/releases/download/v${ver}/lego_v${ver}_linux_${ARCH}.tar.gz" || return 1
    tar -zxf "$BASE_DIR/lego.tar.gz" -C "$BASE_DIR" lego
    rm -f "$BASE_DIR/lego.tar.gz"
    chmod +x "$lego" 2>/dev/null
    [[ -x "$lego" ]] || { echo "[TLS] Failed to extract lego" >&2; return 1; }
  fi
  mkdir -p "$lego_dir"
  chmod 700 "$lego_dir"
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

  CERT_FILE="$lego_dir/certificates/$host.crt"
  KEY_FILE="$lego_dir/certificates/$host.key"
  [[ -s "$CERT_FILE" && -s "$KEY_FILE" ]]
}

setup_tls() {
  TLS_PCS=""
  TLS_SERVER_NAME="${CERT_HOST:-www.nazhumi.com}"

  # DNS-01 只能为域名签发证书，IP / 留空 / 申请失败都回退自签
  if [[ -n "$CERT_HOST" && ! "$CERT_HOST" =~ $IP_RE ]] && issue_cert_for_host "$CERT_HOST"; then
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

# 只有 ws 模式需要证书
[[ "$ACTIVE_MODE" == "ws" ]] && setup_tls

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
stream_reality() {
  echo "{\"network\": \"tcp\", \"security\": \"reality\", \"realitySettings\": {\"show\": false, \"dest\": \"www.iij.ad.jp:443\", \"xver\": 0, \"serverNames\": [\"www.iij.ad.jp\"], \"privateKey\": \"$REALITY_PRIVATE_KEY\", \"shortIds\": [\"cdcf853c\"]}}"
}
stream_tls() {
  echo "{\"network\": \"tcp\", \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"$TLS_SERVER_NAME\", \"alpn\": [\"http/1.1\"], \"certificates\": [{\"certificateFile\": \"$CERT_FILE\", \"keyFile\": \"$KEY_FILE\"}]}}"
}

# ---- settings 片段：proto_settings <proto> [fallbacks JSON 数组] ----
proto_settings() {
  local fb=""
  [[ -n "$2" ]] && fb=", \"fallbacks\": $2"
  case "$1" in
    vless)  echo "{\"clients\": [{\"id\": \"$UUID\", \"email\": \"misaka\"}], \"decryption\": \"none\"$fb}" ;;
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

# ws / cloudflare：前置入口监听 PORT，按 HTTP 路径把 ws 流量回落给各内部 ws 入口
#   ws          前置入口带 TLS(证书由 setup_tls 决定)
#   cloudflare  前置入口明文(TLS 由 Cloudflare 终结)
# 前置入口本身也是一个 VLESS 入口，直接用 UUID
inbounds_front() {
  local p fb=() stream
  for p in "${SHARED[@]}"; do
    fb+=("{\"path\": \"${WS_PATH[$p]}\", \"dest\": ${IPORT[$p]}, \"xver\": 0}")
    INB+=("$(inbound_json "$p-in" 127.0.0.1 "${IPORT[$p]}" "$p" "$(proto_settings "$p")" "$(stream_ws "${WS_PATH[$p]}")")")
  done
  if [[ "$ACTIVE_MODE" == "ws" ]]; then stream=$(stream_tls); else stream=$(stream_tcp_plain); fi
  INB+=("$(inbound_json front-in :: "$PORT" vless "$(proto_settings vless "[$(IFS=,; echo "${fb[*]}")]")" "$stream")")
}

# Reality 链：链头监听自己的端口并套 Reality；被回落到的协议依次监听 127.0.0.1 内部端口，由上一级回落过来
inbounds_chains() {
  local h p fb listen port stream
  for h in "${HEADS[@]}"; do
    p="$h"
    while [[ -n "$p" ]]; do
      fb=""
      [[ -n "${FB[$p]}" ]] && fb="[{\"dest\": ${IPORT[${FB[$p]}]}, \"xver\": 0}]"
      if [[ "$p" == "$h" ]]; then
        listen="::"; port="${HPORT[$h]}"; stream=$(stream_reality)
      else
        listen="127.0.0.1"; port="${IPORT[$p]}"; stream=$(stream_tcp_plain)
      fi
      INB+=("$(inbound_json "$p-in" "$listen" "$port" "$p" "$(proto_settings "$p" "$fb")" "$stream")")
      p="${FB[$p]}"
    done
  done
}

# 收集所有 inbounds，以逗号分隔
collect_inbounds() {
  INB=()
  [[ -n "$ACTIVE_MODE" ]] && inbounds_front
  inbounds_chains
  ( IFS=,; printf '%s\n' "${INB[*]}" )
}

# SIP003 v2ray-plugin 参数：ss_plugin_param <host> <path>(固定 tls)
ss_plugin_param() {
  local s="v2ray-plugin;tls;host=$1;path=$2;mux=0"
  s="${s//;/%3B}"; s="${s//=/%3D}"; s="${s//\//%2F}"
  echo "$s"
}

# reality 链接：reality_link <proto> <port>
# VMess / SS 的 Reality 链接用 URI 格式，客户端要能把它当作 Reality 节点导入
reality_link() {
  local rq="security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=tcp&sid=cdcf853c"
  case "$1" in
    vless)  echo "vless://$UUID@$PUBLIC_IP:$2?encryption=none&$rq#$NAME_ENC-VLESS" ;;
    vmess)  echo "vmess://$UUID@$PUBLIC_IP:$2?encryption=auto&$rq#$NAME_ENC-VMESS" ;;
    trojan) echo "trojan://$UUID@$PUBLIC_IP:$2?$rq#$NAME_ENC-TROJAN" ;;
    shadowsocks) echo "ss://$SS_USERINFO@$PUBLIC_IP:$2?$rq#$NAME_ENC-SS" ;;
  esac
}

# 生成单个订阅节点链接
generate_node() {
  local proto="$1" path="${WS_PATH[$1]}" addr lport h sfx ed="" ti=0 pcs="" iq="" extra=""

  # Reality 链上的协议(链头或被回落到的)：都走链头的端口
  if [[ -n "${RPORT[$proto]}" ]]; then
    reality_link "$proto" "${RPORT[$proto]}"
    return
  fi

  # ws 和 cloudflare 都是 "TLS + WebSocket" 链接，只有连接地址、SNI 和证书校验方式不同
  if [[ "$ACTIVE_MODE" == "cloudflare" ]]; then
    if [[ -z "$CLOUDFLARE_TUNNEL_TOKEN" || -z "$CLOUDFLARE_TUNNEL_HOSTNAME" ]]; then
      echo "[MODE] cloudflare mode needs CLOUDFLARE_TUNNEL_TOKEN and CLOUDFLARE_TUNNEL_HOSTNAME, no $proto link generated" >&2
      return
    fi
    # 隧道的 Service 要指向 http://localhost:$PORT；VMess 链接里的 ?ed=2560 为 0-RTT early data，Xray 服务端自动识别
    addr="$CLOUDFLARE_IP"; lport=443; h="$CLOUDFLARE_TUNNEL_HOSTNAME"; sfx=CF
    [[ "$proto" == "vmess" ]] && ed="?ed=2560"
  else
    addr="$PUBLIC_IP"; lport="$PORT"; h="$TLS_SERVER_NAME"; sfx=WS
    # 新版 Xray 客户端已移除 allowInsecure，自签证书用 pcs(证书哈希)；allowInsecure 保留给旧客户端
    extra=',"allowInsecure":'"$TLS_INSECURE"',"verify_cert":'"$([[ "$TLS_INSECURE" == 1 ]] && echo false || echo true)"
    ti="$TLS_INSECURE"; pcs="$TLS_PCS"
    [[ "$TLS_INSECURE" == "1" ]] && iq="&allowInsecure=1&pcs=$TLS_PCS"
  fi
  local enc="${path//\//%2F}"

  case "$proto" in
    vless)
      echo "vless://$UUID@$addr:$lport?encryption=none&security=tls&sni=$h&fp=chrome&type=ws&host=$h&path=$enc$iq#$NAME_ENC-VLESS-$sfx" ;;
    vmess)
      printf 'vmess://%s\n' "$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"none","net":"ws","type":"none","host":"%s","path":"%s","tls":"tls","sni":"%s","alpn":"","fp":"","insecure":"%s"%s,"vcn":"","pcs":"%s"}' \
        "$(json_escape "$NAME-VMESS-$sfx")" "$addr" "$lport" "$UUID" "$h" "$path$ed" "$h" "$ti" "$extra" "$pcs" | b64)" ;;
    trojan)
      echo "trojan://$UUID@$addr:$lport?security=tls&sni=$h&fp=chrome&type=ws&host=$h&path=$enc$iq#$NAME_ENC-TROJAN-$sfx" ;;
    shadowsocks)
      # v2ray-plugin 无法跳过证书校验，自签证书下该节点连不上，不输出
      if [[ "$ACTIVE_MODE" == "ws" && "$TLS_INSECURE" == "1" ]]; then
        echo "[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, set CERT_HOST + CF_TOKEN. No SS link generated" >&2
        return
      fi
      echo "ss://$SS_USERINFO@$addr:$lport/?plugin=$(ss_plugin_param "$h" "$path")#$NAME_ENC-SS-$sfx" ;;
  esac
}

# ========== 生成 config.json ==========
# 先建空文件并收紧权限，再写入(里面有 UUID 和 Reality 私钥)
: > "$XRAY_CONF"
chmod 600 "$XRAY_CONF"

cat >> "$XRAY_CONF" <<'JSONEOF'
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

collect_inbounds >> "$XRAY_CONF"

cat >> "$XRAY_CONF" <<JSONEOF
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

# 启动前校验配置
if ! "$XRAY_BIN" run -test -c "$XRAY_CONF"; then
  echo "[XRAY] Config test failed, aborting" >&2
  exit 1
fi

# ========== 输出订阅 ==========
# 每行一个原始链接方便单条复制，末尾再给一份合并后的 base64 订阅，方便整段导入
ALL_NODES=""
for proto in "${ENABLED[@]}"; do
  node=$(generate_node "$proto")
  [[ -z "$node" ]] && continue
  echo "$node"
  ALL_NODES+="$node"$'\n'
done

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
