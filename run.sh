#!/bin/bash

# ========== 用户配置 ==========
export NAME=''
export UUID=''
export CLOUDFLARE_TUNNEL_TOKEN=''
export CLOUDFLARE_TUNNEL_HOSTNAME=''
export CLOUDFLARE_IP=''
export CLOUDFLARE_PORT=8000
export VLESS_PORT=''
export VMESS_PORT=''
export TROJAN_PORT=''
export SHADOWSOCKS_PORT=''
export CERT_HOST=''
export CF_TOKEN=''

# ========== REALITY 密钥 ==========
# 由种子确定性派生 X25519 密钥对，结果写入 REALITY_PRIVATE_KEY / REALITY_PUBLIC_KEY
generate_reality_keypair() {
  local seed="$1"
  local priv_raw="/tmp/.reality_priv_raw.bin"
  local priv_der="/tmp/.reality_priv.der"
  local pub_der="/tmp/.reality_pub.der"

  # 32 字节 raw private key
  printf '%s' "$seed" | openssl dgst -sha256 -binary > "$priv_raw"

  # 固定的 PKCS8 DER 头(X25519 专用) + raw private key
  { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'; cat "$priv_raw"; } > "$priv_der"

  # 用 openssl 从 private key 推导出配对的 public key
  openssl pkey -in "$priv_der" -inform DER -pubout -outform DER -out "$pub_der" 2>/dev/null

  # base64url 编码(无 padding)
  REALITY_PRIVATE_KEY=$(base64 -w0 "$priv_raw" | tr '+/' '-_' | tr -d '=')
  REALITY_PUBLIC_KEY=$(tail -c 32 "$pub_der" | base64 -w0 | tr '+/' '-_' | tr -d '=')

  rm -f "$priv_raw" "$priv_der" "$pub_der"
}

generate_reality_keypair "$UUID"
echo "[REALITY] Private key: $REALITY_PRIVATE_KEY"
echo "[REALITY] Public key: $REALITY_PUBLIC_KEY"

# ========== 公网 IP ==========
PUBLIC_IP=$(curl -s 'https://one.one.one.one/cdn-cgi/trace' | grep -oP '^ip=\K[^$]+' || echo "$CLOUDFLARE_IP")
echo "[NET] Public IP: $PUBLIC_IP"

# ========== TLS 证书(供 vmess 使用) ==========
# 证书获取方式(仅 DNS-01，通过 lego + Cloudflare API)：
#   CERT_HOST 为域名且 CF_TOKEN 有效 -> DNS-01 申请正式证书(域名无需指向本机)
#   其余情况(留空/填IP/无Token/申请失败) -> 自签证书兜底
# 最终产出：
#   CERT_FILE / KEY_FILE  证书与私钥路径
#   TLS_SERVER_NAME       TLS server_name / SNI
#   TLS_INSECURE          1=自签证书(订阅链接需跳过校验)，0=可信证书
mkdir -p "/tmp/tls_certs"

# 生成自签证书
# 私钥用随机 RSA，不像 REALITY 那样由 UUID 派生，否则任何拿到 UUID 的人都能算出同一把私钥。
# 用 -config + extfile 写 SAN，兼容 openssl 1.1.1 以下(不支持 -addext)。
generate_self_signed_cert() {
  local cn="$1"
  local ext_conf="/tmp/tls_certs/openssl_ext.cnf"

  cat > "$ext_conf" <<EXTEOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = $cn
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $cn
DNS.2 = localhost
EXTEOF

  # 固定写回默认路径(正式证书申请失败回退时，需覆盖之前可能被改写的路径)
  CERT_FILE="/tmp/tls_certs/cert.pem"
  KEY_FILE="/tmp/tls_certs/key.pem"

  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$KEY_FILE" -out "$CERT_FILE" -days 3650 \
    -config "$ext_conf" -extensions v3_req 2>"/tmp/tls_certs/openssl_err.log"
  rm -f "$ext_conf"

  if [[ ! -s "$CERT_FILE" || ! -s "$KEY_FILE" ]]; then
    echo "[TLS] Failed to generate self-signed certificate, openssl output:" >&2
    cat "/tmp/tls_certs/openssl_err.log" >&2
    echo "[TLS] Check that openssl is installed. Aborting: sing-box cannot start without a certificate" >&2
    exit 1
  fi
  chmod 600 "$KEY_FILE"
}

# 下载 lego 预编译二进制
install_lego() {
  LEGO_BIN="$(pwd)/lego"
  LEGO_DIR="$(pwd)/.lego"

  if [[ ! -x "$LEGO_BIN" ]]; then
    curl -sSL -o lego.tar.gz 'https://github.com/go-acme/lego/releases/download/v4.35.2/lego_v4.35.2_linux_amd64.tar.gz'
    tar -zxf lego.tar.gz lego
    chmod +x "$LEGO_BIN"
  fi
}

# 用 lego 通过 DNS-01(Cloudflare)申请证书，成功返回 0 并写入 CERT_FILE / KEY_FILE
# 不占用任何端口；Token 需同时有 Zone:Read + DNS:Edit 权限。
# 已有证书走 renew(剩余有效期 >30 天时 lego 自动跳过)，没有则走 run。
issue_cert_for_host() {
  local host="$1"
  local sub_cmd="run"
  local out

  if [[ -z "$CF_TOKEN" ]]; then
    echo "[TLS] CF_TOKEN is empty, DNS-01 validation unavailable" >&2
    return 1
  fi

  install_lego
  if [[ ! -x "$LEGO_BIN" ]]; then
    echo "[TLS] lego download failed or binary is not executable" >&2
    return 1
  fi

  [[ -s "$LEGO_DIR/certificates/${host}.crt" ]] && sub_cmd="renew"

  export CF_DNS_API_TOKEN="$CF_TOKEN"
  out=$("$LEGO_BIN" --path "$LEGO_DIR" --email "cert-$UUID@$host" \
        --dns cloudflare --domains "$host" --accept-tos "$sub_cmd" 2>&1) || {
    echo "[TLS] DNS-01 (Cloudflare) certificate request failed, lego output:" >&2
    echo "$out" >&2
    return 1
  }

  CERT_FILE="$LEGO_DIR/certificates/${host}.crt"
  KEY_FILE="$LEGO_DIR/certificates/${host}.key"
  [[ -s "$CERT_FILE" && -s "$KEY_FILE" ]] || return 1
}

setup_tls() {
  local ip_re='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'

  TLS_SERVER_NAME="${CERT_HOST:-www.nazhumi.com}"
  [[ "$CERT_HOST" =~ $ip_re ]] && PUBLIC_IP="$CERT_HOST"

  # DNS-01 只能为域名签发证书，IP / 留空 / 申请失败都回退自签
  if [[ -n "$CERT_HOST" && ! "$CERT_HOST" =~ $ip_re ]] && issue_cert_for_host "$CERT_HOST"; then
    TLS_INSECURE=0
  else
    TLS_INSECURE=1
    echo "[TLS] No trusted certificate available, using self-signed certificate" >&2
    generate_self_signed_cert "$TLS_SERVER_NAME"
  fi

  echo "[TLS] Server name: $TLS_SERVER_NAME, insecure: $TLS_INSECURE, cert: $CERT_FILE, key: $KEY_FILE"
}

setup_tls

# ========== cloudflared ==========
if [[ -n "$CLOUDFLARE_TUNNEL_TOKEN" && -n "$CLOUDFLARE_TUNNEL_HOSTNAME" ]]; then
  curl -sSL -o ./cloudflared 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64'
  chmod +x cloudflared
  ./cloudflared --version
  nohup ./cloudflared --no-autoupdate tunnel run --token "$CLOUDFLARE_TUNNEL_TOKEN" > cloudflared.log 2>&1 &
fi

# ========== sing-box ==========
curl -sSL -o "sing-box-1.8.0-linux-amd64.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v1.8.0/sing-box-1.8.0-linux-amd64.tar.gz"
tar -zxf "sing-box-1.8.0-linux-amd64.tar.gz"
"sing-box-1.8.0-linux-amd64/sing-box" version

# 生成单个 inbound 配置
generate_inbound() {
  local proto="$1" port="$2" listen_port="$3"

  case "$proto" in
    vless)
      if [[ "$port" == "cloudflare" ]]; then
        cat <<EOF
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $listen_port,
      "users": [{"name": "misaka", "uuid": "$UUID", "flow": ""}],
      "transport": {"type": "ws", "path": "/misaka", "headers": {}, "max_early_data": 0, "early_data_header_name": ""},
      "tls": {
        "enabled": true,
        "server_name": "www.iij.ad.jp",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.iij.ad.jp",
            "server_port": 443
          },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": ["cdcf853c"]
        }
      },
      "multiplex": {"enabled": true, "padding": false}
    }
EOF
      else
        cat <<EOF
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $listen_port,
      "users": [{"name": "misaka", "uuid": "$UUID", "flow": ""}],
      "tls": {
        "enabled": true,
        "server_name": "www.iij.ad.jp",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.iij.ad.jp",
            "server_port": 443
          },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": ["cdcf853c"]
        }
      },
      "multiplex": {"enabled": true, "padding": false}
    }
EOF
      fi
      ;;
    vmess)
      if [[ "$port" == "cloudflare" ]]; then
        # Argo 隧道走 ws，TLS 由 Cloudflare 边缘终结(真实受信任证书)，本地不开 TLS，
        # 不需要面板/防火墙开放任何入站端口——cloudflared 是纯出站连接
        cat <<EOF
    {
      "type": "vmess",
      "tag": "vmess-in",
      "listen": "::",
      "listen_port": $listen_port,
      "users": [{"name": "misaka", "uuid": "$UUID"}],
      "transport": {"type": "ws", "path": "/misaka", "headers": {}, "max_early_data": 2560, "early_data_header_name": "Sec-WebSocket-Protocol"}
    }
EOF
      else
        # 直连：raw tcp + 本地 TLS(证书由 setup_tls 按 CERT_HOST 逻辑决定)
        cat <<EOF
    {
      "type": "vmess",
      "tag": "vmess-in",
      "listen": "::",
      "listen_port": $listen_port,
      "users": [{"name": "misaka", "uuid": "$UUID"}],
      "tls": {
        "enabled": true,
        "server_name": "$TLS_SERVER_NAME",
        "certificate_path": "$CERT_FILE",
        "key_path": "$KEY_FILE"
      }
    }
EOF
      fi
      ;;
    trojan)
      if [[ "$port" == "cloudflare" ]]; then
        cat <<EOF
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "::",
      "listen_port": $listen_port,
      "users": [{"name": "misaka", "password": "$UUID"}],
      "transport": {"type": "ws", "path": "/misaka", "headers": {}, "max_early_data": 0, "early_data_header_name": ""},
      "tls": {
        "enabled": true,
        "server_name": "www.iij.ad.jp",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.iij.ad.jp",
            "server_port": 443
          },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": ["cdcf853c"]
        }
      }
    }
EOF
      else
        cat <<EOF
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "::",
      "listen_port": $listen_port,
      "users": [{"name": "misaka", "password": "$UUID"}],
      "tls": {
        "enabled": true,
        "server_name": "www.iij.ad.jp",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.iij.ad.jp",
            "server_port": 443
          },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": ["cdcf853c"]
        }
      }
    }
EOF
      fi
      ;;
    shadowsocks)
      # 标准 Shadowsocks，直接公网监听，不套 TLS/插件
      cat <<EOF
    {
      "type": "shadowsocks",
      "tag": "shadowsocks-in",
      "listen": "::",
      "listen_port": $listen_port,
      "method": "aes-256-gcm",
      "password": "$UUID"
    }
EOF
      ;;
  esac
}

# 生成单个订阅节点链接
generate_node() {
  local proto="$1" port="$2"
  local json verify_cert ss_userinfo

  if [[ "$port" == "cloudflare" ]]; then
    if [[ -z "$CLOUDFLARE_TUNNEL_TOKEN" || -z "$CLOUDFLARE_TUNNEL_HOSTNAME" ]]; then
      return
    fi

    case "$proto" in
      vless)
        echo "vless://$UUID@$CLOUDFLARE_IP:443?encryption=none&security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=$REALITY_PUBLIC_KEY&insecure=0&allowInsecure=0&type=ws&host=$CLOUDFLARE_TUNNEL_HOSTNAME&path=%2Fmisaka&sid=cdcf853c#$NAME-VLESS-CF"
        ;;
      vmess)
        json='{"v":"2","ps":"'"$NAME-VMESS-CF"'","add":"'"$CLOUDFLARE_IP"'","port":"443","id":"'"$UUID"'","aid":"0","scy":"none","net":"ws","type":"none","host":"'"$CLOUDFLARE_TUNNEL_HOSTNAME"'","path":"/misaka?ed=2560","tls":"tls","sni":"'"$CLOUDFLARE_TUNNEL_HOSTNAME"'","alpn":"","fp":"","insecure":"0","vcn":"","pcs":""}'
        echo "vmess://$(echo -n "$json" | base64 -w0)"
        ;;
      trojan)
        echo "trojan://$UUID@$CLOUDFLARE_IP:443?security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=ws&host=$CLOUDFLARE_TUNNEL_HOSTNAME&path=%2Fmisaka&sid=cdcf853c#$NAME-TROJAN-CF"
        ;;
      # shadowsocks 不支持 cloudflare 隧道模式，没有 CF 分支
    esac
  else
    case "$proto" in
      vless)
        echo "vless://$UUID@$PUBLIC_IP:$port?encryption=none&security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=tcp&sid=cdcf853c#$NAME-VLESS"
        ;;
      vmess)
        verify_cert="true"
        [[ "$TLS_INSECURE" == "1" ]] && verify_cert="false"
        json='{"v":"2","ps":"'"$NAME-VMESS"'","add":"'"$PUBLIC_IP"'","port":"'"$port"'","id":"'"$UUID"'","aid":"0","scy":"none","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"'"$TLS_SERVER_NAME"'","alpn":"","fp":"","insecure":"'"$TLS_INSECURE"'","allowInsecure":'"$TLS_INSECURE"',"verify_cert":'"$verify_cert"',"vcn":"","pcs":""}'
        echo "vmess://$(echo -n "$json" | base64 -w0)"
        ;;
      trojan)
        echo "trojan://$UUID@$PUBLIC_IP:$port?security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=tcp&sid=cdcf853c#$NAME-TROJAN"
        ;;
      shadowsocks)
        ss_userinfo=$(echo -n "aes-256-gcm:$UUID" | base64 -w0 | tr '+/' '-_' | tr -d '=')
        echo "ss://${ss_userinfo}@${PUBLIC_IP}:${port}#${NAME}-SS"
        ;;
    esac
  fi
}

# 收集所有已配置协议的 inbounds，以逗号分隔
collect_inbounds() {
  local first=true
  local proto port_var port listen_port

  for proto in vless vmess trojan shadowsocks; do
    port_var="${proto^^}_PORT"
    port="${!port_var}"
    [[ -z "$port" ]] && continue

    if [[ "$port" == "cloudflare" ]]; then
      listen_port="$CLOUDFLARE_PORT"
    else
      listen_port="$port"
    fi

    [[ "$first" == false ]] && echo ","
    generate_inbound "$proto" "$port" "$listen_port"
    first=false
  done
}

# ========== 生成 config.json ==========
cat > "sing-box-1.8.0-linux-amd64/config.json" <<'JSONEOF'
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "cloudflare",
        "address": "https://1.1.1.1/dns-query",
        "strategy": "ipv4_only",
        "detour": "direct"
      },
      {
        "tag": "block",
        "address": "rcode://success"
      }
    ],
    "rules": [
      {
        "rule_set": ["geosite-cn", "geosite-category-ads-all"],
        "server": "block"
      }
    ],
    "final": "cloudflare",
    "strategy": "",
    "disable_cache": false,
    "disable_expire": false
  },
  "inbounds": [
JSONEOF

collect_inbounds >> "sing-box-1.8.0-linux-amd64/config.json"

cat >> "sing-box-1.8.0-linux-amd64/config.json" <<'JSONEOF'
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {"type": "dns", "tag": "dns-out"}
  ],
  "route": {
    "rules": [
      {"protocol": "dns", "outbound": "dns-out"},
      {"ip_is_private": true, "outbound": "direct"},
      {
        "rule_set": ["geoip-cn", "geosite-cn", "geosite-category-ads-all"],
        "outbound": "block"
      }
    ],
    "rule_set": [
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
        "download_detour": "direct"
      }
    ],
    "auto_detect_interface": true,
    "final": "direct"
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "cache.db",
      "cache_id": "mycacheid",
      "store_fakeip": true
    }
  }
}
JSONEOF

# ========== 输出订阅 ==========
# 每行一个原始链接方便单条复制，末尾再给一份合并后的 base64 订阅，方便整段导入
ALL_NODES=""
for proto in vless vmess trojan shadowsocks; do
  port_var="${proto^^}_PORT"
  port="${!port_var}"
  [[ -z "$port" ]] && continue

  node=$(generate_node "$proto" "$port")
  echo "$node"
  ALL_NODES+="$node"$'\n'
done

echo ""
echo "=== Nodes ==="
echo -n "$ALL_NODES"
echo ""
echo "=== Subscription (base64) ==="
echo -n "$ALL_NODES" | base64 -w0
echo ""

# ========== 运行 ==========
"sing-box-1.8.0-linux-amd64/sing-box" run -c "sing-box-1.8.0-linux-amd64/config.json"
