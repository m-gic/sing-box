#!/bin/bash

export NAME=''
export UUID='' # your uuid
export CLOUDFLARE_TUNNEL_TOKEN=''
export CLOUDFLARE_TUNNEL_HOSTNAME=''
export CLOUDFLARE_IP='' # your cf ip
export CLOUDFLARE_PORT=8000
export VLESS_PORT='' # 监听端口，设置为'cloudflare'时使用CLOUDFLARE_PORT
export VMESS_PORT=''
export TROJAN_PORT=''
export SHADOWSOCKS_PORT=''

# 依据UUID生成REALITY所需的X25519密钥对(private_key/public_key)
# 原理：private_key = sha256(UUID) 作为32字节raw标量；
#      public_key 由 private_key 通过X25519运算严格推导，两者天然配对，无需再手动核对
generate_reality_keypair() {
  local seed="$1"
  local priv_raw="/tmp/.reality_priv_raw.bin"
  local priv_der="/tmp/.reality_priv.der"
  local pub_der="/tmp/.reality_pub.der"

  # 32字节 raw private key
  printf '%s' "$seed" | openssl dgst -sha256 -binary > "$priv_raw"

  # 拼接固定的PKCS8 DER头(X25519 raw private key专用) + raw private key
  { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'; cat "$priv_raw"; } > "$priv_der"

  # 用openssl从private key推导出配对的public key
  openssl pkey -in "$priv_der" -inform DER -pubout -outform DER -out "$pub_der" 2>/dev/null

  # base64url编码(无padding)
  REALITY_PRIVATE_KEY=$(base64 -w0 "$priv_raw" | tr '+/' '-_' | tr -d '=')
  REALITY_PUBLIC_KEY=$(tail -c 32 "$pub_der" | base64 -w0 | tr '+/' '-_' | tr -d '=')

  rm -f "$priv_raw" "$priv_der" "$pub_der"
}

generate_reality_keypair "$UUID"
echo "REALITY private_key: $REALITY_PRIVATE_KEY"
echo "REALITY public_key: $REALITY_PUBLIC_KEY"

PUBLIC_IP=$(curl -s 'https://one.one.one.one/cdn-cgi/trace' | grep -oP '^ip=\K[^$]+' || echo "$CLOUDFLARE_IP")

# 下载并运行cloudflared
if [[ -n "$CLOUDFLARE_TUNNEL_TOKEN" ]] && [[ -n "$CLOUDFLARE_TUNNEL_HOSTNAME" ]]; then
  curl -L 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64' -o ./cloudflared
  chmod +x cloudflared
  ./cloudflared --version
  nohup ./cloudflared --no-autoupdate tunnel run --token "$CLOUDFLARE_TUNNEL_TOKEN" > cloudflared.log 2>&1 &
fi
 
curl -O -L https://github.com/SagerNet/sing-box/releases/download/v1.8.0/sing-box-1.8.0-linux-amd64.tar.gz
tar -zxf sing-box-1.8.0-linux-amd64.tar.gz
sing-box-1.8.0-linux-amd64/sing-box version
 
# 生成inbound配置
generate_inbound() {
  local proto=$1 port=$2 listen_port=$3
  
  case $proto in
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
      cat <<EOF
    {
      "type": "vmess",
      "tag": "vmess-in",
      "listen": "::",
      "listen_port": $listen_port,
      "users": [{"name": "misaka", "uuid": "$UUID"}],
      "transport": {"type": "ws", "path": "/misaka", "headers": {}, "max_early_data": 0, "early_data_header_name": ""},
      "tls": {
        "enabled": true,
        "server_name": "www.google.com"
      }
    }
EOF
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
      cat <<EOF
    {
      "type": "shadowtls",
      "tag": "shadowsocks-in",
      "listen": "::",
      "listen_port": $listen_port,
      "version": 3,
      "users": [{"name": "misaka", "password": "$UUID"}],
      "handshake": {
        "server": "www.google.com"
      },
      "strict": false
    }
EOF
      ;;
  esac
}
 
# 生成订阅节点
generate_node() {
  local proto=$1 port=$2
  
  if [[ "$port" == "cloudflare" ]]; then
    [[ -z "$CLOUDFLARE_TUNNEL_TOKEN" ]] || [[ -z "$CLOUDFLARE_TUNNEL_HOSTNAME" ]] && return
    
    case $proto in
      vless)
        echo "vless://$UUID@$CLOUDFLARE_IP:443?encryption=none&security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=$REALITY_PUBLIC_KEY&insecure=0&allowInsecure=0&type=ws&host=$CLOUDFLARE_TUNNEL_HOSTNAME&path=%2Fmisaka&sid=cdcf853c#$NAME-VLESS-CF"
        ;;
      vmess)
        local json='{"v":"2","ps":"'"$NAME-VMESS-CF"'","add":"'"$CLOUDFLARE_IP"'","port":443,"id":"'"$UUID"'","aid":0,"scy":"none","net":"ws","type":"none","host":"'"$CLOUDFLARE_TUNNEL_HOSTNAME"'","path":"/misaka","tls":"tls","sni":"www.google.com","alpn":""}'
        echo "vmess://$(echo -n "$json" | base64 -w 0)"
        ;;
      trojan)
        echo "trojan://$UUID@$CLOUDFLARE_IP:443?security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=ws&host=$CLOUDFLARE_TUNNEL_HOSTNAME&path=%2Fmisaka&sid=cdcf853c#$NAME-TROJAN-CF"
        ;;
      shadowsocks)
        local ss_auth=$(echo -n "$UUID" | base64 -w 0)
        echo "shadowtls://$ss_auth@$CLOUDFLARE_IP:443?version=3&sni=www.google.com#$NAME-SS-CF"
        ;;
    esac
  else
    case $proto in
      vless)
        echo "vless://$UUID@$PUBLIC_IP:$port?encryption=none&security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=tcp&sid=cdcf853c#$NAME-VLESS"
        ;;
      vmess)
        local json='{"v":"2","ps":"'"$NAME-VMESS"'","add":"'"$PUBLIC_IP"'","port":'"$port"',"id":"'"$UUID"'","aid":0,"scy":"none","net":"ws","type":"none","host":"","path":"/misaka","tls":"tls","sni":"www.google.com","alpn":""}'
        echo "vmess://$(echo -n "$json" | base64 -w 0)"
        ;;
      trojan)
        echo "trojan://$UUID@$PUBLIC_IP:$port?security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=tcp&sid=cdcf853c#$NAME-TROJAN"
        ;;
      shadowsocks)
        local ss_auth=$(echo -n "$UUID" | base64 -w 0)
        echo "shadowtls://$ss_auth@$PUBLIC_IP:$port?version=3&sni=www.google.com#$NAME-SS"
        ;;
    esac
  fi
}
 
# 收集所有inbounds
collect_inbounds() {
  local first=true
  for proto in vless vmess trojan shadowsocks; do
    port_var="${proto^^}_PORT"
    port=${!port_var}
    [[ -z "$port" ]] && continue
    
    listen_port=$([[ "$port" == "cloudflare" ]] && echo $CLOUDFLARE_PORT || echo $port)
    
    [[ "$first" == false ]] && echo ","
    generate_inbound "$proto" "$port" "$listen_port"
    first=false
  done
}
 
# 生成config.json
cat > sing-box-1.8.0-linux-amd64/config.json <<'JSONEOF'
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
 
# 追加inbounds
collect_inbounds >> sing-box-1.8.0-linux-amd64/config.json
 
# 追加剩余config
cat >> sing-box-1.8.0-linux-amd64/config.json <<'JSONEOF'
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
 
# 输出所有订阅节点
echo ""
echo "=== 订阅节点 ==="
for proto in vless vmess trojan shadowsocks; do
  port_var="${proto^^}_PORT"
  port=${!port_var}
  [[ -z "$port" ]] && continue
  echo ""
  generate_node "$proto" "$port"
done
echo ""
 
# 运行sing-box
sing-box-1.8.0-linux-amd64/sing-box run -c sing-box-1.8.0-linux-amd64/config.json
