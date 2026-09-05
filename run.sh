#!/bin/bash

export NAME=''
export UUID='' # your uuid
export CLOUDFLARE_TUNNEL_TOKEN=''
export CLOUDFLARE_TUNNEL_HOSTNAME=''
export CLOUDFLARE_IP='saas.sin.fan'# your cf ip

curl -L 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64' -o ./cloudflared
chmod +x cloudflared
./cloudflared --version
nohup ./cloudflared --no-autoupdate tunnel run --token "$CLOUDFLARE_TUNNEL_TOKEN" > cloudflared.log 2>&1 &

curl -O -L https://github.com/SagerNet/sing-box/releases/download/v1.8.0/sing-box-1.8.0-linux-amd64.tar.gz
tar -zxf sing-box-1.8.0-linux-amd64.tar.gz

sing-box-1.8.0-linux-amd64/sing-box version

cat <<EOF > sing-box-1.8.0-linux-amd64/config.json
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
        "rule_set": [
          "geosite-cn",
          "geosite-category-ads-all"
        ],
        "server": "block"
      }
    ],
    "final": "cloudflare",
    "strategy": "",
    "disable_cache": false,
    "disable_expire": false
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 8000,
      "users": [
        {
          "name": "misaka",
          "uuid": "$UUID",
          "flow": ""
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/misaka",
        "headers": {

        },
        "max_early_data": 0,
        "early_data_header_name": ""
      },
      "multiplex": {
        "enabled": true,
        "padding": false
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      },
      {
        "rule_set": [
          "geoip-cn",
          "geosite-cn",
          "geosite-category-ads-all"
        ],
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
EOF

echo "vless://$UUID@$CLOUDFLARE_IP:443?encryption=none&security=tls&sni=$CLOUDFLARE_TUNNEL_HOSTNAME&fp=chrome&insecure=0&allowInsecure=0&type=ws&host=$CLOUDFLARE_TUNNEL_HOSTNAME&path=%2Fmisaka#$NAME"
sing-box-1.8.0-linux-amd64/sing-box run -c sing-box-1.8.0-linux-amd64/config.json
