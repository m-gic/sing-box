#!/usr/bin/env node
'use strict';
// 纯 Node.js 实现，只用内置模块，不需要 npm install、openssl、unzip、curl
// 需要 Node.js 22.15 及以上(用 process.getBuiltinModule 和 tls.getCACertificates，CJS / ESM 两种方式都能运行)
const bi = (m) => process.getBuiltinModule(`node:${m}`);
const crypto = bi('crypto'), fs = bi('fs'), path = bi('path'), cp = bi('child_process');
const https = bi('https'), zlib = bi('zlib'), dns = bi('dns'), tls = bi('tls');
const { X509Certificate } = crypto;

const SELF = path.resolve(process.argv[1]);
const BASE_DIR = path.dirname(SELF);

// ========== 用户配置 ==========
const CONFIG = {
  NAME: process.env.NAME || '',
  UUID: process.env.UUID || '' || crypto.randomUUID(),
  CLOUDFLARE_TUNNEL_TOKEN: process.env.CLOUDFLARE_TUNNEL_TOKEN || '',
  CLOUDFLARE_IP: process.env.CLOUDFLARE_IP || '',
  PORT: process.env.PORT || '',
  VLESS_MODE: process.env.VLESS_MODE || '',
  VMESS_MODE: process.env.VMESS_MODE || '',
  TROJAN_MODE: process.env.TROJAN_MODE || '',
  SHADOWSOCKS_MODE: process.env.SHADOWSOCKS_MODE || '',
  HYSTERIA2_MODE: process.env.HYSTERIA2_MODE || '',
  MIXED_MODE: process.env.MIXED_MODE || '',
  WIREGUARD_MODE: process.env.WIREGUARD_MODE || '',
  CERT_HOST: process.env.CERT_HOST || '',
  KOMARI_ENDPOINT: process.env.KOMARI_ENDPOINT || '',
  KOMARI_TOKEN: process.env.KOMARI_TOKEN || '',
};
const {
  NAME, UUID, CLOUDFLARE_TUNNEL_TOKEN, CLOUDFLARE_IP, PORT, VLESS_MODE, VMESS_MODE, TROJAN_MODE, SHADOWSOCKS_MODE,
  HYSTERIA2_MODE, MIXED_MODE, WIREGUARD_MODE, CERT_HOST, KOMARI_ENDPOINT, KOMARI_TOKEN,
} = CONFIG;

// 把当前 UUID 写回脚本本身(填进上面 UUID 那行的 '' 里)：下次运行直接沿用，不做任何检测
fs.writeFileSync(SELF, fs.readFileSync(SELF, 'utf8').replace(/^ {2}UUID: .*$/m, () => `  UUID: process.env.UUID || '${UUID}' || crypto.randomUUID(),`));

// ========== 基础环境 ==========
process.chdir(BASE_DIR);

// ARCH 用于 cloudflared / komari-agent 的文件名；Xray 的命名不同(64 / arm64-v8a)，下载处单独换算
const ARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch];
if (!ARCH) { console.error(`[ARCH] Unsupported architecture: ${process.arch}`); process.exit(1); }

// ========== 通用函数 ==========
const b64 = (buf) => Buffer.from(buf).toString('base64');
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const validPort = (v) => /^[0-9]+$/.test(v) && parseInt(v, 10) >= 1 && parseInt(v, 10) <= 65535;
const modeError = (msg) => { console.error(`[MODE] ${msg}`); process.exit(1); };
const nonEmpty = (f) => { try { return fs.statSync(f).size > 0; } catch { return false; } };
const readLog = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };

// URL 片段 / 查询值编码(按字节处理，中文、空格、引号都安全)
const urlencode = (s) => [...Buffer.from(String(s))]
  .map((b) => { const c = String.fromCharCode(b); return /[A-Za-z0-9.~_-]/.test(c) ? c : `%${b.toString(16).toUpperCase().padStart(2, '0')}`; })
  .join('');

// HTTPS 请求：跟随重定向；file 不为空时把响应体写进文件(HTTP 错误视为失败)，否则返回 { status, body }
function request(url, { family, timeout = 10000, file = null, redirects = 5 } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { family }, (res) => {
      const { statusCode: status, headers } = res;
      if ([301, 302, 303, 307, 308].includes(status) && headers.location) {
        res.resume();
        if (redirects <= 0) return reject(new Error('too many redirects'));
        return request(new URL(headers.location, url).href, { family, timeout, file, redirects: redirects - 1 }).then(resolve, reject);
      }
      if (file) {
        if (status >= 400) { res.resume(); return reject(new Error(`HTTP ${status}`)); }
        const out = fs.createWriteStream(file);
        res.pipe(out);
        out.on('finish', () => resolve({ status }));
        out.on('error', reject);
        res.on('error', reject);
      } else {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status, body: Buffer.concat(chunks).toString() }));
        res.on('error', reject);
      }
    });
    req.setTimeout(timeout, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

// dl(输出文件, URL)：先写 .part 再改名，失败(含 HTTP 错误)返回 false，不留半截文件
async function dl(dest, url) {
  for (let i = 0; i < 3; i++) {
    try {
      await request(url, { file: `${dest}.part` });
      fs.renameSync(`${dest}.part`, dest);
      return true;
    } catch { fs.rmSync(`${dest}.part`, { force: true }); await sleep(1000); }
  }
  console.error(`[DL] Download failed: ${url}`);
  return false;
}

// 用 Node 自带的 zlib 解压 zip(Xray 发行包)，不依赖 unzip
function unzip(zipFile, dir) {
  const b = fs.readFileSync(zipFile), root = path.resolve(dir);
  let e = b.length - 22;
  while (e >= 0 && b.readUInt32LE(e) !== 0x06054b50) e--;
  if (e < 0) throw new Error('not a zip file');
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
    const f = path.resolve(root, name);
    if (!f.startsWith(root + path.sep)) continue;
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, method === 0 ? data : zlib.inflateRawSync(data));
  }
}

// 子进程管理：脚本退出(含收到 SIGINT / SIGTERM)时一并结束所有子进程
const children = [];
process.on('exit', () => children.forEach((c) => { try { c.kill(); } catch { /* 已退出 */ } }));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(0));

// 按进程名停掉上一次留下的同名进程；没有 pkill 或没有旧进程时什么都不做
async function killPrevious(name, tag) {
  try { cp.execFileSync('pkill', ['-x', name], { stdio: 'ignore' }); } catch { return; }
  console.log(`[${tag}] Stopped previous ${name}`);
  await sleep(1000);
}

// 后台运行：输出写到日志文件
function spawnBg(bin, args, logFile, extraEnv = {}) {
  const fd = fs.openSync(logFile, 'w');
  const child = cp.spawn(bin, args, { env: { ...process.env, ...extraEnv }, stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  children.push(child);
  return child;
}

// ========== 协议与模式 ==========
const PROTOS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
// 各协议的 ws 路径，以及回落用的内部端口(仅监听 127.0.0.1；不用 unix socket，因为 Xray 的 Shadowsocks 入站不支持)
// 内部端口 40001-40005 不能被 PORT 或 *_MODE 里的端口占用
const WS_PATH = { vless: '/misaka-vless', vmess: '/misaka-vmess', trojan: '/misaka-trojan', shadowsocks: '/misaka-ss' };
const IPORT = { vless: 40001, vmess: 40002, trojan: 40003, shadowsocks: 40004 };
const MODES = { vless: VLESS_MODE, vmess: VMESS_MODE, trojan: TROJAN_MODE, shadowsocks: SHADOWSOCKS_MODE };
const NPORT = {};   // 协议 -> 它的 *_MODE 里写的数字端口
const FB = {};      // 协议 -> 它回落到的协议
const PARENT = {};  // 协议 -> 回落到它的协议
const CHAIN = {};   // Reality 链头 -> 整条链上的协议
const HPORT = {};   // Reality 链头 -> 监听端口
const RPORT = {};   // Reality 链上的每个协议 -> 对外端口(即链头端口)，生成链接用
const ENABLED = []; // 所有启用的协议(含被回落到而自动启用的)，订阅链接按此顺序输出
const SHARED = [];  // 采用 ws / cloudflare / try 的协议
const HEADS = [];   // Reality 链头(独占端口的单个协议也算)
let ACTIVE_MODE = '';    // SHARED 统一的模式：ws / cloudflare / 空(try 模式在解析后归并为 cloudflare)
let TRY_TUNNEL = false;  // try 模式：用 Cloudflare 临时隧道(trycloudflare.com)，不需要 Token 和域名
let FRONT_ON = false;    // 是否需要前置入口(ws / cloudflare，或只回落)
let SHARE_FRONT = false; // 前置入口是否与某条 Reality 链共用端口
let FRONT_PORT = 0;
const DEFAULT_FRONT_PORT = 8000; // cloudflare 模式先用它，读到隧道日志里的端口后会覆盖；ws 模式 PORT 留空时也用它
const FRONT_IPORT = 40005;       // 与 Reality 共用端口时，ws 前置入口改监听 127.0.0.1 的这个端口
const WG_CLIENT_ADDR = '10.0.0.2/32'; // WireGuard 客户端在隧道里的内网地址
const NAME_ENC = urlencode(NAME);
let WEB_DEST = '', HY2_PORT = 0, MIXED_PORT = 0, WG_PORT = 0, XRAY_ON = false;

// 回落网站：PORT 和 CERT_HOST 都填了才启用，回落到 CERT_HOST 的 80 端口(明文 HTTP)
if (PORT && CERT_HOST) {
  WEB_DEST = `${CERT_HOST}:80`;
  if (!/^[A-Za-z0-9.-]+:[0-9]{1,5}$/.test(WEB_DEST)) modeError(`CERT_HOST='${CERT_HOST}' is invalid (expected a domain or an IPv4 address)`);
  console.log(`[WEB] Non-ws requests on the front port fall back to ${WEB_DEST}`);
} else if (PORT) {
  console.error('[WEB] PORT is set but CERT_HOST is empty, fallback disabled (PORT only changes the listening port)');
}

// Hysteria2：只接受数字端口(UDP)，不参与回落链，也不占用 TCP 端口
if (HYSTERIA2_MODE) {
  if (!validPort(HYSTERIA2_MODE)) modeError(`HYSTERIA2_MODE='${HYSTERIA2_MODE}' is invalid (expected a port number 1-65535, or empty to disable)`);
  HY2_PORT = parseInt(HYSTERIA2_MODE, 10);
  console.log(`[MODE] port ${HY2_PORT}/udp: hysteria2`);
}

// Mixed(同一个端口同时支持 SOCKS5 和 HTTP 代理，TCP)：数字端口，账号 misaka、密码 UUID，不参与回落链
if (MIXED_MODE) {
  if (!validPort(MIXED_MODE)) modeError(`MIXED_MODE='${MIXED_MODE}' is invalid (expected a port number 1-65535, or empty to disable)`);
  MIXED_PORT = parseInt(MIXED_MODE, 10);
  console.log(`[MODE] port ${MIXED_PORT}/tcp: mixed (socks5 + http)`);
}

// WireGuard(Xray 用户态实现，UDP)：数字端口，不参与回落链，也不占用 TCP 端口
if (WIREGUARD_MODE) {
  if (!validPort(WIREGUARD_MODE)) modeError(`WIREGUARD_MODE='${WIREGUARD_MODE}' is invalid (expected a port number 1-65535, or empty to disable)`);
  WG_PORT = parseInt(WIREGUARD_MODE, 10);
  console.log(`[MODE] port ${WG_PORT}/udp: wireguard`);
}

// 1. 解析各协议的 *_MODE：ws / cloudflare / try、数字端口、协议名(回落)
function parseModes() {
  for (const p of PROTOS) {
    const m = MODES[p], v = `${p.toUpperCase()}_MODE`;
    if (!m) continue;
    if (m === 'ws' || m === 'cloudflare' || m === 'try') {
      if (ACTIVE_MODE && ACTIVE_MODE !== m) modeError(`Protocols using ws / cloudflare / try share one port (PORT), so they must use the same mode (got: ${ACTIVE_MODE} ${m})`);
      SHARED.push(p); ACTIVE_MODE = m;
    } else if (/^[0-9]+$/.test(m)) {
      if (!validPort(m)) modeError(`${v}='${m}': port must be 1-65535`);
      NPORT[p] = parseInt(m, 10);
    } else if (/^[a-z]+$/.test(m)) {
      if (!PROTOS.includes(m)) modeError(`${v}='${m}': '${m}' is not valid (expected ws / cloudflare / try / a port, or a fallback protocol: ${PROTOS.join(' ')})`);
      if (m === p) modeError(`${v}='${m}': a protocol cannot fall back to itself`);
      if (p !== 'vless' && p !== 'trojan') modeError(`${v}='${m}': ${p.toUpperCase()} has no fallback ability, only VLESS and TROJAN can choose a fallback`);
      FB[p] = m;
    } else {
      modeError(`${v}='${m}' is invalid (expected: ws / cloudflare / try / a port / a protocol name, or empty to disable)`);
    }
  }
  // try = 不用 Token 的 Cloudflare 临时隧道，其余逻辑和 cloudflare 模式相同(明文 WS，固定监听 8000)
  if (ACTIVE_MODE === 'try') { ACTIVE_MODE = 'cloudflare'; TRY_TUNNEL = true; }
}

// 2. 把回落关系整理成 Reality 链：得到 ENABLED / HEADS / CHAIN / HPORT / RPORT
function buildChains() {
  // 每个协议只能被一个协议回落到；被回落到的协议不能用 ws / cloudflare / try
  for (const p of Object.keys(FB)) {
    const t = FB[p];
    if (PARENT[t]) modeError(`${t.toUpperCase()} is the fallback of both ${PARENT[t].toUpperCase()} and ${p.toUpperCase()}, it can only have one`);
    PARENT[t] = p;
    if (SHARED.includes(t)) modeError(`${t.toUpperCase()} is already the fallback of ${p.toUpperCase()}: ${t.toUpperCase()}_MODE cannot be ws / cloudflare / try (leave it empty; if it ends the chain, set a port; if it keeps falling back, use a protocol name)`);
  }
  // 链头 = 设了 Reality 相关模式(数字 / 协议名)且没被别人回落到的协议；顺着回落走到链尾，端口取链尾的数字
  for (const p of PROTOS) {
    if (MODES[p] || PARENT[p]) ENABLED.push(p);
    if (MODES[p] && !PARENT[p] && !SHARED.includes(p)) HEADS.push(p);
  }
  for (const h of HEADS) {
    let q = h;
    CHAIN[h] = [h];
    while (FB[q]) { q = FB[q]; CHAIN[h].push(q); }
    if (!NPORT[q]) modeError(`The chain from ${h.toUpperCase()} ends at ${q.toUpperCase()}, which needs a port: set ${q.toUpperCase()}_MODE to a port number`);
    HPORT[h] = NPORT[q];
    for (const p of CHAIN[h]) RPORT[p] = HPORT[h];
  }
  // 没有启用任何代理协议时不报错：只跑 Komari 探针(见下面的 Komari Agent 段)
  XRAY_ON = ENABLED.length > 0 || !!HY2_PORT || !!MIXED_PORT || !!WG_PORT;
  for (const p of ENABLED) { // 既不在 ws / cloudflare 组、也没挂到任何 Reality 链上 = 回落成环
    if (!SHARED.includes(p) && !RPORT[p]) modeError(`${p.toUpperCase()} is part of a fallback loop: the chain needs a head that no protocol falls back to`);
  }
}

// 3. 前置入口：是否需要、监听哪个端口、是否与某条 Reality 链共用
function planFront() {
  if (!ACTIVE_MODE && !WEB_DEST) return;
  FRONT_ON = true;
  // cloudflare 先用 8000(之后从 cloudflared 日志读到隧道的回源端口再覆盖)；其它(ws / 只回落)用 PORT，留空 8000
  const fp = ACTIVE_MODE === 'cloudflare' ? String(DEFAULT_FRONT_PORT) : (PORT || String(DEFAULT_FRONT_PORT));
  if (!validPort(fp)) modeError(`PORT='${PORT}' is not a valid port`);
  FRONT_PORT = parseInt(fp, 10);
  // PORT 与某条 Reality 链端口相同：ws 模式下共用端口，其它情况不能共用
  if (!(PORT && ACTIVE_MODE !== 'cloudflare')) return;
  for (const p of HEADS) {
    if (HPORT[p] !== FRONT_PORT) continue;
    if (ACTIVE_MODE === 'ws') SHARE_FRONT = true;
    else modeError(`PORT=${PORT} is also the Reality port of ${p.toUpperCase()}: sharing a port needs ws mode (cloudflare / fallback-only cannot share it with Reality)`);
  }
}

// 4. 端口检查：各监听端口(Reality 链头 + 前置入口 + Mixed)互不重复，且不占用内部保留端口 40001-40005
function checkPorts() {
  const ports = HEADS.map((p) => HPORT[p]);
  if (FRONT_ON && !SHARE_FRONT) ports.push(FRONT_PORT);
  if (MIXED_PORT) ports.push(MIXED_PORT);
  const dup = ports.find((x, i) => ports.indexOf(x) !== i);
  if (dup !== undefined) modeError(`Port ${dup} is used more than once: every Reality chain, the ws / cloudflare group (PORT) and MIXED_MODE need different TCP ports`);
  const reserved = [...Object.values(IPORT), FRONT_IPORT];
  for (const q of ports) if (reserved.includes(q)) modeError(`Port ${q} conflicts with the internal fallback ports 40001-40005`);
}

// ========== TLS 证书(供 ws / Hysteria2 使用) ==========
// 证书来源：脚本不申请证书。CERT_HOST 是域名，且脚本目录下有它的证书 $CERT_HOST.crt 和私钥 $CERT_HOST.key，
//   并且证书可信(私钥配对、在有效期内、系统信任的 CA 签发、包含 CERT_HOST 这个域名) -> 直接使用，链接不跳过证书校验；
//   其余情况(留空 / 填 IP / 没有证书文件 / 证书不可信) -> 自签证书
// 产出：CERT_FILE / KEY_FILE(证书与私钥路径)、TLS_SERVER_NAME(SNI)、
//   TLS_INSECURE(true=自签，订阅链接需跳过校验；false=可信)、TLS_PCS(自签证书的 SHA256 哈希，hex，链接里的 pcs；可信时为空)
const IP_RE = /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/;
let CERT_FILE = '', KEY_FILE = '', TLS_SERVER_NAME = '', TLS_INSECURE = true, TLS_PCS = '';

const pemBlock = (der, label) => `-----BEGIN ${label}-----\n${b64(der).match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;

// 最小的 DER 编码器：只够生成一张自签 X.509 证书
const der = {
  len: (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255])),
  tlv(tag, ...c) { const body = Buffer.concat(c); return Buffer.concat([Buffer.from([tag]), this.len(body.length), body]); },
  seq(...c) { return this.tlv(0x30, ...c); },
  set(...c) { return this.tlv(0x31, ...c); },
  int(buf) { return this.tlv(0x02, buf[0] & 0x80 ? Buffer.concat([Buffer.from([0]), buf]) : buf); },
  oid(s) {
    const a = s.split('.').map(Number), bytes = [a[0] * 40 + a[1]];
    for (const n of a.slice(2)) { const t = [n & 127]; for (let v = n >> 7; v; v >>= 7) t.unshift((v & 127) | 128); bytes.push(...t); }
    return this.tlv(0x06, Buffer.from(bytes));
  },
  utc(d) { return this.tlv(0x17, Buffer.from(d.toISOString().replace(/^\d\d(\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d).*$/, '$1$2$3$4$5$6Z'))); },
};

// 生成自签证书：私钥用随机 RSA；已有且 30 天内不过期就复用，否则每次重启证书哈希都变，已导入的订阅会失效
function generateSelfSignedCert(cn) {
  const dir = path.join(BASE_DIR, '.selfsigned');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  CERT_FILE = path.join(dir, `${cn}.crt`); KEY_FILE = path.join(dir, `${cn}.key`);
  if (nonEmpty(CERT_FILE) && nonEmpty(KEY_FILE)) {
    try { if (new X509Certificate(fs.readFileSync(CERT_FILE)).validToDate.getTime() - Date.now() > 30 * 86400e3) return; } catch { /* 重新生成 */ }
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const name = der.seq(der.set(der.seq(der.oid('2.5.4.3'), der.tlv(0x0c, Buffer.from(cn)))));
  const sigAlg = der.seq(der.oid('1.2.840.113549.1.1.11'), der.tlv(0x05));
  const serial = crypto.randomBytes(16); serial[0] = (serial[0] & 0x7f) || 1;
  const notBefore = new Date(Date.now() - 86400e3), notAfter = new Date(Date.now() + 3650 * 86400e3);
  const san = der.tlv(0xa3, der.seq(der.seq(der.oid('2.5.29.17'), der.tlv(0x04, der.seq(der.tlv(0x82, Buffer.from(cn)), der.tlv(0x82, Buffer.from('localhost')))))));
  const tbs = der.seq(
    der.tlv(0xa0, der.int(Buffer.from([2]))), der.int(serial), sigAlg, name,
    der.seq(der.utc(notBefore), der.utc(notAfter)), name,
    publicKey.export({ type: 'spki', format: 'der' }), san,
  );
  const sig = crypto.sign('sha256', tbs, privateKey);
  const cert = der.seq(tbs, sigAlg, der.tlv(0x03, Buffer.concat([Buffer.from([0]), sig])));
  fs.writeFileSync(CERT_FILE, pemBlock(cert, 'CERTIFICATE'));
  fs.writeFileSync(KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
}

// 校验证书链：叶子证书要包含域名，沿着中间证书逐级验签，最终落在系统信任的根证书上；返回空串表示可信，否则返回原因
function verifyChain(certs, host) {
  const leaf = certs[0];
  if (!leaf.checkHost(host)) return 'hostname mismatch';
  const roots = tls.getCACertificates('default').map((p) => new X509Certificate(p));
  const now = Date.now();
  const valid = (c) => now >= c.validFromDate.getTime() && now <= c.validToDate.getTime();
  const pool = certs.slice(1);
  let cur = leaf;
  for (let depth = 0; depth < 8; depth++) {
    if (!valid(cur)) return 'certificate expired or not yet valid';
    if (roots.some((r) => r.fingerprint256 === cur.fingerprint256)) return '';
    if (roots.some((r) => valid(r) && cur.checkIssued(r) && cur.verify(r.publicKey))) return '';
    const next = pool.find((i) => i !== cur && i.ca && cur.checkIssued(i) && cur.verify(i.publicKey));
    if (!next) return 'issuer is not trusted';
    cur = next;
  }
  return 'chain too long';
}

// 检查 CERT_HOST 的证书是否可信：脚本目录下的 $CERT_HOST.crt(可以是带中间证书的完整链) 和 $CERT_HOST.key，
// 全部满足才返回 true，并写入 CERT_FILE / KEY_FILE
function trustedCertForHost(host) {
  const crt = path.join(BASE_DIR, `${host}.crt`), key = path.join(BASE_DIR, `${host}.key`);
  if (!nonEmpty(crt) || !nonEmpty(key)) return false;
  let certs;
  try {
    certs = (fs.readFileSync(crt, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []).map((p) => new X509Certificate(p));
    if (!certs.length) throw new Error('no certificate found');
    if (!certs[0].checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(key)))) { console.error(`[TLS] ${crt} and ${key} do not match`); return false; }
  } catch (e) { console.error(`[TLS] Cannot read ${crt} / ${key}: ${e.message}`); return false; }
  const why = verifyChain(certs, host);
  if (why) { console.error(`[TLS] ${crt} is not a trusted certificate for ${host}: ${why}`); return false; }
  CERT_FILE = crt; KEY_FILE = key;
  return true;
}

function setupTls() {
  TLS_PCS = '';
  TLS_SERVER_NAME = CERT_HOST || 'www.nazhumi.com';
  if (CERT_HOST && !IP_RE.test(CERT_HOST) && trustedCertForHost(CERT_HOST)) {
    TLS_INSECURE = false;
  } else {
    TLS_INSECURE = true;
    console.error(`[TLS] No trusted certificate available (put one at ${BASE_DIR}/<CERT_HOST>.crt and .key), using self-signed certificate`);
    generateSelfSignedCert(TLS_SERVER_NAME);
    // 新版 Xray 客户端已移除 allowInsecure，自签证书改用证书哈希固定(链接里的 pcs)
    TLS_PCS = new X509Certificate(fs.readFileSync(CERT_FILE)).fingerprint256.replace(/:/g, '').toLowerCase();
  }
  console.log(`[TLS] Server name: ${TLS_SERVER_NAME}, insecure: ${TLS_INSECURE ? 1 : 0}, cert: ${CERT_FILE}, key: ${KEY_FILE}`);
}

// ========== 密钥 ==========
// X25519：固定的 PKCS8 DER 头 + 32 字节私钥，交给 crypto 推导出配对的公钥(Reality 和 WireGuard 共用)
const x25519Public = (priv32) => crypto.createPublicKey(crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), priv32]), format: 'der', type: 'pkcs8',
})).export({ type: 'spki', format: 'der' }).subarray(-32);

// 私钥首次随机生成并落盘复用(不由 UUID 派生)；读出来的是文本，enc 是它的 base64 / base64url 编码
function loadKey(file, enc) {
  const f = path.join(BASE_DIR, file);
  if (!nonEmpty(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString(enc), { mode: 0o600 });
  return fs.readFileSync(f, 'utf8').trim();
}

let REALITY_PRIVATE_KEY = '', REALITY_PUBLIC_KEY = '';
let WG_SERVER_PRIVATE = '', WG_SERVER_PUBLIC = '', WG_CLIENT_PRIVATE = '', WG_CLIENT_PUBLIC = '';

function loadRealityKeys() {
  REALITY_PRIVATE_KEY = loadKey('.reality_key', 'base64url');
  REALITY_PUBLIC_KEY = b64url(x25519Public(Buffer.from(REALITY_PRIVATE_KEY, 'base64url')));
}

// WireGuard：服务端、客户端各一把私钥，首次随机生成并落盘复用(订阅不会因重启失效)；标准 base64
function loadWgKeys() {
  WG_SERVER_PRIVATE = loadKey('.wg_server_key', 'base64');
  WG_CLIENT_PRIVATE = loadKey('.wg_client_key', 'base64');
  WG_SERVER_PUBLIC = b64(x25519Public(Buffer.from(WG_SERVER_PRIVATE, 'base64')));
  WG_CLIENT_PUBLIC = b64(x25519Public(Buffer.from(WG_CLIENT_PRIVATE, 'base64')));
}

// ========== 链接里的连接地址(PUBLIC_IP) ==========
// 全部是 cloudflare 模式时链接用 CLOUDFLARE_IP / 隧道域名，不需要本机地址；其余情况：
//   CERT_HOST 填 IP    -> 直接当作公网 IP，不再探测
//   CERT_HOST 填域名   -> 探测公网 IP；域名解析结果包含它(域名指向本服务器)时改用域名
//                         (域名走了 Cloudflare 代理等、解析不到本机 IP 时，仍用 IP)
let PUBLIC_IP = '';
const TRACE_URL = 'https://one.one.one.one/cdn-cgi/trace';

async function resolvePublicAddr() {
  if (IP_RE.test(CERT_HOST)) {
    PUBLIC_IP = CERT_HOST;
  } else {
    // 只取 IPv4：IPv6 地址直接拼进 host:port 会让链接失效
    const r = await request(TRACE_URL, { family: 4, timeout: 5000 }).catch(() => null);
    PUBLIC_IP = ((r && r.body.match(/^ip=(.*)$/m)) || [, ''])[1].trim();
    if (CERT_HOST && PUBLIC_IP) {
      const ips = await dns.promises.lookup(CERT_HOST, { family: 4, all: true }).then((l) => l.map((x) => x.address)).catch(() => []);
      if (ips.includes(PUBLIC_IP)) {
        console.log(`[NET] ${CERT_HOST} points to this server, using it instead of the IP`);
        PUBLIC_IP = CERT_HOST;
      }
    }
  }
  if (!PUBLIC_IP) console.error('[NET] Cannot determine the public address, links will be invalid (set CERT_HOST)');
  console.log(`[NET] Address in links: ${PUBLIC_IP}`);
}

// ========== Xray 配置片段 ==========
const SNIFFING = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true }; // 只用于路由匹配，不改写目标地址

const streamTcpPlain = () => ({ network: 'tcp', security: 'none' });
const streamWs = (p) => ({ network: 'ws', security: 'none', wsSettings: { path: p } });
// 默认伪装 www.iij.ad.jp；与 ws 共用端口时 dest 指向本机 ws 入口
const streamReality = (dest = 'www.iij.ad.jp:443', sni = 'www.iij.ad.jp') => ({
  network: 'tcp', security: 'reality',
  realitySettings: { show: false, dest, xver: 0, serverNames: [sni], privateKey: REALITY_PRIVATE_KEY, shortIds: ['cdcf853c'] },
});
// ws 前置入口(tcp + http/1.1)和 Hysteria2(hysteria + h3)共用
const tlsStream = (network, alpn, extra = {}) => ({
  network, security: 'tls',
  tlsSettings: { serverName: TLS_SERVER_NAME, alpn: [alpn], certificates: [{ certificateFile: CERT_FILE, keyFile: KEY_FILE }] },
  ...extra,
});

function protoSettings(p, fallbacks, flow) {
  const fb = fallbacks ? { fallbacks } : {};
  switch (p) {
    case 'vless': return { clients: [{ id: UUID, email: 'misaka', ...(flow ? { flow } : {}) }], decryption: 'none', ...fb };
    case 'vmess': return { clients: [{ id: UUID, email: 'misaka' }] };
    case 'trojan': return { clients: [{ password: UUID, email: 'misaka' }], ...fb };
    case 'shadowsocks': return { method: 'aes-256-gcm', password: UUID, network: 'tcp' };
  }
}

const inbound = (tag, listen, port, protocol, settings, streamSettings) => ({ tag, listen, port, protocol, settings, streamSettings, sniffing: SNIFFING });

let VLESS_FLOW = ''; // 流控 xtls-rprx-vision：仅 VLESS 作为 Reality 链头(tcp + reality)时启用；作为被回落的内部入口(明文 tcp)或走 ws 时不支持 Vision

// 前置入口(ws / cloudflare / 只回落)：监听 FRONT_PORT，按 HTTP 路径把 ws 流量回落给各内部 ws 入口，
// 其余请求回落给 CERT_HOST 的 80 端口(如果启用)。ws 带 TLS；cloudflare 和只回落是明文(cloudflare 的 TLS 由隧道终结)
// 与 Reality 共用端口时只听本机，由 Reality 转进来。前置入口本身也是一个 VLESS 入口，直接用 UUID
function inboundsFront(inb) {
  const fb = [];
  for (const p of SHARED) {
    fb.push({ path: WS_PATH[p], dest: IPORT[p], xver: 0 });
    inb.push(inbound(`${p}-in`, '127.0.0.1', IPORT[p], p, protoSettings(p), streamWs(WS_PATH[p])));
  }
  if (WEB_DEST) fb.push({ dest: WEB_DEST, xver: 0 });
  const stream = ACTIVE_MODE === 'ws' ? tlsStream('tcp', 'http/1.1') : streamTcpPlain();
  const [listen, port] = SHARE_FRONT ? ['127.0.0.1', FRONT_IPORT] : ['::', FRONT_PORT];
  inb.push(inbound('front-in', listen, port, 'vless', protoSettings('vless', fb), stream));
}

// Reality 链：链头监听自己的端口并套 Reality；被回落到的协议依次监听 127.0.0.1 内部端口，由上一级回落过来
function inboundsChains(inb) {
  for (const h of HEADS) {
    for (const p of CHAIN[h]) {
      const fb = FB[p] ? [{ dest: IPORT[FB[p]], xver: 0 }] : undefined;
      let listen, port, stream, flow = '';
      if (p !== h) {
        listen = '127.0.0.1'; port = IPORT[p]; stream = streamTcpPlain();
      } else {
        listen = '::'; port = HPORT[h];
        stream = SHARE_FRONT && port === FRONT_PORT ? streamReality(`127.0.0.1:${FRONT_IPORT}`, TLS_SERVER_NAME) : streamReality();
        if (p === 'vless') flow = VLESS_FLOW;
      }
      inb.push(inbound(`${p}-in`, listen, port, p, protoSettings(p, fb, flow), stream));
    }
  }
}

function buildConfig() {
  const inb = [];
  if (FRONT_ON) inboundsFront(inb);
  inboundsChains(inb);
  if (HY2_PORT) inb.push(inbound('hysteria2-in', '::', HY2_PORT, 'hysteria', { version: 2, clients: [{ auth: UUID, email: 'misaka' }] }, tlsStream('hysteria', 'h3', { hysteriaSettings: { version: 2 } })));
  if (MIXED_PORT) inb.push(inbound('mixed-in', '::', MIXED_PORT, 'socks', { auth: 'password', accounts: [{ user: 'misaka', pass: UUID }], udp: false }, streamTcpPlain()));
  if (WG_PORT) inb.push(inbound('wireguard-in', '::', WG_PORT, 'wireguard', { secretKey: WG_SERVER_PRIVATE, peers: [{ publicKey: WG_CLIENT_PUBLIC, allowedIPs: [WG_CLIENT_ADDR] }], mtu: 1420 }, undefined));
  return {
    log: { loglevel: 'warning' },
    dns: { servers: ['https+local://1.1.1.1/dns-query'], queryStrategy: 'UseIPv4' },
    inbounds: inb,
    outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
        ...(IPV6_AVAILABLE ? [] : [{ type: 'field', ip: ['::/0'], outboundTag: 'block' }]), // 无 IPv6 出口时拒绝 IPv6 目标，让客户端立即回退 IPv4，而不是等拨号超时
        { type: 'field', domain: ['geosite:cn', 'geosite:category-ads-all'], outboundTag: 'block' },
        { type: 'field', ip: ['geoip:cn'], outboundTag: 'block' },
      ],
    },
  };
}

// ========== 订阅链接 ==========
// SIP003 v2ray-plugin 参数(固定 tls)
const ssPluginParam = (host, p) => `v2ray-plugin;tls;host=${host};path=${p};mux=0`.replace(/;/g, '%3B').replace(/=/g, '%3D').replace(/\//g, '%2F');

let SS_USERINFO = '';
let CLOUDFLARE_TUNNEL_HOSTNAME = '';
let IPV6_AVAILABLE = false;

// reality 链接(VMess / SS 也用 URI 格式，客户端要能当作 Reality 节点导入)
function realityLink(proto, port) {
  let sni = 'www.iij.ad.jp';
  if (SHARE_FRONT && port === FRONT_PORT) sni = TLS_SERVER_NAME;
  const rq = `security=reality&sni=${sni}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&type=tcp&sid=cdcf853c`;
  switch (proto) {
    case 'vless': return `vless://${UUID}@${PUBLIC_IP}:${port}?encryption=none${VLESS_FLOW ? `&flow=${VLESS_FLOW}` : ''}&${rq}#${NAME_ENC}`;
    case 'vmess': return `vmess://${UUID}@${PUBLIC_IP}:${port}?encryption=auto&${rq}#${NAME_ENC}`;
    case 'trojan': return `trojan://${UUID}@${PUBLIC_IP}:${port}?${rq}#${NAME_ENC}`;
    case 'shadowsocks': return `ss://${SS_USERINFO}@${PUBLIC_IP}:${port}?${rq}#${NAME_ENC}`;
  }
}

// Hysteria2 链接：自签证书时带 insecure=1(跳过证书校验，不再固定证书哈希)
const hy2Link = () => `hysteria2://${UUID}@${PUBLIC_IP}:${HY2_PORT}/?sni=${TLS_SERVER_NAME}${TLS_INSECURE ? '&insecure=1' : ''}#${NAME_ENC}`;

// Mixed 链接：SOCKS5 和 HTTP 各一条(同一个端口、同一组账号密码)；明文传输，不加密
const mixedLinks = () => `socks5://misaka:${UUID}@${PUBLIC_IP}:${MIXED_PORT}#${NAME_ENC}\nhttp://misaka:${UUID}@${PUBLIC_IP}:${MIXED_PORT}#${NAME_ENC}`;

// WireGuard 链接(v2rayN / NekoBox / sing-box 等客户端可导入)
const wgLink = () => `wireguard://${urlencode(WG_CLIENT_PRIVATE)}@${PUBLIC_IP}:${WG_PORT}?publickey=${urlencode(WG_SERVER_PUBLIC)}&address=${urlencode(WG_CLIENT_ADDR)}&mtu=1420#${NAME_ENC}`;

// 标准 WireGuard 配置文件(wg-quick / WireGuard 官方客户端用)
const wgConf = () => `[Interface]\nPrivateKey = ${WG_CLIENT_PRIVATE}\nAddress = ${WG_CLIENT_ADDR}\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = ${WG_SERVER_PUBLIC}\nEndpoint = ${PUBLIC_IP}:${WG_PORT}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;

// ws / cloudflare 链接的共同参数(连接地址、端口、host、证书校验)，按模式确定一次
//   cloudflare：连 CLOUDFLARE_IP:443(没设置 CLOUDFLARE_IP 就连从 cloudflared 日志探测到的隧道域名)，隧道的 Service 指向的本机端口从 cloudflared 日志里读取
//   ws：连 PUBLIC_IP:FRONT_PORT；自签证书用 pcs(证书哈希)固定，allowInsecure 保留给旧客户端
const WS = { addr: '', port: 0, host: '', iq: '', vmInsecure: 0, vmExtra: null, vmPcs: '' };
function initWsParams() {
  if (ACTIVE_MODE === 'cloudflare') {
    Object.assign(WS, { addr: CLOUDFLARE_IP || CLOUDFLARE_TUNNEL_HOSTNAME, port: 443, host: CLOUDFLARE_TUNNEL_HOSTNAME });
  } else {
    const ins = TLS_INSECURE ? 1 : 0;
    Object.assign(WS, {
      addr: PUBLIC_IP, port: FRONT_PORT, host: TLS_SERVER_NAME, vmInsecure: ins, vmPcs: TLS_PCS,
      vmExtra: { allowInsecure: ins, verify_cert: !TLS_INSECURE },
      iq: TLS_INSECURE ? `&allowInsecure=1&pcs=${TLS_PCS}` : '',
    });
  }
}

// 生成单个订阅节点链接
function generateNode(proto) {
  const p = WS_PATH[proto], enc = p.replace(/\//g, '%2F');
  let ed = '';

  // Reality 链上的协议(链头或被回落到的)：都走链头的端口
  if (RPORT[proto]) return realityLink(proto, RPORT[proto]);

  if (ACTIVE_MODE === 'cloudflare') {
    if (!CLOUDFLARE_TUNNEL_HOSTNAME || (!TRY_TUNNEL && !CLOUDFLARE_TUNNEL_TOKEN)) {
      console.error(`[MODE] cloudflare mode needs CLOUDFLARE_TUNNEL_TOKEN (not needed in try mode) and a tunnel hostname found in the cloudflared log, no ${proto} link generated`);
      return '';
    }
    // VMess 链接里的 ?ed=2560 为 0-RTT early data，Xray 服务端自动识别
    if (proto === 'vmess') ed = '?ed=2560';
  }

  switch (proto) {
    case 'vless':
      return `vless://${UUID}@${WS.addr}:${WS.port}?encryption=none&security=tls&sni=${WS.host}&fp=chrome&type=ws&host=${WS.host}&path=${enc}${WS.iq}#${NAME_ENC}`;
    case 'vmess':
      return `vmess://${b64(JSON.stringify({
        v: '2', ps: NAME, add: WS.addr, port: String(WS.port), id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none',
        host: WS.host, path: p + ed, tls: 'tls', sni: WS.host, alpn: '', fp: '', insecure: String(WS.vmInsecure),
        ...(WS.vmExtra || {}), vcn: '', pcs: WS.vmPcs,
      }))}`;
    case 'trojan':
      return `trojan://${UUID}@${WS.addr}:${WS.port}?security=tls&sni=${WS.host}&fp=chrome&type=ws&host=${WS.host}&path=${enc}${WS.iq}#${NAME_ENC}`;
    case 'shadowsocks':
      // v2ray-plugin 无法跳过证书校验，自签证书下该节点连不上，不输出
      if (ACTIVE_MODE === 'ws' && TLS_INSECURE) {
        console.error(`[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, put one at ${BASE_DIR}/<CERT_HOST>.crt and .key. No SS link generated`);
        return '';
      }
      return `ss://${SS_USERINFO}@${WS.addr}:${WS.port}/?plugin=${ssPluginParam(WS.host, p)}#${NAME_ENC}`;
  }
}

// ========== Komari Agent ==========
// 探针：KOMARI_ENDPOINT 和 KOMARI_TOKEN 都填了才启用，向 Komari 面板上报本机状态
//   有代理协议：agent 后台运行，脚本继续启动 Xray
//   没有代理协议：脚本只作为 Komari 启动脚本，agent 前台运行(脚本不退出)
async function startKomari() {
  const bin = path.join(BASE_DIR, 'komari-agent');
  // 脚本被重启时，按进程名先停掉上一次留下的探针，避免出现两个探针进程
  await killPrevious('komari-agent', 'KOMARI');
  if (!await dl(bin, `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${ARCH}`)) process.exit(1);
  fs.chmodSync(bin, 0o755);
  // Endpoint / Token 通过环境变量只传给这一个进程，不出现在命令行(ps 看不到)
  const agentEnv = { AGENT_ENDPOINT: KOMARI_ENDPOINT, AGENT_TOKEN: KOMARI_TOKEN };
  if (!XRAY_ON) {
    console.log(`[KOMARI] No proxy protocol enabled, running the agent only, reporting to ${KOMARI_ENDPOINT}`);
    const child = cp.spawn(bin, [], { env: { ...process.env, ...agentEnv }, stdio: 'inherit' });
    children.push(child);
    child.on('exit', (code) => process.exit(code ?? 1));
    await new Promise(() => {}); // 一直运行，直到 agent 退出
  }
  spawnBg(bin, [], path.join(BASE_DIR, 'komari-agent.log'), agentEnv);
  console.log(`[KOMARI] Agent started, reporting to ${KOMARI_ENDPOINT}`);
}

// ========== cloudflared ==========
// cloudflare 模式：用 Token 跑固定隧道；try 模式：不需要 Token，用 Cloudflare 临时隧道(每次启动域名都会变)
// 取日志里 cloudflared 下发的 ingress 规则：第一条「有具体域名(不含通配符 *)、Service 是 http://localhost:端口 或 http://127.0.0.1:端口」的规则
function parseIngress(text) {
  const line = text.split('\n').filter((l) => l.includes('Updated to new configuration')).pop();
  const m = line && line.match(/config="(.*)" version=/);
  if (!m) return null;
  let cfg;
  try { cfg = JSON.parse(m[1].replace(/\\"/g, '"')); } catch { return null; } // 日志里的引号带反斜杠，先还原
  for (const r of cfg.ingress || []) {
    const sm = r.hostname && !r.hostname.includes('*') && /^http:\/\/(?:localhost|127\.0\.0\.1):(\d+)$/.exec(r.service || '');
    if (sm) return { hostname: r.hostname, port: sm[1] };
  }
  return null;
}

async function startCloudflared() {
  const bin = path.join(BASE_DIR, 'cloudflared'), log = path.join(BASE_DIR, 'cloudflared.log');
  // 脚本被重启时，按进程名先停掉上一次留下的 cloudflared，避免出现两个隧道进程
  await killPrevious('cloudflared', 'CF');
  if (!await dl(bin, `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}`)) process.exit(1);
  fs.chmodSync(bin, 0o755);
  cp.spawnSync(bin, ['--version'], { stdio: 'inherit' });

  if (TRY_TUNNEL) {
    // 临时隧道：回源到本机 FRONT_PORT(8000)；域名从日志里的 https://xxxx.trycloudflare.com 取
    spawnBg(bin, ['--no-autoupdate', 'tunnel', '--url', `http://localhost:${FRONT_PORT}`], log);
    for (let i = 0; i < 30 && !CLOUDFLARE_TUNNEL_HOSTNAME; i++) {
      const hosts = [...readLog(log).matchAll(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/g)].map((m) => m[1]).filter((h) => !h.startsWith('api.'));
      CLOUDFLARE_TUNNEL_HOSTNAME = hosts[0] || '';
      if (!CLOUDFLARE_TUNNEL_HOSTNAME) await sleep(1000);
    }
    if (CLOUDFLARE_TUNNEL_HOSTNAME) console.log(`[CF] Quick tunnel hostname from log: ${CLOUDFLARE_TUNNEL_HOSTNAME} (service port=${FRONT_PORT})`);
    else console.error(`[CF] Cannot find the trycloudflare.com hostname in ${log}`);
    return;
  }

  // Token 通过环境变量只传给这一个进程，不出现在命令行(ps 看不到)
  spawnBg(bin, ['--no-autoupdate', 'tunnel', 'run'], log, { TUNNEL_TOKEN: CLOUDFLARE_TUNNEL_TOKEN });
  // 从日志取隧道的域名和回源端口：等隧道连上后，cloudflared 会打印一行后台下发的配置(ingress 规则)
  for (let i = 0; i < 30 && !readLog(log).includes('Updated to new configuration'); i++) await sleep(1000);
  const rule = parseIngress(readLog(log));
  if (rule && validPort(rule.port)) {
    CLOUDFLARE_TUNNEL_HOSTNAME = rule.hostname;
    FRONT_PORT = parseInt(rule.port, 10);
    checkPorts(); // 端口变了，重新检查是否与 Reality 端口 / 内部保留端口冲突
    console.log(`[CF] From cloudflared log: hostname=${CLOUDFLARE_TUNNEL_HOSTNAME}, tunnel service port=${FRONT_PORT}`);
  } else {
    console.error(`[CF] Cannot read hostname / port from ${log} (the tunnel needs a Public hostname without * and a Service like http://localhost:PORT)`);
  }
}

// ========== 主流程 ==========
async function main() {
  parseModes();
  buildChains();
  planFront();
  checkPorts();

  if (ENABLED.length > 0) console.log(`[MODE] enabled=${ENABLED.join(' ')}`);
  if (ACTIVE_MODE) console.log(`[MODE] port ${FRONT_PORT}: ${ACTIVE_MODE} (${SHARED.join(' ')})${SHARE_FRONT ? ' shared with reality' : ''}`);
  for (const p of HEADS) console.log(`[MODE] port ${HPORT[p]}: reality (${CHAIN[p].join(' -> ')})`);

  VLESS_FLOW = HEADS.includes('vless') ? 'xtls-rprx-vision' : '';

  const KM_ON = !!(KOMARI_ENDPOINT && KOMARI_TOKEN);
  if (!XRAY_ON && !KM_ON) modeError('Nothing to run: set a protocol *_MODE / HYSTERIA2_MODE / MIXED_MODE / WIREGUARD_MODE, or KOMARI_ENDPOINT + KOMARI_TOKEN');
  if (KM_ON) await startKomari();

  if (HEADS.length) {
    loadRealityKeys();
    console.log(`[REALITY] Private key: ${REALITY_PRIVATE_KEY}`);
    console.log(`[REALITY] Public key: ${REALITY_PUBLIC_KEY}`);
  }
  if (WG_PORT) loadWgKeys();
  SS_USERINFO = b64url(`aes-256-gcm:${UUID}`);

  if (ACTIVE_MODE !== 'cloudflare' || HEADS.length > 0 || HY2_PORT || MIXED_PORT || WG_PORT) await resolvePublicAddr();

  // IPv6 出口检查：没有 IPv6 出口时，路由里会拒绝 IPv6 目标
  IPV6_AVAILABLE = await request(TRACE_URL, { family: 6, timeout: 5000 }).then(() => true, () => false);
  console.log(IPV6_AVAILABLE ? '[NET] IPv6 egress: available' : '[NET] IPv6 egress: unavailable, blocking IPv6 destinations');

  if (ACTIVE_MODE === 'ws' || HY2_PORT) setupTls();

  if (ACTIVE_MODE === 'cloudflare' && (CLOUDFLARE_TUNNEL_TOKEN || TRY_TUNNEL)) await startCloudflared();

  // ---- Xray ----
  const xrayDir = path.join(BASE_DIR, 'xray'), xrayBin = path.join(xrayDir, 'xray'), xrayConf = path.join(xrayDir, 'config.json');
  fs.mkdirSync(xrayDir, { recursive: true });
  const zipFile = path.join(BASE_DIR, 'xray.zip');
  if (!await dl(zipFile, `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH === 'amd64' ? '64' : 'arm64-v8a'}.zip`)) process.exit(1);
  unzip(zipFile, xrayDir);
  fs.rmSync(zipFile, { force: true });
  try { fs.chmodSync(xrayBin, 0o755); } catch { /* 下面统一检查 */ }
  if (!nonEmpty(xrayBin)) { console.error(`[XRAY] Binary not found after extraction: ${xrayBin}`); process.exit(1); }
  // geoip.dat / geosite.dat 随 Xray 发行包一起解压在同一目录
  const xrayEnv = { ...process.env, XRAY_LOCATION_ASSET: xrayDir };
  cp.spawnSync(xrayBin, ['version'], { stdio: 'inherit', env: xrayEnv });

  // 生成 config.json：先建空文件并收紧权限，再写入(里面有 UUID 和 Reality 私钥)
  fs.writeFileSync(xrayConf, '', { mode: 0o600 });
  fs.chmodSync(xrayConf, 0o600);
  fs.writeFileSync(xrayConf, `${JSON.stringify(buildConfig(), null, 2)}\n`);

  // 启动前校验配置
  if (cp.spawnSync(xrayBin, ['run', '-test', '-c', xrayConf], { stdio: 'inherit', env: xrayEnv }).status !== 0) {
    console.error('[XRAY] Config test failed, aborting');
    process.exit(1);
  }

  // ---- 输出订阅 ----
  // 每行一个原始链接方便单条复制，末尾再给一份合并后的 base64 订阅，方便整段导入
  if (ACTIVE_MODE) initWsParams();
  const nodes = [];
  const emit = (s) => { if (s) nodes.push(s); };
  for (const p of ENABLED) emit(generateNode(p));
  if (HY2_PORT) emit(hy2Link());
  if (MIXED_PORT) emit(mixedLinks());
  if (WG_PORT) emit(wgLink());
  const allNodes = nodes.map((n) => `${n}\n`).join('');
  console.log(`\n=== Nodes ===\n${allNodes}\n=== Subscription (base64) ===\n${b64(allNodes)}\n`);
  if (WG_PORT) console.log(`\n=== WireGuard config (wg-quick) ===\n${wgConf()}`);

  // ---- 运行 ----
  const xray = cp.spawn(xrayBin, ['run', '-c', xrayConf], { stdio: 'inherit', env: xrayEnv });
  children.push(xray);
  xray.on('exit', (code) => process.exit(code ?? 1));
}

main().catch((e) => { console.error(e); process.exit(1); });
