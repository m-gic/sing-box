#!/usr/bin/env node
'use strict';
// 纯 Node.js 实现，只用内置模块，需要 Node.js 16+。*_MODE 可用逗号分隔填多个模式，如 VLESS_MODE=ws,443
const builtin = (moduleName) => (typeof require === 'function' ? require(moduleName) : process.getBuiltinModule(`node:${moduleName}`)); // CJS 用 require；ESM 用 getBuiltinModule(Node 22.3+)
const [crypto, fs, path, childProcess, https, http, zlib, dns, tls] = ['crypto', 'fs', 'path', 'child_process', 'https', 'http', 'zlib', 'dns', 'tls'].map(builtin);
const { X509Certificate } = crypto;
const SELF = path.resolve(process.argv[1]), BASE_DIR = path.dirname(SELF);

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

// 把当前 UUID 写回脚本本身(填进上面 UUID 那行的 '' 里)：下次运行直接沿用
fs.writeFileSync(SELF, fs.readFileSync(SELF, 'utf8').replace(/^  UUID: .*$/m, () => `  UUID: process.env.UUID || '${CONFIG.UUID}' || crypto.randomUUID(),`));

process.chdir(BASE_DIR);
const ARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch];
if (!ARCH) { console.error(`[ARCH] Unsupported architecture: ${process.arch}`); process.exit(1); }

// ========== 通用函数 ==========
const toBase64 = (input, encoding = 'base64') => Buffer.from(input).toString(encoding);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const isValidPort = (value) => /^[0-9]+$/.test(value) && +value >= 1 && +value <= 65535;
const die = (message) => { console.error(`[MODE] ${message}`); process.exit(1); };
const fileNonEmpty = (file) => { try { return fs.statSync(file).size > 0; } catch { return false; } };
const readLog = (file) => { try { return fs.readFileSync(file, 'utf8'); } catch { return ''; } };
const urlEncode = (text) => encodeURIComponent(text).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);

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
      if (!file) {
        const chunks = [];
        return res.on('data', (chunk) => chunks.push(chunk)).on('end', () => resolve({ status, body: Buffer.concat(chunks).toString() })).on('error', reject);
      }
      if (status >= 400) { res.resume(); return reject(new Error(`HTTP ${status}`)); }
      res.pipe(fs.createWriteStream(file).on('finish', () => resolve({ status })).on('error', reject));
    });
    req.setTimeout(timeout, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

// 先写 .part 再改名，失败返回 false，不留半截文件
async function download(dest, url) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try { await request(url, { file: `${dest}.part` }); fs.renameSync(`${dest}.part`, dest); return true; } catch { fs.rmSync(`${dest}.part`, { force: true }); await sleep(1000); }
  }
  console.error(`[DL] Download failed: ${url}`);
  return false;
}

// 下载二进制到脚本目录并加执行权限，失败直接退出
async function fetchBinary(fileName, url) {
  const binaryPath = path.join(BASE_DIR, fileName);
  if (!await download(binaryPath, url)) process.exit(1);
  fs.chmodSync(binaryPath, 0o755);
  return binaryPath;
}

// 流式解压 zip：只读中央目录，逐个文件边读边解压边写
async function unzip(zipFile, targetDir) {
  const { pipeline } = builtin('stream').promises, rootDir = path.resolve(targetDir);
  const fileDescriptor = fs.openSync(zipFile, 'r'), fileSize = fs.fstatSync(fileDescriptor).size;
  const readAt = (length, position) => { const buffer = Buffer.alloc(length); fs.readSync(fileDescriptor, buffer, 0, length, position); return buffer; };
  const tail = readAt(Math.min(fileSize, 65557), Math.max(0, fileSize - 65557));
  let endRecordOffset = tail.length - 22;
  while (endRecordOffset >= 0 && tail.readUInt32LE(endRecordOffset) !== 0x06054b50) endRecordOffset--;
  if (endRecordOffset < 0) throw new Error('not a zip file');
  const centralDirectory = readAt(tail.readUInt32LE(endRecordOffset + 12), tail.readUInt32LE(endRecordOffset + 16));
  try {
    for (let entryIndex = 0, position = 0; entryIndex < tail.readUInt16LE(endRecordOffset + 10); entryIndex++) {
      const method = centralDirectory.readUInt16LE(position + 10), compressedSize = centralDirectory.readUInt32LE(position + 20);
      const nameLength = centralDirectory.readUInt16LE(position + 28), localHeaderOffset = centralDirectory.readUInt32LE(position + 42);
      const entryName = centralDirectory.toString('utf8', position + 46, position + 46 + nameLength);
      position += 46 + nameLength + centralDirectory.readUInt16LE(position + 30) + centralDirectory.readUInt16LE(position + 32);
      const outputPath = path.resolve(rootDir, entryName);
      if (entryName.endsWith('/') || !outputPath.startsWith(rootDir + path.sep)) continue;
      fs.mkdirSync(path.dirname(outputPath), { recursive: true });
      if (!compressedSize) { fs.writeFileSync(outputPath, ''); continue; }
      const localHeader = readAt(30, localHeaderOffset), dataStart = localHeaderOffset + 30 + localHeader.readUInt16LE(26) + localHeader.readUInt16LE(28);
      const source = fs.createReadStream(zipFile, { start: dataStart, end: dataStart + compressedSize - 1 }), output = fs.createWriteStream(outputPath);
      await (method === 0 ? pipeline(source, output) : pipeline(source, zlib.createInflateRaw(), output));
    }
  } finally { fs.closeSync(fileDescriptor); }
}

// Go 程序内存参数：GOGC 调低；容器有内存限制时再设 GOMEMLIMIT 软上限
const GO_ENV = (() => {
  const memoryLimit = +(readLog('/sys/fs/cgroup/memory.max').trim() || readLog('/sys/fs/cgroup/memory/memory.limit_in_bytes').trim()); // 无限制时是 'max' 或巨大的数
  return { GOGC: '50', ...(memoryLimit > 0 && memoryLimit < 2 ** 40 ? { GOMEMLIMIT: `${Math.floor(memoryLimit * 0.6 / 1048576)}MiB` } : {}) };
})();

// 子进程：脚本退出(含 SIGINT / SIGTERM)时一并结束
const children = [];
process.on('exit', () => children.forEach((child) => { try { child.kill(); } catch { /* 已退出 */ } }));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(0));

// 按进程名停掉上一次留下的同名进程；没有 pkill 或没有旧进程时什么都不做
async function killPrevious(processName, logTag) {
  try { childProcess.execFileSync('pkill', ['-x', processName], { stdio: 'ignore' }); } catch { return; }
  console.log(`[${logTag}] Stopped previous ${processName}`);
  await sleep(1000);
}

// logFile 不为空时后台运行并把输出写进日志，否则继承当前终端
function spawnChild(binaryPath, args, logFile, extraEnv = {}) {
  const logFileDescriptor = logFile ? fs.openSync(logFile, 'w') : null;
  const child = childProcess.spawn(binaryPath, args, { env: { ...process.env, ...GO_ENV, ...extraEnv }, stdio: logFileDescriptor === null ? 'inherit' : ['ignore', logFileDescriptor, logFileDescriptor] });
  if (logFileDescriptor !== null) fs.closeSync(logFileDescriptor);
  children.push(child);
  return child;
}

// ========== 协议与模式 ==========
const PROTOS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
const WS_PATH = { vless: '/misaka-vless', vmess: '/misaka-vmess', trojan: '/misaka-trojan', shadowsocks: '/misaka-ss' };
// 内部连接用 abstract unix socket(名字带脚本目录哈希，多份并存不冲突)。Shadowsocks 入站不支持 unix socket，只能用本机端口：40004 给 Reality 链，40005 给 ws 入口
const SS_PORTS = [40004, 40005];
const HASH = crypto.createHash('sha1').update(BASE_DIR).digest('hex').slice(0, 8);
const SOCK = (name) => `@xray-${HASH}-${name}`;
const internal = (proto, isWs = false) => {
  if (proto === 'shadowsocks') { const port = SS_PORTS[+isWs]; return { listen: '127.0.0.1', port, dest: port }; }
  const socketName = SOCK(isWs ? `${proto}-ws` : proto);
  return { listen: socketName, dest: socketName };
};
const FRONT_SOCK = SOCK('front'), WEB_SOCK = SOCK('web');
const DEFAULT_FRONT_PORT = 8000, WG_CLIENT_ADDR = '10.0.0.2/32';
const MODES = { vless: CONFIG.VLESS_MODE, vmess: CONFIG.VMESS_MODE, trojan: CONFIG.TROJAN_MODE, shadowsocks: CONFIG.SHADOWSOCKS_MODE };
const NPORT = {}, FB = {}, PARENT = {}, ROLE = {}; // 协议 -> 数字端口 / 回落到的协议 / 回落到它的协议 / Reality 角色
const CHAIN = {}, HPORT = {}, RPORT = {}; // Reality 链头 -> 整条链 / 监听端口；链上每个协议 -> 对外端口
const ENABLED = [], SHARED = [], HEADS = []; // 启用的协议 / 用 ws·cloudflare 的协议 / Reality 链头
let ACTIVE_MODE = '', TRY_TUNNEL = false, FRONT_ON = false, SHARE_FRONT = false, FRONT_TLS = false, FRONT_PORT = 0, XRAY_ON = false;
const NAME_ENC = urlEncode(CONFIG.NAME);

// 前置入口收到的非 ws 请求回落到内置 HTTP 服务：/UUID 返回订阅，其它路径转给 CERT_HOST:80(PORT 和 CERT_HOST 都填了才有)，没有就 404
let WEB_DEST = '';
if (CONFIG.PORT && CONFIG.CERT_HOST) {
  WEB_DEST = `${CONFIG.CERT_HOST}:80`;
  if (!/^[A-Za-z0-9.-]+:[0-9]{1,5}$/.test(WEB_DEST)) die(`CERT_HOST='${CONFIG.CERT_HOST}' is invalid (expected a domain or an IPv4 address)`);
  console.log(`[WEB] Other paths on the front port are forwarded to ${WEB_DEST}`);
}

// Hysteria2(UDP)、Mixed(SOCKS5 + HTTP，账号 misaka 密码 UUID)、WireGuard(UDP)：只接受数字端口，不参与回落链
const modePort = (name, value, description) => {
  if (!value) return 0;
  if (!isValidPort(value)) die(`${name}='${value}' is invalid (expected a port number 1-65535, or empty to disable)`);
  console.log(`[MODE] port ${+value}/${description}`);
  return +value;
};
const HY2_PORT = modePort('HYSTERIA2_MODE', CONFIG.HYSTERIA2_MODE, 'udp: hysteria2');
const MIXED_PORT = modePort('MIXED_MODE', CONFIG.MIXED_MODE, 'tcp: mixed (socks5 + http)');
const WG_PORT = modePort('WIREGUARD_MODE', CONFIG.WIREGUARD_MODE, 'udp: wireguard');

// 1. 解析 *_MODE：每个协议最多一个 ws / cloudflare 角色，和最多一个 Reality 角色(数字端口 或 回落协议名)
function parseModes() {
  for (const proto of PROTOS) {
    const varName = `${proto.toUpperCase()}_MODE`;
    for (const mode of (MODES[proto] || '').split(/[,\s]+/).filter(Boolean)) {
      if (mode === 'ws' || mode === 'cloudflare') {
        if (SHARED.includes(proto)) die(`${varName}: ws / cloudflare can only be given once`);
        if (ACTIVE_MODE && ACTIVE_MODE !== mode) die(`Protocols using ws / cloudflare share one port (PORT), so they must use the same mode (got: ${ACTIVE_MODE} ${mode})`);
        SHARED.push(proto); ACTIVE_MODE = mode;
        continue;
      }
      if (ROLE[proto]) die(`${varName}: only one Reality role (a port or a fallback protocol) per protocol`);
      if (/^[0-9]+$/.test(mode)) {
        if (!isValidPort(mode)) die(`${varName}='${mode}': port must be 1-65535`);
        NPORT[proto] = +mode;
      } else if (PROTOS.includes(mode)) {
        if (mode === proto) die(`${varName}='${mode}': a protocol cannot fall back to itself`);
        if (proto !== 'vless' && proto !== 'trojan') die(`${varName}='${mode}': ${proto.toUpperCase()} has no fallback ability, only VLESS and TROJAN can choose a fallback`);
        FB[proto] = mode;
      } else {
        die(`${varName}='${mode}' is invalid (expected: ws / cloudflare / a port / a fallback protocol: ${PROTOS.join(' ')}, or empty to disable)`);
      }
      ROLE[proto] = mode;
    }
  }
  TRY_TUNNEL = ACTIVE_MODE === 'cloudflare' && CONFIG.CLOUDFLARE_TUNNEL_TOKEN === 'try'; // Token 填 try = Cloudflare 临时隧道
}

// 2. 把回落关系整理成 Reality 链：得到 ENABLED / HEADS / CHAIN / HPORT / RPORT
function buildChains() {
  for (const [proto, target] of Object.entries(FB)) { // 每个协议只能被一个协议回落到
    if (PARENT[target]) die(`${target.toUpperCase()} is the fallback of both ${PARENT[target].toUpperCase()} and ${proto.toUpperCase()}, it can only have one`);
    PARENT[target] = proto;
  }
  for (const proto of PROTOS) { // 链头 = 有 Reality 角色且没被别人回落到的协议
    if (SHARED.includes(proto) || ROLE[proto] || PARENT[proto]) ENABLED.push(proto);
    if (ROLE[proto] && !PARENT[proto]) HEADS.push(proto);
  }
  for (const head of HEADS) { // 顺着回落走到链尾，端口取链尾的数字
    let chainTail = head;
    CHAIN[head] = [head];
    while (FB[chainTail]) { chainTail = FB[chainTail]; CHAIN[head].push(chainTail); }
    if (!NPORT[chainTail]) die(`The chain from ${head.toUpperCase()} ends at ${chainTail.toUpperCase()}, which needs a port: set ${chainTail.toUpperCase()}_MODE to a port number`);
    HPORT[head] = NPORT[chainTail];
    for (const proto of CHAIN[head]) RPORT[proto] = HPORT[head];
  }
  XRAY_ON = ENABLED.length > 0 || !!(HY2_PORT || MIXED_PORT || WG_PORT); // 没有代理协议时只跑 Komari 探针
  for (const proto of ENABLED) if ((ROLE[proto] || PARENT[proto]) && !RPORT[proto]) die(`${proto.toUpperCase()} is part of a fallback loop: the chain needs a head that no protocol falls back to`);
}

// 3. 前置入口：是否需要、监听哪个端口、是否与某条 Reality 链共用
function planFront() {
  if (!ACTIVE_MODE && !CONFIG.PORT) return;
  FRONT_ON = true;
  const frontPort = ACTIVE_MODE === 'cloudflare' ? DEFAULT_FRONT_PORT : (CONFIG.PORT || DEFAULT_FRONT_PORT); // cloudflare 之后会从日志读回源端口覆盖
  if (!isValidPort(String(frontPort))) die(`PORT='${CONFIG.PORT}' is not a valid port`);
  FRONT_PORT = +frontPort;
  // PORT 与某条 Reality 链端口相同：共用端口，Reality 认不出的流量转给本机前置入口(带 TLS)
  SHARE_FRONT = !!CONFIG.PORT && ACTIVE_MODE !== 'cloudflare' && HEADS.some((head) => HPORT[head] === FRONT_PORT);
}

// 4. 端口检查：TCP 监听端口互不重复，且不占用 Shadowsocks 内部端口
function checkPorts() {
  const ports = HEADS.map((head) => HPORT[head]);
  if (FRONT_ON && !SHARE_FRONT) ports.push(FRONT_PORT);
  if (MIXED_PORT) ports.push(MIXED_PORT);
  const duplicate = ports.find((port, index) => ports.indexOf(port) !== index);
  if (duplicate !== undefined) die(`Port ${duplicate} is used more than once: every Reality chain, the ws / cloudflare group (PORT) and MIXED_MODE need different TCP ports`);
  const conflicting = ports.find((port) => SS_PORTS.includes(port));
  if (conflicting !== undefined) die(`Port ${conflicting} conflicts with the internal ports ${SS_PORTS.join(' / ')} used by Shadowsocks`);
}

// ========== TLS 证书(供 ws / Hysteria2 使用) ==========
// 脚本不申请证书。CERT_HOST 是域名且脚本目录下有 $CERT_HOST.crt / .key 且可信 -> 直接使用；否则用自签证书
const IP_RE = /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/;
let CERT_FILE = '', KEY_FILE = '', TLS_SERVER_NAME = '', TLS_INSECURE = true, TLS_PCS = '';

// 最小的 DER 编码器：只够生成一张自签 X.509 证书
const DER = {
  length: (size) => (size < 128 ? Buffer.from([size]) : size < 256 ? Buffer.from([0x81, size]) : Buffer.from([0x82, size >> 8, size & 255])),
  tlv: (tag, ...contents) => { const body = Buffer.concat(contents); return Buffer.concat([Buffer.from([tag]), DER.length(body.length), body]); },
  sequence: (...contents) => DER.tlv(0x30, ...contents),
  integer: (buffer) => DER.tlv(0x02, buffer[0] & 0x80 ? Buffer.concat([Buffer.from([0]), buffer]) : buffer),
  oid: (dotted) => {
    const parts = dotted.split('.').map(Number), bytes = [parts[0] * 40 + parts[1]];
    for (const number of parts.slice(2)) { const encoded = [number & 127]; for (let rest = number >> 7; rest; rest >>= 7) encoded.unshift((rest & 127) | 128); bytes.push(...encoded); }
    return DER.tlv(0x06, Buffer.from(bytes));
  },
  utcTime: (date) => DER.tlv(0x17, Buffer.from(date.toISOString().replace(/^\d\d(\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d).*$/, '$1$2$3$4$5$6Z'))),
};

// 生成自签证书(RSA 2048，10 年)；已有且 30 天内不过期就复用，否则每次重启证书哈希都变，已导入的订阅会失效
function generateSelfSignedCert(commonName) {
  const certDir = path.join(BASE_DIR, '.selfsigned');
  fs.mkdirSync(certDir, { recursive: true, mode: 0o700 });
  CERT_FILE = path.join(certDir, `${commonName}.crt`); KEY_FILE = path.join(certDir, `${commonName}.key`);
  if (fileNonEmpty(CERT_FILE) && fileNonEmpty(KEY_FILE)) {
    try { if (Date.parse(new X509Certificate(fs.readFileSync(CERT_FILE)).validTo) - Date.now() > 30 * 86400e3) return; } catch { /* 重新生成 */ }
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const subjectName = DER.sequence(DER.tlv(0x31, DER.sequence(DER.oid('2.5.4.3'), DER.tlv(0x0c, Buffer.from(commonName)))));
  const signatureAlgorithm = DER.sequence(DER.oid('1.2.840.113549.1.1.11'), DER.tlv(0x05));
  const serialNumber = crypto.randomBytes(16); serialNumber[0] = (serialNumber[0] & 0x7f) || 1;
  const subjectAltName = DER.tlv(0xa3, DER.sequence(DER.sequence(DER.oid('2.5.29.17'), DER.tlv(0x04, DER.sequence(DER.tlv(0x82, Buffer.from(commonName)), DER.tlv(0x82, Buffer.from('localhost')))))));
  const toBeSigned = DER.sequence(
    DER.tlv(0xa0, DER.integer(Buffer.from([2]))), DER.integer(serialNumber), signatureAlgorithm, subjectName,
    DER.sequence(DER.utcTime(new Date(Date.now() - 86400e3)), DER.utcTime(new Date(Date.now() + 3650 * 86400e3))), subjectName,
    publicKey.export({ type: 'spki', format: 'der' }), subjectAltName,
  );
  const certificate = DER.sequence(toBeSigned, signatureAlgorithm, DER.tlv(0x03, Buffer.concat([Buffer.from([0]), crypto.sign('sha256', toBeSigned, privateKey)])));
  fs.writeFileSync(CERT_FILE, `-----BEGIN CERTIFICATE-----\n${toBase64(certificate).match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`);
  fs.writeFileSync(KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
}

// 校验证书链：叶子含域名，沿中间证书逐级验签，最终落在系统信任的根证书上；返回空串表示可信，否则返回原因
function verifyChain(certs, host) {
  if (!certs[0].checkHost(host)) return 'hostname mismatch';
  const rootCerts = (tls.getCACertificates ? tls.getCACertificates('default') : tls.rootCertificates).map((pem) => new X509Certificate(pem)); // Node 22.15 以下只能用内置根证书
  const isValid = (cert) => Date.now() >= Date.parse(cert.validFrom) && Date.now() <= Date.parse(cert.validTo);
  const signedBy = (cert, issuer) => cert.checkIssued(issuer) && cert.verify(issuer.publicKey);
  let current = certs[0];
  for (let depth = 0; depth < 8; depth++) {
    if (!isValid(current)) return 'certificate expired or not yet valid';
    if (rootCerts.some((root) => root.fingerprint256 === current.fingerprint256 || (isValid(root) && signedBy(current, root)))) return '';
    current = certs.slice(1).find((candidate) => candidate !== current && candidate.ca && signedBy(current, candidate));
    if (!current) return 'issuer is not trusted';
  }
  return 'chain too long';
}

// 检查 CERT_HOST 的证书是否可信，可信则写入 CERT_FILE / KEY_FILE
function trustedCertForHost(host) {
  const certPath = path.join(BASE_DIR, `${host}.crt`), keyPath = path.join(BASE_DIR, `${host}.key`);
  if (!fileNonEmpty(certPath) || !fileNonEmpty(keyPath)) return false;
  let certs;
  try {
    certs = (fs.readFileSync(certPath, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []).map((pem) => new X509Certificate(pem));
    if (!certs.length) throw new Error('no certificate found');
    if (!certs[0].checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyPath)))) { console.error(`[TLS] ${certPath} and ${keyPath} do not match`); return false; }
  } catch (error) { console.error(`[TLS] Cannot read ${certPath} / ${keyPath}: ${error.message}`); return false; }
  const reason = verifyChain(certs, host);
  if (reason) { console.error(`[TLS] ${certPath} is not a trusted certificate for ${host}: ${reason}`); return false; }
  CERT_FILE = certPath; KEY_FILE = keyPath;
  return true;
}

function setupTls() {
  TLS_SERVER_NAME = CONFIG.CERT_HOST || 'www.nazhumi.com';
  TLS_INSECURE = !(CONFIG.CERT_HOST && !IP_RE.test(CONFIG.CERT_HOST) && trustedCertForHost(CONFIG.CERT_HOST));
  if (TLS_INSECURE) {
    console.error(`[TLS] No trusted certificate available (put one at ${BASE_DIR}/<CERT_HOST>.crt and .key), using self-signed certificate`);
    generateSelfSignedCert(TLS_SERVER_NAME);
    // 新版 Xray 客户端已移除 allowInsecure，自签证书改用证书哈希固定(链接里的 pcs)
    TLS_PCS = new X509Certificate(fs.readFileSync(CERT_FILE)).fingerprint256.replace(/:/g, '').toLowerCase();
  }
  console.log(`[TLS] Server name: ${TLS_SERVER_NAME}, insecure: ${+TLS_INSECURE}, cert: ${CERT_FILE}, key: ${KEY_FILE}`);
}

// ========== 密钥 ==========
// X25519：固定的 PKCS8 DER 头 + 32 字节私钥，推导出配对的公钥(Reality 和 WireGuard 共用)
const x25519Public = (privateKey32) => crypto.createPublicKey(crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), privateKey32]), format: 'der', type: 'pkcs8',
})).export({ type: 'spki', format: 'der' }).subarray(-32);

// 私钥由 UUID 派生：同一个 UUID 永远得到同一组密钥，不落盘；encoding 是 base64 / base64url
function deriveKey(label, encoding) {
  const privateKey = crypto.createHash('sha256').update(`${label}:${CONFIG.UUID}`).digest();
  privateKey[0] &= 248; privateKey[31] = (privateKey[31] & 127) | 64;
  return [privateKey.toString(encoding), toBase64(x25519Public(privateKey), encoding)];
}

// ========== 链接里的连接地址(PUBLIC_IP) ==========
// CERT_HOST 填 IP -> 直接用；填域名或留空 -> 探测公网 IPv4，域名解析结果包含它时改用域名
let PUBLIC_IP = '';
const TRACE_URL = 'https://one.one.one.one/cdn-cgi/trace';

async function resolvePublicAddr() {
  if (IP_RE.test(CONFIG.CERT_HOST)) {
    PUBLIC_IP = CONFIG.CERT_HOST;
  } else {
    const response = await request(TRACE_URL, { family: 4, timeout: 5000 }).catch(() => null); // 只取 IPv4：IPv6 直接拼进 host:port 会让链接失效
    PUBLIC_IP = ((response && response.body.match(/^ip=(.*)$/m)) || [, ''])[1].trim();
    if (CONFIG.CERT_HOST && PUBLIC_IP) {
      const resolvedIps = await dns.promises.lookup(CONFIG.CERT_HOST, { family: 4, all: true }).then((list) => list.map((entry) => entry.address)).catch(() => []);
      if (resolvedIps.includes(PUBLIC_IP)) { console.log(`[NET] ${CONFIG.CERT_HOST} points to this server, using it instead of the IP`); PUBLIC_IP = CONFIG.CERT_HOST; }
    }
  }
  if (!PUBLIC_IP) console.error('[NET] Cannot determine the public address, links will be invalid (set CERT_HOST)');
  console.log(`[NET] Address in links: ${PUBLIC_IP}`);
}

// ========== Xray 配置 ==========
let REALITY_PRIVATE_KEY = '', REALITY_PUBLIC_KEY = '', VLESS_FLOW = '', IPV6_AVAILABLE = false;
let WG_SERVER_PRIVATE = '', WG_SERVER_PUBLIC = '', WG_CLIENT_PRIVATE = '', WG_CLIENT_PUBLIC = '';
const SNIFFING = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true }; // 只用于路由匹配，不改写目标地址

const streamTcp = () => ({ network: 'tcp', security: 'none' });
const streamWs = (wsPath) => ({ network: 'ws', security: 'none', wsSettings: { path: wsPath } });
const streamReality = (dest = 'www.iij.ad.jp:443', serverName = 'www.iij.ad.jp') => ({
  network: 'tcp', security: 'reality',
  realitySettings: { show: false, dest, xver: 0, serverNames: [serverName], privateKey: REALITY_PRIVATE_KEY, shortIds: ['cdcf853c'] },
});
const streamTls = (network, alpn, extra = {}) => ({
  network, security: 'tls',
  tlsSettings: { serverName: TLS_SERVER_NAME, alpn: [alpn], certificates: [{ certificateFile: CERT_FILE, keyFile: KEY_FILE }] },
  ...extra,
});

function protoSettings(proto, fallbacks, flow) {
  const fallbackSettings = fallbacks ? { fallbacks } : {};
  switch (proto) {
    case 'vless': return { clients: [{ id: CONFIG.UUID, email: 'misaka', ...(flow ? { flow } : {}) }], decryption: 'none', ...fallbackSettings };
    case 'vmess': return { clients: [{ id: CONFIG.UUID, email: 'misaka' }] };
    case 'trojan': return { clients: [{ password: CONFIG.UUID, email: 'misaka' }], ...fallbackSettings };
    case 'shadowsocks': return { method: 'aes-256-gcm', password: CONFIG.UUID, network: 'tcp' };
  }
}

const inbound = (tag, listen, port, protocol, settings, streamSettings) => ({ tag, listen, port, protocol, settings, streamSettings, sniffing: SNIFFING });

function buildConfig() {
  const inbounds = [];
  if (FRONT_ON) {
    // 前置入口(本身是个 VLESS 入口)：按 HTTP 路径把 ws 流量回落给各内部 ws 入口，其余回落给内置 HTTP 服务；与 Reality 共用端口时只听内部 socket
    const fallbacks = [];
    for (const proto of SHARED) {
      const internalAddr = internal(proto, true);
      fallbacks.push({ path: WS_PATH[proto], dest: internalAddr.dest, xver: 0 });
      inbounds.push(inbound(`${proto}-ws-in`, internalAddr.listen, internalAddr.port, proto, protoSettings(proto), streamWs(WS_PATH[proto])));
    }
    fallbacks.push({ dest: WEB_SOCK, xver: 0 });
    const [listen, port] = SHARE_FRONT ? [FRONT_SOCK, undefined] : ['::', FRONT_PORT];
    inbounds.push(inbound('front-in', listen, port, 'vless', protoSettings('vless', fallbacks), FRONT_TLS ? streamTls('tcp', 'http/1.1') : streamTcp()));
  }
  for (const head of HEADS) { // Reality 链：链头监听自己的端口并套 Reality；被回落到的协议监听内部地址
    for (const proto of CHAIN[head]) {
      const fallbacks = FB[proto] ? [{ dest: internal(FB[proto]).dest, xver: 0 }] : undefined;
      if (proto !== head) { const internalAddr = internal(proto); inbounds.push(inbound(`${proto}-in`, internalAddr.listen, internalAddr.port, proto, protoSettings(proto, fallbacks), streamTcp())); continue; }
      const streamSettings = SHARE_FRONT && HPORT[head] === FRONT_PORT ? streamReality(FRONT_SOCK, TLS_SERVER_NAME) : streamReality();
      inbounds.push(inbound(`${proto}-in`, '::', HPORT[head], proto, protoSettings(proto, fallbacks, proto === 'vless' ? VLESS_FLOW : ''), streamSettings));
    }
  }
  if (HY2_PORT) inbounds.push(inbound('hysteria2-in', '::', HY2_PORT, 'hysteria', { version: 2, clients: [{ auth: CONFIG.UUID, email: 'misaka' }] }, streamTls('hysteria', 'h3', { hysteriaSettings: { version: 2 } })));
  if (MIXED_PORT) inbounds.push(inbound('mixed-in', '::', MIXED_PORT, 'socks', { auth: 'password', accounts: [{ user: 'misaka', pass: CONFIG.UUID }], udp: false }, streamTcp()));
  if (WG_PORT) inbounds.push(inbound('wireguard-in', '::', WG_PORT, 'wireguard', { secretKey: WG_SERVER_PRIVATE, peers: [{ publicKey: WG_CLIENT_PUBLIC, allowedIPs: [WG_CLIENT_ADDR] }], mtu: 1420 }));
  return {
    log: { loglevel: 'warning' },
    dns: { servers: ['https+local://1.1.1.1/dns-query'], queryStrategy: 'UseIPv4' },
    inbounds,
    outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
        ...(IPV6_AVAILABLE ? [] : [{ type: 'field', ip: ['::/0'], outboundTag: 'block' }]), // 无 IPv6 出口时拒绝 IPv6 目标，让客户端立即回退 IPv4
        { type: 'field', domain: ['geosite:cn', 'geosite:category-ads-all'], outboundTag: 'block' },
        { type: 'field', ip: ['geoip:cn'], outboundTag: 'block' },
      ],
    },
  };
}

// ========== 订阅链接 ==========
let SS_USERINFO = '', CLOUDFLARE_TUNNEL_HOSTNAME = '';

// Reality 链接(VMess / SS 也用 URI 格式，客户端要能当作 Reality 节点导入)
function realityLink(proto, port) {
  const serverName = SHARE_FRONT && port === FRONT_PORT ? TLS_SERVER_NAME : 'www.iij.ad.jp';
  const prefixParams = { vless: `encryption=none${VLESS_FLOW ? `&flow=${VLESS_FLOW}` : ''}&`, vmess: 'encryption=auto&' }[proto] || '';
  const realityQuery = `security=reality&sni=${serverName}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&type=tcp&sid=cdcf853c`;
  const isShadowsocks = proto === 'shadowsocks';
  return `${isShadowsocks ? 'ss' : proto}://${isShadowsocks ? SS_USERINFO : CONFIG.UUID}@${PUBLIC_IP}:${port}?${prefixParams}${realityQuery}#${NAME_ENC}`;
}

// ws / cloudflare 链接的共同参数：cloudflare 连 CLOUDFLARE_IP(没设置就连隧道域名):443；ws 连 PUBLIC_IP:FRONT_PORT，自签证书用 pcs 固定
function wsParams() {
  if (ACTIVE_MODE === 'cloudflare') return { address: CONFIG.CLOUDFLARE_IP || CLOUDFLARE_TUNNEL_HOSTNAME, port: 443, host: CLOUDFLARE_TUNNEL_HOSTNAME, insecureQuery: '', vmessInsecure: 0, vmessExtra: null, vmessPcs: '' };
  const insecureFlag = +TLS_INSECURE;
  return {
    address: PUBLIC_IP, port: FRONT_PORT, host: TLS_SERVER_NAME, vmessInsecure: insecureFlag, vmessPcs: TLS_PCS,
    vmessExtra: { allowInsecure: insecureFlag, verify_cert: !TLS_INSECURE }, insecureQuery: TLS_INSECURE ? `&allowInsecure=1&pcs=${TLS_PCS}` : '',
  };
}

// ws / cloudflare 节点链接
function wsNode(proto, wsInfo) {
  const wsPath = WS_PATH[proto], encodedPath = wsPath.replace(/\//g, '%2F');
  if (ACTIVE_MODE === 'cloudflare' && (!CLOUDFLARE_TUNNEL_HOSTNAME || !CONFIG.CLOUDFLARE_TUNNEL_TOKEN)) {
    console.error(`[MODE] cloudflare mode needs CLOUDFLARE_TUNNEL_TOKEN (set it to 'try' for a quick tunnel) and a tunnel hostname found in the cloudflared log, no ${proto} link generated`);
    return '';
  }
  const query = `sni=${wsInfo.host}&fp=chrome&type=ws&host=${wsInfo.host}&path=${encodedPath}${wsInfo.insecureQuery}#${NAME_ENC}`;
  switch (proto) {
    case 'vless': return `vless://${CONFIG.UUID}@${wsInfo.address}:${wsInfo.port}?encryption=none&security=tls&${query}`;
    case 'trojan': return `trojan://${CONFIG.UUID}@${wsInfo.address}:${wsInfo.port}?security=tls&${query}`;
    case 'vmess': // ?ed=2560 为 0-RTT early data，Xray 服务端自动识别
      return `vmess://${toBase64(JSON.stringify({
        v: '2', ps: CONFIG.NAME, add: wsInfo.address, port: String(wsInfo.port), id: CONFIG.UUID, aid: '0', scy: 'none', net: 'ws', type: 'none',
        host: wsInfo.host, path: wsPath + (ACTIVE_MODE === 'cloudflare' ? '?ed=2560' : ''), tls: 'tls', sni: wsInfo.host, alpn: '', fp: '', insecure: String(wsInfo.vmessInsecure), ...(wsInfo.vmessExtra || {}), vcn: '', pcs: wsInfo.vmessPcs,
      }))}`;
    case 'shadowsocks': { // v2ray-plugin 无法跳过证书校验，ws 模式自签证书下该节点连不上，不输出
      if (ACTIVE_MODE === 'ws' && TLS_INSECURE) {
        console.error(`[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, put one at ${BASE_DIR}/<CERT_HOST>.crt and .key. No SS link generated`);
        return '';
      }
      const plugin = encodeURIComponent(`v2ray-plugin;tls;host=${wsInfo.host};path=${wsPath};mux=0`);
      return `ss://${SS_USERINFO}@${wsInfo.address}:${wsInfo.port}/?plugin=${plugin}#${NAME_ENC}`;
    }
  }
}

const hy2Link = () => `hysteria2://${CONFIG.UUID}@${PUBLIC_IP}:${HY2_PORT}/?sni=${TLS_SERVER_NAME}${TLS_INSECURE ? '&insecure=1' : ''}#${NAME_ENC}`;
const mixedLinks = () => ['socks5', 'http'].map((scheme) => `${scheme}://misaka:${CONFIG.UUID}@${PUBLIC_IP}:${MIXED_PORT}#${NAME_ENC}`).join('\n');
const wgLink = () => `wireguard://${urlEncode(WG_CLIENT_PRIVATE)}@${PUBLIC_IP}:${WG_PORT}?publickey=${urlEncode(WG_SERVER_PUBLIC)}&address=${urlEncode(WG_CLIENT_ADDR)}&mtu=1420#${NAME_ENC}`;
const wgConf = () => `[Interface]\nPrivateKey = ${WG_CLIENT_PRIVATE}\nAddress = ${WG_CLIENT_ADDR}\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = ${WG_SERVER_PUBLIC}\nEndpoint = ${PUBLIC_IP}:${WG_PORT}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;

// ========== 内置 HTTP 服务(订阅 + 回落) ==========
// 监听 abstract unix socket，由前置入口回落过来：GET /UUID 返回 base64 订阅；其它路径转给 WEB_DEST(没有就 404)
function startWeb(subscriptionBody) {
  const [destHost, destPort] = WEB_DEST ? [WEB_DEST.split(':')[0], +WEB_DEST.split(':')[1]] : [];
  http.createServer((req, res) => {
    const pathname = req.url.split('?')[0];
    console.log(`[WEB] ${req.method} ${pathname === `/${CONFIG.UUID}` ? '/UUID' : pathname}`);
    if ((req.method === 'GET' || req.method === 'HEAD') && pathname === `/${CONFIG.UUID}`) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(req.method === 'HEAD' ? undefined : subscriptionBody);
    }
    if (!WEB_DEST) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not Found'); }
    const upstream = http.request({ host: destHost, port: destPort, path: req.url, method: req.method, headers: req.headers }, (upstreamRes) => { res.writeHead(upstreamRes.statusCode, upstreamRes.headers); upstreamRes.pipe(res); });
    upstream.on('error', () => { res.writeHead(502); res.end(); });
    req.pipe(upstream);
  }).on('error', (error) => console.error(`[WEB] HTTP service failed: ${error.message}`)).listen(`\0${WEB_SOCK.slice(1)}`); // Node 里 abstract socket 以 \0 开头，Xray 里以 @ 开头
}

// ========== 外部程序 ==========
// Komari 探针：KOMARI_ENDPOINT 和 KOMARI_TOKEN 都填了才启用。有代理协议时后台运行；没有时前台运行
async function startKomari() {
  await killPrevious('komari-agent', 'KOMARI');
  const binaryPath = await fetchBinary('komari-agent', `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${ARCH}`);
  const agentEnv = { AGENT_ENDPOINT: CONFIG.KOMARI_ENDPOINT, AGENT_TOKEN: CONFIG.KOMARI_TOKEN }; // 只传给这一个进程，ps 看不到
  if (XRAY_ON) {
    spawnChild(binaryPath, [], path.join(BASE_DIR, 'komari-agent.log'), agentEnv);
    return console.log(`[KOMARI] Agent started, reporting to ${CONFIG.KOMARI_ENDPOINT}`);
  }
  console.log(`[KOMARI] No proxy protocol enabled, running the agent only, reporting to ${CONFIG.KOMARI_ENDPOINT}`);
  spawnChild(binaryPath, [], null, agentEnv).on('exit', (code) => process.exit(code ?? 1));
  await new Promise(() => {});
}

// 取 cloudflared 日志里下发的 ingress 规则：第一条「有具体域名(不含 *)、Service 是 http://localhost:端口 或 127.0.0.1:端口」的规则
function parseIngress(text) {
  const configMatch = text.split('\n').filter((line) => line.includes('Updated to new configuration')).pop()?.match(/config="(.*)" version=/);
  if (!configMatch) return null;
  let config;
  try { config = JSON.parse(configMatch[1].replace(/\\"/g, '"')); } catch { return null; }
  for (const rule of config.ingress || []) {
    const serviceMatch = rule.hostname && !rule.hostname.includes('*') && /^http:\/\/(?:localhost|127\.0\.0\.1):(\d+)$/.exec(rule.service || '');
    if (serviceMatch) return { hostname: rule.hostname, port: serviceMatch[1] };
  }
  return null;
}

// cloudflare 模式：用 Token 跑固定隧道；Token 填 try 时用临时隧道(每次启动域名都会变)。域名和回源端口都从日志里取
async function startCloudflared() {
  await killPrevious('cloudflared', 'CF');
  const binaryPath = await fetchBinary('cloudflared', `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}`);
  const logFile = path.join(BASE_DIR, 'cloudflared.log');
  childProcess.spawnSync(binaryPath, ['--version'], { stdio: 'inherit' });

  if (TRY_TUNNEL) {
    spawnChild(binaryPath, ['--no-autoupdate', 'tunnel', '--url', `http://localhost:${FRONT_PORT}`], logFile);
    for (let attempt = 0; attempt < 30 && !CLOUDFLARE_TUNNEL_HOSTNAME; attempt++) {
      CLOUDFLARE_TUNNEL_HOSTNAME = [...readLog(logFile).matchAll(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/g)].map((match) => match[1]).find((hostname) => !hostname.startsWith('api.')) || '';
      if (!CLOUDFLARE_TUNNEL_HOSTNAME) await sleep(1000);
    }
    if (CLOUDFLARE_TUNNEL_HOSTNAME) console.log(`[CF] Quick tunnel hostname from log: ${CLOUDFLARE_TUNNEL_HOSTNAME} (service port=${FRONT_PORT})`);
    else console.error(`[CF] Cannot find the trycloudflare.com hostname in ${logFile}`);
    return;
  }

  spawnChild(binaryPath, ['--no-autoupdate', 'tunnel', 'run'], logFile, { TUNNEL_TOKEN: CONFIG.CLOUDFLARE_TUNNEL_TOKEN });
  for (let attempt = 0; attempt < 30 && !readLog(logFile).includes('Updated to new configuration'); attempt++) await sleep(1000);
  const ingressRule = parseIngress(readLog(logFile));
  if (ingressRule && isValidPort(ingressRule.port)) {
    CLOUDFLARE_TUNNEL_HOSTNAME = ingressRule.hostname;
    FRONT_PORT = +ingressRule.port;
    checkPorts(); // 端口变了，重新检查冲突
    console.log(`[CF] From cloudflared log: hostname=${CLOUDFLARE_TUNNEL_HOSTNAME}, tunnel service port=${FRONT_PORT}`);
  } else {
    console.error(`[CF] Cannot read hostname / port from ${logFile} (the tunnel needs a Public hostname without * and a Service like http://localhost:PORT)`);
  }
}

// ========== 主流程 ==========
async function main() {
  parseModes();
  buildChains();
  planFront();
  FRONT_TLS = ACTIVE_MODE === 'ws' || SHARE_FRONT; // ws 模式，或和 Reality 共用端口(Reality 只能把 TLS 流量转给它)
  checkPorts();

  if (ENABLED.length) console.log(`[MODE] enabled=${ENABLED.join(' ')}`);
  if (ACTIVE_MODE) console.log(`[MODE] port ${FRONT_PORT}: ${ACTIVE_MODE} (${SHARED.join(' ')})${SHARE_FRONT ? ' shared with reality' : ''}`);
  for (const head of HEADS) console.log(`[MODE] port ${HPORT[head]}: reality (${CHAIN[head].join(' -> ')})`);
  VLESS_FLOW = HEADS.includes('vless') ? 'xtls-rprx-vision' : ''; // 流控 Vision 仅 VLESS 作为 Reality 链头时支持

  const KOMARI_ON = !!(CONFIG.KOMARI_ENDPOINT && CONFIG.KOMARI_TOKEN);
  if (!XRAY_ON && !KOMARI_ON) die('Nothing to run: set a protocol *_MODE / HYSTERIA2_MODE / MIXED_MODE / WIREGUARD_MODE, or KOMARI_ENDPOINT + KOMARI_TOKEN');
  if (KOMARI_ON) await startKomari();

  if (HEADS.length) {
    [REALITY_PRIVATE_KEY, REALITY_PUBLIC_KEY] = deriveKey('reality', 'base64url');
    console.log(`[REALITY] Private key: ${REALITY_PRIVATE_KEY}\n[REALITY] Public key: ${REALITY_PUBLIC_KEY}`);
  }
  if (WG_PORT) { // WireGuard：服务端、客户端各一把私钥(标准 base64)
    [WG_SERVER_PRIVATE, WG_SERVER_PUBLIC] = deriveKey('wg-server', 'base64');
    [WG_CLIENT_PRIVATE, WG_CLIENT_PUBLIC] = deriveKey('wg-client', 'base64');
  }
  SS_USERINFO = toBase64(`aes-256-gcm:${CONFIG.UUID}`, 'base64url');

  if (ACTIVE_MODE !== 'cloudflare' || HEADS.length || HY2_PORT || MIXED_PORT || WG_PORT) await resolvePublicAddr();
  IPV6_AVAILABLE = await request(TRACE_URL, { family: 6, timeout: 5000 }).then(() => true, () => false);
  console.log(IPV6_AVAILABLE ? '[NET] IPv6 egress: available' : '[NET] IPv6 egress: unavailable, blocking IPv6 destinations');
  if (FRONT_TLS || HY2_PORT) setupTls();
  if (ACTIVE_MODE === 'cloudflare' && CONFIG.CLOUDFLARE_TUNNEL_TOKEN) await startCloudflared();

  // ---- Xray ----
  const xrayDir = path.join(BASE_DIR, 'xray'), xrayBin = path.join(xrayDir, 'xray'), xrayConf = path.join(xrayDir, 'config.json'), zipFile = path.join(BASE_DIR, 'xray.zip');
  fs.mkdirSync(xrayDir, { recursive: true });
  if (!await download(zipFile, `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH === 'amd64' ? '64' : 'arm64-v8a'}.zip`)) process.exit(1);
  await unzip(zipFile, xrayDir);
  fs.rmSync(zipFile, { force: true });
  try { fs.chmodSync(xrayBin, 0o755); } catch { /* 下面统一检查 */ }
  if (!fileNonEmpty(xrayBin)) { console.error(`[XRAY] Binary not found after extraction: ${xrayBin}`); process.exit(1); }
  const xrayEnv = { ...process.env, ...GO_ENV, XRAY_LOCATION_ASSET: xrayDir }; // geoip.dat / geosite.dat 随发行包解压在同一目录
  const runXray = (args) => childProcess.spawnSync(xrayBin, args, { stdio: 'inherit', env: xrayEnv });
  runXray(['version']);

  fs.writeFileSync(xrayConf, '', { mode: 0o600 }); // 先收紧权限再写入(里面有 UUID 和 Reality 私钥)
  fs.chmodSync(xrayConf, 0o600);
  fs.writeFileSync(xrayConf, `${JSON.stringify(buildConfig(), null, 2)}\n`);
  if (runXray(['run', '-test', '-c', xrayConf]).status !== 0) { console.error('[XRAY] Config test failed, aborting'); process.exit(1); }

  // ---- 输出订阅：每行一个原始链接，末尾再给一份合并后的 base64 ----
  const wsInfo = ACTIVE_MODE ? wsParams() : null;
  const nodes = ENABLED.flatMap((proto) => [RPORT[proto] && realityLink(proto, RPORT[proto]), SHARED.includes(proto) && wsNode(proto, wsInfo)]); // 一个协议可同时有 Reality 和 ws 两条链接
  nodes.push(HY2_PORT && hy2Link(), MIXED_PORT && mixedLinks(), WG_PORT && wgLink());
  const allNodes = nodes.filter(Boolean).map((node) => `${node}\n`).join('');
  console.log(`\n=== Nodes ===\n${allNodes}\n=== Subscription (base64) ===\n${toBase64(allNodes)}\n`);
  if (WG_PORT) console.log(`\n=== WireGuard config (wg-quick) ===\n${wgConf()}`);
  if (FRONT_ON) { // 订阅地址：cloudflare 走隧道域名；ws 走 TLS；只填 PORT 时是明文 HTTP
    startWeb(toBase64(allNodes));
    const baseUrl = ACTIVE_MODE === 'cloudflare' ? (CLOUDFLARE_TUNNEL_HOSTNAME && `https://${CLOUDFLARE_TUNNEL_HOSTNAME}`) : `${FRONT_TLS ? 'https' : 'http'}://${PUBLIC_IP}:${FRONT_PORT}`;
    if (baseUrl) console.log(`\n=== Subscription URL ===\n${baseUrl}/${CONFIG.UUID}${FRONT_TLS && TLS_INSECURE ? '\n(自签证书：客户端需要允许不校验证书)' : ''}\n`);
  }

  try { builtin('v8').setFlagsFromString('--expose-gc'); builtin('vm').runInNewContext('gc')(); } catch { /* 没有就算了 */ } // 后面脚本只看着子进程，先回收前面用过的堆
  spawnChild(xrayBin, ['run', '-c', xrayConf], null, { XRAY_LOCATION_ASSET: xrayDir }).on('exit', (code) => process.exit(code ?? 1));
}

main().catch((error) => { console.error(error); process.exit(1); });
