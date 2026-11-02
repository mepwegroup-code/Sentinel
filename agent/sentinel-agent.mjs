#!/usr/bin/env node
/**
 * ============================================================================
 * SENTINEL OS - Local Network (LAN) Sensor & Telemetry Agent
 * ============================================================================
 * Chạy trực tiếp trên máy cục bộ của bạn để quét và đo lường thực tế
 * toàn bộ thiết bị trong mạng Wi-Fi / LAN nội bộ (RFC 1918).
 *
 * Cách sử dụng:
 *   node sentinel-agent.mjs
 * hoặc gửi kết quả trực tiếp lên web Sentinel OS:
 *   node sentinel-agent.mjs --server http://localhost:3000
 * ============================================================================
 */

import os from 'node:os';
import net from 'node:net';
import dns from 'node:dns/promises';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

const args = process.argv.slice(2);
const serverArgIdx = args.indexOf('--server');
const serverUrl = serverArgIdx !== -1 && args[serverArgIdx + 1] ? args[serverArgIdx + 1].replace(/\/$/, '') : null;
const tokenArgIdx = args.indexOf('--token');
const sessionToken = tokenArgIdx !== -1 && args[tokenArgIdx + 1] ? args[tokenArgIdx + 1] : 'default-session';
const agentAuthToken = process.env.SENTINEL_AGENT_TOKEN || '';
if (serverUrl) {
  let parsed;
  try { parsed = new URL(serverUrl); } catch {
    console.error('[ERROR] --server must be a valid HTTP(S) URL');
    process.exit(1);
  }
  const isLoopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopback)) {
    console.error('[ERROR] Remote Sentinel servers require HTTPS.');
    process.exit(1);
  }
  if (agentAuthToken.length < 32) {
    console.error('[ERROR] Set SENTINEL_AGENT_TOKEN environment variable (32+ characters) before uploading LAN telemetry.');
    process.exit(1);
  }
}


console.log('\x1b[36m%s\x1b[0m', '════════════════════════════════════════════════════════════════');
console.log('\x1b[1m\x1b[32m%s\x1b[0m', '  SENTINEL OS 2.5 — REAL LOCAL LAN AUDIT SENSOR');
console.log('\x1b[36m%s\x1b[0m', '════════════════════════════════════════════════════════════════');
console.log('  [+] Đang nhận diện giao diện mạng nội bộ (Local NICs)...');

// 1. Select a Windows/macOS/Linux host NIC, not Docker or WSL virtual switches.
const networkInterfaces = os.networkInterfaces();
const physicalOptions = Object.entries(networkInterfaces).flatMap(([name, ifaces]) =>
  (ifaces || []).filter(iface =>
    !iface.internal && iface.family === 'IPv4' &&
    (/^10\./.test(iface.address) || /^192\.168\./.test(iface.address) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(iface.address))
  ).map(iface => ({ name, address: iface.address, netmask: iface.netmask, mac: iface.mac }))
);
const ifaceArgIdx = args.indexOf('--interface');
const requestedIface = ifaceArgIdx >= 0 ? args[ifaceArgIdx + 1] : null;
if (args.includes('--list-interfaces')) {
  console.table(physicalOptions);
  process.exit(0);
}
const preferred = physicalOptions.filter(nic => !/^(vEthernet|docker|wsl|vmware|virtualbox|hyper-v)/i.test(nic.name));
const options = preferred.length ? preferred : physicalOptions;
const candidates = requestedIface ? physicalOptions.filter(nic => nic.name === requestedIface) : options;
if (candidates.length !== 1) {
  console.error('[ERROR] Specify a single authorized NIC with --interface "Wi-Fi" or --interface "Ethernet".');
  console.table(physicalOptions);
  process.exit(1);
}
const chosen = candidates[0];
if (chosen.netmask !== '255.255.255.0') {
  console.error('[ERROR] This agent currently supports /24 subnets only. Refusing to guess another network scope.');
  process.exit(1);
}
const primaryIface = chosen.name;
const primaryIp = chosen.address;
const primaryNetmask = chosen.netmask;
const ipParts = primaryIp.split('.').map(Number);
const subnetPrefix = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}`;
const gatewayIp = `${subnetPrefix}.1`; // Candidate only; do not synthesize an ARP entry.
console.log(`  [*] Interface: ${primaryIface}`);
console.log(`  [*] Local IP: ${primaryIp}`);
console.log(`  [*] Authorized /24 scope: ${subnetPrefix}.0/24`);
console.log('  [*] Gateway candidate (.1): only confirmed if observed in ARP.');

// 2. Hàm đo TCP RTT thực tế tới IP và Port
function probeTcp(ip, port, timeoutMs = 800) {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    const sock = new net.Socket();
    let settled = false;

    sock.setTimeout(timeoutMs);

    sock.connect(port, ip, () => {
      if (settled) return;
      settled = true;
      const end = process.hrtime.bigint();
      const rttMs = Number(end - start) / 1000000;
      sock.destroy();
      resolve({ open: true, rttMs: Math.round(rttMs * 10) / 10 });
    });

    sock.on('timeout', () => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve({ open: false, rttMs: -1, reason: 'TIMEOUT' });
    });

    sock.on('error', () => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve({ open: false, rttMs: -1, reason: 'REFUSED' });
    });
  });
}

// 3. Đọc ARP table từ hệ điều hành (thật 100%, không bịa)
async function getSystemArpTable() {
  const isWindows = process.platform === 'win32';
  const arpEntries = new Map();

  try {
    const { stdout } = await execAsync('arp -a');
    const lines = stdout.split('\n');

    for (const line of lines) {
      let ip = null;
      let mac = null;

      if (isWindows) {
        // Windows arp -a format: 192.168.1.1       00-11-22-33-44-55     dynamic
        const winMatch = line.trim().match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F-]{17})/);
        if (winMatch) {
          ip = winMatch[1];
          mac = winMatch[2].replace(/-/g, ':').toUpperCase();
        }
      } else {
        // Linux / macOS arp -a format: ? (192.168.1.1) at 0:11:22:33:44:55 on en0
        const unixMatch = line.trim().match(/\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?\s+at\s+([0-9a-fA-F:]{11,17})/i);
        if (unixMatch) {
          ip = unixMatch[1];
          mac = unixMatch[2].toUpperCase().split(':').map(part => part.padStart(2, '0')).join(':');
        }
      }

      if (ip && mac && ip.startsWith(subnetPrefix + '.') &&
          /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac) &&
          mac !== 'FF:FF:FF:FF:FF:FF' && !ip.endsWith('.0') && !ip.endsWith('.255')) {
        arpEntries.set(ip, mac);
      }
    }
  } catch (err) {
    console.warn('  [!] Không thể đọc lệnh arp -a trực tiếp:', err.message);
  }

  return arpEntries;
}

// 4. Quét ARP Sweep nhanh bằng cách gửi probe TCP tới các IP thông dụng trong subnet để kích thích ARP Cache
console.log('  [+] Đang gửi TCP Discovery Probe tới dải IP nội bộ để cập nhật bảng ARP...');
const COMMON_HOST_IDS = [
  1, 2, 3, 4, 5, 10, 20, 25, 50, 68, 77, 88, 99, 100, 101, 102, 103, 104, 105, 
  110, 120, 130, 140, 150, 160, 180, 190, 200, 210, 220, 230, 240, 250, 254
];

const probePorts = [80, 443, 53, 445, 139, 22, 8080];

// Probe gateway và local trước
await Promise.all([
  probeTcp(gatewayIp, 80, 500),
  probeTcp(gatewayIp, 53, 500),
  probeTcp(primaryIp, 80, 200)
]);

// Quét song song nhẹ nhàng tránh nghẽn
const batchSize = 10;
for (let i = 0; i < COMMON_HOST_IDS.length; i += batchSize) {
  const batch = COMMON_HOST_IDS.slice(i, i + batchSize);
  await Promise.all(
    batch.map(async (hostId) => {
      const targetIp = `${subnetPrefix}.${hostId}`;
      if (targetIp === primaryIp) return;
      for (const p of [80, 53]) {
        await probeTcp(targetIp, p, 300);
      }
    })
  );
}

console.log('  [+] Đang trích xuất danh sách thiết bị thực từ ARP cache của hệ điều hành...');
const arpMap = await getSystemArpTable();

// Gateway is included only if actually observed in the host ARP table.
// Never create an imaginary device when ARP has no gateway entry.

// Thêm chính máy này
if (!arpMap.has(primaryIp)) {
  const localMac = chosen.mac?.toUpperCase() || 'LOCAL-NIC';
  arpMap.set(primaryIp, localMac || 'LOCAL-NIC');
}

console.log(`  [*] Phát hiện \x1b[32m${arpMap.size}\x1b[0m thiết bị đang kết nối thực tế trong mạng LAN.`);
console.log('');

// 5. Kiểm tra chi tiết từng thiết bị thực tế
const discoveredDevices = [];
let idx = 1;

for (const [ip, mac] of arpMap.entries()) {
  process.stdout.write(`  -> Đang kiểm tra [${idx++}/${arpMap.size}] ${ip} ... `);

  // Reverse DNS hostname
  let hostname = '';
  try {
    const hostnames = await dns.reverse(ip);
    hostname = hostnames[0] || '';
  } catch {
    hostname = ip === gatewayIp ? 'router.local (Default Gateway)' : ip === primaryIp ? `${os.hostname()} (Máy này)` : 'N/A';
  }

  // Probe open ports
  const openPorts = [];
  let bestRtt = -1;

  for (const port of probePorts) {
    const probe = await probeTcp(ip, port, 400);
    if (probe.open) {
      openPorts.push(port);
      if (bestRtt === -1 || probe.rttMs < bestRtt) {
        bestRtt = probe.rttMs;
      }
    }
  }

  if (bestRtt === -1) {
    const pingProbe = await probeTcp(ip, 80, 300);
    bestRtt = pingProbe.open ? pingProbe.rttMs : null;
  }

  const device = {
    ip,
    mac,
    hostname,
    openPorts,
    latencyMs: bestRtt,
    status: openPorts.length > 0 || ip === primaryIp ? 'online' : 'arp-seen',
    isCurrentDevice: ip === primaryIp,
    isGateway: ip === gatewayIp,
    measuredAt: new Date().toISOString()
  };

  discoveredDevices.push(device);
  console.log(`\x1b[32mARP-seen\x1b[0m (TCP RTT: ${bestRtt === null ? 'N/A' : bestRtt + 'ms'}, Cổng mở: [${openPorts.join(', ') || 'None'}])`);
}

console.log('\n\x1b[36m%s\x1b[0m', '════════════════════════════════════════════════════════════════');
console.log('\x1b[1m  KẾT QUẢ QUÉT THỰC TẾ (REAL MEASURED LAN DEVICES):\x1b[0m');
console.log('\x1b[36m%s\x1b[0m', '────────────────────────────────────────────────────────────────');
console.table(discoveredDevices.map(d => ({
  'IP Address': d.ip,
  'MAC Address': d.mac,
  'Hostname': d.hostname.slice(0, 24),
  'TCP RTT': d.latencyMs === null ? 'N/A' : `${d.latencyMs} ms`,
  'Open Ports': d.openPorts.join(', ') || 'None',
  'Role': d.isGateway ? 'GATEWAY' : d.isCurrentDevice ? 'THIS MACHINE' : 'HOST'
})));

const reportPayload = {
  agentVersion: '2.5.0',
  sessionToken,
  timestamp: new Date().toISOString(),
  os: `${os.platform()} ${os.release()} (${os.arch()})`,
  primaryIface,
  clientLocalIp: primaryIp,
  gatewayIp,
  subnetRange: `${subnetPrefix}.0/24`,
  devicesCount: discoveredDevices.length,
  devices: discoveredDevices,
  source: 'measured'
};

// 6. Gửi kết quả lên server Sentinel OS nếu có --server
if (serverUrl) {
  console.log(`\n  [+] Đang đồng bộ kết quả lên Sentinel OS Dashboard: ${serverUrl}/api/lan-agent-report ...`);
  try {
    const res = await fetch(`${serverUrl}/api/lan-agent-report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${agentAuthToken}` },
      body: JSON.stringify(reportPayload),
      signal: AbortSignal.timeout(6000)
    });
    if (res.ok) {
      console.log('\x1b[32m  [✔] Đồng bộ telemetry thành công! Mở trình duyệt để xem báo cáo trực tiếp.\x1b[0m');
    } else {
      console.warn(`  [!] Server trả về mã lỗi: ${res.status}`);
    }
  } catch (err) {
    console.warn(`  [!] Không thể gửi telemetry tới ${serverUrl}:`, err.message);
  }
} else {
  console.log('\n  [💡] Mẹo: Bạn có thể đẩy trực tiếp kết quả này lên giao diện Sentinel OS bằng lệnh:');
  console.log(`       \x1b[33mSet SENTINEL_AGENT_TOKEN and run: node sentinel-agent.mjs --server https://YOUR-SENTINEL-DOMAIN\x1b[0m\n`);
}
