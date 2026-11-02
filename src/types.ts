export type DataProvenance = 'measured' | 'estimated' | 'unavailable';

export interface WhoisRecord {
  domain: string;
  registrar?: string;
  createdDate?: string;
  updatedDate?: string;
  expiresDate?: string;
  nameServers?: string[];
  status?: string[];
  dnssec?: boolean;
  registrantCountry?: string;
  registrantOrg?: string;
  ipAddresses?: string[];
  rawWhois?: string;
  source?: DataProvenance;
}

export interface DnsRecords {
  A?: string[];
  AAAA?: string[];
  MX?: { exchange: string; priority: number }[];
  TXT?: string[][];
  NS?: string[];
  SOA?: any;
  CNAME?: string[];
  source?: DataProvenance;
}

export interface PortScanResult {
  port: number;
  service: string;
  serviceGuess?: string;
  serviceConfirmed?: string;
  status: 'open' | 'closed' | 'filtered';
  errorCode?: string;
  banner?: string | null;
  latencyMs?: number | null;
  riskLevel?: 'Low' | 'Medium' | 'High' | 'Critical';
  description?: string;
  isWeb?: boolean;
  defaultProtocol?: 'http' | 'https' | 'tcp';
  accessUrl?: string;
  source?: DataProvenance;
}

export interface PortHttpAccessResult {
  target: string;
  port: number;
  protocol: 'http' | 'https';
  url: string;
  path: string;
  method: string;
  statusCode: number;
  statusMessage: string;
  responseTimeMs: number;
  headers: Record<string, string>;
  bodyPreview: string;
  contentType: string;
  htmlTitle?: string;
  serverBanner?: string;
  certInfo?: {
    issuer?: string;
    subject?: string;
    validTo?: string;
    cipher?: string;
    protocol?: string;
  };
  securityHeadersStatus?: {
    hsts: boolean;
    csp: boolean;
    xFrameOptions: boolean;
    xContentTypeOptions: boolean;
  };
}

export interface PortSocketAccessResult {
  target: string;
  port: number;
  connected: boolean;
  connectTimeMs: number;
  banner?: string;
  rawAscii: string;
  hexDump: string;
  bytesReceived: number;
  serviceFingerprint?: string;
  probePayloadSent?: string;
  error?: string;
}

export interface SecurityHeaderCheck {
  name: string;
  present: boolean;
  value?: string;
  rating: 'good' | 'warning' | 'critical';
  recommendation: string;
  cehReference?: string;
}

export interface WebAuditResult {
  url: string;
  statusCode: number;
  reachable?: boolean;
  error?: string;
  errorCode?: string;
  source?: DataProvenance;
  serverBanner?: string;
  xPoweredBy?: string;
  httpVersion?: string;
  tlsVersion?: string;
  cipherSuite?: string;
  certIssuer?: string;
  certExpiry?: string;
  certValidFrom?: string;
  certDaysRemaining?: number | null;
  securityScore: number; // 0 - 100
  securityGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  headers: SecurityHeaderCheck[];
  robotsTxt?: {
    present: boolean;
    disallowedPaths: string[];
    rawContent?: string;
    sensitiveExposures: string[];
    error?: string;
    source?: DataProvenance;
  };
  vulnerabilities: {
    id: string;
    title: string;
    severity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
    category: string;
    description: string;
    remediation: string;
    cehModule: string;
  }[];
}

export interface StressTestRequest {
  targetUrl: string;
  durationSeconds: number; // 2 - 15s
  concurrency: number; // 1 - 20
  requestMethod?: 'GET' | 'HEAD' | 'POST';
  customHeaders?: Record<string, string>;
}

export interface StressTestResult {
  targetUrl: string;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  durationSeconds: number;
  requestsPerSecond: number;
  avgLatencyMs: number;
  minLatencyMs: number;
  maxLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  statusCodes: Record<string, number>;
  wafDetected: boolean;
  wafProvider?: string;
  rateLimitEnforced: boolean;
  timeSeries: { timeOffset: number; rps: number; latency: number }[];
  resilienceRating: 'Resilient' | 'Moderate' | 'Vulnerable' | 'Rate-Limited';
  recommendations: string[];
}

export interface CEHModuleInfo {
  id: string;
  moduleNumber: number;
  title: string;
  category: string;
  summary: string;
  keyTechniques: string[];
  tools: string[];
  countermeasures: string[];
}

export interface HiddenLinkItem {
  id: string;
  url: string;
  anchorText: string;
  hidingTechnique: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  snippet: string;
  remediation: string;
}

export interface JunkLinkItem {
  id: string;
  url: string;
  domain: string;
  category: 'Spam Affiliate' | 'Suspicious TLD' | 'URL Shortener' | 'Phishing Redirect' | 'Broken Junk Link';
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  reason: string;
  remediation: string;
}

export interface VirusThreatItem {
  id: string;
  name: string;
  type: 'WebShell' | 'Obfuscated Script' | 'CryptoMiner' | 'Malicious Redirector' | 'PHP Injection';
  severity: 'High' | 'Critical';
  signatureMatch: string;
  codeSnippet: string;
  location: string;
  remediation: string;
}

export interface TrojanThreatItem {
  id: string;
  name: string;
  type: 'C2 Beacon' | 'Reverse Shell' | 'Payload Dropper' | 'Steganography Shell' | 'Cron Persistence';
  severity: 'High' | 'Critical';
  c2Endpoint?: string;
  description: string;
  indicators: string[];
  remediation: string;
}

export interface MalwareScanResult {
  targetUrl: string;
  scanTimestamp: string;
  cleanlinessScore: number; // 0 - 100
  status: 'CLEAN' | 'WARNING' | 'INFECTED' | 'CRITICAL';
  totalThreatsCount: number;
  hiddenLinks: HiddenLinkItem[];
  junkLinks: JunkLinkItem[];
  virusSignatures: VirusThreatItem[];
  trojanThreats: TrojanThreatItem[];
  summary: string;
  reachable?: boolean;
  error?: string;
  analyzedSource?: 'remote_fetch' | 'user_provided';
  source?: DataProvenance;
}

export interface SpeedTestMetrics {
  downloadSpeedMbps: number;
  uploadSpeedMbps: number;
  unloadedLatencyMs: number;
  loadedLatencyMs: number;
  jitterMs: number;
  clientIp?: string;
  clientIsp?: string;
  serverLocation?: string;
  bytesDownloaded?: number;
  bytesUploaded?: number;
  testDurationSec?: number;
  bufferbloatGrade?: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  connectionType?: string;
  timestamp?: string;
}

export interface LanDevice {
  ip: string;
  mac?: string;
  subnet?: string;
  subnetMask?: string;
  gateway?: string;
  vendor?: string;
  hostname?: string;
  deviceType: 'Router/Gateway' | 'Workstation' | 'Mobile Phone' | 'IoT / Smart Device' | 'Network Printer' | 'Suspicious Device' | 'Rogue Intruder';
  status: 'online' | 'offline' | 'unresponsive';
  openPorts: number[];
  riskLevel: 'Safe' | 'Low' | 'Medium' | 'High' | 'Critical';
  isRogue: boolean;
  anomalyIndicators: string[];
  firstSeen?: string;
  responseLatencyMs?: number;
}

export interface NetworkVulnerability {
  id: string;
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  category: 'Gateway Security' | 'DNS & Routing' | 'ARP & MITM' | 'UPnP & Ports' | 'Wi-Fi Hygiene';
  description: string;
  detectedOn?: string;
  remediation: string;
}

export interface ClientLanAuditResult {
  clientPublicIp: string;
  clientLocalIp: string;
  gatewayIp: string;
  subnetRange: string;
  scanTimestamp: string;
  isp?: string;
  dnsServers?: string[];
  isVpnOrProxy?: boolean;
  dnsLeakDetected?: boolean;
  webrtcLeakDetected?: boolean;
  hygieneScore: number | null; // 0 - 100
  securityStatus: 'SECURE' | 'WARNING' | 'COMPROMISED' | 'UNAUDITED';
  totalDevicesFound: number;
  suspiciousDevicesCount: number;
  devices: LanDevice[];
  vulnerabilities: NetworkVulnerability[];
  aiIntruderReport?: string;
  reachable?: boolean;
  error?: string;
  errorCode?: string;
  source?: DataProvenance;
  agentRequired?: boolean;
  agentDownloadUrl?: string;
  curlCommand?: string;
}

export interface ThreatLocation {
  country: string;
  countryCode: string;
  city: string;
  lat: number;
  lng: number;
  actorOrOrg: string;
}

export interface GlobalThreatAttack {
  id: string;
  source: ThreatLocation;
  target: ThreatLocation;
  category: 'ddos' | 'exploit' | 'botnet';
  type: string;
  protocol: 'TCP' | 'UDP' | 'HTTP/2' | 'DNS' | 'ICMP' | 'HTTPS';
  bandwidthGbps: number;
  packetsPerSecMpps: number;
  // Volume & Speed Telemetry for Inbound Direction:
  inboundMbps: number;           // Live throughput arriving at user network
  outboundMbps: number;          // Outbound response/ACK or reflection traffic
  totalPacketsReceived: number;  // Total incoming packet count (e.g. 1,420,500)
  totalPacketsSent: number;      // Total outbound response packet count
  volumeBytesIn: number;         // Total byte volume received (e.g. MB/GB)
  volumeBytesOut: number;        // Total byte volume transmitted
  avgPacketSize: number;         // Average packet size in bytes (e.g. 64B SYN, 1420B UDP flood)
  latencyMs: number;             // Ping/RTT latency from international origin to user IP
  routeTransitProvider?: string; // International Tier-1 transit (e.g. AAG, APG, Lumen, Telia)
  severity: 'Critical' | 'High' | 'Medium';
  timestamp: string;
  cveReference?: string;
  description: string;
  mitigation: string;
}

export interface RegionalHotspot {
  id: string;
  name: string;
  countryCode: string;
  lat: number;
  lng: number;
  threatLevel: 'Extreme' | 'High' | 'Elevated';
  activeAttacks: number;
  topAttackType: string;
  peakGbps?: number;
  intensity: number; // 0.1 to 1.0
  activeCVEs?: string[];
  source?: string;
  lastSeen?: string;
  malware?: string;
}

export interface InternationalRouteSpeed {
  id: string;
  direction: string; // e.g. "Bắc Mỹ (US East / Ashburn)", "Đông Á (Hồng Kông / Tokyo)", etc.
  originCountry: string;
  originCode: string;
  transitCable: string; // e.g. "AAG Submarine Cable", "APG", "IA (TGN-IA)"
  speedMbps?: number | null;    // Real-time measured inbound throughput from server
  peakSpeedMbps?: number | null;
  latencyMs: number | null;
  jitterMs: number | null;
  packetLossPercent: number;
  inboundVolumeMB?: number | null;
  outboundVolumeMB?: number | null;
  totalPacketsIn?: number | null;
  totalPacketsOut?: number | null;
  health: 'optimal' | 'congested' | 'under_attack';
  source?: DataProvenance;
}

export interface NetworkTrafficVolumeTelemetry {
  inboundBytesTotal?: number;
  outboundBytesTotal?: number;
  inboundPacketsTotal?: number;
  outboundPacketsTotal?: number;
  currentInboundSpeedMbps?: number;
  currentOutboundSpeedMbps?: number;
  peakInboundSpeedMbps?: number;
  avgPacketSizeBytes?: number;
  activeInternationalStreams?: number;
  source?: DataProvenance;
}

export interface UserNetworkProfile {
  clientIp: string;
  isp?: string;
  city?: string;
  country?: string;
  countryCode?: string;
  asn?: string;
  lat?: number | null;
  lng?: number | null;
  gatewayIp?: string;
  localSubnet?: string;
  threatExposureScore?: number | null; // 0-100
  openPortRiskCount?: number | null;
  inboundProbesPerMin?: number | null;
  firewallStatus?: 'Active' | 'Defending' | 'Vulnerable' | 'Unknown';
  trafficTelemetry?: NetworkTrafficVolumeTelemetry;
  geoSource?: DataProvenance;
}

export interface UserLanThreatNode {
  id: string;
  name: string;
  ip: string;
  mac: string;
  type: 'router' | 'workstation' | 'mobile' | 'iot' | 'rogue';
  x: number; // 0-100 normalized spatial percentage
  y: number;
  threatScore: number; // 0-100
  status: 'secure' | 'warning' | 'critical';
  openPorts: number[];
  riskDescription: string;
  heatRadius: number;
}

export interface GlobalThreatIntel {
  globalDDoSIndex?: number;
  totalActiveAttacks?: number;
  peakAttackBandwidthGbps?: number;
  totalBandwidthTbps?: number;
  userNetwork?: UserNetworkProfile;
  internationalRoutes?: InternationalRouteSpeed[];
  trafficVolume?: NetworkTrafficVolumeTelemetry;
  lanNodes?: UserLanThreatNode[];
  topTargetedCountries?: { country: string; code: string; count: number; flag: string }[];
  topOriginCountries?: { country: string; code: string; count: number; flag: string }[];
  topExploitVectors?: { name: string; percentage: number; cve: string; type: string }[];
  recentAttacks: GlobalThreatAttack[];
  hotspots: RegionalHotspot[];
  feedSource?: string;
  feedStatus?: 'live' | 'unavailable';
}

// -------------------------------------------------------------
// INTERNAL NETWORK REVIEW & ENDPOINT MANAGEMENT TYPES
// -------------------------------------------------------------

export interface EndpointPortInfo {
  port: number;
  service: string;
  protocol: 'TCP' | 'UDP';
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  banner?: string;
}

export interface EndpointDevice {
  id: string;
  ip: string;
  mac: string;
  subnet?: string;
  subnetMask?: string;
  gateway?: string;
  hostname: string;
  customName?: string;
  vendor: string;
  deviceType: 'router' | 'workstation' | 'laptop' | 'smartphone' | 'tv' | 'camera' | 'nas_server' | 'iot' | 'printer' | 'rogue';
  connectionType: 'ethernet_1g' | 'ethernet_2.5g' | 'wifi_6_5g' | 'wifi_5g' | 'wifi_2.4g';
  linkSpeedMbps: number;
  currentRxMbps: number;
  currentTxMbps: number;
  totalDataMB: number;
  latencyMs: number;
  rssiSignalDbm?: number;
  packetLossPercent: number;
  status: 'online' | 'idle' | 'offline';
  trustLevel: 'trusted' | 'monitored' | 'suspicious' | 'blocked';
  isIsolated: boolean;
  bandwidthLimitMbps?: number;
  openPorts: EndpointPortInfo[];
  vulnerabilitiesCount: number;
  firstSeen: string;
  lastSeen: string;
  notes?: string;
}

export interface SuggestedNetworkPackage {
  id: string;
  tier: 'essential' | 'recommended' | 'ultra_pro';
  name: string;
  speedMbps: number;
  uploadSpeedMbps: number;
  recommendedFor: string;
  estimatedPriceVndPerMonth: string;
  estimatedPriceUsdPerMonth: string;
  maxConcurrent4kStreams: number;
  maxSimultaneousUsers: number;
  gameDownloadTime50Gb: string;
  videoCallQuality: string;
  suitabilityScore: number; // 0-100%
  pros: string[];
  keyHighlights: string;
  ispExamples: { provider: string; planName: string; approxCost: string }[];
}

export interface InternalNetworkBottleneck {
  id: string;
  type: 'wifi_congestion' | 'cable_speed' | 'bandwidth_saturation' | 'bufferbloat' | 'iot_isolation';
  severity: 'Critical' | 'Warning' | 'Info';
  title: string;
  description: string;
  affectedDevicesCount: number;
  remediation: string;
}

export interface InternalNetworkReview {
  healthScore: number; // 0-100
  totalDevicesCount: number;
  activeOnlineCount: number;
  totalBandwidthDemandRxMbps: number;
  totalBandwidthDemandTxMbps: number;
  peakSimultaneousRxMbps: number;
  peakSimultaneousTxMbps: number;
  currentMeasuredSpeedMbps: number;
  headroomBufferPercent: number;
  minimumRequiredSpeedMbps: number;
  recommendedSpeedMbps: number;
  proUltraSpeedMbps: number;
  deviceCategoryBreakdown: {
    category: string;
    count: number;
    rxMbps: number;
    txMbps: number;
    color: string;
  }[];
  bottlenecks: InternalNetworkBottleneck[];
  packages: SuggestedNetworkPackage[];
  qosRecommendations: {
    rule: string;
    priority: 'High' | 'Medium' | 'Low';
    description: string;
  }[];
}

export interface InternalNetworkScanResult {
  subnet: string;
  gateway: string;
  clientIp: string;
  scannedRange: string;
  scanDurationMs: number;
  totalEndpointsFound: number;
  endpoints: EndpointDevice[];
  review: InternalNetworkReview | null;
  timestamp: string;
  reachable?: boolean;
  error?: string;
  errorCode?: string;
  source?: DataProvenance;
  agentRequired?: boolean;
  agentDownloadUrl?: string;
  curlCommand?: string;
}
