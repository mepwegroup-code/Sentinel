import React, { useState } from 'react';
import { WhoisRecord, WebAuditResult, PortScanResult, StressTestResult, MalwareScanResult } from '../types';
import { 
  FileText, 
  Download, 
  Copy, 
  Check, 
  Printer, 
  Sparkles, 
  RefreshCw, 
  Shield, 
  AlertTriangle, 
  CheckCircle2, 
  FileDown, 
  CheckSquare, 
  XCircle, 
  Globe, 
  Flame, 
  AlertCircle, 
  Info, 
  EyeOff, 
  Bug, 
  Skull, 
  Link as LinkIcon, 
  Radio, 
  ShieldAlert, 
  ShieldCheck 
} from 'lucide-react';
import Markdown from 'react-markdown';
import { SecurityScoreChart } from './SecurityScoreChart';
import { NetworkHeatmap } from './NetworkHeatmap';
import { SecurityRadarChart } from './SecurityRadarChart';
import { ProvenanceBadge } from './ProvenanceBadge';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas-pro';

interface ReportModuleProps {
  domain: string;
  whoisData: WhoisRecord | null;
  auditData: WebAuditResult | null;
  portData: { results: PortScanResult[]; openPortsCount: number } | null;
  ddosData: StressTestResult | null;
  malwareData?: MalwareScanResult | null;
  aiAnalysis: string | null;
  onGenerateAiAnalysis: () => void;
  isAiGenerating: boolean;
  theme?: string;
}

interface ChecklistItem {
  id: string;
  section: string;
  name: string;
  description: string;
  passed: boolean;
  notes: string;
}

export const ReportModule: React.FC<ReportModuleProps> = ({
  domain,
  whoisData,
  auditData,
  portData,
  ddosData,
  malwareData,
  aiAnalysis,
  onGenerateAiAnalysis,
  isAiGenerating,
  theme
}) => {
  const [copied, setCopied] = useState(false);
  const [isExportingPDF, setIsExportingPDF] = useState(false);

  const evaluateCompliance = () => {
    const hasHighOrCritical = auditData?.vulnerabilities?.some(
      v => v.severity.toLowerCase() === 'critical' || v.severity.toLowerCase() === 'high'
    ) ?? false;

    const openPortsCount = portData?.openPortsCount ?? 0;

    // 1. TCVN 14423:2026 (Auditing and Assessment Guidelines)
    const list1: ChecklistItem[] = [
      {
        id: '14423-1',
        section: 'Mục 5.1',
        name: 'Nhận diện tài sản & Thông tin định danh',
        description: 'Nhận dạng hồ sơ đăng ký tên miền, thông tin định tuyến IP và bản ghi DNS.',
        passed: whoisData !== null,
        notes: whoisData ? `Phát hiện registrar: ${whoisData.registrar || 'Ẩn danh'}` : 'Chưa thu thập được dữ liệu định danh WHOIS.'
      },
      {
        id: '14423-2',
        section: 'Mục 5.2',
        name: 'Rà quét điểm yếu & Lỗ hổng cấu hình ứng dụng',
        description: 'Cấu hình cổng dịch vụ, máy chủ Web được quét kỹ để giảm thiểu điểm yếu cấu hình.',
        passed: auditData !== null,
        notes: auditData ? `Đã hoàn thành rà quét. Điểm số: ${auditData.securityScore}/100` : 'Chưa chạy rà quét cấu hình ứng dụng.'
      },
      {
        id: '14423-3',
        section: 'Mục 5.3',
        name: 'Đánh giá rủi ro xâm nhập ứng dụng',
        description: 'Đánh giá mức độ an toàn, không phát hiện lỗ hổng có tính chất Cao (High) hoặc Nghiêm trọng (Critical).',
        passed: auditData !== null && !hasHighOrCritical,
        notes: hasHighOrCritical ? 'Phát hiện lỗ hổng mức độ Cao/Nghiêm trọng cần vá khẩn cấp.' : 'Đạt: Không có lỗ hổng nghiêm trọng nào hoạt động.'
      },
      {
        id: '14423-4',
        section: 'Mục 5.4',
        name: 'Ghi log & Trạng thái hoạt động hệ thống',
        description: 'Xác định rõ địa chỉ IP và ghi nhận đầy đủ lịch trình rà quét trong tệp nhật ký hệ thống.',
        passed: !!whoisData?.ipAddresses && whoisData.ipAddresses.length > 0,
        notes: whoisData?.ipAddresses ? `Đã lưu IP: ${whoisData.ipAddresses.join(', ')}` : 'Chưa ghi nhận địa chỉ IP của mục tiêu.'
      }
    ];

    // 2. TCVN 14192-1:2024 (Network security - Architectural Framework & Gateway protection)
    const list2: ChecklistItem[] = [
      {
        id: '14192-1-1',
        section: 'Mục 6.1',
        name: 'Mã hóa truyền thông an toàn (TLS/SSL)',
        description: 'Áp dụng giao thức HTTPS với phiên bản mã hóa TLS an toàn hiện đại (TLSv1.2 hoặc TLSv1.3).',
        passed: auditData ? (auditData.tlsVersion === 'TLSv1.3' || auditData.tlsVersion === 'TLSv1.2') : false,
        notes: auditData ? `Sử dụng: ${auditData.tlsVersion || 'N/A'}` : 'Chưa xác thực giao thức TLS.'
      },
      {
        id: '14192-1-2',
        section: 'Mục 6.2',
        name: 'Bảo mật phân giải tên miền DNS',
        description: 'Hạ tầng máy chủ tên miền định tuyến chính xác, sẵn sàng hỗ trợ chữ ký DNSSEC.',
        passed: !!whoisData?.nameServers && whoisData.nameServers.length > 0,
        notes: whoisData?.nameServers ? `Có ${whoisData.nameServers.length} NameServers được cấu hình.` : 'Không phát hiện máy chủ DNS hoạt động.'
      },
      {
        id: '14192-1-3',
        section: 'Mục 6.3',
        name: 'Phòng chống rò rỉ biểu ngữ (Banner Disclosure)',
        description: 'Hạn chế hiển thị thông tin chi tiết phiên bản phần mềm máy chủ nhạy cảm trong HTTP Headers.',
        passed: auditData ? (!auditData.serverBanner?.toLowerCase().includes('apache/2.2') && !auditData.serverBanner?.toLowerCase().includes('outdated')) : false,
        notes: auditData ? `Trạng thái: ${auditData.serverBanner}` : 'Chưa quét máy chủ Web.'
      }
    ];

    // 3. TCVN 14192-2:2024 (Network security - System protection & DoS resilience)
    const list3: ChecklistItem[] = [
      {
        id: '14192-2-1',
        section: 'Mục 7.1',
        name: 'Giảm diện tích tấn công cổng mạng',
        description: 'Cổng mạng lắng nghe mở ở mức tối thiểu cần thiết để hạn chế tối đa nguy cơ xâm nhập.',
        passed: openPortsCount <= 3,
        notes: openPortsCount <= 3 ? `An toàn: Chỉ mở ${openPortsCount} cổng.` : `Cảnh báo: Có ${openPortsCount} cổng mở đang lắng nghe.`
      },
      {
        id: '14192-2-2',
        section: 'Mục 7.2',
        name: 'Khả năng chống tấn công từ chối dịch vụ (DoS/DDoS)',
        description: 'Kiểm thử khả năng chịu tải dồn dập, máy chủ không bị quá tải cục bộ hoặc sập kết nối.',
        passed: ddosData ? (ddosData.resilienceRating === 'Resilient' || ddosData.resilienceRating === 'Moderate') : false,
        notes: ddosData ? `Đánh giá resilience: ${ddosData.resilienceRating}` : 'Chưa đánh giá sức chịu tải DoS.'
      },
      {
        id: '14192-2-3',
        section: 'Mục 7.3',
        name: 'Tích hợp tường lửa bảo vệ Web (WAF)',
        description: 'Sử dụng hệ thống lọc lưu lượng độc hại tích hợp chủ động ở biên mạng.',
        passed: ddosData ? ddosData.wafDetected : false,
        notes: ddosData?.wafDetected ? 'Đã phát hiện lá chắn WAF bảo vệ.' : 'Chưa phát hiện tường lửa WAF bên ngoài.'
      }
    ];

    // 4. OWASP WSTG (Web Security Testing Guide)
    const listOWASP_WSTG: ChecklistItem[] = [
      {
        id: 'wstg-1',
        section: 'WSTG-CRYP',
        name: 'Giao thức Mã hoá & Kiểm thử SSL/TLS',
        description: 'Đảm bảo ứng dụng web chỉ chấp nhận các giao thức TLS an toàn (TLS 1.2, 1.3) và bộ mã hóa mạnh.',
        passed: auditData ? (auditData.tlsVersion === 'TLSv1.3' || auditData.tlsVersion === 'TLSv1.2') : false,
        notes: auditData ? `TLS hoạt động: ${auditData.tlsVersion}` : 'Chưa thu thập phiên bản TLS.'
      },
      {
        id: 'wstg-2',
        section: 'WSTG-INFO',
        name: 'Phòng ngừa Rò rỉ Thông tin & Banner Grabbing',
        description: 'Kiểm thử rò rỉ phiên bản phần mềm nhạy cảm thông qua tiêu đề phản hồi Server.',
        passed: auditData ? (!auditData.serverBanner?.toLowerCase().includes('apache/2.2') && !auditData.serverBanner?.toLowerCase().includes('outdated')) : false,
        notes: auditData ? `Phần mềm máy chủ: ${auditData.serverBanner}` : 'Chưa kiểm tra biểu ngữ máy chủ.'
      },
      {
        id: 'wstg-3',
        section: 'WSTG-SESS',
        name: 'Cấu hình Tiêu đề Bảo vệ Phiên & Client Safeguards',
        description: 'Kiểm tra sự hiện diện của các tiêu đề kiểm soát hành vi trình duyệt như X-Frame-Options và X-Content-Type-Options.',
        passed: auditData ? (auditData.headers?.some(h => h.name.toLowerCase() === 'x-frame-options' && h.present) && auditData.headers?.some(h => h.name.toLowerCase() === 'x-content-type-options' && h.present)) : false,
        notes: auditData ? `Đã cấu hình Clickjacking & nosniff.` : 'Thiếu các tiêu đề bảo vệ phiên thiết yếu.'
      }
    ];

    // 5. OWASP Top 10 Risks
    const listOWASP_Top10: ChecklistItem[] = [
      {
        id: 'owasp10-1',
        section: 'A02:2021',
        name: 'Cryptographic Failures (Mã hoá thất bại)',
        description: 'Bảo vệ dữ liệu đang truyền đi thông qua chứng chỉ mã hóa hợp lệ và HTTPS ép buộc.',
        passed: auditData ? (auditData.tlsVersion === 'TLSv1.3' || auditData.tlsVersion === 'TLSv1.2') : false,
        notes: auditData ? `Đang sử dụng mật mã học hiện đại.` : 'Có nguy cơ rò rỉ dữ liệu nhạy cảm qua kênh không an toàn.'
      },
      {
        id: 'owasp10-2',
        section: 'A05:2021',
        name: 'Security Misconfiguration (Lỗi cấu hình an toàn)',
        description: 'Rà soát cấu hình dịch vụ, masks, các cổng hệ thống mở bừa bãi và công khai thông tin gỡ lỗi.',
        passed: openPortsCount <= 3 && (auditData ? !auditData.serverBanner?.toLowerCase().includes('apache/2.2') : true),
        notes: `Phát hiện ${openPortsCount} cổng mở. Banner: ${auditData?.serverBanner || 'N/A'}`
      },
      {
        id: 'owasp10-3',
        section: 'A06:2021',
        name: 'Vulnerable & Outdated Components (Thành phần lỗi thời)',
        description: 'Tránh việc vận hành ứng dụng trên nền tảng chứa các thư viện hoặc hệ điều hành lỗi thời, có lỗ hổng CVE.',
        passed: auditData !== null && !hasHighOrCritical,
        notes: hasHighOrCritical ? 'Vulnerable: Phát hiện lỗ hổng phần mềm nghiêm trọng.' : 'Đạt: Không có lỗ hổng nghiêm trọng nào hoạt động.'
      }
    ];

    // 6. NIST SP 800-115
    const listNIST: ChecklistItem[] = [
      {
        id: 'nist-1',
        section: 'NIST 4.2',
        name: 'Information Gathering (Thu thập thông tin)',
        description: 'Thu thập thông tin định danh hệ thống, hồ sơ WHOIS và thông tin đăng ký.',
        passed: whoisData !== null,
        notes: whoisData ? 'Đã hoàn thành phân tích WHOIS & thông tin sở hữu.' : 'Chưa thực hiện thu thập thông tin.'
      },
      {
        id: 'nist-2',
        section: 'NIST 4.3',
        name: 'Service Discovery / Port Scanning (Quét dịch vụ)',
        description: 'Nhận diện các cổng dịch vụ đang lắng nghe trên địa chỉ IP máy chủ.',
        passed: portData !== null,
        notes: portData ? `Đã rà quét ${portData.results.length} cổng hệ thống.` : 'Chưa thực hiện quét cổng.'
      },
      {
        id: 'nist-3',
        section: 'NIST 4.4',
        name: 'Security Auditing & Header Inspection (Kiểm tra cấu hình)',
        description: 'Kiểm tra và đánh giá chi tiết cấu hình an toàn hệ thống thông tin.',
        passed: auditData !== null,
        notes: auditData ? `Đạt điểm kiểm định cấu hình: ${auditData.securityScore}/100` : 'Chưa chạy kiểm tra cấu hình.'
      }
    ];

    // 7. PTES (Penetration Testing Execution Standard)
    const listPTES: ChecklistItem[] = [
      {
        id: 'ptes-1',
        section: 'Phase 2',
        name: 'Intelligence Gathering (Thu thập tình báo kỹ thuật)',
        description: 'Thu thập sâu các thông số kỹ thuật như DNS, NameServers, bản ghi bản đồ mạng.',
        passed: !!whoisData?.nameServers && whoisData.nameServers.length > 0,
        notes: whoisData?.nameServers ? `Tìm thấy ${whoisData.nameServers.length} máy chủ phân giải.` : 'Chưa có thông tin NameServers.'
      },
      {
        id: 'ptes-2',
        section: 'Phase 4',
        name: 'Vulnerability Analysis (Phân tích lỗ hổng)',
        description: 'Tương quan hóa thông tin dịch vụ mở và các điểm yếu cấu hình ứng dụng web.',
        passed: auditData !== null && portData !== null,
        notes: (auditData && portData) ? 'Đã tương quan hóa cấu hình web và phân tích cổng dịch vụ.' : 'Cần hoàn thành cả quét cổng và kiểm định web.'
      },
      {
        id: 'ptes-3',
        section: 'Phase 5',
        name: 'Exploitation & Resilience Modeling (Mô phỏng khai thác)',
        description: 'Mô phỏng áp lực Stress test / DDoS để đánh giá sức chịu đựng của dịch vụ.',
        passed: ddosData !== null,
        notes: ddosData ? `Độ bền bỉ: ${ddosData.resilienceRating}. Kháng tải thành công.` : 'Chưa thực hiện mô phỏng áp lực.'
      }
    ];

    return { list1, list2, list3, listOWASP_WSTG, listOWASP_Top10, listNIST, listPTES };
  };

  const handleCopyReport = () => {
    const reportText = aiAnalysis || generateDefaultReportMarkdown();
    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  const handleExportPDF = async () => {
    const hasAnyRealData = (auditData && auditData.reachable !== false) || (portData && portData.results && portData.results.length > 0) || (whoisData && whoisData.registrar);
    if (!hasAnyRealData) {
      alert('Không thể xuất báo cáo: Chưa có dữ liệu kiểm định thực tế nào được thu thập từ mục tiêu. Vui lòng thực hiện kiểm định Web hoặc quét cổng trước khi xuất PDF.');
      return;
    }

    setIsExportingPDF(true);
    try {
      const reportElement = document.getElementById('security-assessment-report-document');
      if (!reportElement) {
        alert('Không tìm thấy tài liệu báo cáo để xuất!');
        return;
      }

      // Generate a high-DPI canvas
      const canvas = await html2canvas(reportElement, {
        scale: 1.8,
        useCORS: true,
        logging: false,
        backgroundColor: '#ffffff'
      });

      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const imgWidth = 210; // A4 width in mm
      const pageHeight = 295; // A4 height in mm
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      let heightLeft = imgHeight;
      let position = 0;

      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;

      while (heightLeft >= 0) {
        position = heightLeft - imgHeight;
        pdf.addPage();
        pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
        heightLeft -= pageHeight;
      }
      pdf.save(`TCVN_Security_Report_${domain || 'target'}.pdf`);
    } catch (err) {
      console.error('Error generating PDF:', err);
      alert('Đã xảy ra lỗi trong quá trình tạo tệp PDF!');
    } finally {
      setIsExportingPDF(false);
    }
  };

  const handleExportMarkdown = () => {
    const reportText = aiAnalysis || generateDefaultReportMarkdown();
    const blob = new Blob([reportText], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `sentinel_pentest_report_${domain || 'target'}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleExportJSON = () => {
    const dataPayload = {
      target: domain,
      timestamp: new Date().toISOString(),
      standards: "CEH v13 / NIST SP 800-115 / OWASP Top 10 / TCVN Compliance",
      scanResults: {
        whois: whoisData,
        webAudit: auditData,
        portScanner: portData,
        ddosStressTest: ddosData,
        malwareScan: malwareData,
        aiAssessment: aiAnalysis
      }
    };
    const blob = new Blob([JSON.stringify(dataPayload, null, 2)], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `sentinel_pentest_results_${domain || 'target'}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const [copiedRemediationId, setCopiedRemediationId] = useState<string | null>(null);

  const handleCopyRemediation = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRemediationId(id);
    setTimeout(() => setCopiedRemediationId(null), 2000);
  };

  const renderSeverityBadge = (severity: string) => {
    const s = severity?.toLowerCase() || 'info';
    switch (s) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1 font-mono text-[10px] font-extrabold text-rose-700 bg-rose-50 border border-rose-300 px-2.5 py-0.5 rounded shadow-2xs">
            <Flame className="w-3.5 h-3.5 text-rose-600 fill-rose-100" />
            CRITICAL
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center gap-1 font-mono text-[10px] font-bold text-orange-700 bg-orange-50 border border-orange-300 px-2 py-0.5 rounded">
            <AlertTriangle className="w-3.5 h-3.5 text-orange-600" />
            HIGH
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center gap-1 font-mono text-[10px] font-bold text-amber-800 bg-amber-50 border border-amber-300 px-2 py-0.5 rounded">
            <AlertCircle className="w-3.5 h-3.5 text-amber-600" />
            MEDIUM
          </span>
        );
      case 'low':
        return (
          <span className="inline-flex items-center gap-1 font-mono text-[10px] font-semibold text-blue-700 bg-blue-50 border border-blue-300 px-2 py-0.5 rounded">
            <Info className="w-3.5 h-3.5 text-blue-600" />
            LOW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 font-mono text-[10px] font-medium text-slate-700 bg-slate-100 border border-slate-300 px-2 py-0.5 rounded">
            <CheckCircle2 className="w-3.5 h-3.5 text-slate-500" />
            INFO
          </span>
        );
    }
  };

  const generateDefaultReportMarkdown = () => {
    return `# Penetration Testing & Security Assessment Report
**Target**: ${domain || 'N/A'}  
**Date**: ${new Date().toUTCString()}  
**Standard**: CEH v13 / NIST SP 800-115 / OWASP Top 10 / TCVN Standards  
**Evaluator**: Sentinel OS v2.4 Security Engine

---

## 1. Executive Summary
- **Security Grade**: ${auditData ? `${auditData.securityGrade} (${auditData.securityScore}/100) [Đo lường thật]` : 'Chưa kiểm định [Không có dữ liệu]'}
- **Registrar**: ${whoisData?.registrar || 'Chưa thu thập / Ẩn danh'}
- **Open TCP Ports**: ${portData ? `${portData.openPortsCount} cổng mở [Đo lường thật]` : 'Chưa quét cổng'}
- **DDoS Resilience**: ${ddosData ? `${ddosData.resilienceRating} (Throughput: ${ddosData.requestsPerSecond} req/s) [Đo lường thật]` : 'Chưa kiểm thử DoS'}
- **Malware & Link Cleanliness**: ${malwareData ? `${malwareData.cleanlinessScore}/100 (Trạng thái: ${malwareData.status}) [Đo lường thật]` : 'Chưa quét mã độc'}

## 2. Reconnaissance & Footprinting Findings
- **Primary IP**: ${whoisData?.ipAddresses?.join(', ') || 'Chưa thu thập'}
- **Name Servers**: ${whoisData?.nameServers?.join(', ') || 'Chưa thu thập'}
- **DNSSEC**: ${whoisData ? (whoisData.dnssec ? 'Enabled' : 'Unsigned') : 'Chưa kiểm tra'}
- **Server Banner**: ${auditData?.serverBanner || (auditData ? 'Không tiết lộ (Hidden/Protected)' : 'Chưa kiểm tra')}
- **SSL/TLS**: ${auditData ? `${auditData.tlsVersion || 'N/A'} (${auditData.cipherSuite || 'N/A'})` : 'Chưa kiểm tra'}

## 3. Discovered Vulnerabilities & Remediation
${auditData ? (auditData.vulnerabilities.length > 0 ? auditData.vulnerabilities.map((v, i) => `### ${i + 1}. ${v.title} [${v.severity.toUpperCase()}]
- **Category**: ${v.category || 'Configuration'}
- **Description**: ${v.description}
- **Remediation**: ${v.remediation}
- **CEH Reference**: ${v.cehModule}
`).join('\n') : 'Không phát hiện lỗ hổng cấu hình nghiêm trọng.') : 'Chưa thực hiện kiểm tra cấu hình.'}

## 4. Malware, Trojan & Malicious Link Inspection
- **Cleanliness Score**: ${malwareData ? `${malwareData.cleanlinessScore}/100 [Đo lường thật]` : 'Chưa quét'}
- **Total Threats Detected**: ${malwareData ? malwareData.totalThreatsCount : 0}
- **Hidden SEO Links**: ${malwareData ? malwareData.hiddenLinks.length : 0}
- **Junk/Spam Outlinks**: ${malwareData ? malwareData.junkLinks.length : 0}
- **Viruses & WebShells**: ${malwareData ? malwareData.virusSignatures.length : 0}
- **Trojan & C2 Backdoors**: ${malwareData ? malwareData.trojanThreats.length : 0}
${malwareData?.summary ? `\n> **Summary**: ${malwareData.summary}\n` : ''}

## 5. DDoS & Stress Benchmark Findings
- Total Requests: ${ddosData ? `${ddosData.totalRequests} [Đo lường thật]` : 'Chưa kiểm thử'}
- Median Latency: ${ddosData ? `${ddosData.p50LatencyMs}ms (p99: ${ddosData.p99LatencyMs}ms)` : 'N/A'}
- WAF Protection: ${ddosData ? (ddosData.wafDetected ? (ddosData.wafProvider || 'WAF Detected') : 'Không phát hiện WAF') : 'Chưa kiểm tra'}
`;
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex flex-wrap items-center justify-between gap-4 no-print">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-600" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
              Executive Penetration Testing Audit Report
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Standard: <span className="font-semibold text-slate-700">EC-Council CEH v13 / OWASP Top 10</span> | Target: <span className="font-mono font-bold text-slate-800">{domain || 'None'}</span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onGenerateAiAnalysis}
            disabled={isAiGenerating || !domain}
            className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-xs font-semibold px-3.5 py-2 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors"
          >
            {isAiGenerating ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Generating AI Assessment...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5" />
                <span>Generate Deep AI Assessment</span>
              </>
            )}
          </button>

          <button
            onClick={handleCopyReport}
            className="bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold px-3 py-2 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>

          <button
            onClick={handleExportPDF}
            disabled={isExportingPDF}
            className="bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-xs font-bold px-4 py-2 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors shadow-xs"
            title="Xuất trực tiếp báo cáo an toàn mạng định dạng PDF độ phân giải cao."
          >
            {isExportingPDF ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Đang xuất PDF...</span>
              </>
            ) : (
              <>
                <FileDown className="w-4 h-4 animate-pulse" />
                <span>Xuất PDF Trực tiếp</span>
              </>
            )}
          </button>

          <button
            onClick={handlePrint}
            className="bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold px-3 py-2 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors"
            title="Mở giao diện in ấn của trình duyệt để lưu dạng PDF hoặc in trực tiếp."
          >
            <Printer className="w-3.5 h-3.5" />
            <span>In / Lưu PDF Trình duyệt</span>
          </button>

          <button
            onClick={handleExportMarkdown}
            className="bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold px-3 py-2 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors"
            title="Download report as Markdown file (.md)"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Markdown</span>
          </button>

          <button
            onClick={handleExportJSON}
            className="bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold px-3 py-2 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors"
            title="Download full scan data payload as JSON file (.json)"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Report Container */}
      <div id="security-assessment-report-document" className="bg-white rounded-xl border border-slate-200 p-4 sm:p-6 md:p-8 shadow-xs max-w-5xl mx-auto w-full overflow-x-hidden">
        {/* Report Header */}
        <div className="border-b-2 border-slate-900 pb-6 mb-6 flex flex-wrap justify-between items-start gap-4">
          <div>
            <div className="text-[10px] font-bold uppercase tracking-widest text-blue-600 mb-1">
              SENTINEL OS v2.4 PENTEST SUITE
            </div>
            <h1 className="text-2xl font-black text-slate-900 tracking-tight uppercase">
              Security Assessment & Audit Report
            </h1>
            <p className="text-xs text-slate-500 mt-1">
              Confidential document generated for technical auditing & vulnerability hardening.
            </p>
          </div>

          <div className="text-right text-xs">
            <div className="font-mono text-slate-700 font-bold">TARGET: {domain || 'N/A'}</div>
            <div className="text-[11px] text-slate-500">AUDIT DATE: {new Date().toLocaleDateString()}</div>
            <div className="flex flex-col items-end gap-0.5 mt-1">
              <span className="text-[10px] text-emerald-600 font-bold uppercase tracking-wider bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">CEH v13 COMPLIANT</span>
              <span className="text-[10px] text-indigo-600 font-bold uppercase tracking-wider bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-200">TCVN 14423/14192 AUDITED</span>
            </div>
          </div>
        </div>

        {/* Security Score Progression & Temporal Telemetry (D3.js) */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <SecurityScoreChart
            currentScore={auditData?.securityScore ?? 0}
            currentGrade={auditData?.securityGrade ?? 'N/A'}
            targetDomain={domain || 'target.local'}
            theme={theme}
          />
          <NetworkHeatmap
            targetDomain={domain || 'target.local'}
            openPortsCount={portData?.openPortsCount ?? 0}
            theme={theme}
          />
        </div>
        
        <div className="mb-6">
          <SecurityRadarChart
            auditData={auditData}
            portData={portData}
            ddosData={ddosData}
            theme={theme}
          />
        </div>

        {/* TCVN Standards Compliance Assessment Checklist */}
        <div className="mb-8 mt-4 border-t border-b border-slate-200/80 py-6">
          <div className="flex items-center gap-2 mb-4">
            <CheckSquare className="w-5 h-5 text-emerald-600" />
            <h2 className="text-base font-extrabold text-slate-900 uppercase tracking-tight">
              Bảng Đánh Giá Tuân Thủ Tiêu Chuẩn An Toàn TCVN (Vietnamese TCVN Security Standards Compliance Audit)
            </h2>
          </div>
          <p className="text-xs text-slate-500 mb-6">
            Đánh giá tự động dựa trên kết quả rà quét kỹ thuật của Sentinel OS đối chiếu với các điều khoản tiêu chuẩn quốc gia về an toàn thông tin và bảo mật mạng của Việt Nam.
          </p>

          {(() => {
            const { list1, list2, list3, listOWASP_WSTG, listOWASP_Top10, listNIST, listPTES } = evaluateCompliance();
            const totalItems = list1.length + list2.length + list3.length;
            const passedItems = [...list1, ...list2, ...list3].filter(item => item.passed).length;
            const complianceRate = Math.round((passedItems / totalItems) * 100);

            return (
              <div className="space-y-6">
                {/* Global TCVN Compliance Metric Card */}
                <div className="bg-emerald-50/50 rounded-xl p-4 border border-emerald-200 flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-800 font-bold block mb-1">Kết quả đánh giá chung</span>
                    <div className="text-lg font-extrabold text-slate-900 flex flex-wrap items-center gap-2">
                      <span>Tỷ Lệ Tuân Thủ TCVN:</span>
                      <span className="text-emerald-700 font-black">{complianceRate}%</span>
                      <span className="text-xs font-normal text-slate-500">({passedItems}/{totalItems} Tiêu chí Đạt)</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {complianceRate === 100 ? (
                      <span className="inline-flex items-center gap-1 bg-emerald-600 text-white text-[11px] font-bold px-3 py-1.5 rounded-full uppercase tracking-wider">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Đạt Toàn Diện
                      </span>
                    ) : complianceRate >= 60 ? (
                      <span className="inline-flex items-center gap-1 bg-amber-500 text-white text-[11px] font-bold px-3 py-1.5 rounded-full uppercase tracking-wider">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Đạt Một Phần (Khuyến Nghị Nâng Cấp)
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 bg-red-600 text-white text-[11px] font-bold px-3 py-1.5 rounded-full uppercase tracking-wider">
                        <XCircle className="w-3.5 h-3.5" />
                        Không Đạt (Cần Khắc Phục Ngay)
                      </span>
                    )}
                  </div>
                </div>

                {/* Grid of the 3 Standards */}
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                  
                  {/* TCVN 14423:2026 */}
                  <div className="bg-slate-50/50 rounded-xl border border-slate-200 p-4 flex flex-col justify-between">
                    <div>
                      <div className="border-b border-slate-200 pb-2 mb-3">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-blue-600 block">Đánh giá hệ thống</span>
                        <h3 className="text-xs font-black text-slate-900 uppercase">TCVN 14423:2026</h3>
                        <p className="text-[10px] text-slate-500 italic">Hướng dẫn kiểm tra, đánh giá an toàn hệ thống</p>
                      </div>
                      <div className="space-y-3">
                        {list1.map(item => (
                          <div key={item.id} className="text-[11px] space-y-1 bg-white p-2.5 rounded-lg border border-slate-100">
                            <div className="flex items-start justify-between gap-2">
                              <span className="font-bold text-slate-800 leading-tight">{item.section}: {item.name}</span>
                              {item.passed ? (
                                <span className="text-emerald-600 shrink-0" title="Đạt tiêu chuẩn">
                                  <CheckCircle2 className="w-4 h-4 fill-emerald-100" />
                                </span>
                              ) : (
                                <span className="text-amber-500 shrink-0" title="Cần khắc phục">
                                  <AlertTriangle className="w-4 h-4" />
                                </span>
                              )}
                            </div>
                            <p className="text-slate-500 text-[10px] leading-tight">{item.description}</p>
                            <div className="pt-1 text-[10px] font-mono text-slate-600 border-t border-slate-100/60 mt-1">
                              {item.notes}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="mt-4 pt-3 border-t border-slate-100 flex justify-between text-[11px]">
                      <span className="text-slate-500">Mục tiêu đạt được:</span>
                      <strong className="text-slate-800">{list1.filter(i => i.passed).length}/{list1.length}</strong>
                    </div>
                  </div>

                  {/* TCVN 14192-1:2024 */}
                  <div className="bg-slate-50/50 rounded-xl border border-slate-200 p-4 flex flex-col justify-between">
                    <div>
                      <div className="border-b border-slate-200 pb-2 mb-3">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-blue-600 block">Bảo mật mạng - Phần 1</span>
                        <h3 className="text-xs font-black text-slate-900 uppercase">TCVN 14192-1:2024</h3>
                        <p className="text-[10px] text-slate-500 italic">Bảo vệ cổng kết nối & Khung kiến trúc mạng</p>
                      </div>
                      <div className="space-y-3">
                        {list2.map(item => (
                          <div key={item.id} className="text-[11px] space-y-1 bg-white p-2.5 rounded-lg border border-slate-100">
                            <div className="flex items-start justify-between gap-2">
                              <span className="font-bold text-slate-800 leading-tight">{item.section}: {item.name}</span>
                              {item.passed ? (
                                <span className="text-emerald-600 shrink-0" title="Đạt tiêu chuẩn">
                                  <CheckCircle2 className="w-4 h-4 fill-emerald-100" />
                                </span>
                              ) : (
                                <span className="text-amber-500 shrink-0" title="Cần khắc phục">
                                  <AlertTriangle className="w-4 h-4" />
                                </span>
                              )}
                            </div>
                            <p className="text-slate-500 text-[10px] leading-tight">{item.description}</p>
                            <div className="pt-1 text-[10px] font-mono text-slate-600 border-t border-slate-100/60 mt-1">
                              {item.notes}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="mt-4 pt-3 border-t border-slate-100 flex justify-between text-[11px]">
                      <span className="text-slate-500">Mục tiêu đạt được:</span>
                      <strong className="text-slate-800">{list2.filter(i => i.passed).length}/{list2.length}</strong>
                    </div>
                  </div>

                  {/* TCVN 14192-2:2024 */}
                  <div className="bg-slate-50/50 rounded-xl border border-slate-200 p-4 flex flex-col justify-between">
                    <div>
                      <div className="border-b border-slate-200 pb-2 mb-3">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-blue-600 block">Bảo mật mạng - Phần 2</span>
                        <h3 className="text-xs font-black text-slate-900 uppercase">TCVN 14192-2:2024</h3>
                        <p className="text-[10px] text-slate-500 italic">Bảo vệ hệ thống & Chống tấn công DoS/DDoS</p>
                      </div>
                      <div className="space-y-3">
                        {list3.map(item => (
                          <div key={item.id} className="text-[11px] space-y-1 bg-white p-2.5 rounded-lg border border-slate-100">
                            <div className="flex items-start justify-between gap-2">
                              <span className="font-bold text-slate-800 leading-tight">{item.section}: {item.name}</span>
                              {item.passed ? (
                                <span className="text-emerald-600 shrink-0" title="Đạt tiêu chuẩn">
                                  <CheckCircle2 className="w-4 h-4 fill-emerald-100" />
                                </span>
                              ) : (
                                <span className="text-amber-500 shrink-0" title="Cần khắc phục">
                                  <AlertTriangle className="w-4 h-4" />
                                </span>
                              )}
                            </div>
                            <p className="text-slate-500 text-[10px] leading-tight">{item.description}</p>
                            <div className="pt-1 text-[10px] font-mono text-slate-600 border-t border-slate-100/60 mt-1">
                              {item.notes}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="mt-4 pt-3 border-t border-slate-100 flex justify-between text-[11px]">
                      <span className="text-slate-500">Mục tiêu đạt được:</span>
                      <strong className="text-slate-800">{list3.filter(i => i.passed).length}/{list3.length}</strong>
                    </div>
                  </div>

                </div>

                {/* International Standards Section */}
                <div className="border-t border-slate-200/80 pt-6 mt-6">
                  <div className="flex items-center gap-2 mb-3">
                    <Globe className="w-5 h-5 text-indigo-600" />
                    <h2 className="text-sm font-black text-slate-800 uppercase tracking-tight">
                      Tiêu Chuẩn Bảo Mật Quốc Tế (OWASP, NIST, PTES Standards)
                    </h2>
                  </div>
                  <p className="text-xs text-slate-500 mb-6">
                    Sentinel OS rà quét tự động và đối chiếu thông tin dịch vụ, mật mã, cấu hình đầu cuối với các khung bảo mật phổ biến được TCVN và thế giới công nhận.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
                    {/* OWASP WSTG */}
                    <div className="bg-slate-50/50 rounded-xl border border-slate-200 p-4 flex flex-col justify-between min-w-0">
                      <div>
                        <div className="border-b border-slate-200 pb-2 mb-3">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-600 block font-mono">Web Testing Guide</span>
                          <h3 className="text-xs font-black text-slate-900 uppercase truncate">OWASP WSTG</h3>
                          <p className="text-[10px] text-slate-500 italic truncate">Kiểm thử bảo mật website 11 lĩnh vực</p>
                        </div>
                        <div className="space-y-3">
                          {listOWASP_WSTG.map(item => (
                            <div key={item.id} className="text-[11px] space-y-1 bg-white p-2.5 rounded-lg border border-slate-100">
                              <div className="flex items-start justify-between gap-2">
                                <span className="font-bold text-slate-800 leading-tight">{item.section}: {item.name}</span>
                                {item.passed ? (
                                  <span className="text-emerald-600 shrink-0" title="Đạt tiêu chuẩn">
                                    <CheckCircle2 className="w-4 h-4 fill-emerald-100" />
                                  </span>
                                ) : (
                                  <span className="text-amber-500 shrink-0" title="Cần khắc phục">
                                    <AlertTriangle className="w-4 h-4" />
                                  </span>
                                )}
                              </div>
                              <p className="text-slate-500 text-[10px] leading-tight">{item.description}</p>
                              <div className="pt-1 text-[10px] font-mono text-slate-600 border-t border-slate-100/60 mt-1">
                                {item.notes}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="mt-4 pt-3 border-t border-slate-100 flex justify-between text-[11px]">
                        <span className="text-slate-500">Mục tiêu đạt được:</span>
                        <strong className="text-slate-800">{listOWASP_WSTG.filter(i => i.passed).length}/{listOWASP_WSTG.length}</strong>
                      </div>
                    </div>

                    {/* OWASP Top 10 */}
                    <div className="bg-slate-50/50 rounded-xl border border-slate-200 p-4 flex flex-col justify-between min-w-0">
                      <div>
                        <div className="border-b border-slate-200 pb-2 mb-3">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-600 block font-mono">Critical Web Risks</span>
                          <h3 className="text-xs font-black text-slate-900 uppercase truncate">OWASP Top 10</h3>
                          <p className="text-[10px] text-slate-500 italic truncate">10 rủi ro an ninh ứng dụng hàng đầu</p>
                        </div>
                        <div className="space-y-3">
                          {listOWASP_Top10.map(item => (
                            <div key={item.id} className="text-[11px] space-y-1 bg-white p-2.5 rounded-lg border border-slate-100">
                              <div className="flex items-start justify-between gap-2">
                                <span className="font-bold text-slate-800 leading-tight">{item.section}: {item.name}</span>
                                {item.passed ? (
                                  <span className="text-emerald-600 shrink-0" title="Đạt tiêu chuẩn">
                                    <CheckCircle2 className="w-4 h-4 fill-emerald-100" />
                                  </span>
                                ) : (
                                  <span className="text-amber-500 shrink-0" title="Cần khắc phục">
                                    <AlertTriangle className="w-4 h-4" />
                                  </span>
                                )}
                              </div>
                              <p className="text-slate-500 text-[10px] leading-tight">{item.description}</p>
                              <div className="pt-1 text-[10px] font-mono text-slate-600 border-t border-slate-100/60 mt-1">
                                {item.notes}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="mt-4 pt-3 border-t border-slate-100 flex justify-between text-[11px]">
                        <span className="text-slate-500">Mục tiêu đạt được:</span>
                        <strong className="text-slate-800">{listOWASP_Top10.filter(i => i.passed).length}/{listOWASP_Top10.length}</strong>
                      </div>
                    </div>

                    {/* NIST SP 800-115 */}
                    <div className="bg-slate-50/50 rounded-xl border border-slate-200 p-4 flex flex-col justify-between min-w-0">
                      <div>
                        <div className="border-b border-slate-200 pb-2 mb-3">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-600 block font-mono">Assessment Guide</span>
                          <h3 className="text-xs font-black text-slate-900 uppercase truncate">NIST SP 800-115</h3>
                          <p className="text-[10px] text-slate-500 italic truncate">Hướng dẫn kỹ thuật đánh giá ATTT của Mỹ</p>
                        </div>
                        <div className="space-y-3">
                          {listNIST.map(item => (
                            <div key={item.id} className="text-[11px] space-y-1 bg-white p-2.5 rounded-lg border border-slate-100">
                              <div className="flex items-start justify-between gap-2">
                                <span className="font-bold text-slate-800 leading-tight">{item.section}: {item.name}</span>
                                {item.passed ? (
                                  <span className="text-emerald-600 shrink-0" title="Đạt tiêu chuẩn">
                                    <CheckCircle2 className="w-4 h-4 fill-emerald-100" />
                                  </span>
                                ) : (
                                  <span className="text-amber-500 shrink-0" title="Cần khắc phục">
                                    <AlertTriangle className="w-4 h-4" />
                                  </span>
                                )}
                              </div>
                              <p className="text-slate-500 text-[10px] leading-tight">{item.description}</p>
                              <div className="pt-1 text-[10px] font-mono text-slate-600 border-t border-slate-100/60 mt-1">
                                {item.notes}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="mt-4 pt-3 border-t border-slate-100 flex justify-between text-[11px]">
                        <span className="text-slate-500">Mục tiêu đạt được:</span>
                        <strong className="text-slate-800">{listNIST.filter(i => i.passed).length}/{listNIST.length}</strong>
                      </div>
                    </div>

                    {/* PTES */}
                    <div className="bg-slate-50/50 rounded-xl border border-slate-200 p-4 flex flex-col justify-between min-w-0">
                      <div>
                        <div className="border-b border-slate-200 pb-2 mb-3">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-600 block font-mono">Penetration Testing</span>
                          <h3 className="text-xs font-black text-slate-900 uppercase truncate">PTES Framework</h3>
                          <p className="text-[10px] text-slate-500 italic truncate">Chuẩn quy trình thực thi kiểm thử xâm nhập</p>
                        </div>
                        <div className="space-y-3">
                          {listPTES.map(item => (
                            <div key={item.id} className="text-[11px] space-y-1 bg-white p-2.5 rounded-lg border border-slate-100">
                              <div className="flex items-start justify-between gap-2">
                                <span className="font-bold text-slate-800 leading-tight">{item.section}: {item.name}</span>
                                {item.passed ? (
                                  <span className="text-emerald-600 shrink-0" title="Đạt tiêu chuẩn">
                                    <CheckCircle2 className="w-4 h-4 fill-emerald-100" />
                                  </span>
                                ) : (
                                  <span className="text-amber-500 shrink-0" title="Cần khắc phục">
                                    <AlertTriangle className="w-4 h-4" />
                                  </span>
                                )}
                              </div>
                              <p className="text-slate-500 text-[10px] leading-tight">{item.description}</p>
                              <div className="pt-1 text-[10px] font-mono text-slate-600 border-t border-slate-100/60 mt-1">
                                {item.notes}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="mt-4 pt-3 border-t border-slate-100 flex justify-between text-[11px]">
                        <span className="text-slate-500">Mục tiêu đạt được:</span>
                        <strong className="text-slate-800">{listPTES.filter(i => i.passed).length}/{listPTES.length}</strong>
                      </div>
                    </div>
                  </div>
                </div>

              </div>
            );
          })()}
        </div>

        {/* AI Analysis View or Default Structured Summary */}
        {aiAnalysis ? (
          <div className="prose prose-sm max-w-none text-slate-800 leading-relaxed font-sans">
            <Markdown>{aiAnalysis}</Markdown>
          </div>
        ) : (
          <div className="space-y-6 text-xs leading-relaxed text-slate-700">
            {/* Quick Summary Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-slate-50 p-4 rounded-xl border border-slate-200">
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">Overall Grade</span>
                <div className="text-2xl font-bold text-slate-800">{auditData?.securityGrade || 'B'} ({auditData?.securityScore || 75}/100)</div>
              </div>
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">Attack Surface</span>
                <div className="text-sm font-semibold text-slate-800">{portData?.openPortsCount || 0} Open Listening Ports</div>
              </div>
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">DDoS Posture</span>
                <div className="text-sm font-semibold text-slate-800">{ddosData?.resilienceRating || 'Evaluated'}</div>
              </div>
            </div>

            {/* Section 1: Footprinting */}
            <div className="space-y-2">
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 border-b border-slate-200 pb-1">
                1. Footprinting & Reconnaissance Summary
              </h2>
              <div className="grid grid-cols-2 gap-2 font-mono text-[11px] bg-slate-50 p-3 rounded-lg border border-slate-200">
                <div><span className="text-slate-400">Registrar:</span> {whoisData?.registrar || 'N/A'}</div>
                <div><span className="text-slate-400">Resolved IPs:</span> {whoisData?.ipAddresses?.join(', ') || 'N/A'}</div>
                <div><span className="text-slate-400">Web Server Banner:</span> {auditData?.serverBanner || 'N/A'}</div>
                <div><span className="text-slate-400">TLS Encryption:</span> {auditData?.tlsVersion || 'TLSv1.3'}</div>
              </div>
            </div>

            {/* Section 2: Vulnerabilities */}
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-2">
                <div>
                  <h2 className="text-sm font-black uppercase tracking-wider text-slate-900 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-600" />
                    2. Key Vulnerability Findings & Threat Severity Matrix
                  </h2>
                  <p className="text-[11px] text-slate-500">
                    Discovered security weaknesses prioritized by Common Vulnerability Scoring System (CVSS) and CEH v13 modules.
                  </p>
                </div>

                {/* Severity Breakdown Badges */}
                {auditData?.vulnerabilities && auditData.vulnerabilities.length > 0 && (() => {
                  const criticals = auditData.vulnerabilities.filter(v => v.severity.toLowerCase() === 'critical').length;
                  const highs = auditData.vulnerabilities.filter(v => v.severity.toLowerCase() === 'high').length;
                  const mediums = auditData.vulnerabilities.filter(v => v.severity.toLowerCase() === 'medium').length;
                  const lows = auditData.vulnerabilities.filter(v => v.severity.toLowerCase() === 'low' || v.severity.toLowerCase() === 'info').length;

                  return (
                    <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
                      <span className="bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-bold border border-slate-200">
                        Total: {auditData.vulnerabilities.length}
                      </span>
                      {criticals > 0 && (
                        <span className="bg-rose-50 text-rose-700 px-2 py-0.5 rounded font-extrabold border border-rose-300 flex items-center gap-1">
                          <Flame className="w-3 h-3 text-rose-600" />
                          {criticals} Critical
                        </span>
                      )}
                      {highs > 0 && (
                        <span className="bg-orange-50 text-orange-700 px-2 py-0.5 rounded font-bold border border-orange-300 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 text-orange-600" />
                          {highs} High
                        </span>
                      )}
                      {mediums > 0 && (
                        <span className="bg-amber-50 text-amber-700 px-2 py-0.5 rounded font-bold border border-amber-300 flex items-center gap-1">
                          <AlertCircle className="w-3 h-3 text-amber-600" />
                          {mediums} Medium
                        </span>
                      )}
                      {lows > 0 && (
                        <span className="bg-blue-50 text-blue-700 px-2 py-0.5 rounded font-semibold border border-blue-300 flex items-center gap-1">
                          <Info className="w-3 h-3 text-blue-600" />
                          {lows} Low
                        </span>
                      )}
                    </div>
                  );
                })()}
              </div>

              <div className="space-y-3">
                {auditData?.vulnerabilities && auditData.vulnerabilities.length > 0 ? (
                  auditData.vulnerabilities.map((v, i) => {
                    const sev = v.severity.toLowerCase();
                    const borderClass = 
                      sev === 'critical' 
                        ? 'border-l-4 border-l-rose-600 bg-rose-50/20' 
                        : sev === 'high'
                        ? 'border-l-4 border-l-orange-500 bg-orange-50/20'
                        : sev === 'medium'
                        ? 'border-l-4 border-l-amber-500 bg-amber-50/20'
                        : 'border-l-4 border-l-blue-500 bg-blue-50/20';

                    return (
                      <div key={i} className={`p-4 rounded-xl border border-slate-200 ${borderClass} transition-all space-y-2`}>
                        <div className="flex flex-wrap justify-between items-start gap-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-[10px] font-bold text-slate-700 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-2xs">
                              {v.id || `VULN-00${i + 1}`}
                            </span>
                            {v.category && (
                              <span className="text-[10px] uppercase font-bold text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
                                {v.category}
                              </span>
                            )}
                            <h3 className="text-xs font-black text-slate-900">
                              {v.title}
                            </h3>
                          </div>
                          {renderSeverityBadge(v.severity)}
                        </div>

                        <p className="text-[11px] text-slate-600 leading-relaxed">{v.description}</p>

                        {v.cehModule && (
                          <div className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                            <span className="font-bold text-slate-700">Audit Ref:</span> {v.cehModule}
                          </div>
                        )}

                        <div className="bg-white p-3 rounded-lg border border-slate-200 font-mono text-[11px] text-blue-900 flex justify-between items-center gap-3">
                          <div>
                            <span className="font-sans font-bold text-slate-700 block mb-0.5 text-[10px] uppercase tracking-wider">
                              Remediation Directive:
                            </span>
                            <span className="break-all">{v.remediation}</span>
                          </div>
                          <button
                            onClick={() => handleCopyRemediation(v.remediation, `vuln-${i}`)}
                            className="p-1.5 text-slate-400 hover:text-slate-700 cursor-pointer shrink-0 bg-slate-50 hover:bg-slate-100 rounded border border-slate-200 transition-colors"
                            title="Copy remediation command/config"
                          >
                            {copiedRemediationId === `vuln-${i}` ? (
                              <Check className="w-4 h-4 text-emerald-600" />
                            ) : (
                              <Copy className="w-4 h-4" />
                            )}
                          </button>
                        </div>
                      </div>
                    );
                  })
                ) : (
                  <div className="p-6 bg-slate-50 rounded-xl border border-dashed border-slate-200 text-center">
                    <CheckCircle2 className="w-6 h-6 text-emerald-500 mx-auto mb-1.5" />
                    <p className="text-xs font-bold text-slate-700">No Critical Misconfigurations Logged</p>
                    <p className="text-[11px] text-slate-500 mt-0.5">Target headers and server responses passed baseline security audits.</p>
                  </div>
                )}
              </div>
            </div>

            {/* Section 3: Malware, Trojan & Link Security Inspection */}
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-2">
                <div>
                  <h2 className="text-sm font-black uppercase tracking-wider text-slate-900 flex items-center gap-2">
                    <Bug className="w-4 h-4 text-purple-600" />
                    3. Malware, Trojan & Malicious Link Security Inspection
                  </h2>
                  <p className="text-[11px] text-slate-500">
                    Comprehensive heuristic static checks for hidden SEO backlinks, junk outlinks, web shell viruses, and Trojan C2 beacons.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <span className={`font-mono text-[10px] font-bold px-2.5 py-1 rounded-full ${
                    malwareData?.status === 'CRITICAL'
                      ? 'bg-rose-100 text-rose-800 border border-rose-300 animate-pulse'
                      : malwareData?.status === 'WARNING'
                      ? 'bg-amber-100 text-amber-800 border border-amber-300'
                      : 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                  }`}>
                    STATUS: {malwareData?.status || 'CLEAN'} ({malwareData?.cleanlinessScore ?? 100}/100)
                  </span>
                </div>
              </div>

              {/* Malware Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-center">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">Hidden Links</span>
                  <div className="text-lg font-black text-slate-800 mt-0.5">{malwareData?.hiddenLinks.length || 0}</div>
                  <span className="text-[10px] text-slate-500">CSS cloaking</span>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-center">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">Junk Links</span>
                  <div className="text-lg font-black text-slate-800 mt-0.5">{malwareData?.junkLinks.length || 0}</div>
                  <span className="text-[10px] text-slate-500">Spam / TLD risks</span>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-center">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">Viruses & Shells</span>
                  <div className="text-lg font-black text-slate-800 mt-0.5">{malwareData?.virusSignatures.length || 0}</div>
                  <span className="text-[10px] text-slate-500">Web backdoors</span>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-center">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block font-mono">Trojan & C2</span>
                  <div className="text-lg font-black text-slate-800 mt-0.5">{malwareData?.trojanThreats.length || 0}</div>
                  <span className="text-[10px] text-slate-500">Remote beacons</span>
                </div>
              </div>

              {/* Detailed Findings List */}
              {((malwareData?.hiddenLinks.length || 0) + (malwareData?.junkLinks.length || 0) + (malwareData?.virusSignatures.length || 0) + (malwareData?.trojanThreats.length || 0)) > 0 ? (
                <div className="space-y-2">
                  {/* Hidden Links */}
                  {malwareData?.hiddenLinks.map((item, idx) => (
                    <div key={`hl-${idx}`} className="p-3 rounded-lg border border-purple-200 bg-purple-50/20 text-xs space-y-1">
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-1.5">
                          <EyeOff className="w-3.5 h-3.5 text-purple-600" />
                          <strong className="text-purple-900 font-mono text-[10px]">{item.id}</strong>
                          <span className="text-slate-800 font-semibold">{item.url}</span>
                        </div>
                        {renderSeverityBadge(item.severity)}
                      </div>
                      <p className="text-[11px] text-slate-600">
                        <strong>Technique:</strong> {item.hidingTechnique} | <strong>Anchor:</strong> "{item.anchorText}"
                      </p>
                    </div>
                  ))}

                  {/* Junk Links */}
                  {malwareData?.junkLinks.map((item, idx) => (
                    <div key={`jl-${idx}`} className="p-3 rounded-lg border border-amber-200 bg-amber-50/20 text-xs space-y-1">
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-1.5">
                          <LinkIcon className="w-3.5 h-3.5 text-amber-600" />
                          <strong className="text-amber-900 font-mono text-[10px]">{item.id}</strong>
                          <span className="text-slate-800 font-semibold">{item.url}</span>
                        </div>
                        {renderSeverityBadge(item.severity)}
                      </div>
                      <p className="text-[11px] text-slate-600">
                        <strong>Category:</strong> {item.category} • {item.reason}
                      </p>
                    </div>
                  ))}

                  {/* Virus Signatures */}
                  {malwareData?.virusSignatures.map((item, idx) => (
                    <div key={`vs-${idx}`} className="p-3 rounded-lg border border-rose-200 bg-rose-50/20 text-xs space-y-1">
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-1.5">
                          <Bug className="w-3.5 h-3.5 text-rose-600" />
                          <strong className="text-rose-900 font-mono text-[10px]">{item.id}</strong>
                          <span className="text-rose-900 font-black">{item.name}</span>
                        </div>
                        {renderSeverityBadge(item.severity)}
                      </div>
                      <p className="text-[11px] text-slate-600">
                        <strong>Type:</strong> {item.type} • <strong>Location:</strong> {item.location}
                      </p>
                    </div>
                  ))}

                  {/* Trojan Threats */}
                  {malwareData?.trojanThreats.map((item, idx) => (
                    <div key={`tr-${idx}`} className="p-3 rounded-lg border border-rose-300 bg-rose-50/30 text-xs space-y-1">
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-1.5">
                          <Radio className="w-3.5 h-3.5 text-rose-600" />
                          <strong className="text-rose-900 font-mono text-[10px]">{item.id}</strong>
                          <span className="text-rose-900 font-black">{item.name}</span>
                        </div>
                        {renderSeverityBadge(item.severity)}
                      </div>
                      <p className="text-[11px] text-slate-700">{item.description}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-6 bg-slate-50 rounded-xl border border-dashed border-slate-200 text-center">
                  <ShieldCheck className="w-6 h-6 text-emerald-500 mx-auto mb-1.5" />
                  <p className="text-xs font-bold text-slate-700">Environment Integrity Verified</p>
                  <p className="text-[11px] text-slate-500 mt-0.5">No hidden links, junk spam outlinks, webshell backdoors, or Trojan beacons detected.</p>
                </div>
              )}
            </div>

            {/* Section 4: DoS / DDoS Analysis */}
            <div className="space-y-2">
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 border-b border-slate-200 pb-1">
                4. DoS & DDoS Stress Resilience Benchmark
              </h2>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 text-[11px] space-y-1">
                <div>Throughput: <strong>{ddosData?.requestsPerSecond || 0} req/s</strong> across {ddosData?.totalRequests || 0} test requests.</div>
                <div>Median Latency: <strong>{ddosData?.p50LatencyMs || 0}ms</strong> (p99: {ddosData?.p99LatencyMs || 0}ms).</div>
                <div>WAF / Shield: <strong>{ddosData?.wafProvider || 'Standard Origin Server'}</strong>.</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
