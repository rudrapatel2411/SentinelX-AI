import {
  SecurityIndicator,
  CommonAnalysisResult,
  ThreatIntelSourceResult,
} from "@/lib/types/security";
import { PROTECTED_BRANDS, ProtectedBrand } from "@/lib/config/protected-brands";
import { RiskEngine } from "@/lib/security/risk-engine";
import { ThreatIntelligenceService } from "@/lib/security/threat-intelligence";
import { AIService } from "@/lib/ai/openai";

// High-abuse TLDs according to Spamhaus/APWG threat telemetry
const HIGH_ABUSE_TLDS = new Set([
  "xyz",
  "top",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "click",
  "buzz",
  "fit",
  "rest",
  "work",
  "loan",
  "cam",
  "icu",
  "monster",
]);

// High-risk path segments commonly used in credential phishing
const CREDENTIAL_PATHS = [
  /login/i,
  /signin/i,
  /sign-in/i,
  /verify/i,
  /verification/i,
  /account-update/i,
  /update-billing/i,
  /security-check/i,
  /kyc/i,
  /authenticate/i,
  /webscr/i,
  /wallet-connect/i,
  /otp/i,
  /password-reset/i,
];

// Top known legitimate high-traffic root domains for risk mitigation
const KNOWN_BENIGN_ROOTS = new Set([
  "google.com",
  "youtube.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "github.com",
  "wikipedia.org",
  "linkedin.com",
  "netflix.com",
  "cloudflare.com",
  "paypal.com",
  "sbi.co.in",
  "hdfcbank.com",
  "icicibank.com",
]);

/**
 * Calculates Levenshtein edit distance between two strings
 */
function levenshteinDistance(a: string, b: string): number {
  const an = a ? a.length : 0;
  const bn = b ? b.length : 0;
  if (an === 0) return bn;
  if (bn === 0) return an;
  const matrix = Array.from({ length: bn + 1 }, () => new Array(an + 1).fill(0));
  for (let i = 0; i <= an; ++i) matrix[0][i] = i;
  for (let i = 0; i <= bn; ++i) matrix[i][0] = i;
  for (let i = 1; i <= bn; ++i) {
    for (let j = 1; j <= an; ++j) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[bn][an];
}

export class UrlAnalyzer {
  /**
   * Performs full deterministic inspection + threat intel + risk calculation + AI explanation
   */
  public static async analyze(targetUrlString: string): Promise<CommonAnalysisResult> {
    const analysisId = RiskEngine.generateAnalysisId();
    const createdAt = new Date().toISOString();
    const indicators: SecurityIndicator[] = [];
    const threatIntelResults: ThreatIntelSourceResult[] = [];

    // Normalize URL
    let sanitizedUrl = targetUrlString.trim();
    if (!/^https?:\/\//i.test(sanitizedUrl)) {
      sanitizedUrl = `https://${sanitizedUrl}`;
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(sanitizedUrl);
    } catch {
      // Malformed URL
      indicators.push({
        id: "url.syntax.malformed",
        title: "Malformed URL Syntax",
        description: "The provided string cannot be parsed as a standard RFC 3986 URL.",
        severity: "HIGH",
        weight: 25,
        confidence: 0.95,
        category: "suspicious_structure",
        source: "SentinelX URL Engine",
      });

      const riskEval = RiskEngine.evaluate(indicators);
      return {
        id: analysisId,
        type: "url",
        target: targetUrlString,
        riskScore: riskEval.riskScore,
        classification: riskEval.classification,
        confidence: riskEval.confidence,
        confidenceLabel: riskEval.confidenceLabel,
        indicators,
        riskFactors: riskEval.riskFactors,
        threatIntel: threatIntelResults,
        aiExplanation: {
          summary: "Invalid or malformed URL syntax.",
          threatCategory: "Syntax Anomaly",
          reasons: ["The input could not be parsed into a valid hostname and protocol."],
          recommendedAction: "Do not attempt to open this URL.",
          aiWritingLikelihood: null,
          available: false,
        },
        recommendations: [
          "Do not click or load malformed URLs.",
          "Verify the original source of the link.",
        ],
        createdAt,
        metadata: { rawInput: targetUrlString, parsed: false },
      };
    }

    const protocol = parsedUrl.protocol.toLowerCase();
    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname;
    const search = parsedUrl.search;
    const port = parsedUrl.port;

    // 1. Protocol Inspection (HTTPS vs HTTP)
    if (protocol === "https:") {
      indicators.push({
        id: "url.protocol.https",
        title: "Encrypted Transport (HTTPS)",
        description: "Communication is encrypted using TLS. Note: HTTPS indicates encryption only, NOT website legitimacy.",
        severity: "LOW",
        weight: 0, // HTTPS does not reduce malicious risk
        confidence: 1.0,
        category: "informational",
        source: "SentinelX URL Engine",
      });
    } else if (protocol === "http:") {
      indicators.push({
        id: "url.protocol.http_unencrypted",
        title: "Unencrypted Protocol (HTTP Plaintext)",
        description: "Traffic is transmitted in cleartext without SSL/TLS encryption, exposing credentials to interception.",
        severity: "MEDIUM",
        weight: 15,
        confidence: 1.0,
        category: "credential_harvesting",
        source: "SentinelX URL Engine",
      });
    } else {
      indicators.push({
        id: "url.protocol.unusual",
        title: `Unusual URL Scheme (${protocol})`,
        description: `URL uses non-standard web protocol: ${protocol}`,
        severity: "HIGH",
        weight: 25,
        confidence: 0.9,
        category: "suspicious_structure",
        source: "SentinelX URL Engine",
      });
    }

    // 2. IP Address Hostname Detection
    const isIpV4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const isIpV6 = hostname.startsWith("[") && hostname.endsWith("]");
    if (isIpV4 || isIpV6) {
      indicators.push({
        id: "url.host.ip_address",
        title: "Direct IP Address Hostname",
        description: `URL uses a raw IP address (${hostname}) instead of a registered domain name, common in phishing and C2 servers.`,
        severity: "HIGH",
        weight: 25,
        confidence: 0.95,
        category: "suspicious_structure",
        source: "SentinelX URL Engine",
      });
    }

    // 3. Punycode / Internationalized Domain Name (IDN) Homograph Attack
    if (hostname.includes("xn--") || /[^\u0000-\u007F]/.test(hostname)) {
      indicators.push({
        id: "url.host.punycode_homograph",
        title: "Punycode / Homograph Character Encoding Detected",
        description: `Domain contains non-ASCII or Punycode encoding (${hostname}), often used to visually impersonate legitimate brand names.`,
        severity: "HIGH",
        weight: 25,
        confidence: 0.9,
        category: "brand_impersonation",
        source: "SentinelX URL Engine",
      });
    }

    // 4. Excessive Subdomains (Domain fronting / sub-domain chaining)
    const hostParts = hostname.split(".");
    if (hostParts.length > 4 && !isIpV4) {
      indicators.push({
        id: "url.host.excessive_subdomains",
        title: `Excessive Subdomain Depth (${hostParts.length} levels)`,
        description: `Domain contains ${hostParts.length} levels (${hostname}), a technique used to obscure the true apex domain.`,
        severity: "MEDIUM",
        weight: 15,
        confidence: 0.8,
        category: "suspicious_structure",
        source: "SentinelX URL Engine",
      });
    }

    // 5. TLD Reputation Check
    const tld = hostParts[hostParts.length - 1];
    if (HIGH_ABUSE_TLDS.has(tld)) {
      indicators.push({
        id: "url.tld.high_abuse",
        title: `High-Abuse Top-Level Domain (.${tld})`,
        description: `The .${tld} TLD has statistically higher rates of spam and phishing registrations. Evaluated with other indicators.`,
        severity: "LOW",
        weight: 5,
        confidence: 0.7,
        category: "reputation",
        source: "SentinelX URL Engine",
      });
    }

    // 6. Brand Impersonation & Lookalike Detection
    let isLegitimateBrand = false;
    const fullUrlLower = parsedUrl.href.toLowerCase();

    for (const brand of PROTECTED_BRANDS) {
      // Check if domain is genuinely owned by this brand
      const isOfficialDomain = brand.domains.some((d) => hostname === d || hostname.endsWith(`.${d}`));
      if (isOfficialDomain) {
        isLegitimateBrand = true;
        indicators.push({
          id: `url.brand.official_${brand.name.toLowerCase().replace(/[^a-z0-9]/g, "_")}`,
          title: `Verified Official Domain (${brand.name})`,
          description: `Hostname matches the registered authoritative infrastructure for ${brand.name}.`,
          severity: "LOW",
          weight: 20,
          confidence: 0.95,
          category: "reputation",
          source: "SentinelX URL Engine",
          mitigating: true, // Deducts risk
        });
        break;
      }

      // Check for Brand Keywords in Subdomains or Path
      const keywordMatch = brand.keywords.find((kw) => hostname.includes(kw) || fullUrlLower.includes(kw));
      if (keywordMatch) {
        indicators.push({
          id: `url.brand.spoof_${brand.name.toLowerCase().replace(/[^a-z0-9]/g, "_")}`,
          title: `Potential Brand Impersonation: ${brand.name}`,
          description: `Domain or path contains high-affinity keyword '${keywordMatch}' targeting ${brand.name} but does not resolve to its official domain (${brand.domains[0]}).`,
          severity: "HIGH",
          weight: 25,
          confidence: 0.85,
          category: "brand_impersonation",
          source: "SentinelX URL Engine",
        });
      }

      // Check Levenshtein distance on domain labels
      const domainWithoutTld = hostParts.slice(0, -1).join(".");
      for (const officialDomain of brand.domains) {
        const officialRoot = officialDomain.split(".")[0];
        const dist = levenshteinDistance(domainWithoutTld, officialRoot);
        if (dist > 0 && dist <= 2 && domainWithoutTld.length >= 4) {
          indicators.push({
            id: `url.brand.typosquat_${brand.name.toLowerCase().replace(/[^a-z0-9]/g, "_")}`,
            title: `Potential Typosquatting of ${brand.name}`,
            description: `Domain name '${domainWithoutTld}' is visually and orthographically very close (edit distance ${dist}) to '${officialRoot}'.`,
            severity: "HIGH",
            weight: 25,
            confidence: 0.85,
            category: "brand_impersonation",
            source: "SentinelX URL Engine",
          });
          break;
        }
      }
    }

    // 7. Known Benign Root Mitigation
    if (!isLegitimateBrand) {
      const rootDomain = hostParts.slice(-2).join(".");
      if (KNOWN_BENIGN_ROOTS.has(rootDomain)) {
        indicators.push({
          id: "url.reputation.known_benign_root",
          title: `High-Reputation Root Domain (${rootDomain})`,
          description: `Domain belongs to a globally established top-tier infrastructure provider.`,
          severity: "LOW",
          weight: 15,
          confidence: 0.9,
          category: "reputation",
          source: "SentinelX URL Engine",
          mitigating: true,
        });
      }
    }

    // 8. Credential Harvesting Path Patterns
    const pathAndQuery = `${pathname}${search}`;
    for (const pattern of CREDENTIAL_PATHS) {
      if (pattern.test(pathAndQuery)) {
        indicators.push({
          id: "url.path.credential_harvesting_pattern",
          title: "Sensitive Authentication / Account Action Path",
          description: `URL path or parameters target account authentication or sensitive credentials ('${pathAndQuery.slice(0, 45)}').`,
          severity: "MEDIUM",
          weight: 15,
          confidence: 0.8,
          category: "credential_harvesting",
          source: "SentinelX URL Engine",
        });
        break;
      }
    }

    // 9. Non-standard Port
    if (port && port !== "80" && port !== "443" && port !== "8080") {
      indicators.push({
        id: "url.port.non_standard",
        title: `Non-Standard Network Port (:${port})`,
        description: `URL directs traffic through port ${port}, an uncommon configuration for legitimate public services.`,
        severity: "MEDIUM",
        weight: 15,
        confidence: 0.85,
        category: "suspicious_structure",
        source: "SentinelX URL Engine",
      });
    }

    // 10. Query String Obfuscation (Base64 strings, redirect chains)
    if (search.length > 80 && /[A-Za-z0-9+/=]{40,}/.test(search)) {
      indicators.push({
        id: "url.query.encoded_payload",
        title: "Base64 / Encoded Query Payload Detected",
        description: "URL parameters contain high-density encoded strings often used to pass obfuscated redirects or harvested data.",
        severity: "MEDIUM",
        weight: 15,
        confidence: 0.8,
        category: "suspicious_structure",
        source: "SentinelX URL Engine",
      });
    }

    // 11. Real Threat Intelligence Lookups (VirusTotal + Google Safe Browsing)
    const [vtResult, gsbResult] = await Promise.all([
      ThreatIntelligenceService.checkVirusTotalUrl(parsedUrl.href),
      ThreatIntelligenceService.checkGoogleSafeBrowsing(parsedUrl.href),
    ]);

    threatIntelResults.push(vtResult.intelResult, gsbResult.intelResult);
    indicators.push(...vtResult.indicators, ...gsbResult.indicators);

    // 12. Evaluate Deterministic Risk Engine
    const riskEval = RiskEngine.evaluate(indicators);

    // 13. Generate AI Explanation (AI does NOT modify riskScore)
    const aiResult = await AIService.generateExplanation({
      type: "url",
      target: parsedUrl.href,
      riskScore: riskEval.riskScore,
      classification: riskEval.classification,
      indicators,
      threatIntel: threatIntelResults,
      metadata: {
        protocol,
        hostname,
        pathname,
        port,
        isIpAddress: isIpV4 || isIpV6,
      },
    });

    // 14. Actionable Recommendations
    const recommendations: string[] = [];
    if (riskEval.classification === "DANGEROUS") {
      recommendations.push("🚫 Do NOT open this URL or click links leading to it.");
      recommendations.push("🚫 Do NOT submit passwords, personal data, or payment card details.");
      recommendations.push("🛡️ If you already entered credentials, immediately change your password on the official website.");
    } else if (riskEval.classification === "SUSPICIOUS") {
      recommendations.push("⚠️ Exercise extreme caution before interacting with this website.");
      recommendations.push("🔍 Verify the true domain name and ensure it matches the official service.");
      recommendations.push("🔒 Avoid downloading files or entering sensitive credentials.");
    } else {
      recommendations.push("✅ No known threats were detected in the performed checks.");
      recommendations.push("💡 Always verify the address bar before entering confidential information.");
    }

    return {
      id: analysisId,
      type: "url",
      target: parsedUrl.href,
      riskScore: riskEval.riskScore,
      classification: riskEval.classification,
      confidence: riskEval.confidence,
      confidenceLabel: riskEval.confidenceLabel,
      indicators,
      riskFactors: riskEval.riskFactors,
      threatIntel: threatIntelResults,
      aiExplanation: aiResult,
      recommendations,
      createdAt,
      metadata: {
        protocol,
        hostname,
        pathname,
        search: search ? `${search.slice(0, 60)}...` : "",
        tld,
        port: port || (protocol === "https:" ? "443" : "80"),
        isIpHost: isIpV4 || isIpV6,
      },
    };
  }
}
