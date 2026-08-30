import {
  SecurityIndicator,
  ThreatIntelSourceResult,
} from "@/lib/types/security";

/**
 * Real Threat Intelligence Client
 * Interfaces with VirusTotal v3 and Google Safe Browsing v4 with zero data fabrication
 */
export class ThreatIntelligenceService {
  /**
   * Checks a file's SHA-256 hash against VirusTotal.
   * Privacy Note: Queries hash reputation only; does NOT upload user files.
   */
  public static async checkFileHash(
    sha256: string
  ): Promise<{
    intelResult: ThreatIntelSourceResult;
    indicators: SecurityIndicator[];
  }> {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey || apiKey.trim() === "") {
      return {
        intelResult: {
          name: "VirusTotal File Hash Lookup",
          status: "UNAVAILABLE",
          details: "VirusTotal API key not configured in environment.",
        },
        indicators: [],
      };
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(
        `https://www.virustotal.com/api/v3/files/${sha256}`,
        {
          headers: {
            "x-apikey": apiKey.trim(),
            Accept: "application/json",
          },
          signal: controller.signal,
        }
      );
      clearTimeout(timeoutId);

      if (response.status === 404) {
        return {
          intelResult: {
            name: "VirusTotal File Hash Lookup",
            status: "CHECKED_CLEAN",
            details: "File hash unknown to VirusTotal catalog (0 historical detections).",
            positives: 0,
            total: 0,
          },
          indicators: [
            {
              id: "vt.file.unknown",
              title: "No Previous VirusTotal Threat Records",
              description: "Hash has not been reported as known malware in VirusTotal database.",
              severity: "LOW",
              weight: 0,
              confidence: 0.7,
              category: "informational",
              source: "VirusTotal",
            },
          ],
        };
      }

      if (!response.ok) {
        return {
          intelResult: {
            name: "VirusTotal File Hash Lookup",
            status: "UNAVAILABLE",
            details: `VirusTotal returned status ${response.status}: ${response.statusText}`,
          },
          indicators: [],
        };
      }

      const json = await response.json();
      const stats = json?.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = stats.harmless || 0;
      const undetected = stats.undetected || 0;
      const total = malicious + suspicious + harmless + undetected;

      const detectedThreats: string[] = [];
      const analysisResults = json?.data?.attributes?.last_analysis_results || {};
      for (const [engine, res] of Object.entries(analysisResults)) {
        const item = res as { category?: string; result?: string };
        if (item.category === "malicious" && item.result) {
          detectedThreats.push(`${engine}: ${item.result}`);
        }
      }

      const indicators: SecurityIndicator[] = [];

      if (malicious > 0 || suspicious > 0) {
        const isCritical = malicious >= 5;
        indicators.push({
          id: "vt.file.malicious",
          title: `VirusTotal Flagged by ${malicious + suspicious}/${total} Engines`,
          description: `Identified as potentially malicious by ${malicious} security engine(s) and suspicious by ${suspicious} engine(s). Threats: ${detectedThreats.slice(0, 3).join(", ") || "Generic malware"}`,
          severity: isCritical ? "CRITICAL" : "HIGH",
          weight: isCritical ? 40 : 25,
          confidence: Math.min(1.0, 0.6 + (malicious / 10) * 0.4),
          category: "threat_intelligence",
          source: "VirusTotal",
        });

        return {
          intelResult: {
            name: "VirusTotal File Hash Lookup",
            status: "THREAT_DETECTED",
            details: `${malicious}/${total} security vendors flagged this hash as malicious.`,
            positives: malicious + suspicious,
            total,
            detectedThreats: detectedThreats.slice(0, 8),
          },
          indicators,
        };
      }

      // Hash has been analyzed and confirmed clean by engines
      if (harmless + undetected > 0) {
        indicators.push({
          id: "vt.file.clean",
          title: `VirusTotal Clean Verdict (${undetected + harmless}/${total} Engines)`,
          description: `All ${total} scanning engines analyzed this hash with 0 malicious flags.`,
          severity: "LOW",
          weight: 15,
          confidence: 0.9,
          category: "threat_intelligence",
          source: "VirusTotal",
          mitigating: true, // Deducts risk because known clean
        });
      }

      return {
        intelResult: {
          name: "VirusTotal File Hash Lookup",
          status: "CHECKED_CLEAN",
          details: `Analyzed by ${total} security vendors with 0 detections.`,
          positives: 0,
          total,
        },
        indicators,
      };
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Unknown error";
      return {
        intelResult: {
          name: "VirusTotal File Hash Lookup",
          status: "UNAVAILABLE",
          details: `Lookup failed: ${errMsg}`,
        },
        indicators: [],
      };
    }
  }

  /**
   * Checks a URL against Google Safe Browsing API v4.
   */
  public static async checkGoogleSafeBrowsing(
    targetUrl: string
  ): Promise<{
    intelResult: ThreatIntelSourceResult;
    indicators: SecurityIndicator[];
  }> {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!apiKey || apiKey.trim() === "") {
      return {
        intelResult: {
          name: "Google Safe Browsing",
          status: "UNAVAILABLE",
          details: "Google Safe Browsing API key not configured.",
        },
        indicators: [],
      };
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const requestBody = {
        client: {
          clientId: "sentinelx-ai",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: targetUrl }],
        },
      };

      const response = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey.trim()}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(requestBody),
          signal: controller.signal,
        }
      );
      clearTimeout(timeoutId);

      if (!response.ok) {
        return {
          intelResult: {
            name: "Google Safe Browsing",
            status: "UNAVAILABLE",
            details: `Safe Browsing returned HTTP ${response.status}`,
          },
          indicators: [],
        };
      }

      const data = await response.json();
      const matches = data.matches || [];

      if (matches.length > 0) {
        const threatTypes = matches.map((m: { threatType: string }) => m.threatType);
        const uniqueThreats = Array.from(new Set(threatTypes)) as string[];

        const indicators: SecurityIndicator[] = [
          {
            id: "gsb.threat.detected",
            title: `Google Safe Browsing Match: ${uniqueThreats.join(", ")}`,
            description: `Google Safe Browsing lists this URL as an active threat source (${uniqueThreats.join(", ")}).`,
            severity: "CRITICAL",
            weight: 40,
            confidence: 0.95,
            category: "threat_intelligence",
            source: "Google Safe Browsing",
          },
        ];

        return {
          intelResult: {
            name: "Google Safe Browsing",
            status: "THREAT_DETECTED",
            details: `Threat list match: ${uniqueThreats.join(", ")}`,
            detectedThreats: uniqueThreats,
          },
          indicators,
        };
      }

      return {
        intelResult: {
          name: "Google Safe Browsing",
          status: "CHECKED_CLEAN",
          details: "No match found in active threat lists.",
        },
        indicators: [],
      };
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Unknown error";
      return {
        intelResult: {
          name: "Google Safe Browsing",
          status: "UNAVAILABLE",
          details: `Check failed: ${errMsg}`,
        },
        indicators: [],
      };
    }
  }

  /**
   * Checks a URL against VirusTotal v3.
   */
  public static async checkVirusTotalUrl(
    targetUrl: string
  ): Promise<{
    intelResult: ThreatIntelSourceResult;
    indicators: SecurityIndicator[];
  }> {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey || apiKey.trim() === "") {
      return {
        intelResult: {
          name: "VirusTotal URL Scanner",
          status: "UNAVAILABLE",
          details: "VirusTotal API key not configured.",
        },
        indicators: [],
      };
    }

    try {
      // VirusTotal URL identifier is base64url encoded without padding
      const urlId = Buffer.from(targetUrl)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(
        `https://www.virustotal.com/api/v3/urls/${urlId}`,
        {
          headers: {
            "x-apikey": apiKey.trim(),
            Accept: "application/json",
          },
          signal: controller.signal,
        }
      );
      clearTimeout(timeoutId);

      if (response.status === 404) {
        return {
          intelResult: {
            name: "VirusTotal URL Scanner",
            status: "CHECKED_CLEAN",
            details: "URL unlisted in VirusTotal catalog (0 historical detections).",
            positives: 0,
            total: 0,
          },
          indicators: [],
        };
      }

      if (!response.ok) {
        return {
          intelResult: {
            name: "VirusTotal URL Scanner",
            status: "UNAVAILABLE",
            details: `VirusTotal returned status ${response.status}`,
          },
          indicators: [],
        };
      }

      const json = await response.json();
      const stats = json?.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = stats.harmless || 0;
      const undetected = stats.undetected || 0;
      const total = malicious + suspicious + harmless + undetected;

      const detectedThreats: string[] = [];
      const analysisResults = json?.data?.attributes?.last_analysis_results || {};
      for (const [engine, res] of Object.entries(analysisResults)) {
        const item = res as { category?: string; result?: string };
        if (item.category === "malicious" && item.result) {
          detectedThreats.push(`${engine}: ${item.result}`);
        }
      }

      const indicators: SecurityIndicator[] = [];

      if (malicious > 0 || suspicious > 0) {
        const isCritical = malicious >= 3;
        indicators.push({
          id: "vt.url.malicious",
          title: `VirusTotal Flagged URL (${malicious + suspicious}/${total} Engines)`,
          description: `${malicious} engine(s) classified this URL as malicious. Threats: ${detectedThreats.slice(0, 3).join(", ") || "Phishing/Malware"}`,
          severity: isCritical ? "CRITICAL" : "HIGH",
          weight: isCritical ? 40 : 25,
          confidence: Math.min(1.0, 0.65 + (malicious / 5) * 0.35),
          category: "threat_intelligence",
          source: "VirusTotal",
        });

        return {
          intelResult: {
            name: "VirusTotal URL Scanner",
            status: "THREAT_DETECTED",
            details: `${malicious}/${total} security engines detected malicious content on this URL.`,
            positives: malicious + suspicious,
            total,
            detectedThreats: detectedThreats.slice(0, 6),
          },
          indicators,
        };
      }

      return {
        intelResult: {
          name: "VirusTotal URL Scanner",
          status: "CHECKED_CLEAN",
          details: `Clean verdict across ${total} scanning engines.`,
          positives: 0,
          total,
        },
        indicators: [],
      };
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Unknown error";
      return {
        intelResult: {
          name: "VirusTotal URL Scanner",
          status: "UNAVAILABLE",
          details: `URL lookup failed: ${errMsg}`,
        },
        indicators: [],
      };
    }
  }
}
