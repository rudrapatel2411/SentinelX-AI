export type RiskClassification = "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "UNKNOWN";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type IndicatorCategory =
  | "threat_intelligence"
  | "brand_impersonation"
  | "credential_harvesting"
  | "active_content"
  | "suspicious_structure"
  | "financial_request"
  | "urgency_threat"
  | "reputation"
  | "informational"
  | "general";

export interface SecurityIndicator {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  weight: number; // Base weight (e.g. CRITICAL: 40, HIGH: 25, MED: 15, LOW: 5)
  confidence: number; // 0.0 - 1.0
  category: IndicatorCategory;
  source: string; // e.g., "VirusTotal", "Google Safe Browsing", "SentinelX PDF Analyzer"
  mitigating?: boolean; // If true, deducts risk
}

export type ThreatIntelStatus =
  | "CHECKED_CLEAN"
  | "THREAT_DETECTED"
  | "UNAVAILABLE"
  | "SKIPPED";

export interface ThreatIntelSourceResult {
  name: string;
  status: ThreatIntelStatus;
  details?: string;
  positives?: number;
  total?: number;
  detectedThreats?: string[];
  scanDate?: string;
}

export interface RiskFactorBreakdown {
  category: IndicatorCategory;
  categoryName: string;
  scoreContribution: number;
  indicatorCount: number;
}

export interface AIExplanationResult {
  summary: string;
  threatCategory: string;
  reasons: string[];
  recommendedAction: string;
  aiWritingLikelihood: number | null;
  aiWritingReasoning?: string | null;
  available: boolean;
}

export interface CommonAnalysisResult {
  id: string; // Format: SX-YYYYMMDD-XXXXXX
  type: "file" | "message" | "url";
  target: string; // File name, URL string, or message excerpt
  riskScore: number; // 0 - 100
  classification: RiskClassification;
  confidence: number; // 0.0 - 1.0 (High, Medium, Low)
  confidenceLabel: "High" | "Medium" | "Low";
  indicators: SecurityIndicator[];
  riskFactors: RiskFactorBreakdown[];
  threatIntel: ThreatIntelSourceResult[];
  aiExplanation: AIExplanationResult;
  recommendations: string[];
  createdAt: string;
  metadata: Record<string, unknown>;
  persistenceStatus?: "SAVED" | "DATABASE_OFFLINE";
}

export interface FileMetadata {
  fileName: string;
  fileSize: number;
  fileSizeFormatted: string;
  detectedMimeType: string;
  declaredExtension: string;
  isExtensionSpoofed: boolean;
  sha256: string;
  sha1: string;
  md5: string;
  magicBytesHex: string;
}

export interface ExtractedEntity {
  type: "url" | "phone" | "email" | "upi" | "crypto" | "money_amount";
  value: string;
  raw?: string;
}
