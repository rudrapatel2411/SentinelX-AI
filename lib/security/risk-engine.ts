import {
  SecurityIndicator,
  RiskClassification,
  RiskFactorBreakdown,
  IndicatorCategory,
} from "@/lib/types/security";
import crypto from "crypto";

export interface RiskEvaluationResult {
  riskScore: number;
  classification: RiskClassification;
  confidence: number;
  confidenceLabel: "High" | "Medium" | "Low";
  riskFactors: RiskFactorBreakdown[];
  effectiveScore: number;
}

const CATEGORY_NAMES: Record<IndicatorCategory, string> = {
  threat_intelligence: "Threat Intelligence",
  brand_impersonation: "Brand Impersonation",
  credential_harvesting: "Credential Harvesting",
  active_content: "Active & Executable Content",
  suspicious_structure: "Structural Anomalies",
  financial_request: "Financial & Payment Requests",
  urgency_threat: "Urgency & Coercion",
  reputation: "Reputation & Age",
  informational: "Informational Telemetry",
  general: "General Risk Indicators",
};

/**
 * Global Deterministic Risk Engine
 * 
 * Aggregates weighted security indicators with category diminishing-returns
 * to prevent double/triple-counting of correlated findings.
 */
export class RiskEngine {
  /**
   * Generates a standardized Analysis ID in the format: SX-YYYYMMDD-XXXXXX
   */
  public static generateAnalysisId(): string {
    const now = new Date();
    const yyyy = now.getFullYear();
    const mm = String(now.getMonth() + 1).padStart(2, "0");
    const dd = String(now.getDate()).padStart(2, "0");
    const randSuffix = crypto.randomBytes(3).toString("hex").toUpperCase();
    return `SX-${yyyy}${mm}${dd}-${randSuffix}`;
  }

  /**
   * Evaluates a collection of indicators and returns deterministic score,
   * classification, confidence, and category breakdown.
   */
  public static evaluate(indicators: SecurityIndicator[]): RiskEvaluationResult {
    if (!indicators || indicators.length === 0) {
      return {
        riskScore: 0,
        classification: "SAFE",
        confidence: 0.8,
        confidenceLabel: "High",
        riskFactors: [],
        effectiveScore: 0,
      };
    }

    // Group indicators by category
    const categoryGroups = new Map<IndicatorCategory, SecurityIndicator[]>();
    for (const ind of indicators) {
      if (!categoryGroups.has(ind.category)) {
        categoryGroups.set(ind.category, []);
      }
      categoryGroups.get(ind.category)!.push(ind);
    }

    let totalRawScore = 0;
    const riskFactors: RiskFactorBreakdown[] = [];

    // Calculate score per category using diminishing returns
    for (const [category, items] of categoryGroups.entries()) {
      if (category === "informational") {
        continue; // Informational indicators don't contribute risk
      }

      // Sort by weight descending so most severe items count first
      const sortedItems = [...items].sort((a, b) => {
        const aVal = a.mitigating ? -a.weight : a.weight;
        const bVal = b.mitigating ? -b.weight : b.weight;
        return bVal - aVal;
      });

      let categoryScore = 0;
      for (let i = 0; i < sortedItems.length; i++) {
        const item = sortedItems[i];
        // Diminishing returns factor: 1st item 100%, 2nd item 40%, 3rd+ items 15%
        let factor = 1.0;
        if (i === 1) factor = 0.4;
        else if (i > 1) factor = 0.15;

        // Apply item weight multiplied by confidence
        const itemEffectiveWeight = item.weight * (item.confidence || 1.0);
        if (item.mitigating) {
          // Mitigations reduce risk
          categoryScore -= itemEffectiveWeight * factor;
        } else {
          categoryScore += itemEffectiveWeight * factor;
        }
      }

      const clampedCategoryScore = Math.max(0, Math.round(categoryScore));
      if (clampedCategoryScore > 0 || items.some((it) => !it.mitigating && it.weight > 0)) {
        riskFactors.push({
          category,
          categoryName: CATEGORY_NAMES[category] || category,
          scoreContribution: clampedCategoryScore,
          indicatorCount: items.length,
        });
      }

      totalRawScore += categoryScore;
    }

    // Sort risk factors by contribution descending
    riskFactors.sort((a, b) => b.scoreContribution - a.scoreContribution);

    // Final score clamped strictly between 0 and 100
    const finalScore = Math.min(100, Math.max(0, Math.round(totalRawScore)));

    // Classification boundaries:
    // 0 - 29: SAFE
    // 30 - 69: SUSPICIOUS
    // 70 - 100: DANGEROUS
    let classification: RiskClassification = "SAFE";
    if (finalScore >= 70) {
      classification = "DANGEROUS";
    } else if (finalScore >= 30) {
      classification = "SUSPICIOUS";
    } else {
      classification = "SAFE";
    }

    // Calculate confidence based on evidence quality
    let confidenceVal = 0.75;
    const hasCriticalOrHigh = indicators.some(
      (i) => (i.severity === "CRITICAL" || i.severity === "HIGH") && i.confidence >= 0.8
    );
    const hasMultipleSources = new Set(indicators.map((i) => i.source)).size >= 2;
    const hasThreatIntelHit = indicators.some(
      (i) => i.category === "threat_intelligence" && !i.mitigating && i.weight > 0
    );

    if (hasThreatIntelHit || (hasCriticalOrHigh && hasMultipleSources)) {
      confidenceVal = 0.95;
    } else if (hasCriticalOrHigh || indicators.length >= 3) {
      confidenceVal = 0.85;
    } else if (indicators.length === 0) {
      confidenceVal = 0.7;
    } else {
      confidenceVal = 0.8;
    }

    let confidenceLabel: "High" | "Medium" | "Low" = "Medium";
    if (confidenceVal >= 0.85) confidenceLabel = "High";
    else if (confidenceVal >= 0.65) confidenceLabel = "Medium";
    else confidenceLabel = "Low";

    return {
      riskScore: finalScore,
      classification,
      confidence: confidenceVal,
      confidenceLabel,
      riskFactors,
      effectiveScore: finalScore,
    };
  }
}
