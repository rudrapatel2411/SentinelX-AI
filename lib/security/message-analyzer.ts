import {
  CommonAnalysisResult,
  SecurityIndicator,
} from "@/lib/types/security";
import { MessageRulesEngine } from "@/lib/security/message-rules";
import { RiskEngine } from "@/lib/security/risk-engine";
import { AIService } from "@/lib/ai/openai";
import { PROTECTED_BRANDS } from "@/lib/config/protected-brands";

export class MessageAnalyzer {
  /**
   * Evaluates text messages (SMS, WhatsApp, Telegram, Email, Discord, etc.)
   * Performs entity extraction, scam rules, correlation, risk evaluation, and AI explanation.
   */
  public static async analyze(rawText: string): Promise<CommonAnalysisResult> {
    const analysisId = RiskEngine.generateAnalysisId();
    const createdAt = new Date().toISOString();
    const text = rawText.trim();

    if (!text || text.length === 0) {
      const riskEval = RiskEngine.evaluate([]);
      return {
        id: analysisId,
        type: "message",
        target: "(Empty message)",
        riskScore: 0,
        classification: "SAFE",
        confidence: 0.8,
        confidenceLabel: "High",
        indicators: [],
        riskFactors: [],
        threatIntel: [],
        aiExplanation: {
          summary: "No text provided for analysis.",
          threatCategory: "Empty Input",
          reasons: ["Empty message string provided."],
          recommendedAction: "Provide message content to analyze.",
          aiWritingLikelihood: null,
          available: false,
        },
        recommendations: ["Submit non-empty message content for inspection."],
        createdAt,
        metadata: { entities: [] },
      };
    }

    // 1. Extract digital entities (URLs, emails, phones, UPIs, crypto, amounts)
    const entities = MessageRulesEngine.extractEntities(text);

    // 2. Evaluate deterministic scam rules
    const indicators: SecurityIndicator[] = MessageRulesEngine.evaluateScamRules(text, entities);

    // 3. Inspect extracted URLs for obvious brand mismatches
    const extractedUrls = entities.filter((e) => e.type === "url");
    for (const urlEntity of extractedUrls) {
      try {
        const parsed = new URL(urlEntity.value);
        const host = parsed.hostname.toLowerCase();
        for (const brand of PROTECTED_BRANDS) {
          const isOfficial = brand.domains.some((d) => host === d || host.endsWith(`.${d}`));
          const hasKeyword = brand.keywords.some((kw) => host.includes(kw));
          if (hasKeyword && !isOfficial) {
            indicators.push({
              id: `msg.url.impersonation_${brand.name.toLowerCase().replace(/[^a-z0-9]/g, "_")}`,
              title: `Extracted Link Impersonates ${brand.name}`,
              description: `URL embedded in message ('${urlEntity.value}') contains ${brand.name} branding keywords but does not match official domain.`,
              severity: "CRITICAL",
              weight: 35,
              confidence: 0.9,
              category: "brand_impersonation",
              source: "SentinelX Message Rules",
            });
          }
        }
      } catch {
        // malformed URL
      }
    }

    // If clean text with no threat indicators
    if (indicators.length === 0) {
      indicators.push({
        id: "msg.clean.no_threat_patterns",
        title: "No Common Scam / Phishing Patterns Detected",
        description: "Message text does not trigger known banking urgency, lottery, courier, or credential-theft signatures.",
        severity: "LOW",
        weight: 0,
        confidence: 0.85,
        category: "informational",
        source: "SentinelX Message Rules",
      });
    }

    // 4. Run Deterministic Risk Engine (AI CANNOT MODIFY THIS)
    const riskEval = RiskEngine.evaluate(indicators);

    // 5. Generate AI Explanation & Linguistic Analysis
    const aiResult = await AIService.generateExplanation({
      type: "message",
      target: text.length > 120 ? `${text.slice(0, 117)}...` : text,
      riskScore: riskEval.riskScore,
      classification: riskEval.classification,
      indicators,
      rawContentForLinguisticAnalysis: text,
      metadata: {
        extractedEntitiesCount: entities.length,
        extractedUrls: extractedUrls.map((u) => u.value),
      },
    });

    // 6. Actionable recommendations
    const recommendations: string[] = [];
    if (riskEval.classification === "DANGEROUS") {
      recommendations.push("🚫 Do NOT click any links, call listed phone numbers, or reply to this sender.");
      recommendations.push("🔒 NEVER share OTPs, PINs, passwords, or KYC documents.");
      recommendations.push("🛡️ Block the sender and report the message as spam/phishing on your messaging app.");
      if (entities.some((e) => e.type === "upi" || e.type === "crypto")) {
        recommendations.push("💸 Do NOT send money or scan QR codes provided in this communication.");
      }
    } else if (riskEval.classification === "SUSPICIOUS") {
      recommendations.push("⚠️ Verify sender identity through an independent, official communication channel.");
      recommendations.push("🔍 If the message mentions a bank or delivery, log into their official app directly.");
      recommendations.push("⛔ Avoid acting on urgent deadlines until you have confirmed legitimacy.");
    } else {
      recommendations.push("✅ No obvious scam signatures were identified in this message.");
      recommendations.push("💡 As a general security practice, never share private credentials or OTPs.");
    }

    // Target excerpt for display
    const targetPreview = text.length > 90 ? `${text.slice(0, 87)}...` : text;

    return {
      id: analysisId,
      type: "message",
      target: targetPreview,
      riskScore: riskEval.riskScore,
      classification: riskEval.classification,
      confidence: riskEval.confidence,
      confidenceLabel: riskEval.confidenceLabel,
      indicators,
      riskFactors: riskEval.riskFactors,
      threatIntel: [],
      aiExplanation: aiResult,
      recommendations,
      createdAt,
      metadata: {
        fullTextLength: text.length,
        entities,
        extractedUrls: extractedUrls.map((u) => u.value),
        extractedPhones: entities.filter((e) => e.type === "phone").map((p) => p.value),
        extractedEmails: entities.filter((e) => e.type === "email").map((e) => e.value),
        extractedUpis: entities.filter((e) => e.type === "upi").map((u) => u.value),
        extractedAmounts: entities.filter((e) => e.type === "money_amount").map((m) => m.value),
      },
    };
  }
}
