import { ExtractedEntity, SecurityIndicator } from "@/lib/types/security";

export interface ScamRuleMatch {
  ruleId: string;
  category: string;
  indicator: SecurityIndicator;
}

export class MessageRulesEngine {
  /**
   * Extracts structural digital entities from unstructured text
   */
  public static extractEntities(text: string): ExtractedEntity[] {
    const entities: ExtractedEntity[] = [];

    // 1. URLs extraction
    const urlRegex = /(https?:\/\/[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|info|site|online|tech|co|in|cc|to|link|app)[^\s<>"]*)/gi;
    const urlMatches = text.match(urlRegex) || [];
    for (const rawUrl of Array.from(new Set(urlMatches))) {
      let normalized = rawUrl.replace(/[.,;!?)\]]+$/, ""); // trim trailing punctuation
      if (!/^https?:\/\//i.test(normalized)) {
        normalized = `https://${normalized}`;
      }
      entities.push({ type: "url", value: normalized, raw: rawUrl });
    }

    // 2. Email extraction
    const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
    const emailMatches = text.match(emailRegex) || [];
    for (const email of Array.from(new Set(emailMatches))) {
      entities.push({ type: "email", value: email.toLowerCase() });
    }

    // 3. Phone numbers (international, Indian, US formats)
    const phoneRegex = /(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}|\+91[-.\s]?[6-9]\d{9}/g;
    const phoneMatches = text.match(phoneRegex) || [];
    for (const phone of Array.from(new Set(phoneMatches))) {
      const clean = phone.trim();
      if (clean.replace(/\D/g, "").length >= 10 && clean.replace(/\D/g, "").length <= 13) {
        entities.push({ type: "phone", value: clean });
      }
    }

    // 4. UPI IDs (e.g., pay@okhdfcbank, user99@paytm, name@sbi)
    const upiRegex = /[a-zA-Z0-9.\-_]{2,256}@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|ibl|upi|apl|axl|federal|airtel|postbank)/gi;
    const upiMatches = text.match(upiRegex) || [];
    for (const upi of Array.from(new Set(upiMatches))) {
      entities.push({ type: "upi", value: upi.toLowerCase() });
    }

    // 5. Crypto addresses (BTC, ETH)
    const btcRegex = /\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b/g;
    const ethRegex = /\b0x[a-fA-F0-9]{40}\b/g;
    const btcMatches = text.match(btcRegex) || [];
    const ethMatches = text.match(ethRegex) || [];
    for (const btc of Array.from(new Set(btcMatches))) {
      entities.push({ type: "crypto", value: btc });
    }
    for (const eth of Array.from(new Set(ethMatches))) {
      entities.push({ type: "crypto", value: eth });
    }

    // 6. Monetary amounts ($500, ₹50,000, 50000 INR, €1000)
    const moneyRegex = /(?:[$€£₹]|Rs\.?|INR|USD|EUR)\s*[\d,]+(?:\.\d{2})?|\b[\d,]+\s*(?:dollars|rupees|inr|usd|eur|usdt)\b/gi;
    const moneyMatches = text.match(moneyRegex) || [];
    for (const m of Array.from(new Set(moneyMatches))) {
      entities.push({ type: "money_amount", value: m.trim() });
    }

    return entities;
  }

  /**
   * Applies deterministic heuristic scam detection patterns
   */
  public static evaluateScamRules(text: string, entities: ExtractedEntity[]): SecurityIndicator[] {
    const indicators: SecurityIndicator[] = [];
    const lower = text.toLowerCase();

    // 1. Banking & OTP Credential Theft Scams
    const otpKeywords = ["otp", "one time password", "verification code", "security code", "passcode"];
    const bankBlockKeywords = [
      "account will be blocked",
      "account suspended",
      "account deactivated",
      "card blocked",
      "kyc pending",
      "update kyc",
      "pan card update",
      "pan update",
      "unauthorized transaction",
      "sim card blocked",
      "electricity power will be disconnected",
      "power cutoff tonight",
    ];

    const hasOtp = otpKeywords.some((kw) => lower.includes(kw));
    const hasBankBlock = bankBlockKeywords.some((kw) => lower.includes(kw));

    if (hasOtp && hasBankBlock) {
      indicators.push({
        id: "msg.scam.banking_otp_theft",
        title: "Critical Banking / OTP Harvest Scam Pattern",
        description: "Message combines immediate threat of account deactivation/power cutoff with requests for verification codes or immediate action.",
        severity: "CRITICAL",
        weight: 45,
        confidence: 1.0,
        category: "credential_harvesting",
        source: "SentinelX Message Rules",
      });

      indicators.push({
        id: "msg.scam.banking_suspension_threat",
        title: "Coercive Account Suspension Threat",
        description: "Fabricates urgent penalty or account freeze to provoke impulsive panic.",
        severity: "HIGH",
        weight: 30,
        confidence: 1.0,
        category: "urgency_threat",
        source: "SentinelX Message Rules",
      });
    } else if (hasBankBlock) {
      indicators.push({
        id: "msg.scam.banking_suspension_threat",
        title: "Urgent Account Suspension / KYC Coercion",
        description: "Message threatens imminent service deactivation, account freeze, or KYC expiry to provoke impulsive panic.",
        severity: "HIGH",
        weight: 30,
        confidence: 1.0,
        category: "urgency_threat",
        source: "SentinelX Message Rules",
      });
    } else if (hasOtp && (lower.includes("share") || lower.includes("send") || lower.includes("call"))) {
      indicators.push({
        id: "msg.scam.otp_sharing_request",
        title: "Explicit Request to Share OTP / Passcode",
        description: "Legitimate institutions and service providers NEVER ask customers to verbally or digitally share one-time passcodes.",
        severity: "CRITICAL",
        weight: 45,
        confidence: 1.0,
        category: "credential_harvesting",
        source: "SentinelX Message Rules",
      });
    }

    // 2. Lottery / Reward / Prize / Advance Fee Scam
    const rewardKeywords = [
      "congratulations",
      "you won",
      "you have won",
      "selected for reward",
      "lucky winner",
      "lottery prize",
      "claim reward",
      "claim your prize",
      "cash gift",
      "spin and win",
    ];
    const feeKeywords = [
      "processing fee",
      "registration fee",
      "delivery charges",
      "tax fee",
      "pay ₹",
      "pay $",
      "transfer fee",
      "advance charge",
      "claim fee",
    ];

    const hasReward = rewardKeywords.some((kw) => lower.includes(kw));
    const hasFee = feeKeywords.some((kw) => lower.includes(kw));

    if (hasReward && hasFee) {
      indicators.push({
        id: "msg.scam.advance_fee_lottery",
        title: "Advance-Fee Lottery / Prize Scam Pattern",
        description: "Classic scam pattern promising a large sum of money or reward in exchange for an upfront 'processing fee' or 'tax payment'.",
        severity: "CRITICAL",
        weight: 40,
        confidence: 1.0,
        category: "financial_request",
        source: "SentinelX Message Rules",
      });
    } else if (hasReward) {
      indicators.push({
        id: "msg.scam.unsolicited_reward",
        title: "Unsolicited Prize / Reward Lure",
        description: "Message claims the recipient won an unsolicited prize or lottery, a primary hook used to harvest credentials or advance fees.",
        severity: "HIGH",
        weight: 25,
        confidence: 1.0,
        category: "financial_request",
        source: "SentinelX Message Rules",
      });
    }

    // 3. Courier / Postal Delivery Scam (e.g. USPS/FedEx/IndiaPost package failure)
    const courierKeywords = [
      "package could not be delivered",
      "delivery failed",
      "parcel detained",
      "package pending",
      "customs duty unpaid",
      "reschedule your delivery",
      "update shipping address",
      "postal package on hold",
      "usps parcel",
      "dhl delivery",
      "india post package",
    ];

    if (courierKeywords.some((kw) => lower.includes(kw))) {
      indicators.push({
        id: "msg.scam.courier_delivery_lure",
        title: "Delivery / Courier Smishing Pattern",
        description: "Impersonates postal or shipping carriers claiming an undelivered parcel to trick users into visiting phishing links or paying fake fees.",
        severity: "HIGH",
        weight: 30,
        confidence: 1.0,
        category: "brand_impersonation",
        source: "SentinelX Message Rules",
      });
    }

    // 4. Job / Part-time Task Scam
    const jobKeywords = [
      "part-time job",
      "work from home",
      "daily salary",
      "earn 3000 to 5000",
      "earn $",
      "earn ₹",
      "like youtube videos",
      "telegram task",
      "daily payout",
      "freelance task",
      "simple typing work",
      "no experience needed",
    ];

    if (jobKeywords.some((kw) => lower.includes(kw))) {
      indicators.push({
        id: "msg.scam.part_time_job_lure",
        title: "Part-Time Task / Telegram Job Scam Lure",
        description: "Offers unrealistic guaranteed daily earnings for trivial online tasks (e.g., YouTube likes, Google reviews) designed to lure victims into pyramid deposit schemes.",
        severity: "HIGH",
        weight: 30,
        confidence: 1.0,
        category: "financial_request",
        source: "SentinelX Message Rules",
      });
    }

    // 5. High-Yield Investment & Crypto Doubler Scam
    const investmentKeywords = [
      "guaranteed profit",
      "guaranteed return",
      "double your investment",
      "100% risk free",
      "crypto investment signal",
      "forex profit",
      "bitcoin doubler",
      "deposit and get 2x",
      "passive income guaranteed",
    ];

    if (investmentKeywords.some((kw) => lower.includes(kw))) {
      indicators.push({
        id: "msg.scam.investment_doubler",
        title: "High-Yield Investment / Crypto Ponzi Lure",
        description: "Claims guaranteed or doubled financial returns, a hallmark indicator of fraudulent high-yield investment programs (HYIP) or crypto drainers.",
        severity: "CRITICAL",
        weight: 40,
        confidence: 1.0,
        category: "financial_request",
        source: "SentinelX Message Rules",
      });
    }

    // 6. Artificial Urgency & Coercion Language
    const urgencyKeywords = [
      "urgent",
      "immediately",
      "within 24 hours",
      "within 12 hours",
      "act now",
      "last warning",
      "final notice",
      "police action",
      "court notice",
      "legal warrant",
      "before it is too late",
    ];

    const urgencyCount = urgencyKeywords.filter((kw) => lower.includes(kw)).length;
    if (urgencyCount >= 1 && !hasOtp) {
      indicators.push({
        id: "msg.psych.high_urgency_pressure",
        title: "Psychological Urgency & Coercion",
        description: `Message relies on manufactured time pressure (${urgencyCount} urgency markers) to bypass rational skepticism.`,
        severity: "MEDIUM",
        weight: 15,
        confidence: 0.9,
        category: "urgency_threat",
        source: "SentinelX Message Rules",
      });
    }

    // 7. Embedded Links in Suspicious Message Context
    const hasUrls = entities.some((e) => e.type === "url");
    if (hasUrls && (indicators.length > 0 || lower.includes("click") || lower.includes("link"))) {
      indicators.push({
        id: "msg.link.action_required_link",
        title: "External Link in Coercive / Financial Context",
        description: "Directs recipient to external URLs while making urgent financial or security claims.",
        severity: "HIGH",
        weight: 25,
        confidence: 0.95,
        category: "suspicious_structure",
        source: "SentinelX Message Rules",
      });
    }

    // 8. Payment Handle (UPI / Crypto) in Unknown Message
    const hasPaymentHandle = entities.some((e) => e.type === "upi" || e.type === "crypto");
    if (hasPaymentHandle) {
      indicators.push({
        id: "msg.payment.direct_wallet_request",
        title: "Direct Payment Handle / Crypto Address Present",
        description: "Message includes direct non-reversible payment destinations (UPI ID or cryptocurrency wallet).",
        severity: "MEDIUM",
        weight: 15,
        confidence: 0.95,
        category: "financial_request",
        source: "SentinelX Message Rules",
      });
    }

    return indicators;
  }
}
