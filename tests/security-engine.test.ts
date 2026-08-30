import { describe, it, expect } from "vitest";
import { RiskEngine } from "@/lib/security/risk-engine";
import { MessageRulesEngine } from "@/lib/security/message-rules";
import { UrlAnalyzer } from "@/lib/security/url-analyzer";
import { FileScanner } from "@/lib/security/file-scanner";
import { SecurityIndicator } from "@/lib/types/security";

describe("🛡️ SentinelX Global Risk Engine", () => {
  it("should generate standardized Analysis IDs matching SX-YYYYMMDD-XXXXXX", () => {
    const id = RiskEngine.generateAnalysisId();
    expect(id).toMatch(/^SX-\d{8}-[A-F0-9]{6}$/);
  });

  it("should return SAFE (0) for empty indicator list", () => {
    const res = RiskEngine.evaluate([]);
    expect(res.riskScore).toBe(0);
    expect(res.classification).toBe("SAFE");
  });

  it("should test exact classification boundaries: 29 SAFE, 30 SUSPICIOUS, 69 SUSPICIOUS, 70 DANGEROUS", () => {
    // 1. Exactly 29 (e.g., one HIGH 25 + one LOW 4 in different categories)
    const ind29: SecurityIndicator[] = [
      {
        id: "test.high",
        title: "Test High",
        description: "Test",
        severity: "HIGH",
        weight: 25,
        confidence: 1.0,
        category: "brand_impersonation",
        source: "Test",
      },
      {
        id: "test.low",
        title: "Test Low",
        description: "Test",
        severity: "LOW",
        weight: 4,
        confidence: 1.0,
        category: "suspicious_structure",
        source: "Test",
      },
    ];
    const eval29 = RiskEngine.evaluate(ind29);
    expect(eval29.riskScore).toBe(29);
    expect(eval29.classification).toBe("SAFE");

    // 2. Exactly 30 -> SUSPICIOUS
    const ind30: SecurityIndicator[] = [
      {
        id: "test.high",
        title: "Test High",
        description: "Test",
        severity: "HIGH",
        weight: 25,
        confidence: 1.0,
        category: "brand_impersonation",
        source: "Test",
      },
      {
        id: "test.low",
        title: "Test Low",
        description: "Test",
        severity: "LOW",
        weight: 5,
        confidence: 1.0,
        category: "suspicious_structure",
        source: "Test",
      },
    ];
    const eval30 = RiskEngine.evaluate(ind30);
    expect(eval30.riskScore).toBe(30);
    expect(eval30.classification).toBe("SUSPICIOUS");

    // 3. Exactly 69 -> SUSPICIOUS
    const ind69: SecurityIndicator[] = [
      {
        id: "test.crit",
        title: "Test Critical",
        description: "Test",
        severity: "CRITICAL",
        weight: 40,
        confidence: 1.0,
        category: "threat_intelligence",
        source: "Test",
      },
      {
        id: "test.high",
        title: "Test High",
        description: "Test",
        severity: "HIGH",
        weight: 25,
        confidence: 1.0,
        category: "brand_impersonation",
        source: "Test",
      },
      {
        id: "test.low",
        title: "Test Low",
        description: "Test",
        severity: "LOW",
        weight: 4,
        confidence: 1.0,
        category: "reputation",
        source: "Test",
      },
    ];
    const eval69 = RiskEngine.evaluate(ind69);
    expect(eval69.riskScore).toBe(69);
    expect(eval69.classification).toBe("SUSPICIOUS");

    // 4. Exactly 70 -> DANGEROUS
    const ind70: SecurityIndicator[] = [
      {
        id: "test.crit",
        title: "Test Critical",
        description: "Test",
        severity: "CRITICAL",
        weight: 40,
        confidence: 1.0,
        category: "threat_intelligence",
        source: "Test",
      },
      {
        id: "test.high",
        title: "Test High",
        description: "Test",
        severity: "HIGH",
        weight: 25,
        confidence: 1.0,
        category: "brand_impersonation",
        source: "Test",
      },
      {
        id: "test.low",
        title: "Test Low",
        description: "Test",
        severity: "LOW",
        weight: 5,
        confidence: 1.0,
        category: "reputation",
        source: "Test",
      },
    ];
    const eval70 = RiskEngine.evaluate(ind70);
    expect(eval70.riskScore).toBe(70);
    expect(eval70.classification).toBe("DANGEROUS");
  });

  it("should prevent double-counting via category diminishing returns", () => {
    // Three HIGH (weight: 25) indicators in the SAME category (e.g. active_content)
    const indicators: SecurityIndicator[] = [
      {
        id: "pdf.js",
        title: "Embedded JS",
        description: "Test",
        severity: "HIGH",
        weight: 25,
        confidence: 1.0,
        category: "active_content",
        source: "SentinelX PDF Analyzer",
      },
      {
        id: "pdf.openaction",
        title: "OpenAction",
        description: "Test",
        severity: "HIGH",
        weight: 25,
        confidence: 1.0,
        category: "active_content",
        source: "SentinelX PDF Analyzer",
      },
      {
        id: "pdf.launch",
        title: "Launch",
        description: "Test",
        severity: "HIGH",
        weight: 25,
        confidence: 1.0,
        category: "active_content",
        source: "SentinelX PDF Analyzer",
      },
    ];

    const res = RiskEngine.evaluate(indicators);
    // 1st: 25, 2nd: 25 * 0.4 = 10, 3rd: 25 * 0.15 = 3.75 -> Total = 38.75 -> 39
    // Without diminishing returns it would have been 75 (DANGEROUS) incorrectly!
    expect(res.riskScore).toBe(39);
    expect(res.classification).toBe("SUSPICIOUS");
  });

  it("should clamp scores strictly between 0 and 100", () => {
    // Excessive mitigations cannot bring score below 0
    const overMitigated: SecurityIndicator[] = [
      {
        id: "clean",
        title: "Clean",
        description: "Test",
        severity: "LOW",
        weight: 40,
        confidence: 1.0,
        category: "reputation",
        source: "Test",
        mitigating: true,
      },
    ];
    expect(RiskEngine.evaluate(overMitigated).riskScore).toBe(0);

    // Excessive attacks cannot exceed 100
    const extremeAttacks: SecurityIndicator[] = [
      { id: "1", title: "C1", description: "", severity: "CRITICAL", weight: 40, confidence: 1.0, category: "threat_intelligence", source: "Test" },
      { id: "2", title: "C2", description: "", severity: "CRITICAL", weight: 40, confidence: 1.0, category: "brand_impersonation", source: "Test" },
      { id: "3", title: "C3", description: "", severity: "CRITICAL", weight: 40, confidence: 1.0, category: "credential_harvesting", source: "Test" },
      { id: "4", title: "C4", description: "", severity: "CRITICAL", weight: 40, confidence: 1.0, category: "active_content", source: "Test" },
    ];
    expect(RiskEngine.evaluate(extremeAttacks).riskScore).toBe(100);
  });
});

describe("💬 SentinelX Message / Scam Analyzer Rules", () => {
  it("should extract entities: URLs, emails, phone numbers, and UPI IDs", () => {
    const text = "Hi, urgent! Pay ₹499 to support@okhdfcbank or click https://sbi-kyc-verify.xyz?id=99. Call +91 9876543210 or email help@phish.com";
    const entities = MessageRulesEngine.extractEntities(text);

    const urls = entities.filter((e) => e.type === "url").map((e) => e.value);
    const emails = entities.filter((e) => e.type === "email").map((e) => e.value);
    const phones = entities.filter((e) => e.type === "phone").map((e) => e.value);
    const upis = entities.filter((e) => e.type === "upi").map((e) => e.value);
    const amounts = entities.filter((e) => e.type === "money_amount").map((e) => e.value);

    expect(urls).toContain("https://sbi-kyc-verify.xyz?id=99");
    expect(emails).toContain("help@phish.com");
    expect(upis).toContain("support@okhdfcbank");
    expect(phones.length).toBeGreaterThan(0);
    expect(amounts.length).toBeGreaterThan(0);
  });

  it("should detect Banking OTP & Account Suspension Scam patterns as DANGEROUS", () => {
    const msg = "Dear customer, your bank account will be blocked today due to pending KYC. Verify immediately and share OTP with officer.";
    const entities = MessageRulesEngine.extractEntities(msg);
    const indicators = MessageRulesEngine.evaluateScamRules(msg, entities);
    const evalRes = RiskEngine.evaluate(indicators);

    expect(indicators.some((i) => i.id === "msg.scam.banking_otp_theft")).toBe(true);
    expect(evalRes.classification).toBe("DANGEROUS");
    expect(evalRes.riskScore).toBeGreaterThanOrEqual(70);
  });

  it("should detect Advance-Fee Lottery Scam as High Risk", () => {
    const msg = "Congratulations! You won ₹50,000 lottery cash prize. Pay ₹499 processing fee to claim reward immediately.";
    const entities = MessageRulesEngine.extractEntities(msg);
    const indicators = MessageRulesEngine.evaluateScamRules(msg, entities);
    const evalRes = RiskEngine.evaluate(indicators);

    expect(indicators.some((i) => i.id === "msg.scam.advance_fee_lottery")).toBe(true);
    expect(evalRes.riskScore).toBeGreaterThanOrEqual(35);
  });

  it("should classify a benign friendly message as SAFE", () => {
    const msg = "Hey, are we still meeting for lunch at 1pm tomorrow? Let me know!";
    const entities = MessageRulesEngine.extractEntities(msg);
    const indicators = MessageRulesEngine.evaluateScamRules(msg, entities);
    const evalRes = RiskEngine.evaluate(indicators);

    expect(evalRes.riskScore).toBe(0);
    expect(evalRes.classification).toBe("SAFE");
  });
});

describe("🔗 SentinelX Link Analyzer", () => {
  it("should detect brand typosquatting / impersonation on lookalike domains", async () => {
    const res = await UrlAnalyzer.analyze("https://paypa1-security-login.xyz/verify");
    
    expect(res.indicators.some((i) => i.category === "brand_impersonation")).toBe(true);
    expect(res.indicators.some((i) => i.source === "SentinelX URL Engine")).toBe(true);
    expect(res.riskScore).toBeGreaterThanOrEqual(30);
  });

  it("should detect IP address hostnames as suspicious", async () => {
    const res = await UrlAnalyzer.analyze("http://192.168.1.100/login.php");
    expect(res.indicators.some((i) => i.id === "url.host.ip_address")).toBe(true);
    expect(res.indicators.some((i) => i.id === "url.protocol.http_unencrypted")).toBe(true);
  });

  it("should recognize verified official brand domains and apply mitigations", async () => {
    const res = await UrlAnalyzer.analyze("https://www.paypal.com/signin");
    expect(res.indicators.some((i) => i.id.startsWith("url.brand.official_"))).toBe(true);
    expect(res.classification).toBe("SAFE");
    expect(res.riskScore).toBeLessThan(30);
  });
});

describe("📁 SentinelX File Guardian", () => {
  it("should detect the standard EICAR antivirus test file signature", async () => {
    const eicarBuffer = Buffer.from("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    const res = await FileScanner.scan(eicarBuffer, "eicar.com");

    expect(res.indicators.some((i) => i.id === "file.test.eicar_signature")).toBe(true);
    expect(res.classification).toBe("DANGEROUS");
    expect(res.metadata.sha256).toBeDefined();
  });

  it("should detect file extension spoofing (e.g. PE Executable named invoice.pdf)", async () => {
    // Create a mock buffer with MZ header and PE signature
    const mockExe = Buffer.alloc(512);
    mockExe[0] = 0x4d; // 'M'
    mockExe[1] = 0x5a; // 'Z'
    mockExe.writeUInt32LE(0x80, 0x3c); // PE header offset
    mockExe.write("PE\0\0", 0x80, "ascii");

    const res = await FileScanner.scan(mockExe, "invoice_2026.pdf");
    expect(res.indicators.some((i) => i.id === "file.spoof.extension_mismatch")).toBe(true);
    expect(res.classification).toBe("DANGEROUS");
  });
});
