import { UrlAnalyzer } from "../lib/security/url-analyzer";
import { MessageAnalyzer } from "../lib/security/message-analyzer";
import { FileScanner } from "../lib/security/file-scanner";
import { AnalysisStorage } from "../lib/security/analysis-storage";

async function main() {
  console.log("🌱 Seeding SentinelX AI with synthetic security benchmarks...");

  // 1. Phishing URL Benchmark
  console.log("   -> Running URL Analyzer on lookalike domain...");
  const urlRes = await UrlAnalyzer.analyze("https://paypa1-security-verification.xyz/login?session=active");
  await AnalysisStorage.saveAnalysis(urlRes);

  // 2. Safe URL Benchmark
  console.log("   -> Running URL Analyzer on official domain...");
  const safeUrlRes = await UrlAnalyzer.analyze("https://www.paypal.com/signin");
  await AnalysisStorage.saveAnalysis(safeUrlRes);

  // 3. Banking SMS Scam Benchmark
  console.log("   -> Running Message Analyzer on banking OTP scam...");
  const msgRes = await MessageAnalyzer.analyze(
    "Dear customer, your SBI bank account will be blocked today due to pending KYC verification. Please click https://sbi-kyc-verify.xyz/login immediately to update PAN and verify your OTP with the security officer."
  );
  await AnalysisStorage.saveAnalysis(msgRes);

  // 4. Safe Chat Message Benchmark
  console.log("   -> Running Message Analyzer on benign message...");
  const safeMsgRes = await MessageAnalyzer.analyze(
    "Hi Sarah, let's connect at 2 PM to review the quarterly security architecture slides. See you then!"
  );
  await AnalysisStorage.saveAnalysis(safeMsgRes);

  // 5. EICAR Standard Antivirus Test Sample
  console.log("   -> Running File Guardian on EICAR test signature...");
  const eicarBuffer = Buffer.from("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
  const eicarRes = await FileScanner.scan(eicarBuffer, "eicar-standard-antivirus-test.com");
  await AnalysisStorage.saveAnalysis(eicarRes);

  console.log("✅ Seed completed successfully! Synthetic security samples ready in database.");
}

main().catch((e) => {
  console.error("Seeding notice: PostgreSQL is offline or unreachable. Skipping DB seed.", e.message);
  process.exit(0);
});
