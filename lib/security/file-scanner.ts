import crypto from "crypto";
import {
  CommonAnalysisResult,
  SecurityIndicator,
  ThreatIntelSourceResult,
  FileMetadata,
} from "@/lib/types/security";
import { RiskEngine } from "@/lib/security/risk-engine";
import { ThreatIntelligenceService } from "@/lib/security/threat-intelligence";
import { AIService } from "@/lib/ai/openai";
import { PdfAnalyzer } from "@/lib/security/parsers/pdf-analyzer";
import { OfficeAnalyzer } from "@/lib/security/parsers/office-analyzer";
import { ArchiveAnalyzer } from "@/lib/security/parsers/archive-analyzer";
import { ExeAnalyzer } from "@/lib/security/parsers/exe-analyzer";
import { ApkAnalyzer } from "@/lib/security/parsers/apk-analyzer";
import { ImageAnalyzer } from "@/lib/security/parsers/image-analyzer";

const EICAR_TEST_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

export class FileScanner {
  /**
   * Master file scanner coordinator.
   * Performs magic bytes detection, hashing, bounded static analysis,
   * VirusTotal hash lookup, deterministic risk calculation, and AI explanation.
   */
  public static async scan(
    buffer: Buffer,
    originalFilename: string
  ): Promise<CommonAnalysisResult> {
    const analysisId = RiskEngine.generateAnalysisId();
    const createdAt = new Date().toISOString();
    const indicators: SecurityIndicator[] = [];
    const threatIntelResults: ThreatIntelSourceResult[] = [];

    // 1. Calculate Cryptographic Hashes
    const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");
    const sha1 = crypto.createHash("sha1").update(buffer).digest("hex");
    const md5 = crypto.createHash("md5").update(buffer).digest("hex");

    const magicBytesHex = buffer.slice(0, 8).toString("hex").toUpperCase();
    const declaredExt = (originalFilename.split(".").pop() || "").toLowerCase();

    // 2. Detect True File Type & Check for Extension Spoofing
    const { detectedMimeType, trueType } = this.detectTrueFileType(buffer, originalFilename);
    const isExtensionSpoofed = this.checkExtensionSpoofing(trueType, declaredExt);

    if (isExtensionSpoofed) {
      indicators.push({
        id: "file.spoof.extension_mismatch",
        title: `File Extension Mismatch / Spoofing Attempt`,
        description: `File claims extension '.${declaredExt}' but binary magic bytes match '${trueType}' (${detectedMimeType}). Concealing executables as documents or media is a high-risk evasion technique.`,
        severity: "CRITICAL",
        weight: 45,
        confidence: 1.0,
        category: "suspicious_structure",
        source: "SentinelX Magic Bytes Engine",
      });

      indicators.push({
        id: "file.spoof.evasion_behavior",
        title: "Disguised Executable Binary Payload",
        description: "Binary payload obfuscation detected to bypass user inspection and file filtering rules.",
        severity: "HIGH",
        weight: 35,
        confidence: 1.0,
        category: "active_content",
        source: "SentinelX Magic Bytes Engine",
      });
    }

    // 3. EICAR Standard Antivirus Test Pattern Detection
    const rawContentSample = buffer.slice(0, 2048).toString("ascii");
    if (rawContentSample.includes(EICAR_TEST_STRING)) {
      indicators.push({
        id: "file.test.eicar_signature",
        title: "EICAR Standard Antivirus Test Signature Detected",
        description: "File contains the official industry-standard EICAR antivirus test string used to verify security scanner functionality.",
        severity: "CRITICAL",
        weight: 45,
        confidence: 1.0,
        category: "threat_intelligence",
        source: "SentinelX Signature Engine",
      });

      indicators.push({
        id: "file.test.eicar_active_threat",
        title: "Standard Test Malware Artifact Match",
        description: "Matches universal antivirus benchmark signature (EICAR.Standard.Test).",
        severity: "CRITICAL",
        weight: 35,
        confidence: 1.0,
        category: "active_content",
        source: "SentinelX Signature Engine",
      });
    }

    // 4. Run Format-Specific Static Analysis
    switch (trueType) {
      case "pdf": {
        const pdfIndicators = PdfAnalyzer.analyze(buffer);
        indicators.push(...pdfIndicators);
        break;
      }
      case "office": {
        const officeIndicators = await OfficeAnalyzer.analyze(buffer);
        indicators.push(...officeIndicators);
        break;
      }
      case "apk": {
        const apkIndicators = await ApkAnalyzer.analyze(buffer);
        indicators.push(...apkIndicators);
        break;
      }
      case "zip": {
        const zipIndicators = await ArchiveAnalyzer.analyze(buffer);
        indicators.push(...zipIndicators);
        break;
      }
      case "exe": {
        const exeIndicators = ExeAnalyzer.analyze(buffer);
        indicators.push(...exeIndicators);
        break;
      }
      case "image": {
        const imgIndicators = ImageAnalyzer.analyze(buffer, declaredExt);
        indicators.push(...imgIndicators);
        break;
      }
      case "text": {
        indicators.push({
          id: "file.info.plain_text",
          title: "Plaintext Text Document",
          description: "File contains unformatted text with no binary executable structures.",
          severity: "LOW",
          weight: 0,
          confidence: 1.0,
          category: "informational",
          source: "SentinelX File Scanner",
        });
        break;
      }
      default: {
        indicators.push({
          id: "file.struct.generic_binary",
          title: "Unclassified Binary Stream",
          description: `File structure did not match high-level parsed schemas. Magic header: 0x${magicBytesHex}.`,
          severity: "LOW",
          weight: 5,
          confidence: 0.7,
          category: "informational",
          source: "SentinelX File Scanner",
        });
        break;
      }
    }

    // 5. Query VirusTotal by SHA-256 Hash (Privacy guarantee: hash only, no file upload)
    const vtResult = await ThreatIntelligenceService.checkFileHash(sha256);
    threatIntelResults.push(vtResult.intelResult);
    indicators.push(...vtResult.indicators);

    // 6. Evaluate Deterministic Risk Engine (AI DOES NOT MODIFY THIS)
    const riskEval = RiskEngine.evaluate(indicators);

    // Format file size
    const fileSizeFormatted =
      buffer.length > 1024 * 1024
        ? `${(buffer.length / (1024 * 1024)).toFixed(2)} MB`
        : `${(buffer.length / 1024).toFixed(1)} KB`;

    const metadata: FileMetadata = {
      fileName: originalFilename,
      fileSize: buffer.length,
      fileSizeFormatted,
      detectedMimeType,
      declaredExtension: declaredExt,
      isExtensionSpoofed,
      sha256,
      sha1,
      md5,
      magicBytesHex,
    };

    // 7. Generate AI Explanation Layer
    const aiResult = await AIService.generateExplanation({
      type: "file",
      target: originalFilename,
      riskScore: riskEval.riskScore,
      classification: riskEval.classification,
      indicators,
      threatIntel: threatIntelResults,
      metadata: {
        ...metadata,
        trueType,
      },
    });

    // 8. Actionable recommendations
    const recommendations: string[] = [];
    if (riskEval.classification === "DANGEROUS") {
      recommendations.push("🚫 Do NOT open, execute, or extract this file.");
      recommendations.push("🗑️ Delete this file immediately from your storage drive.");
      recommendations.push("🛡️ If you executed this file previously, disconnect your network and initiate a full system endpoint scan.");
    } else if (riskEval.classification === "SUSPICIOUS") {
      recommendations.push("⚠️ Exercise caution before opening this document or archive.");
      recommendations.push("🔒 Disable macro execution in Office applications.");
      recommendations.push("🔍 Open in an isolated sandbox or protected viewer if inspection is necessary.");
    } else {
      recommendations.push("✅ No known threats were detected in the performed checks.");
      recommendations.push("💡 Always verify the trusted source before running downloaded software.");
    }

    return {
      id: analysisId,
      type: "file",
      target: originalFilename,
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
        ...metadata,
        trueType,
      },
    };
  }

  /**
   * Inspects magic byte signatures
   */
  private static detectTrueFileType(
    buffer: Buffer,
    filename: string
  ): { detectedMimeType: string; trueType: string } {
    if (buffer.length >= 4 && buffer.slice(0, 4).toString("utf-8").startsWith("%PDF")) {
      return { detectedMimeType: "application/pdf", trueType: "pdf" };
    }

    // Windows PE Executable (MZ)
    if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) {
      return { detectedMimeType: "application/x-msdownload", trueType: "exe" };
    }

    // PNG
    if (buffer.length >= 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) {
      return { detectedMimeType: "image/png", trueType: "image" };
    }

    // JPEG
    if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
      return { detectedMimeType: "image/jpeg", trueType: "image" };
    }

    // GIF
    if (buffer.length >= 6 && buffer.slice(0, 6).toString("ascii").startsWith("GIF8")) {
      return { detectedMimeType: "image/gif", trueType: "image" };
    }

    // WebP
    if (buffer.length >= 12 && buffer.slice(0, 4).toString("ascii") === "RIFF" && buffer.slice(8, 12).toString("ascii") === "WEBP") {
      return { detectedMimeType: "image/webp", trueType: "image" };
    }

    // ZIP container (Could be standard ZIP, Office OOXML, or APK)
    if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b && (buffer[2] === 0x03 || buffer[2] === 0x05)) {
      const sample = buffer.slice(0, 4096).toString("binary");
      const ext = (filename.split(".").pop() || "").toLowerCase();

      if (sample.includes("AndroidManifest.xml") || ext === "apk") {
        return { detectedMimeType: "application/vnd.android.package-archive", trueType: "apk" };
      }

      if (
        sample.includes("word/") ||
        sample.includes("xl/") ||
        sample.includes("ppt/") ||
        ["docx", "xlsx", "pptx", "docm", "xlsm", "pptm"].includes(ext)
      ) {
        return { detectedMimeType: "application/vnd.openxmlformats-officedocument", trueType: "office" };
      }

      return { detectedMimeType: "application/zip", trueType: "zip" };
    }

    // Check if plain text
    let isAscii = true;
    for (let i = 0; i < Math.min(buffer.length, 512); i++) {
      const byte = buffer[i];
      if (byte === 0 || (byte < 7 && byte > 14 && byte < 32 && byte !== 9 && byte !== 10 && byte !== 13)) {
        isAscii = false;
        break;
      }
    }

    if (isAscii) {
      return { detectedMimeType: "text/plain", trueType: "text" };
    }

    return { detectedMimeType: "application/octet-stream", trueType: "binary" };
  }

  private static checkExtensionSpoofing(trueType: string, declaredExt: string): boolean {
    const documentExts = ["pdf", "txt", "rtf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv"];
    const imageExts = ["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg"];

    // Executable disguised as document or image
    if (trueType === "exe" && (documentExts.includes(declaredExt) || imageExts.includes(declaredExt))) {
      return true;
    }

    // Script / APK disguised as PDF or Image
    if (trueType === "apk" && (documentExts.includes(declaredExt) || imageExts.includes(declaredExt))) {
      return true;
    }

    // Binary / ZIP disguised as image or text
    if (trueType === "pdf" && imageExts.includes(declaredExt)) {
      return true;
    }

    return false;
  }
}
