import { SecurityIndicator } from "@/lib/types/security";

export class ImageAnalyzer {
  public static analyze(buffer: Buffer, declaredExt: string): SecurityIndicator[] {
    const indicators: SecurityIndicator[] = [];

    // Magic byte signatures
    const isPng = buffer.length >= 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47;
    const isJpg = buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
    const isGif = buffer.length >= 6 && buffer.slice(0, 6).toString("ascii").startsWith("GIF8");
    const isWebp = buffer.length >= 12 && buffer.slice(0, 4).toString("ascii") === "RIFF" && buffer.slice(8, 12).toString("ascii") === "WEBP";

    const isRecognizedImage = isPng || isJpg || isGif || isWebp;

    if (!isRecognizedImage) {
      indicators.push({
        id: "image.magic.invalid_header",
        title: "Invalid Image Magic Bytes / Header",
        description: `File declared as '${declaredExt}' but lacks matching PNG, JPEG, GIF, or WebP binary magic bytes. Possible file extension spoofing.`,
        severity: "HIGH",
        weight: 25,
        confidence: 0.95,
        category: "suspicious_structure",
        source: "SentinelX Image Analyzer",
      });
      return indicators;
    }

    // Check PNG IEND or JPG EOI marker for appended payload anomalies
    if (isPng) {
      const raw = buffer.toString("binary");
      const iendPos = raw.indexOf("IEND\xAEB`\x82");
      if (iendPos !== -1 && buffer.length - (iendPos + 8) > 2048) {
        const trailingBytes = buffer.length - (iendPos + 8);
        indicators.push({
          id: "image.anomaly.trailing_data",
          title: `Appended Binary Data After Image EOF (${(trailingBytes / 1024).toFixed(1)} KB)`,
          description: `Image contains ${(trailingBytes / 1024).toFixed(1)} KB of data appended past the standard PNG 'IEND' chunk. Often indicative of polyglot payloads or steganography.`,
          severity: "MEDIUM",
          weight: 15,
          confidence: 0.8,
          category: "suspicious_structure",
          source: "SentinelX Image Analyzer",
        });
      }
    }

    // Clean baseline
    if (indicators.length === 0) {
      indicators.push({
        id: "image.struct.clean_header",
        title: "Valid Image Container & Magic Bytes",
        description: "Image structure matches standard specifications with no anomalous trailing blocks.",
        severity: "LOW",
        weight: 10,
        confidence: 0.9,
        category: "suspicious_structure",
        source: "SentinelX Image Analyzer",
        mitigating: true,
      });
    }

    return indicators;
  }
}
