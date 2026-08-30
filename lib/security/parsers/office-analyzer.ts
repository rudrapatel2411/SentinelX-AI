import JSZip from "jszip";
import { SecurityIndicator } from "@/lib/types/security";

/**
 * Safe static analyzer for Microsoft Office documents (DOCX, XLSX, PPTX)
 * Inspects OOXML package structure, VBA macro streams, external relationships, and OLE objects.
 */
export class OfficeAnalyzer {
  public static async analyze(buffer: Buffer): Promise<SecurityIndicator[]> {
    const indicators: SecurityIndicator[] = [];

    try {
      const zip = await JSZip.loadAsync(buffer);
      const fileNames = Object.keys(zip.files);

      // 1. VBA Macro Detection
      const hasVbaMacro = fileNames.some(
        (name) =>
          name.includes("vbaProject.bin") ||
          name.includes("vbaData.xml") ||
          name.endsWith(".vba")
      );

      if (hasVbaMacro) {
        indicators.push({
          id: "office.macro.vba_project",
          title: "VBA Macro Project Detected (vbaProject.bin)",
          description: "Document contains Visual Basic for Applications (VBA) macro code. Macros can execute arbitrary commands upon opening or user interaction.",
          severity: "HIGH",
          weight: 25,
          confidence: 0.95,
          category: "active_content",
          source: "SentinelX Office Analyzer",
        });
      }

      // 2. Embedded OLE Objects / Dropped Binaries
      const oleEmbeddings = fileNames.filter(
        (name) =>
          name.includes("embeddings/oleObject") ||
          name.includes("embeddings/package") ||
          name.endsWith(".exe") ||
          name.endsWith(".bin") ||
          name.endsWith(".bat") ||
          name.endsWith(".vbs")
      );

      if (oleEmbeddings.length > 0) {
        indicators.push({
          id: "office.embed.ole_objects",
          title: `Embedded OLE Objects / Binaries (${oleEmbeddings.length} found)`,
          description: `Document packages embedded OLE objects or binary blobs: ${oleEmbeddings.slice(0, 3).join(", ")}. Frequently used to conceal executable droppers.`,
          severity: "HIGH",
          weight: 25,
          confidence: 0.9,
          category: "active_content",
          source: "SentinelX Office Analyzer",
        });
      }

      // 3. Remote Template Injection / External Relationships
      const relFiles = fileNames.filter((name) => name.endsWith(".rels"));
      let externalRelsCount = 0;
      const remoteUrls: string[] = [];

      for (const relFile of relFiles) {
        const fileData = zip.file(relFile);
        if (fileData) {
          const content = await fileData.async("string");
          if (content.includes('TargetMode="External"')) {
            externalRelsCount++;
            const urlMatches = content.match(/Target="(https?:\/\/[^"]+)"/gi);
            if (urlMatches) {
              for (const u of urlMatches) {
                const cleaned = u.replace(/^Target="/i, "").replace(/"$/, "");
                remoteUrls.push(cleaned);
              }
            }
          }
        }
      }

      if (externalRelsCount > 0) {
        indicators.push({
          id: "office.network.remote_template_injection",
          title: `External Relationship / Remote Template Reference (${externalRelsCount} targets)`,
          description: `Document references external network resources at launch. Targets: ${remoteUrls.slice(0, 2).join(", ") || "External URL"}. Often used in remote template injection attacks.`,
          severity: "HIGH",
          weight: 25,
          confidence: 0.9,
          category: "active_content",
          source: "SentinelX Office Analyzer",
        });
      }

      // 4. ActiveX Controls
      const hasActiveX = fileNames.some((name) => name.includes("activeX"));
      if (hasActiveX) {
        indicators.push({
          id: "office.active.activex_controls",
          title: "ActiveX Controls Embedded",
          description: "Document contains legacy ActiveX components which may execute external COM objects.",
          severity: "MEDIUM",
          weight: 15,
          confidence: 0.85,
          category: "active_content",
          source: "SentinelX Office Analyzer",
        });
      }

      // 5. Clean baseline
      if (indicators.length === 0) {
        indicators.push({
          id: "office.struct.clean_ooxml",
          title: "Clean OOXML Document Structure",
          description: "Document verified as standard Office Open XML container with no VBA macros, remote templates, ActiveX controls, or embedded OLE payloads.",
          severity: "LOW",
          weight: 15,
          confidence: 0.9,
          category: "suspicious_structure",
          source: "SentinelX Office Analyzer",
          mitigating: true,
        });
      }
    } catch {
      indicators.push({
        id: "office.struct.corrupt_container",
        title: "Corrupted Office Document Package",
        description: "File claims to be an Office document but could not be parsed as a valid OOXML ZIP container.",
        severity: "HIGH",
        weight: 20,
        confidence: 0.85,
        category: "suspicious_structure",
        source: "SentinelX Office Analyzer",
      });
    }

    return indicators;
  }
}
