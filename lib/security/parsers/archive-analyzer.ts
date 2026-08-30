import JSZip from "jszip";
import { SecurityIndicator } from "@/lib/types/security";

const DANGEROUS_EXTENSIONS = new Set([
  "exe",
  "scr",
  "bat",
  "cmd",
  "ps1",
  "vbs",
  "vbe",
  "js",
  "jse",
  "wsf",
  "wsh",
  "hta",
  "jar",
  "iso",
  "img",
  "lnk",
  "pif",
  "cpl",
]);

const NESTED_ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "tar", "gz", "bz2", "xz"]);

export class ArchiveAnalyzer {
  public static async analyze(buffer: Buffer): Promise<SecurityIndicator[]> {
    const indicators: SecurityIndicator[] = [];

    try {
      const zip = await JSZip.loadAsync(buffer);
      const entries = Object.values(zip.files);
      const totalFiles = entries.filter((e) => !e.dir).length;

      // 1. File Count & Archive Bomb / Compression Ratio Check
      let totalUncompressedSize = 0;
      const compressedSize = buffer.length;

      for (const entry of entries) {
        if (!entry.dir) {
          // JSZip provides uncompressed size in _data or metadata if available
          const internalEntry = entry as unknown as { _data?: { uncompressedSize?: number } };
          const uncompressed = internalEntry._data?.uncompressedSize || 0;
          totalUncompressedSize += uncompressed;
        }
      }

      // Check ratio
      if (compressedSize > 0 && totalUncompressedSize > 50 * 1024 * 1024) {
        const ratio = totalUncompressedSize / compressedSize;
        if (ratio > 100) {
          indicators.push({
            id: "zip.bomb.extreme_ratio",
            title: `Potential Archive Bomb Detected (Ratio: ${Math.round(ratio)}:1)`,
            description: `Compressed size is ${(compressedSize / 1024).toFixed(1)} KB while uncompressed expansion exceeds ${(totalUncompressedSize / (1024 * 1024)).toFixed(1)} MB. Characteristic of decompression denial-of-service bombs.`,
            severity: "CRITICAL",
            weight: 40,
            confidence: 0.95,
            category: "suspicious_structure",
            source: "SentinelX Archive Analyzer",
          });
        }
      }

      // 2. Executable & Dangerous Extensions Inside Archive
      const executableEntries: string[] = [];
      const doubleExtensionEntries: string[] = [];
      const nestedArchives: string[] = [];

      for (const entry of entries) {
        if (entry.dir) continue;
        const name = entry.name.toLowerCase();
        const parts = name.split("/");
        const filename = parts[parts.length - 1];
        const dotParts = filename.split(".");

        if (dotParts.length >= 2) {
          const ext = dotParts[dotParts.length - 1];
          if (DANGEROUS_EXTENSIONS.has(ext)) {
            executableEntries.push(filename);
          }

          if (NESTED_ARCHIVE_EXTENSIONS.has(ext)) {
            nestedArchives.push(filename);
          }

          // Check double extension (e.g. invoice.pdf.exe or statement.docx.scr)
          if (dotParts.length >= 3) {
            const secondExt = dotParts[dotParts.length - 2];
            const decoyDocs = ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"];
            if (decoyDocs.includes(secondExt) && DANGEROUS_EXTENSIONS.has(ext)) {
              doubleExtensionEntries.push(filename);
            }
          }
        }
      }

      // Double extension obfuscation
      if (doubleExtensionEntries.length > 0) {
        indicators.push({
          id: "zip.payload.double_extension",
          title: `Double-Extension Executable Cloaking (${doubleExtensionEntries.length} files)`,
          description: `Archive contains files using disguised double extensions: ${doubleExtensionEntries.slice(0, 3).join(", ")}. Designed to trick users into running executables disguised as documents.`,
          severity: "CRITICAL",
          weight: 40,
          confidence: 0.95,
          category: "suspicious_structure",
          source: "SentinelX Archive Analyzer",
        });
      }

      // Executable files in archive
      if (executableEntries.length > 0) {
        indicators.push({
          id: "zip.payload.executable_files",
          title: `Executable Binaries / Scripts in Archive (${executableEntries.length} files)`,
          description: `Archive packages executable files: ${executableEntries.slice(0, 3).join(", ")}. Exercise caution before extracting or running packaged programs.`,
          severity: "HIGH",
          weight: 25,
          confidence: 0.9,
          category: "active_content",
          source: "SentinelX Archive Analyzer",
        });
      }

      // Nested archives
      if (nestedArchives.length > 0) {
        indicators.push({
          id: "zip.struct.nested_archives",
          title: `Nested Archives (${nestedArchives.length} files)`,
          description: `Archive contains encapsulated sub-archives: ${nestedArchives.slice(0, 3).join(", ")}. Frequently used to evade single-pass email perimeter scanners.`,
          severity: "MEDIUM",
          weight: 15,
          confidence: 0.8,
          category: "suspicious_structure",
          source: "SentinelX Archive Analyzer",
        });
      }

      // Clean baseline
      if (indicators.length === 0) {
        indicators.push({
          id: "zip.struct.clean_archive",
          title: `Clean Archive Structure (${totalFiles} files)`,
          description: "Archive verified with safe compression ratios and no executable binaries, disguised extensions, or nested archives.",
          severity: "LOW",
          weight: 15,
          confidence: 0.85,
          category: "suspicious_structure",
          source: "SentinelX Archive Analyzer",
          mitigating: true,
        });
      }
    } catch {
      indicators.push({
        id: "zip.struct.corrupt",
        title: "Corrupted / Unreadable Archive Structure",
        description: "File claims to be a ZIP archive but could not be parsed.",
        severity: "MEDIUM",
        weight: 15,
        confidence: 0.85,
        category: "suspicious_structure",
        source: "SentinelX Archive Analyzer",
      });
    }

    return indicators;
  }
}
