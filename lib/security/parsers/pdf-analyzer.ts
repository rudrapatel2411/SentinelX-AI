import { SecurityIndicator } from "@/lib/types/security";

/**
 * Safe static analyzer for PDF documents
 * Analyzes structure, active streams, and actions without executing code
 */
export class PdfAnalyzer {
  public static analyze(buffer: Buffer): SecurityIndicator[] {
    const indicators: SecurityIndicator[] = [];
    const rawString = buffer.toString("binary");

    // 1. PDF Header & EOF Verification
    const hasPdfHeader = buffer.slice(0, 8).toString("utf-8").startsWith("%PDF-");
    const hasEofMarker = rawString.includes("%%EOF");

    if (!hasPdfHeader) {
      indicators.push({
        id: "pdf.struct.invalid_header",
        title: "Missing or Invalid PDF Header",
        description: "File does not begin with standard '%PDF-1.x' signature.",
        severity: "HIGH",
        weight: 25,
        confidence: 0.95,
        category: "suspicious_structure",
        source: "SentinelX PDF Analyzer",
      });
    }

    // 2. Embedded JavaScript / JS Streams
    const jsMatches = rawString.match(/\/JavaScript|\/JS\b/g);
    if (jsMatches && jsMatches.length > 0) {
      indicators.push({
        id: "pdf.active.embedded_javascript",
        title: `Embedded JavaScript Detected (${jsMatches.length} references)`,
        description: "Document contains embedded JavaScript objects (/JavaScript, /JS). Malicious PDFs frequently use JavaScript to trigger reader exploits or dynamic downloads.",
        severity: "HIGH",
        weight: 25,
        confidence: 0.9,
        category: "active_content",
        source: "SentinelX PDF Analyzer",
      });
    }

    // 3. Auto-Execute Actions (/OpenAction, /AA)
    const openActionMatches = rawString.match(/\/OpenAction|\/AA\b/g);
    if (openActionMatches && openActionMatches.length > 0) {
      indicators.push({
        id: "pdf.active.open_action",
        title: "Automatic Execution Action (/OpenAction)",
        description: "Document specifies actions that trigger automatically when the file is opened by a viewer without explicit user interaction.",
        severity: "HIGH",
        weight: 25,
        confidence: 0.9,
        category: "active_content",
        source: "SentinelX PDF Analyzer",
      });
    }

    // 4. Launch Actions (/Launch) - Can spawn local processes
    const launchMatches = rawString.match(/\/Launch\b/g);
    if (launchMatches && launchMatches.length > 0) {
      indicators.push({
        id: "pdf.active.launch_action",
        title: "Process Launch Action (/Launch)",
        description: "Document contains /Launch directive designed to execute an external application or system command.",
        severity: "CRITICAL",
        weight: 40,
        confidence: 0.95,
        category: "active_content",
        source: "SentinelX PDF Analyzer",
      });
    }

    // 5. Embedded Files / Droppers (/EmbeddedFiles, /FileSpec)
    const embeddedFileMatches = rawString.match(/\/EmbeddedFiles|\/FileSpec\b/g);
    if (embeddedFileMatches && embeddedFileMatches.length > 0) {
      indicators.push({
        id: "pdf.active.embedded_files",
        title: "Embedded Dropper / Attached Files (/EmbeddedFiles)",
        description: "Document contains embedded secondary files within its stream data, commonly used as droppers for secondary payloads.",
        severity: "HIGH",
        weight: 25,
        confidence: 0.85,
        category: "suspicious_structure",
        source: "SentinelX PDF Analyzer",
      });
    }

    // 6. External URIs (/URI)
    const uriMatches = rawString.match(/\/URI\s*\((https?:\/\/[^)]+)\)/gi);
    if (uriMatches && uriMatches.length > 0) {
      indicators.push({
        id: "pdf.network.external_uri",
        title: `External URLs in Document (${uriMatches.length} links)`,
        description: `Document contains ${uriMatches.length} external hyperlinks linking out to the web.`,
        severity: "LOW",
        weight: 5,
        confidence: 0.9,
        category: "informational",
        source: "SentinelX PDF Analyzer",
      });
    }

    // 7. Clean baseline if no active/malicious indicators
    if (indicators.length === 0 && hasPdfHeader && hasEofMarker) {
      indicators.push({
        id: "pdf.struct.clean_static",
        title: "Clean PDF Static Structure",
        description: "Standard PDF structure verified with no embedded scripts, auto-actions, launch directives, or embedded dropper streams.",
        severity: "LOW",
        weight: 15,
        confidence: 0.9,
        category: "suspicious_structure",
        source: "SentinelX PDF Analyzer",
        mitigating: true,
      });
    }

    return indicators;
  }
}
