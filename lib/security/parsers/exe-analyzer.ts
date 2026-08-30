import { SecurityIndicator } from "@/lib/types/security";

/**
 * Calculates Shannon entropy of a byte buffer (0.0 to 8.0)
 * High entropy (> 7.2) indicates compression, packing, or encryption
 */
function calculateEntropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0;
  const frequencies = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    frequencies[buffer[i]]++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / buffer.length;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

const SUSPICIOUS_APIS = [
  { name: "CreateRemoteThread", desc: "Process injection / thread hijacking", weight: 20, severity: "HIGH" as const },
  { name: "WriteProcessMemory", desc: "Process memory manipulation", weight: 20, severity: "HIGH" as const },
  { name: "VirtualAllocEx", desc: "Remote process memory allocation", weight: 20, severity: "HIGH" as const },
  { name: "URLDownloadToFile", desc: "Unattended secondary payload downloader", weight: 20, severity: "HIGH" as const },
  { name: "InternetOpenUrl", desc: "Outbound network connection initiation", weight: 10, severity: "MEDIUM" as const },
  { name: "SetWindowsHookEx", desc: "System keylogging / event hooking", weight: 20, severity: "HIGH" as const },
  { name: "IsDebuggerPresent", desc: "Anti-debugging / analysis evasion", weight: 15, severity: "MEDIUM" as const },
  { name: "AdjustTokenPrivileges", desc: "Privilege escalation attempt", weight: 15, severity: "MEDIUM" as const },
];

const KNOWN_PACKER_SECTIONS = ["upx0", "upx1", "upx2", ".vmp0", ".vmp1", ".themida", "aspack", "pecompact"];

export class ExeAnalyzer {
  public static analyze(buffer: Buffer): SecurityIndicator[] {
    const indicators: SecurityIndicator[] = [];

    // 1. Basic PE Header Parsing
    if (buffer.length < 64 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
      indicators.push({
        id: "exe.struct.invalid_mz",
        title: "Invalid DOS / PE Executable Header",
        description: "File does not begin with standard 'MZ' signature.",
        severity: "HIGH",
        weight: 20,
        confidence: 0.9,
        category: "suspicious_structure",
        source: "SentinelX PE Analyzer",
      });
      return indicators;
    }

    const peOffset = buffer.readUInt32LE(0x3c);
    if (peOffset + 4 > buffer.length || buffer.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0") {
      indicators.push({
        id: "exe.struct.invalid_pe",
        title: "Corrupted PE Signature",
        description: "File has valid MZ header but lacks standard 'PE\\0\\0' NT header structure.",
        severity: "HIGH",
        weight: 20,
        confidence: 0.9,
        category: "suspicious_structure",
        source: "SentinelX PE Analyzer",
      });
      return indicators;
    }

    // 2. Machine Architecture
    const machine = buffer.readUInt16LE(peOffset + 4);
    let archName = "Unknown Architecture";
    if (machine === 0x014c) archName = "x86 (32-bit)";
    else if (machine === 0x8664) archName = "x64 (64-bit AMD64)";
    else if (machine === 0xaa64) archName = "ARM64";

    indicators.push({
      id: "exe.info.architecture",
      title: `Windows Portable Executable (${archName})`,
      description: `Target is a native Windows binary compiled for ${archName}. Executables carry inherent capability to execute machine code.`,
      severity: "MEDIUM",
      weight: 15,
      confidence: 1.0,
      category: "active_content",
      source: "SentinelX PE Analyzer",
    });

    // 3. Section Headers & Entropy Calculation
    const numSections = buffer.readUInt16LE(peOffset + 6);
    const optHeaderSize = buffer.readUInt16LE(peOffset + 20);
    const sectionTableOffset = peOffset + 24 + optHeaderSize;

    let maxSectionEntropy = 0;
    let highestEntropySection = "";
    const sectionNames: string[] = [];
    let hasPackerSection = false;

    if (sectionTableOffset + numSections * 40 <= buffer.length) {
      for (let i = 0; i < Math.min(numSections, 16); i++) {
        const secOffset = sectionTableOffset + i * 40;
        const nameRaw = buffer.toString("ascii", secOffset, secOffset + 8).replace(/\0/g, "").trim().toLowerCase();
        sectionNames.push(nameRaw);

        if (KNOWN_PACKER_SECTIONS.includes(nameRaw)) {
          hasPackerSection = true;
        }

        const rawDataSize = buffer.readUInt32LE(secOffset + 16);
        const rawDataOffset = buffer.readUInt32LE(secOffset + 20);

        if (rawDataOffset + rawDataSize <= buffer.length && rawDataSize > 512) {
          const secBuffer = buffer.slice(rawDataOffset, rawDataOffset + rawDataSize);
          const entropy = calculateEntropy(secBuffer);
          if (entropy > maxSectionEntropy) {
            maxSectionEntropy = entropy;
            highestEntropySection = nameRaw;
          }
        }
      }
    }

    // Entropy indicator
    if (maxSectionEntropy >= 7.2) {
      indicators.push({
        id: "exe.entropy.packed_obfuscated",
        title: `High Section Entropy (${maxSectionEntropy.toFixed(2)}/8.0 in '${highestEntropySection}')`,
        description: `Section '${highestEntropySection}' exhibits high Shannon entropy (${maxSectionEntropy.toFixed(2)}), an indicator of packed, encrypted, or compressed code sections.`,
        severity: "HIGH",
        weight: 20,
        confidence: 0.85,
        category: "suspicious_structure",
        source: "SentinelX PE Analyzer",
      });
    }

    if (hasPackerSection) {
      indicators.push({
        id: "exe.packer.known_signature",
        title: "Packer / Crypter Section Signature Identified",
        description: "Binary contains section headers matching known runtime packers (UPX/VMProtect/Themida), often used to evade signature detection.",
        severity: "HIGH",
        weight: 25,
        confidence: 0.9,
        category: "suspicious_structure",
        source: "SentinelX PE Analyzer",
      });
    }

    // 4. Digital Signature Presence
    // Optional Header Magic: 0x10b (PE32) or 0x20b (PE32+)
    if (optHeaderSize > 0 && peOffset + 24 + 144 <= buffer.length) {
      const optMagic = buffer.readUInt16LE(peOffset + 24);
      let certDirOffset = 0;
      if (optMagic === 0x10b && optHeaderSize >= 136) {
        certDirOffset = peOffset + 24 + 128; // DataDirectory[4] for PE32
      } else if (optMagic === 0x20b && optHeaderSize >= 152) {
        certDirOffset = peOffset + 24 + 144; // DataDirectory[4] for PE32+
      }

      if (certDirOffset > 0 && certDirOffset + 8 <= buffer.length) {
        const certVirtualAddress = buffer.readUInt32LE(certDirOffset);
        const certSize = buffer.readUInt32LE(certDirOffset + 4);

        if (certVirtualAddress === 0 || certSize === 0) {
          indicators.push({
            id: "exe.cert.unsigned",
            title: "Unsigned Binary (No Authenticode Digital Signature)",
            description: "Binary lacks an embedded Authenticode digital signature table. Publisher identity cannot be cryptographically verified.",
            severity: "MEDIUM",
            weight: 15,
            confidence: 0.95,
            category: "reputation",
            source: "SentinelX PE Analyzer",
          });
        } else {
          indicators.push({
            id: "exe.cert.signed",
            title: "Authenticode Digital Signature Table Present",
            description: `Binary contains an embedded security certificate table (${certSize} bytes).`,
            severity: "LOW",
            weight: 10,
            confidence: 0.85,
            category: "reputation",
            source: "SentinelX PE Analyzer",
            mitigating: true,
          });
        }
      }
    }

    // 5. Suspicious API Import String Scanning
    const rawString = buffer.toString("binary");
    const matchedApis: string[] = [];

    for (const api of SUSPICIOUS_APIS) {
      if (rawString.includes(api.name)) {
        matchedApis.push(`${api.name} (${api.desc})`);
      }
    }

    if (matchedApis.length >= 2) {
      indicators.push({
        id: "exe.imports.suspicious_capabilities",
        title: `Suspicious Windows API Capabilities (${matchedApis.length} detected)`,
        description: `Static scan found references to high-risk APIs: ${matchedApis.slice(0, 3).join(", ")}. Commonly used for memory injection, keylogging, or stealth downloading.`,
        severity: "HIGH",
        weight: 25,
        confidence: 0.85,
        category: "active_content",
        source: "SentinelX PE Analyzer",
      });
    }

    return indicators;
  }
}
