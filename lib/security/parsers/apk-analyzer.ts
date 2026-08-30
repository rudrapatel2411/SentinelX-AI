import JSZip from "jszip";
import { SecurityIndicator } from "@/lib/types/security";

const HIGH_RISK_PERMISSIONS: Record<string, { desc: string; severity: "HIGH" | "CRITICAL"; weight: number }> = {
  "BIND_ACCESSIBILITY_SERVICE": { desc: "Accessibility Service Abuse (Primary vector for Android Banking Trojans to read screen and inject keystrokes)", severity: "CRITICAL", weight: 35 },
  "SEND_SMS": { desc: "Send SMS without user confirmation (Toll fraud / SMS botnets)", severity: "HIGH", weight: 20 },
  "READ_SMS": { desc: "Read SMS messages (Intercept banking OTPs / 2FA)", severity: "HIGH", weight: 25 },
  "RECEIVE_SMS": { desc: "Intercept incoming SMS messages", severity: "HIGH", weight: 20 },
  "SYSTEM_ALERT_WINDOW": { desc: "Display overlay windows over other applications (Phishing credential overlays)", severity: "HIGH", weight: 25 },
  "REQUEST_INSTALL_PACKAGES": { desc: "Install secondary APK packages silently (Dropper capability)", severity: "HIGH", weight: 20 },
  "RECEIVE_BOOT_COMPLETED": { desc: "Auto-start background services upon device boot", severity: "HIGH", weight: 10 },
  "RECORD_AUDIO": { desc: "Record audio through device microphone", severity: "HIGH", weight: 15 },
  "READ_CONTACTS": { desc: "Access user contacts database", severity: "HIGH", weight: 15 },
  "CAMERA": { desc: "Access device camera", severity: "HIGH", weight: 15 },
};

export class ApkAnalyzer {
  public static async analyze(buffer: Buffer): Promise<SecurityIndicator[]> {
    const indicators: SecurityIndicator[] = [];

    try {
      const zip = await JSZip.loadAsync(buffer);
      const fileNames = Object.keys(zip.files);

      const hasManifest = fileNames.includes("AndroidManifest.xml");
      const dexFiles = fileNames.filter((n) => n.endsWith(".dex"));
      const nativeLibs = fileNames.filter((n) => n.startsWith("lib/") && n.endsWith(".so"));

      if (!hasManifest) {
        indicators.push({
          id: "apk.struct.missing_manifest",
          title: "Missing AndroidManifest.xml",
          description: "Archive lacks the core Android manifest file required for valid APK packages.",
          severity: "HIGH",
          weight: 20,
          confidence: 0.9,
          category: "suspicious_structure",
          source: "SentinelX APK Analyzer",
        });
        return indicators;
      }

      indicators.push({
        id: "apk.info.package_structure",
        title: `Android Application Package (${dexFiles.length} DEX, ${nativeLibs.length} Native Libs)`,
        description: `Package contains ${dexFiles.length} compiled Dalvik executable(s) and ${nativeLibs.length} native shared binary libraries.`,
        severity: "LOW",
        weight: 0,
        confidence: 1.0,
        category: "informational",
        source: "SentinelX APK Analyzer",
      });

      // Inspect AndroidManifest.xml binary strings
      const manifestFile = zip.file("AndroidManifest.xml");
      if (manifestFile) {
        const manifestBuffer = await manifestFile.async("nodebuffer");
        const rawString = manifestBuffer.toString("binary");

        const foundPermissions: string[] = [];
        let hasAccessibilityAbuse = false;

        for (const [perm, data] of Object.entries(HIGH_RISK_PERMISSIONS)) {
          if (rawString.includes(perm)) {
            foundPermissions.push(`${perm}: ${data.desc}`);
            if (perm === "BIND_ACCESSIBILITY_SERVICE") {
              hasAccessibilityAbuse = true;
            }
          }
        }

        if (hasAccessibilityAbuse) {
          indicators.push({
            id: "apk.perm.accessibility_abuse",
            title: "Critical Accessibility Service Permission Requested",
            description: "APK requests 'BIND_ACCESSIBILITY_SERVICE'. Malicious Android banking apps and spyware exploit this permission to steal credentials from other banking apps and simulate touch actions.",
            severity: "CRITICAL",
            weight: 35,
            confidence: 0.95,
            category: "active_content",
            source: "SentinelX APK Analyzer",
          });
        }

        if (foundPermissions.length > 0) {
          indicators.push({
            id: "apk.perm.high_risk_permissions",
            title: `High-Risk Android Permissions Requested (${foundPermissions.length} permissions)`,
            description: `Manifest requests sensitive device capabilities: ${foundPermissions.slice(0, 3).join("; ")}. Note: Permissions are functional indicators; evaluate with app purpose.`,
            severity: foundPermissions.length >= 3 ? "HIGH" : "MEDIUM",
            weight: Math.min(30, foundPermissions.length * 8),
            confidence: 0.85,
            category: "active_content",
            source: "SentinelX APK Analyzer",
          });
        }
      }

      // Check for hidden secondary DEX/JAR/APK inside assets or resources (Common in droppers)
      const hiddenPayloads = fileNames.filter(
        (n) =>
          (n.startsWith("assets/") || n.startsWith("res/")) &&
          (n.endsWith(".dex") || n.endsWith(".jar") || n.endsWith(".apk") || n.endsWith(".bin"))
      );

      if (hiddenPayloads.length > 0) {
        indicators.push({
          id: "apk.payload.hidden_asset_binaries",
          title: `Encapsulated Binary Payloads in Assets (${hiddenPayloads.length} files)`,
          description: `APK packages secondary executable payloads in asset folders: ${hiddenPayloads.slice(0, 3).join(", ")}. Often unpacked dynamically at runtime.`,
          severity: "HIGH",
          weight: 25,
          confidence: 0.9,
          category: "suspicious_structure",
          source: "SentinelX APK Analyzer",
        });
      }
    } catch {
      indicators.push({
        id: "apk.struct.corrupt",
        title: "Corrupted APK Package Structure",
        description: "File could not be decompressed as a valid Android APK archive.",
        severity: "HIGH",
        weight: 20,
        confidence: 0.85,
        category: "suspicious_structure",
        source: "SentinelX APK Analyzer",
      });
    }

    return indicators;
  }
}
