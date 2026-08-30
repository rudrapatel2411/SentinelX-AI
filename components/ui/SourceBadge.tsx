import React from "react";
import { Severity } from "@/lib/types/security";

interface SourceBadgeProps {
  source: string;
}

export const SourceBadge: React.FC<SourceBadgeProps> = ({ source }) => {
  let badgeStyle = "bg-slate-800 text-slate-300 border-slate-700";

  if (source.includes("VirusTotal")) {
    badgeStyle = "bg-blue-950/70 text-blue-300 border-blue-800/80";
  } else if (source.includes("Google Safe Browsing")) {
    badgeStyle = "bg-emerald-950/70 text-emerald-300 border-emerald-800/80";
  } else if (source.includes("PDF")) {
    badgeStyle = "bg-rose-950/70 text-rose-300 border-rose-800/80";
  } else if (source.includes("Office")) {
    badgeStyle = "bg-orange-950/70 text-orange-300 border-orange-800/80";
  } else if (source.includes("URL")) {
    badgeStyle = "bg-cyan-950/70 text-cyan-300 border-cyan-800/80";
  } else if (source.includes("Message")) {
    badgeStyle = "bg-purple-950/70 text-purple-300 border-purple-800/80";
  } else if (source.includes("PE") || source.includes("APK")) {
    badgeStyle = "bg-amber-950/70 text-amber-300 border-amber-800/80";
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border font-mono ${badgeStyle}`}
    >
      {source}
    </span>
  );
};

interface SeverityPillProps {
  severity: Severity;
  mitigating?: boolean;
}

export const SeverityPill: React.FC<SeverityPillProps> = ({ severity, mitigating }) => {
  if (mitigating) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider bg-emerald-950/60 text-emerald-300 border border-emerald-700/60">
        Mitigation
      </span>
    );
  }

  switch (severity) {
    case "CRITICAL":
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider bg-rose-950 text-rose-300 border border-rose-700">
          Critical
        </span>
      );
    case "HIGH":
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider bg-red-950/80 text-red-300 border border-red-800">
          High
        </span>
      );
    case "MEDIUM":
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider bg-amber-950/80 text-amber-300 border border-amber-800">
          Medium
        </span>
      );
    case "LOW":
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider bg-slate-800 text-slate-300 border border-slate-700">
          Low
        </span>
      );
  }
};
