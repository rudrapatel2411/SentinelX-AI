import React from "react";
import { UnifiedAnalyzer, AnalyzerTab } from "@/components/analyzer/UnifiedAnalyzer";

interface AnalyzeTypePageProps {
  params: {
    type: string;
  };
}

export default function AnalyzeTypePage({ params }: AnalyzeTypePageProps) {
  let tab: AnalyzerTab = "file";
  if (params.type === "message" || params.type === "link" || params.type === "url" || params.type === "file") {
    tab = params.type === "link" ? "url" : (params.type as AnalyzerTab);
  }

  const titles = {
    file: "File Guardian — Static Malware & Structure Inspection",
    message: "Message / Scam Analyzer — Fraud & Smishing Detection",
    url: "Link Analyzer — Domain Reputation & Brand Spoofing Check",
  };

  return (
    <div className="py-10 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-8">
      <div className="text-center space-y-2 max-w-2xl mx-auto">
        <h1 className="text-2xl sm:text-3xl font-black text-slate-100 tracking-tight">
          {titles[tab]}
        </h1>
        <p className="text-xs sm:text-sm text-slate-400">
          Deterministic rules • Real Threat Intelligence • AI Explanation
        </p>
      </div>

      <UnifiedAnalyzer initialTab={tab} />
    </div>
  );
}
