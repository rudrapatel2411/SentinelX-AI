"use client";

import React, { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { UnifiedAnalyzer, AnalyzerTab } from "@/components/analyzer/UnifiedAnalyzer";

function AnalyzeContent() {
  const searchParams = useSearchParams();
  const tabParam = searchParams.get("tab");
  const urlParam = searchParams.get("url") || "";

  let initialTab: AnalyzerTab = "file";
  if (tabParam === "message" || tabParam === "url" || tabParam === "file") {
    initialTab = tabParam;
  }

  return (
    <div className="py-10 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-8">
      <div className="text-center space-y-2 max-w-2xl mx-auto">
        <h1 className="text-3xl font-black text-slate-100 tracking-tight">
          SentinelX AI Security Analyzer
        </h1>
        <p className="text-xs sm:text-sm text-slate-400">
          Upload a file, paste an unverified message, or submit a URL for real-time security assessment.
        </p>
      </div>

      <UnifiedAnalyzer initialTab={initialTab} initialUrl={urlParam} />
    </div>
  );
}

export default function AnalyzePage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-slate-500 font-mono">Loading SentinelX Analyzer...</div>}>
      <AnalyzeContent />
    </Suspense>
  );
}
