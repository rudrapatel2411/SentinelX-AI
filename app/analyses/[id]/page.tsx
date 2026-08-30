"use client";

import React, { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { CommonAnalysisResult } from "@/lib/types/security";
import { AnalysisResultView } from "@/components/results/AnalysisResultView";
import Link from "next/link";
import { Shield, ArrowLeft, RotateCcw } from "lucide-react";

export default function AnalysisDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params?.id as string;

  const [analysis, setAnalysis] = useState<CommonAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const fetchAnalysis = async () => {
      setIsLoading(true);
      setErrorMsg(null);
      try {
        const res = await fetch(`/api/analyses/${id}`);
        const data = await res.json();
        if (data.success && data.analysis) {
          setAnalysis(data.analysis);
        } else {
          setErrorMsg(data.error || "Analysis report not found in records.");
        }
      } catch {
        setErrorMsg("Failed to retrieve analysis report.");
      } finally {
        setIsLoading(false);
      }
    };
    fetchAnalysis();
  }, [id]);

  if (isLoading) {
    return (
      <div className="py-20 px-4 max-w-4xl mx-auto text-center space-y-3 font-mono text-xs text-slate-400">
        <Shield className="w-8 h-8 text-cyan-400 animate-pulse mx-auto" />
        <p>Loading security audit report for {id}...</p>
      </div>
    );
  }

  if (errorMsg || !analysis) {
    return (
      <div className="py-20 px-4 max-w-xl mx-auto text-center space-y-6">
        <div className="p-8 rounded-2xl cyber-panel border-slate-800 space-y-4">
          <Shield className="w-10 h-10 text-slate-600 mx-auto" />
          <h2 className="text-lg font-bold text-slate-200">Analysis Record Not Found</h2>
          <p className="text-xs text-slate-400 font-mono">
            {errorMsg || `ID '${id}' does not match any stored analysis records.`}
          </p>
          <div className="pt-2 flex items-center justify-center gap-3">
            <Link
              href="/history"
              className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-semibold"
            >
              Browse Registry
            </Link>
            <Link
              href="/analyze"
              className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold shadow-cyan-glow"
            >
              Start New Analysis
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="py-10 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <Link
          href="/history"
          className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 font-mono transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Analysis Registry</span>
        </Link>
      </div>

      <AnalysisResultView
        analysis={analysis}
        onReset={() => router.push("/analyze")}
        onNavigateToLinkScan={(url) => router.push(`/analyze?tab=url&url=${encodeURIComponent(url)}`)}
      />
    </div>
  );
}
