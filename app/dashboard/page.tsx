"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { DashboardStats } from "@/lib/security/analysis-storage";
import { CommonAnalysisResult } from "@/lib/types/security";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Link as LinkIcon,
  MessageSquare,
  Activity,
  ArrowUpRight,
  Database,
  RotateCcw,
  Sparkles,
} from "lucide-react";

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchStats = async () => {
    setIsLoading(true);
    try {
      const res = await fetch("/api/analyses?mode=dashboard");
      const data = await res.json();
      if (data.success) {
        setStats(data.stats);
      }
    } catch {
      // ignore
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  return (
    <div className="py-10 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-slate-100 tracking-tight flex items-center gap-2">
            <Activity className="w-6 h-6 text-cyan-400" />
            <span>Security Operations Dashboard</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400">
            Real telemetry and threat distribution computed from actual analyses.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchStats}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          <Link
            href="/analyze"
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold shadow-cyan-glow transition-all"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>New Scan</span>
          </Link>
        </div>
      </div>

      {/* Database Offline Notice if applicable */}
      {stats && !stats.isDatabaseConnected && (
        <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800/60 text-amber-300 text-xs flex items-center gap-2.5">
          <Database className="w-4 h-4 shrink-0" />
          <span>
            Database persistence is currently in local session mode (PostgreSQL offline). Scans complete live with full technical results and in-memory scoring.
          </span>
        </div>
      )}

      {/* 4 Summary Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="cyber-panel rounded-2xl p-5 border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400 font-semibold uppercase tracking-wider">
            <span>Total Analyses</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-3xl sm:text-4xl font-black font-mono text-slate-100">
            {isLoading ? "..." : stats?.total ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Real-time scan counter</span>
        </div>

        <div className="cyber-panel rounded-2xl p-5 border-rose-900/30 space-y-2">
          <div className="flex items-center justify-between text-xs text-rose-400 font-semibold uppercase tracking-wider">
            <span>Dangerous Threats</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <p className="text-3xl sm:text-4xl font-black font-mono text-rose-400">
            {isLoading ? "..." : stats?.dangerous ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Risk score ≥ 70</span>
        </div>

        <div className="cyber-panel rounded-2xl p-5 border-amber-900/30 space-y-2">
          <div className="flex items-center justify-between text-xs text-amber-400 font-semibold uppercase tracking-wider">
            <span>Suspicious Items</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <p className="text-3xl sm:text-4xl font-black font-mono text-amber-400">
            {isLoading ? "..." : stats?.suspicious ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Risk score 30–69</span>
        </div>

        <div className="cyber-panel rounded-2xl p-5 border-emerald-900/30 space-y-2">
          <div className="flex items-center justify-between text-xs text-emerald-400 font-semibold uppercase tracking-wider">
            <span>Safe Items</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-3xl sm:text-4xl font-black font-mono text-emerald-400">
            {isLoading ? "..." : stats?.safe ?? 0}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">Risk score 0–29</span>
        </div>
      </div>

      {/* Threat Distribution & Recent Analyses */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Category Breakdown */}
        <div className="cyber-panel rounded-2xl p-6 border-slate-800 space-y-4">
          <h3 className="text-sm font-bold text-slate-200">
            Threat Indicators by Category
          </h3>

          {stats?.categoryBreakdown && stats.categoryBreakdown.length > 0 ? (
            <div className="space-y-3 pt-2">
              {stats.categoryBreakdown.map((cat, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium capitalize">
                      {cat.category.replace(/_/g, " ")}
                    </span>
                    <span className="font-mono font-bold text-cyan-400">{cat.count} flags</span>
                  </div>
                  <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-cyan-500 h-full rounded-full"
                      style={{ width: `${Math.min(100, cat.count * 15)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-xs text-slate-500 font-mono space-y-1">
              <p>No threat indicators logged yet.</p>
              <p className="text-[10px]">Execute a scan in the Analyzer to populate metrics.</p>
            </div>
          )}
        </div>

        {/* Recent Analyses List */}
        <div className="cyber-panel rounded-2xl p-6 border-slate-800 space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200">Recent Security Analyses</h3>
            <Link
              href="/history"
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1"
            >
              <span>View All</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {stats?.recentAnalyses && stats.recentAnalyses.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                    <th className="pb-3">Analysis ID</th>
                    <th className="pb-3">Type</th>
                    <th className="pb-3">Target</th>
                    <th className="pb-3">Score</th>
                    <th className="pb-3">Classification</th>
                    <th className="pb-3 text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {stats.recentAnalyses.map((item: CommonAnalysisResult) => (
                    <tr key={item.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-3 text-slate-300 font-bold">
                        <Link href={`/analyses/${item.id}`} className="hover:text-cyan-400 underline">
                          {item.id}
                        </Link>
                      </td>
                      <td className="py-3">
                        <span className="flex items-center gap-1 text-slate-400 uppercase text-[10px]">
                          {item.type === "file" && <FileText className="w-3 h-3 text-cyan-400" />}
                          {item.type === "url" && <LinkIcon className="w-3 h-3 text-cyan-400" />}
                          {item.type === "message" && <MessageSquare className="w-3 h-3 text-cyan-400" />}
                          <span>{item.type}</span>
                        </span>
                      </td>
                      <td className="py-3 text-slate-200 font-sans max-w-[180px] truncate">
                        {item.target}
                      </td>
                      <td className="py-3 font-bold text-slate-100">
                        {item.riskScore}/100
                      </td>
                      <td className="py-3">
                        <RiskBadge classification={item.classification} size="sm" showIcon={false} />
                      </td>
                      <td className="py-3 text-right text-slate-500 text-[10px]">
                        {new Date(item.createdAt).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-12 text-center text-xs text-slate-500 font-mono space-y-3">
              <p>No analyses recorded in database yet.</p>
              <Link
                href="/analyze"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-xs font-semibold hover:bg-cyan-500/20 transition-colors"
              >
                <span>Run Your First Analysis</span>
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
