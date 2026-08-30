"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { CommonAnalysisResult } from "@/lib/types/security";
import {
  History,
  Search,
  FileText,
  Link as LinkIcon,
  MessageSquare,
  Filter,
  RotateCcw,
  ExternalLink,
  Shield,
} from "lucide-react";

export default function HistoryPage() {
  const [analyses, setAnalyses] = useState<CommonAnalysisResult[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState<"all" | "file" | "message" | "url">("all");
  const [filterClassification, setFilterClassification] = useState<"all" | "SAFE" | "SUSPICIOUS" | "DANGEROUS">("all");
  const [isLoading, setIsLoading] = useState(true);
  const [dbConnected, setDbConnected] = useState(true);

  const fetchAnalyses = async () => {
    setIsLoading(true);
    try {
      const res = await fetch("/api/analyses?limit=50");
      const data = await res.json();
      if (data.success) {
        setAnalyses(data.analyses || []);
        setDbConnected(data.dbConnected);
      }
    } catch {
      // ignore
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyses();
  }, []);

  const filteredItems = analyses.filter((item) => {
    const matchesSearch =
      item.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.target.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === "all" || item.type === filterType;
    const matchesClass = filterClassification === "all" || item.classification === filterClassification;
    return matchesSearch && matchesType && matchesClass;
  });

  return (
    <div className="py-10 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-slate-100 tracking-tight flex items-center gap-2">
            <History className="w-6 h-6 text-cyan-400" />
            <span>Analysis Records Registry</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400">
            Historical audit logs and security evidence reports.
          </p>
        </div>

        <button
          onClick={fetchAnalyses}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {!dbConnected && (
        <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800/60 text-amber-300 text-xs">
          Database is offline in local environment. Analysis history is stored when PostgreSQL is running.
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="cyber-panel rounded-2xl p-4 border-slate-800 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by Analysis ID or target file/url/text..."
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
          />
        </div>

        {/* Type & Severity Filters */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value as any)}
            className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 font-medium focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Modules</option>
            <option value="file">📁 Files</option>
            <option value="message">💬 Messages</option>
            <option value="url">🔗 Links</option>
          </select>

          <select
            value={filterClassification}
            onChange={(e) => setFilterClassification(e.target.value as any)}
            className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 font-medium focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Classifications</option>
            <option value="DANGEROUS">🔴 Dangerous</option>
            <option value="SUSPICIOUS">🟡 Suspicious</option>
            <option value="SAFE">🟢 Safe</option>
          </select>
        </div>
      </div>

      {/* Analysis Records Table */}
      <div className="cyber-panel rounded-2xl border-slate-800 overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center text-xs font-mono text-slate-500">
            Loading security logs...
          </div>
        ) : filteredItems.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 font-mono text-[11px]">
                  <th className="py-3.5 px-4">Analysis ID</th>
                  <th className="py-3.5 px-4">Module</th>
                  <th className="py-3.5 px-4">Target Content</th>
                  <th className="py-3.5 px-4">Score</th>
                  <th className="py-3.5 px-4">Classification</th>
                  <th className="py-3.5 px-4">Indicators</th>
                  <th className="py-3.5 px-4">Timestamp</th>
                  <th className="py-3.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredItems.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3.5 px-4 font-mono font-bold text-slate-200">
                      <Link href={`/analyses/${item.id}`} className="hover:text-cyan-400 underline">
                        {item.id}
                      </Link>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="flex items-center gap-1 text-slate-400 uppercase text-[10px] font-mono">
                        {item.type === "file" && <FileText className="w-3 h-3 text-cyan-400" />}
                        {item.type === "url" && <LinkIcon className="w-3 h-3 text-cyan-400" />}
                        {item.type === "message" && <MessageSquare className="w-3 h-3 text-cyan-400" />}
                        <span>{item.type}</span>
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 max-w-[240px] truncate font-sans">
                      {item.target}
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold text-slate-100">
                      {item.riskScore}/100
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskBadge classification={item.classification} size="sm" showIcon={false} />
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-400">
                      {item.indicators?.length || 0} flags
                    </td>
                    <td className="py-3.5 px-4 text-slate-500 font-mono text-[11px]">
                      {new Date(item.createdAt).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <Link
                        href={`/analyses/${item.id}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-cyan-400 text-[11px] font-mono transition-colors"
                      >
                        <span>View</span>
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-16 text-center text-xs text-slate-500 font-mono space-y-3">
            <Shield className="w-8 h-8 text-slate-700 mx-auto" />
            <p>No analyses match your search or filter parameters.</p>
          </div>
        )}
      </div>
    </div>
  );
}
