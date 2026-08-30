import React from "react";
import Link from "next/link";
import { Shield, Lock, FileCode, ExternalLink } from "lucide-react";

export const Footer: React.FC = () => {
  return (
    <footer className="w-full border-t border-slate-800/80 bg-slate-950 text-slate-400 py-12 px-4 sm:px-6 lg:px-8 mt-20">
      <div className="max-w-7xl mx-auto space-y-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="space-y-3 md:col-span-2">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              <span className="text-sm font-black tracking-tight text-slate-100">
                SENTINEL<span className="text-cyan-400">X</span> AI
              </span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed max-w-md">
              Protecting Every Click, Every Download, Every Payment. Built with deterministic static parsers, real-time threat intelligence feeds, bounded risk scoring, and AI contextualization.
            </p>
            <div className="text-[11px] font-mono text-slate-500">
              Architecture: Input → Validation → Static Inspection → Threat Intel → Risk Engine → AI Explanation
            </div>
          </div>

          <div className="space-y-2 text-xs">
            <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
              Security Analyzers
            </h4>
            <ul className="space-y-1.5 text-slate-400">
              <li>
                <Link href="/analyze?tab=file" className="hover:text-cyan-400 transition-colors">
                  📁 File Guardian (PE, PDF, Office, ZIP, APK)
                </Link>
              </li>
              <li>
                <Link href="/analyze?tab=message" className="hover:text-cyan-400 transition-colors">
                  💬 Message / Scam Analyzer
                </Link>
              </li>
              <li>
                <Link href="/analyze?tab=url" className="hover:text-cyan-400 transition-colors">
                  🔗 Link & Domain Reputation Engine
                </Link>
              </li>
            </ul>
          </div>

          <div className="space-y-2 text-xs">
            <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
              Platform & Governance
            </h4>
            <ul className="space-y-1.5 text-slate-400">
              <li>
                <Link href="/dashboard" className="hover:text-cyan-400 transition-colors">
                  Security Operations Dashboard
                </Link>
              </li>
              <li>
                <Link href="/history" className="hover:text-cyan-400 transition-colors">
                  Analysis Records Registry
                </Link>
              </li>
              <li className="text-slate-500 font-mono text-[10px] pt-1">
                Zero permanent storage of uploaded malware samples.
              </li>
            </ul>
          </div>
        </div>

        {/* Security Disclaimers */}
        <div className="border-t border-slate-800/80 pt-6 space-y-2 text-[11px] text-slate-500 leading-relaxed">
          <p>
            <strong>Security Disclaimer:</strong> SentinelX provides automated threat analysis based on bounded static rules, heuristic patterns, and external threat intelligence records. A clean verdict indicates no threats were detected in the performed automated checks; it is not an absolute guarantee of safety.
          </p>
          <p>
            <strong>AI Authorship Notice:</strong> Linguistic pattern analysis is probabilistic and does not prove artificial intelligence authorship.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-between pt-2 text-[10px] text-slate-600">
            <span>© {new Date().getFullYear()} SentinelX AI Cybersecurity Platform. All rights reserved.</span>
            <span>Version 1.0.0 (Production Quality Demo)</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
