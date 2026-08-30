"use client";

import React from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { UnifiedAnalyzer } from "@/components/analyzer/UnifiedAnalyzer";
import {
  Shield,
  FileText,
  MessageSquare,
  Link as LinkIcon,
  CheckCircle2,
  Lock,
  Cpu,
  Database,
  Sparkles,
  ArrowRight,
  ShieldAlert,
  ChevronRight,
} from "lucide-react";

export default function HomePage() {
  return (
    <div className="space-y-24 py-10 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      {/* 1. Hero Section with Integrated Scanner */}
      <section className="text-center space-y-8 pt-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="space-y-4 max-w-4xl mx-auto"
        >
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-950/80 border border-cyan-500/30 text-cyan-300 text-xs font-mono shadow-cyan-glow">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>Deterministic Security • Threat Intelligence • AI Explanation</span>
          </div>

          <h1 className="text-3xl sm:text-5xl lg:text-6xl font-black text-slate-100 tracking-tight leading-tight">
            Protecting Every Click, <br className="hidden sm:inline" />
            <span className="bg-gradient-to-r from-cyan-400 via-cyan-300 to-indigo-400 bg-clip-text text-transparent">
              Every Download, Every Payment.
            </span>
          </h1>

          <p className="text-sm sm:text-base text-slate-400 max-w-2xl mx-auto leading-relaxed">
            SentinelX AI inspects suspicious files, messages, and links using deterministic static parsers, live threat intelligence feeds, and transparent risk scoring.
          </p>
        </motion.div>

        {/* Unified Analyzer Component */}
        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="pt-2"
        >
          <UnifiedAnalyzer />
        </motion.div>
      </section>

      {/* 2. Three Dedicated Security Modules */}
      <section className="space-y-10">
        <div className="text-center space-y-2">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-slate-100">
            Three Specialized Security Engines
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto">
            Each module executes format-specific static parsers and deterministic heuristics before calculating a shared risk score.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Module 1: File Guardian */}
          <div className="cyber-panel cyber-panel-hover rounded-2xl p-6 space-y-4 border-slate-800 transition-all flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-12 h-12 rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-cyan-glow">
                <FileText className="w-6 h-6" />
              </div>
              <h3 className="text-lg font-bold text-slate-100">📁 File Guardian</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Safe static structural inspection for PDF, Office OOXML, ZIP archives, Windows PE binaries, and Android APKs. Detects embedded macros, JavaScript, auto-actions, and extension spoofing.
              </p>
              <ul className="space-y-1.5 text-xs text-slate-300">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>SHA-256 / SHA-1 / MD5 hashes</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Magic bytes spoofing detection</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>VirusTotal SHA-256 hash lookup</span>
                </li>
              </ul>
            </div>
            <Link
              href="/analyze?tab=file"
              className="inline-flex items-center gap-1 text-xs font-bold text-cyan-400 hover:text-cyan-300 pt-2"
            >
              <span>Scan a File</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Module 2: Message / Scam Analyzer */}
          <div className="cyber-panel cyber-panel-hover rounded-2xl p-6 space-y-4 border-slate-800 transition-all flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-12 h-12 rounded-xl bg-indigo-950/80 border border-indigo-500/40 flex items-center justify-center text-indigo-400 shadow-indigo-glow">
                <MessageSquare className="w-6 h-6" />
              </div>
              <h3 className="text-lg font-bold text-slate-100">💬 Message / Scam Analyzer</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Natural entity extraction for URLs, phone numbers, UPI handles, crypto addresses, and monetary amounts. Identifies banking OTP theft, lottery lures, courier smishing, and investment scams.
              </p>
              <ul className="space-y-1.5 text-xs text-slate-300">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Multi-category scam heuristics</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
                  <span>1-Click Extracted URL inspection</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Linguistic AI-writing estimate</span>
                </li>
              </ul>
            </div>
            <Link
              href="/analyze?tab=message"
              className="inline-flex items-center gap-1 text-xs font-bold text-indigo-400 hover:text-indigo-300 pt-2"
            >
              <span>Analyze a Message</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Module 3: Link Analyzer */}
          <div className="cyber-panel cyber-panel-hover rounded-2xl p-6 space-y-4 border-slate-800 transition-all flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-12 h-12 rounded-xl bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-safe-glow">
                <LinkIcon className="w-6 h-6" />
              </div>
              <h3 className="text-lg font-bold text-slate-100">🔗 Link Analyzer</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Full URL syntax parsing, protocol inspection, IP host detection, and brand typosquatting heuristics across protected brand lists (PayPal, Google, Apple, SBI, HDFC, Netflix).
              </p>
              <ul className="space-y-1.5 text-xs text-slate-300">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Brand typosquatting & homographs</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Google Safe Browsing API check</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>VirusTotal URL vendor telemetry</span>
                </li>
              </ul>
            </div>
            <Link
              href="/analyze?tab=url"
              className="inline-flex items-center gap-1 text-xs font-bold text-emerald-400 hover:text-emerald-300 pt-2"
            >
              <span>Scan a URL</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </section>

      {/* 3. Core Architecture: How SentinelX Actually Works */}
      <section className="cyber-panel rounded-3xl p-8 border-slate-800 space-y-8">
        <div className="text-center space-y-2 max-w-2xl mx-auto">
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest font-bold">
            Security Engineering Philosophy
          </span>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-slate-100">
            How SentinelX Evaluates Threats
          </h2>
          <p className="text-xs sm:text-sm text-slate-400">
            SentinelX is NOT an AI wrapper. Technical evidence and threat intelligence determine the verdict; AI is used purely to explain findings to humans.
          </p>
        </div>

        {/* Visual Pipeline Flow */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 text-center">
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-slate-800 text-cyan-400 flex items-center justify-center mx-auto font-mono text-xs font-bold">
              01
            </div>
            <h4 className="text-xs font-bold text-slate-200">Input Validation</h4>
            <p className="text-[11px] text-slate-400">Magic bytes, RFC 3986 URL parsing, sanitize & hash</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-slate-800 text-cyan-400 flex items-center justify-center mx-auto font-mono text-xs font-bold">
              02
            </div>
            <h4 className="text-xs font-bold text-slate-200">Static Inspection</h4>
            <p className="text-[11px] text-slate-400">PE headers, PDF JS streams, VBA macros, scam rules</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-slate-800 text-cyan-400 flex items-center justify-center mx-auto font-mono text-xs font-bold">
              03
            </div>
            <h4 className="text-xs font-bold text-slate-200">Threat Intel Feeds</h4>
            <p className="text-[11px] text-slate-400">Live VirusTotal hash/URL & Google Safe Browsing</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center justify-center mx-auto font-mono text-xs font-bold shadow-cyan-glow">
              04
            </div>
            <h4 className="text-xs font-bold text-cyan-300">Global Risk Engine</h4>
            <p className="text-[11px] text-slate-300">Weighted scores (0–100), diminishing returns</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-indigo-950 text-indigo-300 border border-indigo-800 flex items-center justify-center mx-auto font-mono text-xs font-bold">
              05
            </div>
            <h4 className="text-xs font-bold text-indigo-300">AI Context Layer</h4>
            <p className="text-[11px] text-slate-400">Prompt-guarded summary & protective actions</p>
          </div>
        </div>
      </section>
    </div>
  );
}
