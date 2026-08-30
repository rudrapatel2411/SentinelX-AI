"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FileDropzone } from "@/components/analyzer/FileDropzone";
import { MessageInput } from "@/components/analyzer/MessageInput";
import { LinkInput } from "@/components/analyzer/LinkInput";
import { ScanningAnimation } from "@/components/ui/ScanningAnimation";
import { AnalysisResultView } from "@/components/results/AnalysisResultView";
import { CommonAnalysisResult } from "@/lib/types/security";
import {
  FileText,
  MessageSquare,
  Link as LinkIcon,
  ShieldCheck,
  AlertCircle,
  ArrowRight,
} from "lucide-react";

export type AnalyzerTab = "file" | "message" | "url";

interface UnifiedAnalyzerProps {
  initialTab?: AnalyzerTab;
  initialUrl?: string;
}

export const UnifiedAnalyzer: React.FC<UnifiedAnalyzerProps> = ({
  initialTab = "file",
  initialUrl = "",
}) => {
  const [activeTab, setActiveTab] = useState<AnalyzerTab>(initialTab);

  // Input states
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [messageText, setMessageText] = useState("");
  const [urlText, setUrlText] = useState(initialUrl);

  // Execution states
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<CommonAnalysisResult | null>(null);

  const handleReset = () => {
    setAnalysisResult(null);
    setErrorMsg(null);
  };

  const handleNavigateToLinkScan = (url: string) => {
    setActiveTab("url");
    setUrlText(url);
    setAnalysisResult(null);
    setErrorMsg(null);
  };

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setErrorMsg(null);

    if (activeTab === "file" && !selectedFile) {
      setErrorMsg("Please select or drop a file to analyze.");
      return;
    }
    if (activeTab === "message" && !messageText.trim()) {
      setErrorMsg("Please paste or type a message to analyze.");
      return;
    }
    if (activeTab === "url" && !urlText.trim()) {
      setErrorMsg("Please enter a URL to analyze.");
      return;
    }

    setIsLoading(true);

    try {
      if (activeTab === "file") {
        const formData = new FormData();
        formData.append("file", selectedFile!);

        const res = await fetch("/api/analyze/file", {
          method: "POST",
          body: formData,
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || "File scan failed.");
        }
        setAnalysisResult(data.analysis);
      } else if (activeTab === "message") {
        const res = await fetch("/api/analyze/message", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: messageText.trim() }),
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || "Message scan failed.");
        }
        setAnalysisResult(data.analysis);
      } else if (activeTab === "url") {
        const res = await fetch("/api/analyze/link", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: urlText.trim() }),
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || "URL scan failed.");
        }
        setAnalysisResult(data.analysis);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Analysis request failed";
      setErrorMsg(msg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6">
      {/* If an analysis result is present, display full report */}
      {analysisResult ? (
        <AnalysisResultView
          analysis={analysisResult}
          onReset={handleReset}
          onNavigateToLinkScan={handleNavigateToLinkScan}
        />
      ) : (
        <div className="cyber-panel rounded-3xl p-6 md:p-8 border-slate-800 shadow-2xl relative overflow-hidden">
          {/* Top subtle glow banner */}
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-indigo-500 to-cyan-400" />

          {/* Tab Selector */}
          <div className="flex items-center justify-center p-1.5 rounded-2xl bg-slate-950/80 border border-slate-800 max-w-lg mx-auto mb-8">
            <button
              type="button"
              onClick={() => {
                setActiveTab("file");
                setErrorMsg(null);
              }}
              disabled={isLoading}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 px-3 rounded-xl text-xs md:text-sm font-bold transition-all ${
                activeTab === "file"
                  ? "bg-cyan-500 text-slate-950 shadow-cyan-glow"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>File Guardian</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setActiveTab("message");
                setErrorMsg(null);
              }}
              disabled={isLoading}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 px-3 rounded-xl text-xs md:text-sm font-bold transition-all ${
                activeTab === "message"
                  ? "bg-cyan-500 text-slate-950 shadow-cyan-glow"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <MessageSquare className="w-4 h-4" />
              <span>Message / Scam</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setActiveTab("url");
                setErrorMsg(null);
              }}
              disabled={isLoading}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 px-3 rounded-xl text-xs md:text-sm font-bold transition-all ${
                activeTab === "url"
                  ? "bg-cyan-500 text-slate-950 shadow-cyan-glow"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <LinkIcon className="w-4 h-4" />
              <span>Link Analyzer</span>
            </button>
          </div>

          {/* Loading Animation during active scan */}
          {isLoading ? (
            <ScanningAnimation type={activeTab} />
          ) : (
            <form onSubmit={handleSubmit} className="space-y-6">
              <AnimatePresence mode="wait">
                <motion.div
                  key={activeTab}
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -10 }}
                  transition={{ duration: 0.2 }}
                >
                  {activeTab === "file" && (
                    <FileDropzone
                      onFileSelected={(file) => {
                        setSelectedFile(file);
                        setErrorMsg(null);
                      }}
                      disabled={isLoading}
                    />
                  )}

                  {activeTab === "message" && (
                    <MessageInput
                      value={messageText}
                      onChange={(val) => {
                        setMessageText(val);
                        setErrorMsg(null);
                      }}
                      disabled={isLoading}
                    />
                  )}

                  {activeTab === "url" && (
                    <LinkInput
                      value={urlText}
                      onChange={(val) => {
                        setUrlText(val);
                        setErrorMsg(null);
                      }}
                      disabled={isLoading}
                    />
                  )}
                </motion.div>
              </AnimatePresence>

              {errorMsg && (
                <motion.div
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="p-3.5 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2"
                >
                  <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                  <span>{errorMsg}</span>
                </motion.div>
              )}

              {/* Submit CTA Button */}
              <div className="flex items-center justify-center pt-2">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full sm:w-auto px-8 py-4 rounded-xl bg-gradient-to-r from-cyan-500 to-cyan-400 hover:from-cyan-400 hover:to-cyan-300 text-slate-950 font-black text-sm md:text-base flex items-center justify-center gap-2.5 shadow-cyan-glow transition-all active:scale-[0.99]"
                >
                  <ShieldCheck className="w-5 h-5" />
                  <span>Analyze with SentinelX</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </div>
  );
};
