"use client";

import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Search, Database, Cpu, Lock } from "lucide-react";

interface ScanningAnimationProps {
  type: "file" | "message" | "url";
}

const SCAN_STEPS = {
  file: [
    { text: "Validating file signature & magic bytes...", icon: Lock },
    { text: "Computing SHA-256 cryptographic hashes...", icon: Shield },
    { text: "Executing bounded static structural inspection...", icon: Search },
    { text: "Querying VirusTotal threat intelligence catalog...", icon: Database },
    { text: "Evaluating deterministic risk engine...", icon: Cpu },
  ],
  message: [
    { text: "Extracting embedded entities (URLs, contacts, payment handles)...", icon: Search },
    { text: "Running multi-category scam & urgency heuristics...", icon: Shield },
    { text: "Evaluating credential harvest & coercion rules...", icon: Lock },
    { text: "Computing deterministic risk score...", icon: Cpu },
    { text: "Synthesizing AI context & linguistic indicators...", icon: Database },
  ],
  url: [
    { text: "Parsing URL syntax, protocol & domain structure...", icon: Search },
    { text: "Analyzing brand impersonation & homograph heuristics...", icon: Shield },
    { text: "Querying Google Safe Browsing threat lists...", icon: Database },
    { text: "Querying VirusTotal URL intelligence engines...", icon: Database },
    { text: "Computing deterministic risk classification...", icon: Cpu },
  ],
};

export const ScanningAnimation: React.FC<ScanningAnimationProps> = ({ type }) => {
  const steps = SCAN_STEPS[type];
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < steps.length - 1 ? prev + 1 : prev));
    }, 600);
    return () => clearInterval(interval);
  }, [steps.length]);

  const CurrentIcon = steps[currentStepIndex].icon;

  return (
    <div className="flex flex-col items-center justify-center p-8 text-center space-y-6">
      {/* Radar pulse radar animation */}
      <div className="relative flex items-center justify-center">
        <motion.div
          animate={{ scale: [1, 1.4, 1], opacity: [0.3, 0.7, 0.3] }}
          transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
          className="absolute w-24 h-24 rounded-full bg-cyan-500/10 border border-cyan-500/30"
        />
        <motion.div
          animate={{ scale: [1, 1.8, 1], opacity: [0.1, 0.4, 0.1] }}
          transition={{ duration: 2.5, repeat: Infinity, ease: "easeInOut" }}
          className="absolute w-28 h-28 rounded-full bg-cyan-500/5 border border-cyan-400/20"
        />
        <div className="relative z-10 w-16 h-16 rounded-2xl bg-slate-900 border border-cyan-500/40 flex items-center justify-center shadow-cyan-glow">
          <CurrentIcon className="w-8 h-8 text-cyan-400 animate-pulse" />
        </div>
      </div>

      <div className="space-y-2 max-w-md">
        <h4 className="text-lg font-bold text-slate-100 flex items-center justify-center gap-2">
          <span>SentinelX Security Analysis in Progress</span>
        </h4>
        <div className="h-6">
          <AnimatePresence mode="wait">
            <motion.p
              key={currentStepIndex}
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              className="text-xs font-mono text-cyan-300/90 tracking-wide"
            >
              {steps[currentStepIndex].text}
            </motion.p>
          </AnimatePresence>
        </div>
      </div>

      {/* Progress dots */}
      <div className="flex items-center space-x-2">
        {steps.map((_, idx) => (
          <div
            key={idx}
            className={`w-2 h-2 rounded-full transition-all duration-300 ${
              idx <= currentStepIndex
                ? "bg-cyan-400 shadow-[0_0_8px_#00e5ff]"
                : "bg-slate-800"
            }`}
          />
        ))}
      </div>
    </div>
  );
};
