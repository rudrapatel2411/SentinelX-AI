"use client";

import React from "react";
import { Link as LinkIcon, Sparkles, Globe } from "lucide-react";

interface LinkInputProps {
  value: string;
  onChange: (val: string) => void;
  disabled?: boolean;
}

const LINK_PRESETS = [
  {
    label: "PayPal Phishing Lookalike",
    color: "text-rose-400 border-rose-900/40",
    url: "https://paypa1-security-verification.xyz/login?session=active",
  },
  {
    label: "Raw IP Hostname",
    color: "text-amber-400 border-amber-900/40",
    url: "http://192.168.1.100/admin/auth.php",
  },
  {
    label: "Legitimate Brand Domain",
    color: "text-emerald-400 border-emerald-900/40",
    url: "https://www.paypal.com/signin",
  },
  {
    label: "Subdomain Fronting",
    color: "text-amber-400 border-amber-900/40",
    url: "https://accounts.google.com.security-verify.top/update",
  },
];

export const LinkInput: React.FC<LinkInputProps> = ({
  value,
  onChange,
  disabled = false,
}) => {
  return (
    <div className="space-y-4">
      <div className="relative flex items-center">
        <div className="absolute left-4 text-cyan-400 pointer-events-none">
          <Globe className="w-5 h-5" />
        </div>
        <input
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          placeholder="Enter or paste URL (e.g. https://suspicious-domain.xyz/login)..."
          className="w-full pl-12 pr-4 py-4 rounded-2xl bg-slate-950/60 border border-slate-800 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 font-mono transition-all"
        />
      </div>

      <div className="flex items-center justify-between text-xs text-slate-500">
        <span className="flex items-center gap-1.5">
          <LinkIcon className="w-3.5 h-3.5 text-cyan-400" />
          Analyzes domain reputation, SSL transport, brand spoofing & threat intelligence
        </span>
      </div>

      {/* Preset Test Scenarios */}
      <div className="space-y-2 pt-1">
        <span className="text-xs font-semibold text-slate-400 flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          Test Presets (Click to load):
        </span>
        <div className="flex flex-wrap gap-2">
          {LINK_PRESETS.map((preset, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => onChange(preset.url)}
              disabled={disabled}
              className={`px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border text-xs font-medium font-mono transition-colors ${preset.color}`}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
