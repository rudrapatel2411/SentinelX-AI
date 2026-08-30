"use client";

import React from "react";
import { MessageSquare, Sparkles, AlertCircle } from "lucide-react";

interface MessageInputProps {
  value: string;
  onChange: (val: string) => void;
  disabled?: boolean;
}

const MESSAGE_PRESETS = [
  {
    label: "Banking / KYC Suspension Scam",
    color: "text-rose-400 border-rose-900/40",
    text: "Dear customer, your SBI bank account will be blocked today due to pending KYC verification. Please click https://sbi-kyc-verify.xyz/login immediately to update PAN and verify your OTP with the security officer.",
  },
  {
    label: "Advance-Fee Lottery / Prize Scam",
    color: "text-amber-400 border-amber-900/40",
    text: "Congratulations! You have been selected as the lucky winner of ₹50,000 cash prize. Pay a small processing fee of ₹499 to claim@okhdfcbank to release your reward funds within 24 hours.",
  },
  {
    label: "Courier / Delivery Smishing",
    color: "text-amber-400 border-amber-900/40",
    text: "USPS Notice: Your postal package could not be delivered due to incomplete shipping address. Reschedule delivery immediately at https://usps-redelivery-tracking.top/confirm to avoid parcel return to sender.",
  },
  {
    label: "Safe Benign Message",
    color: "text-emerald-400 border-emerald-900/40",
    text: "Hi Alex, can you review the quarterly cybersecurity audit slides before our meeting at 3 PM today? Thanks!",
  },
];

export const MessageInput: React.FC<MessageInputProps> = ({
  value,
  onChange,
  disabled = false,
}) => {
  return (
    <div className="space-y-4">
      <div className="relative">
        <textarea
          rows={6}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          placeholder="Paste SMS, WhatsApp, Telegram, Email, or Discord text here..."
          className="w-full rounded-2xl bg-slate-950/60 border border-slate-800 p-4 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 font-sans transition-all resize-none"
        />

        <div className="flex items-center justify-between mt-2 text-xs text-slate-500">
          <span className="flex items-center gap-1.5">
            <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />
            Paste full unedited message for optimal entity extraction
          </span>
          <span className="font-mono">{value.length} / 10,000 chars</span>
        </div>
      </div>

      {/* Preset Test Scenarios */}
      <div className="space-y-2 pt-1">
        <span className="text-xs font-semibold text-slate-400 flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          Test Presets (Click to load):
        </span>
        <div className="flex flex-wrap gap-2">
          {MESSAGE_PRESETS.map((preset, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => onChange(preset.text)}
              disabled={disabled}
              className={`px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border text-xs font-medium transition-colors ${preset.color}`}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
