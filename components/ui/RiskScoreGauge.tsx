"use client";

import React from "react";
import { motion } from "framer-motion";

interface RiskScoreGaugeProps {
  score: number; // 0 - 100
  size?: number; // width/height in px (default: 120)
  strokeWidth?: number;
  showLabel?: boolean;
}

export const RiskScoreGauge: React.FC<RiskScoreGaugeProps> = ({
  score,
  size = 130,
  strokeWidth = 10,
  showLabel = true,
}) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  // Determine dynamic colors
  let strokeColor = "#10b981"; // Emerald / Safe
  let glowColor = "rgba(16, 185, 129, 0.4)";
  let labelColor = "text-emerald-400";

  if (score >= 70) {
    strokeColor = "#f43f5e"; // Rose / Danger
    glowColor = "rgba(244, 63, 94, 0.5)";
    labelColor = "text-rose-400";
  } else if (score >= 30) {
    strokeColor = "#f59e0b"; // Amber / Warning
    glowColor = "rgba(245, 158, 11, 0.4)";
    labelColor = "text-amber-400";
  }

  return (
    <div className="flex flex-col items-center justify-center relative">
      <div
        className="relative flex items-center justify-center"
        style={{ width: size, height: size }}
      >
        {/* Background track */}
        <svg width={size} height={size} className="transform -rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Animated score stroke */}
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1.2, ease: "easeOut" }}
            strokeLinecap="round"
            fill="transparent"
            style={{
              filter: `drop-shadow(0 0 8px ${glowColor})`,
            }}
          />
        </svg>

        {/* Center score display */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          <motion.span
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className={`text-3xl font-black font-mono tracking-tight ${labelColor}`}
          >
            {score}
          </motion.span>
          <span className="text-[10px] uppercase tracking-widest text-slate-400 font-semibold">
            / 100
          </span>
        </div>
      </div>

      {showLabel && (
        <span className="mt-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
          Risk Score
        </span>
      )}
    </div>
  );
};
