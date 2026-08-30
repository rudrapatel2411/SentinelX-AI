import React from "react";
import { RiskClassification } from "@/lib/types/security";
import { ShieldAlert, ShieldCheck, AlertTriangle, HelpCircle } from "lucide-react";

interface RiskBadgeProps {
  classification: RiskClassification;
  size?: "sm" | "md" | "lg";
  showIcon?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  classification,
  size = "md",
  showIcon = true,
}) => {
  const sizeClasses = {
    sm: "px-2 py-0.5 text-xs font-semibold gap-1",
    md: "px-3 py-1 text-xs font-bold tracking-wider uppercase gap-1.5",
    lg: "px-4 py-1.5 text-sm font-extrabold tracking-widest uppercase gap-2",
  };

  switch (classification) {
    case "DANGEROUS":
      return (
        <span
          className={`inline-flex items-center rounded-full cyber-badge-glow-danger ${sizeClasses[size]}`}
        >
          {showIcon && <ShieldAlert className="w-3.5 h-3.5" />}
          Dangerous
        </span>
      );
    case "SUSPICIOUS":
      return (
        <span
          className={`inline-flex items-center rounded-full cyber-badge-glow-warning ${sizeClasses[size]}`}
        >
          {showIcon && <AlertTriangle className="w-3.5 h-3.5" />}
          Suspicious
        </span>
      );
    case "SAFE":
      return (
        <span
          className={`inline-flex items-center rounded-full cyber-badge-glow-safe ${sizeClasses[size]}`}
        >
          {showIcon && <ShieldCheck className="w-3.5 h-3.5" />}
          Safe
        </span>
      );
    default:
      return (
        <span
          className={`inline-flex items-center rounded-full bg-slate-800/80 border border-slate-700 text-slate-300 ${sizeClasses[size]}`}
        >
          {showIcon && <HelpCircle className="w-3.5 h-3.5" />}
          Unknown
        </span>
      );
  }
};
