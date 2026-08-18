import React from "react";
import { SeverityLevel, AlertStatus, IncidentStatus, UserRole } from "../../types";

export const SeverityBadge: React.FC<{ severity: SeverityLevel; className?: string }> = ({
  severity,
  className = "",
}) => {
  const styles: Record<SeverityLevel, { bg: string; text: string; dot: string; border: string }> = {
    CRITICAL: {
      bg: "bg-red-950/70",
      text: "text-red-400",
      dot: "bg-red-500 shadow-[0_0_8px_#ef4444]",
      border: "border-red-800/60",
    },
    HIGH: {
      bg: "bg-orange-950/70",
      text: "text-orange-400",
      dot: "bg-orange-500 shadow-[0_0_8px_#f97316]",
      border: "border-orange-800/60",
    },
    MEDIUM: {
      bg: "bg-amber-950/70",
      text: "text-amber-400",
      dot: "bg-amber-500 shadow-[0_0_8px_#f59e0b]",
      border: "border-amber-800/60",
    },
    LOW: {
      bg: "bg-emerald-950/70",
      text: "text-emerald-400",
      dot: "bg-emerald-500 shadow-[0_0_8px_#10b981]",
      border: "border-emerald-800/60",
    },
    INFO: {
      bg: "bg-slate-800/70",
      text: "text-slate-300",
      dot: "bg-slate-400",
      border: "border-slate-700/60",
    },
  };

  const style = styles[severity] || styles.INFO;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${style.bg} ${style.text} ${style.border} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
      {severity}
    </span>
  );
};

export const StatusBadge: React.FC<{
  status: AlertStatus | IncidentStatus;
  className?: string;
}> = ({ status, className = "" }) => {
  const getStyles = () => {
    switch (status) {
      case "NEW":
      case "OPEN":
        return "bg-rose-950/50 text-rose-300 border-rose-800/50";
      case "INVESTIGATING":
        return "bg-amber-950/50 text-amber-300 border-amber-800/50";
      case "RESOLVED":
        return "bg-emerald-950/50 text-emerald-300 border-emerald-800/50";
      case "FALSE_POSITIVE":
        return "bg-slate-800/50 text-slate-400 border-slate-700/50";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${getStyles()} ${className}`}
    >
      {status.replace("_", " ")}
    </span>
  );
};

export const RoleBadge: React.FC<{ role: UserRole }> = ({ role }) => {
  const styles: Record<UserRole, string> = {
    ADMIN: "bg-purple-950/60 text-purple-300 border-purple-800/60",
    ANALYST: "bg-cyan-950/60 text-cyan-300 border-cyan-800/60",
    VIEWER: "bg-slate-800/60 text-slate-300 border-slate-700/60",
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
        styles[role] || styles.VIEWER
      }`}
    >
      {role}
    </span>
  );
};
