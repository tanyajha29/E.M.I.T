import React from 'react';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

interface RiskBadgeProps {
  level?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  confidence?: number;
  className?: string;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  level = 'LOW',
  confidence,
  className = '',
}) => {
  const norm = (level || 'LOW').toUpperCase();

  const getStyle = () => {
    switch (norm) {
      case 'CRITICAL':
        return 'bg-[#FF3333]/15 text-[#FF3333] border-[#FF3333]/50 shadow-[0_0_10px_rgba(255,51,51,0.25)]';
      case 'HIGH':
        return 'bg-[#FF8800]/15 text-[#FF8800] border-[#FF8800]/50 shadow-[0_0_10px_rgba(255,136,0,0.25)]';
      case 'MEDIUM':
        return 'bg-[#FF8800]/10 text-[#FF8800] border-[#FF8800]/30';
      case 'LOW':
      default:
        return 'bg-[#BB88FF]/15 text-[#BB88FF] border-[#BB88FF]/40 shadow-[0_0_10px_rgba(187,136,255,0.2)]';
    }
  };

  const Icon = norm === 'CRITICAL' || norm === 'HIGH' ? ShieldAlert : ShieldCheck;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border font-mono text-[11px] font-bold uppercase tracking-wider ${getStyle()} ${className}`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" />
      <span>{norm} RISK</span>
      {typeof confidence === 'number' && (
        <span className="text-[10px] opacity-75 font-normal">
          ({Math.round(confidence <= 1 ? confidence * 100 : confidence)}% conf)
        </span>
      )}
    </span>
  );
};

export default RiskBadge;
