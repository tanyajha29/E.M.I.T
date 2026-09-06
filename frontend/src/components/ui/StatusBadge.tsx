import React from 'react';

interface StatusBadgeProps {
  status: string;
  size?: 'sm' | 'md';
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  size = 'sm',
  className = '',
}) => {
  const normalized = (status || 'UNKNOWN').toUpperCase();

  const getStyles = () => {
    switch (normalized) {
      case 'OPEN':
      case 'COMPLETED':
      case 'CONNECTED':
      case 'AVAILABLE':
        return 'bg-[#00FF00]/10 text-[#00FF00] border-[#00FF00]/40';
      case 'ANALYZING':
      case 'RUNNING':
        return 'bg-[#00FF00]/15 text-[#00FF00] border-[#00FF00]/60 animate-pulse';
      case 'PARTIAL':
      case 'WARNING':
      case 'SUSPICIOUS':
        return 'bg-[#FF8800]/10 text-[#FF8800] border-[#FF8800]/40';
      case 'PENDING':
      case 'QUEUED':
        return 'bg-[#38BDF8]/10 text-[#38BDF8] border-[#38BDF8]/40';
      case 'FAILED':
      case 'OFFLINE':
      case 'DISCONNECTED':
      case 'MALICIOUS':
        return 'bg-[#FF3333]/10 text-[#FF3333] border-[#FF3333]/40';
      case 'UNAVAILABLE':
      case 'NOT_CONFIGURED':
      case 'DISABLED':
        return 'bg-[#181818] text-[#888888] border-[#333333]';
      case 'ARCHIVED':
      case 'CANCELLED':
        return 'bg-[#181818] text-[#777777] border-[#2a2a2a]';
      default:
        return 'bg-[#181818] text-[#AAAAAA] border-[#333333]';
    }
  };

  const sizeClasses = size === 'sm' 
    ? 'px-2 py-0.5 text-[10px]' 
    : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-bold uppercase tracking-wider rounded border ${sizeClasses} ${getStyles()} ${className}`}
    >
      {normalized === 'RUNNING' || normalized === 'ANALYZING' ? (
        <span className="h-1.5 w-1.5 rounded-full bg-[#00FF00] animate-ping" />
      ) : null}
      {status || '—'}
    </span>
  );
};

export default StatusBadge;
