import React from 'react';

export type StatusVariant = 'healthy' | 'running' | 'warning' | 'critical' | 'neutral' | 'offline';

interface StatusIndicatorProps {
  status: StatusVariant;
  label?: string;
  pulse?: boolean;
  className?: string;
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({
  status,
  label,
  pulse = true,
  className = '',
}) => {
  const config: Record<StatusVariant, { dot: string; glow: string; text: string }> = {
    healthy: {
      dot: 'bg-[#00FF00]',
      glow: 'bg-[#00FF00]/50',
      text: 'text-[#00FF00]',
    },
    running: {
      dot: 'bg-[#00FF00]',
      glow: 'bg-[#00FF00]/50',
      text: 'text-[#00FF00]',
    },
    warning: {
      dot: 'bg-[#FF8800]',
      glow: 'bg-[#FF8800]/50',
      text: 'text-[#FF8800]',
    },
    critical: {
      dot: 'bg-[#FF3333]',
      glow: 'bg-[#FF3333]/50',
      text: 'text-[#FF3333]',
    },
    neutral: {
      dot: 'bg-[#888888]',
      glow: 'bg-[#888888]/40',
      text: 'text-[#AAAAAA]',
    },
    offline: {
      dot: 'bg-[#FF3333]',
      glow: 'bg-[#FF3333]/50',
      text: 'text-[#FF3333]',
    },
  };

  const current = config[status] || config.neutral;

  return (
    <span className={`inline-flex items-center gap-2 font-mono ${className}`}>
      <span className="relative flex h-2 w-2">
        {pulse && (
          <span
            className={`absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping ${current.glow}`}
          />
        )}
        <span className={`relative inline-flex rounded-full h-2 w-2 ${current.dot}`} />
      </span>
      {label && (
        <span className={`text-[11px] font-bold tracking-wider uppercase ${current.text}`}>
          {label}
        </span>
      )}
    </span>
  );
};

export default StatusIndicator;
