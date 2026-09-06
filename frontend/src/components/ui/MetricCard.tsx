import React, { useEffect, useState } from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  label: string;
  value: number | string;
  sublabel?: string;
  icon?: LucideIcon;
  accentColor?: 'green' | 'orange' | 'purple' | 'red' | 'blue' | 'white' | 'violet' | 'teal' | 'amber' | 'neutral';
  className?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  sublabel,
  icon: Icon,
  accentColor = 'green',
  className = '',
}) => {
  // Fast number roll-up animation for numeric values
  const [displayNum, setDisplayNum] = useState<number | string>(() => {
    return typeof value === 'number' ? 0 : value;
  });

  useEffect(() => {
    if (typeof value !== 'number') {
      setDisplayNum(value);
      return;
    }

    if (value === 0) {
      setDisplayNum(0);
      return;
    }

    let start = 0;
    const end = value;
    const duration = 400; // 400ms roll-up
    const stepTime = 20;
    const totalSteps = duration / stepTime;
    const increment = (end - start) / totalSteps;

    const timer = setInterval(() => {
      start += increment;
      if ((increment > 0 && start >= end) || (increment < 0 && start <= end)) {
        setDisplayNum(end);
        clearInterval(timer);
      } else {
        setDisplayNum(Math.floor(start));
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, [value]);

  const colorMap: Record<string, { borderHover: string; glow: string; text: string; iconBg: string }> = {
    green: {
      borderHover: 'hover:border-[#00FF00]',
      glow: 'hover:shadow-[0_0_15px_rgba(0,255,0,0.25)]',
      text: 'text-[#00FF00]',
      iconBg: 'bg-[#00FF00]/10 text-[#00FF00] border-[#00FF00]/30',
    },
    teal: {
      borderHover: 'hover:border-[#00FF00]',
      glow: 'hover:shadow-[0_0_15px_rgba(0,255,0,0.25)]',
      text: 'text-[#00FF00]',
      iconBg: 'bg-[#00FF00]/10 text-[#00FF00] border-[#00FF00]/30',
    },
    orange: {
      borderHover: 'hover:border-[#FF8800]',
      glow: 'hover:shadow-[0_0_15px_rgba(255,136,0,0.25)]',
      text: 'text-[#FF8800]',
      iconBg: 'bg-[#FF8800]/10 text-[#FF8800] border-[#FF8800]/30',
    },
    amber: {
      borderHover: 'hover:border-[#FF8800]',
      glow: 'hover:shadow-[0_0_15px_rgba(255,136,0,0.25)]',
      text: 'text-[#FF8800]',
      iconBg: 'bg-[#FF8800]/10 text-[#FF8800] border-[#FF8800]/30',
    },
    purple: {
      borderHover: 'hover:border-[#BB88FF]',
      glow: 'hover:shadow-[0_0_15px_rgba(187,136,255,0.25)]',
      text: 'text-[#BB88FF]',
      iconBg: 'bg-[#BB88FF]/10 text-[#BB88FF] border-[#BB88FF]/30',
    },
    violet: {
      borderHover: 'hover:border-[#BB88FF]',
      glow: 'hover:shadow-[0_0_15px_rgba(187,136,255,0.25)]',
      text: 'text-[#BB88FF]',
      iconBg: 'bg-[#BB88FF]/10 text-[#BB88FF] border-[#BB88FF]/30',
    },
    red: {
      borderHover: 'hover:border-[#FF3333]',
      glow: 'hover:shadow-[0_0_15px_rgba(255,51,51,0.25)]',
      text: 'text-[#FF3333]',
      iconBg: 'bg-[#FF3333]/10 text-[#FF3333] border-[#FF3333]/30',
    },
    white: {
      borderHover: 'hover:border-[#FFFFFF]',
      glow: 'hover:shadow-[0_0_15px_rgba(255,255,255,0.2)]',
      text: 'text-white',
      iconBg: 'bg-white/10 text-white border-white/30',
    },
    neutral: {
      borderHover: 'hover:border-[#00FF00]',
      glow: 'hover:shadow-[0_0_15px_rgba(0,255,0,0.2)]',
      text: 'text-white',
      iconBg: 'bg-[#181818] text-[#AAAAAA] border-[#333333]',
    },
  };

  const style = colorMap[accentColor] || colorMap.green;

  return (
    <div
      className={`bg-[#101010] border border-[#222222] rounded p-4 transition-all duration-200 hover:scale-[1.01] flex flex-col justify-between font-mono ${style.borderHover} ${style.glow} ${className}`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-[11px] font-semibold text-[#AAAAAA] uppercase tracking-wider">
          {label}
        </span>
        {Icon && (
          <div className={`p-1.5 rounded border shrink-0 ${style.iconBg}`}>
            <Icon className="h-4 w-4" />
          </div>
        )}
      </div>

      <div className="mt-3">
        <span className={`text-2xl font-bold tracking-tight block ${style.text}`}>
          {displayNum !== undefined && displayNum !== null ? displayNum : '—'}
        </span>
        {sublabel && (
          <span className="text-[10px] text-[#888888] mt-0.5 block">
            {sublabel}
          </span>
        )}
      </div>
    </div>
  );
};

export default MetricCard;
