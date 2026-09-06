import React from 'react';
import { LucideIcon, FolderSearch } from 'lucide-react';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon = FolderSearch,
  title,
  description,
  action,
  className = '',
}) => {
  return (
    <div
      className={`py-16 px-6 text-center border border-dashed border-[#222222] rounded bg-[#0A0A0A] flex flex-col items-center justify-center font-mono ${className}`}
    >
      <div className="p-3 bg-[#101010] border border-[#222222] rounded mb-3">
        <Icon className="h-6 w-6 text-[#00FF00]" />
      </div>
      <h4 className="text-xs font-bold text-white uppercase tracking-widest">
        {title}
      </h4>
      {description && (
        <p className="text-xs text-[#AAAAAA] max-w-md mt-1.5 leading-relaxed">
          {description}
        </p>
      )}
      {action && (
        <button
          onClick={action.onClick}
          className="mt-4 px-4 py-2 bg-[#181818] hover:bg-[#222222] border border-[#00FF00]/40 text-xs font-bold text-[#00FF00] rounded transition-colors uppercase tracking-wider"
        >
          {action.label}
        </button>
      )}
    </div>
  );
};

export default EmptyState;
