import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
  className?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Service Communication Failure',
  message = 'Unable to synchronize forensic records with the E.M.I.T. API backend.',
  onRetry,
  className = '',
}) => {
  return (
    <div
      role="alert"
      className={`border border-[#FF3333]/40 bg-[#101010] p-5 rounded flex items-start gap-4 font-mono shadow-[0_0_15px_rgba(255,51,51,0.15)] ${className}`}
    >
      <div className="p-2 bg-[#FF3333]/15 border border-[#FF3333]/40 rounded shrink-0">
        <AlertTriangle className="h-5 w-5 text-[#FF3333]" />
      </div>
      <div className="flex-1">
        <h4 className="text-xs font-bold text-[#FF3333] uppercase tracking-wider">
          {title}
        </h4>
        <p className="text-xs text-[#AAAAAA] mt-1 leading-relaxed">
          {message}
        </p>
        {onRetry && (
          <button
            onClick={onRetry}
            className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 bg-[#181818] hover:bg-[#222222] border border-[#FF3333]/40 text-[#FF3333] text-xs font-bold uppercase tracking-wider rounded transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Retry Operation</span>
          </button>
        )}
      </div>
    </div>
  );
};

export default ErrorState;
