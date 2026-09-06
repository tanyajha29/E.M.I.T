import React from 'react';

interface LoadingSkeletonProps {
  rows?: number;
  type?: 'card' | 'table' | 'text' | 'metrics';
  className?: string;
}

export const LoadingSkeleton: React.FC<LoadingSkeletonProps> = ({
  rows = 3,
  type = 'card',
  className = '',
}) => {
  if (type === 'metrics') {
    return (
      <div className={`grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 ${className}`}>
        {[...Array(5)].map((_, i) => (
          <div
            key={i}
            className="bg-[#101010] border border-[#222222] rounded p-4 animate-pulse space-y-3"
          >
            <div className="h-3 w-20 bg-[#181818] rounded" />
            <div className="h-7 w-12 bg-[#181818] rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (type === 'table') {
    return (
      <div className={`border border-[#222222] rounded bg-[#101010] p-4 space-y-3 ${className}`}>
        <div className="h-4 w-1/4 bg-[#181818] rounded animate-pulse mb-4" />
        {[...Array(rows)].map((_, i) => (
          <div key={i} className="flex items-center gap-4 py-2 border-b border-[#222222] last:border-0">
            <div className="h-3 w-1/6 bg-[#181818] rounded animate-pulse" />
            <div className="h-3 w-1/3 bg-[#181818] rounded animate-pulse" />
            <div className="h-3 w-1/6 bg-[#181818] rounded animate-pulse" />
            <div className="h-3 w-1/4 bg-[#181818] rounded animate-pulse" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className={`grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 ${className}`}>
      {[...Array(rows)].map((_, i) => (
        <div
          key={i}
          className="bg-[#101010] border border-[#222222] rounded p-6 animate-pulse space-y-4"
        >
          <div className="flex justify-between items-center">
            <div className="h-4 w-1/2 bg-[#181818] rounded" />
            <div className="h-4 w-16 bg-[#181818] rounded" />
          </div>
          <div className="space-y-2">
            <div className="h-3 w-full bg-[#181818] rounded" />
            <div className="h-3 w-4/5 bg-[#181818] rounded" />
          </div>
          <div className="pt-4 border-t border-[#222222] flex justify-between">
            <div className="h-3 w-20 bg-[#181818] rounded" />
            <div className="h-3 w-16 bg-[#181818] rounded" />
          </div>
        </div>
      ))}
    </div>
  );
};

export default LoadingSkeleton;
