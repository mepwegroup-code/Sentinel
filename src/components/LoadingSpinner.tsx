import React from 'react';

export const LoadingSpinner: React.FC = () => {
  return (
    <div className="flex items-center justify-center space-x-2">
      <div className="w-4 h-4 rounded-full border-2 border-indigo-200 border-t-indigo-600 animate-spin"></div>
      <span className="text-xs font-semibold text-slate-500">Đang quét...</span>
    </div>
  );
};
