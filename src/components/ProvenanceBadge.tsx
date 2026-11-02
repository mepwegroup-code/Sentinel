import React from 'react';
import { CheckCircle, Calculator, BookOpen, AlertCircle } from 'lucide-react';

export type ProvenanceType = 'measured' | 'estimated' | 'educational' | 'unavailable';

interface ProvenanceBadgeProps {
  type: ProvenanceType;
  label?: string;
  size?: 'sm' | 'md';
  className?: string;
}

export const ProvenanceBadge: React.FC<ProvenanceBadgeProps> = ({
  type,
  label,
  size = 'sm',
  className = ''
}) => {
  const configs: Record<ProvenanceType, { text: string; bg: string; textCol: string; border: string; icon: React.ReactNode }> = {
    measured: {
      text: label || 'Đo lường thật',
      bg: 'bg-emerald-500/10',
      textCol: 'text-emerald-700 dark:text-emerald-400',
      border: 'border-emerald-500/30',
      icon: <CheckCircle className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />
    },
    estimated: {
      text: label || 'Ước lượng kỹ thuật',
      bg: 'bg-amber-500/10',
      textCol: 'text-amber-700 dark:text-amber-400',
      border: 'border-amber-500/30',
      icon: <Calculator className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />
    },
    educational: {
      text: label || 'Mô phỏng giáo dục',
      bg: 'bg-purple-500/10',
      textCol: 'text-purple-700 dark:text-purple-400',
      border: 'border-purple-500/30',
      icon: <BookOpen className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />
    },
    unavailable: {
      text: label || 'Không khả dụng',
      bg: 'bg-slate-500/10',
      textCol: 'text-slate-600 dark:text-slate-400',
      border: 'border-slate-500/30',
      icon: <AlertCircle className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />
    }
  };

  const c = configs[type] || configs.unavailable;
  const padding = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm';

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-medium rounded-full border ${c.bg} ${c.textCol} ${c.border} ${padding} ${className}`}
      title={`Nguồn dữ liệu: ${c.text}`}
    >
      {c.icon}
      <span>[{c.text}]</span>
    </span>
  );
};
