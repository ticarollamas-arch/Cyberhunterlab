import React from 'react';
import { Code2, Terminal, ShieldAlert } from 'lucide-react';
import { cn } from '../lib/utils';

interface CodeInputProps {
  label: string;
  value: string;
  onChange: (val: string) => void;
  placeholder?: string;
  icon?: React.ReactNode;
}

export const CodeInput = ({ label, value, onChange, placeholder, icon }: CodeInputProps) => {
  return (
    <div className="flex flex-col gap-2 w-full">
      <div className="flex items-center gap-2 px-1">
        <span className="text-zinc-500">{icon || <Code2 size={14} />}</span>
        <label className="text-[11px] font-mono uppercase tracking-widest text-zinc-500 italic opacity-70">
          {label}
        </label>
      </div>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={cn(
          "w-full h-48 bg-[#1a1a1a] border border-zinc-800 rounded-lg p-4 font-mono text-sm text-zinc-300",
          "focus:outline-none focus:border-zinc-600 transition-colors resize-none placeholder:text-zinc-700",
          "selection:bg-zinc-700 selection:text-white"
        )}
      />
    </div>
  );
};
