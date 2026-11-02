import React, { useState } from 'react';
import { CEH_MODULES } from '../data/cehModules';
import { BookOpen, Shield, Search, Terminal, Lock, ChevronRight, CheckCircle2, FileText } from 'lucide-react';

export const CEHKnowledgeBase: React.FC = () => {
  const [selectedModuleId, setSelectedModuleId] = useState<string>('mod-13');
  const [searchFilter, setSearchFilter] = useState('');

  const filteredModules = CEH_MODULES.filter(m => 
    m.title.toLowerCase().includes(searchFilter.toLowerCase()) ||
    m.summary.toLowerCase().includes(searchFilter.toLowerCase()) ||
    m.keyTechniques.some(t => t.toLowerCase().includes(searchFilter.toLowerCase()))
  );

  const activeModule = CEH_MODULES.find(m => m.id === selectedModuleId) || CEH_MODULES[0];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-blue-600" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
              EC-Council CEH v13 Official Curriculum Reference Matrix
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Official ethical hacking methodologies, footprinting concepts, scanning standards, and enterprise countermeasures.
          </p>
        </div>

        <div className="w-full sm:w-64">
          <div className="flex items-center bg-slate-50 rounded-lg px-3 py-1.5 border border-slate-200 focus-within:border-blue-500 focus-within:bg-white transition-all">
            <Search className="w-3.5 h-3.5 text-slate-400 mr-2" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter topics or tools..."
              className="bg-transparent border-none outline-hidden text-xs w-full text-slate-800"
            />
          </div>
        </div>
      </div>

      {/* Main Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Module Nav */}
        <div className="lg:col-span-4 space-y-2">
          {filteredModules.map((mod) => {
            const isSelected = mod.id === selectedModuleId;
            return (
              <div
                key={mod.id}
                onClick={() => setSelectedModuleId(mod.id)}
                className={`p-4 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-blue-600 text-white border-blue-600 shadow-sm'
                    : 'bg-white text-slate-800 border-slate-200 hover:border-slate-300 hover:bg-slate-50/70'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={`text-[10px] uppercase font-bold tracking-wider ${isSelected ? 'text-blue-100' : 'text-slate-400'}`}>
                    Module {mod.moduleNumber < 10 ? `0${mod.moduleNumber}` : mod.moduleNumber}
                  </span>
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${isSelected ? 'bg-blue-700 text-blue-100' : 'bg-slate-100 text-slate-600'}`}>
                    {mod.category}
                  </span>
                </div>
                <h3 className="font-bold text-sm">{mod.title}</h3>
                <p className={`text-xs mt-1 line-clamp-2 leading-relaxed ${isSelected ? 'text-blue-100' : 'text-slate-500'}`}>
                  {mod.summary}
                </p>
              </div>
            );
          })}
        </div>

        {/* Module Content */}
        <div className="lg:col-span-8 bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-6">
          <div className="border-b border-slate-100 pb-4">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-bold uppercase tracking-widest text-blue-600">
                CEH v13 Official Curricula
              </span>
              <span className="text-xs font-mono text-slate-400">Exam 312-50</span>
            </div>
            <h2 className="text-xl font-bold text-slate-800">
              Module {activeModule.moduleNumber}: {activeModule.title}
            </h2>
            <p className="text-xs text-slate-600 mt-2 leading-relaxed">{activeModule.summary}</p>
          </div>

          {/* Key Techniques */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-blue-600" />
              Core Ethical Hacking Techniques
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
              {activeModule.keyTechniques.map((tech, idx) => (
                <div key={idx} className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg flex items-start gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-600 shrink-0 mt-0.5" />
                  <span className="text-slate-700 leading-snug">{tech}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Tools & Utilities */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3 flex items-center gap-2">
              <FileText className="w-4 h-4 text-indigo-600" />
              Industry Tools & Utility Mapping
            </h3>
            <div className="flex flex-wrap gap-2">
              {activeModule.tools.map((tool, idx) => (
                <span
                  key={idx}
                  className="px-2.5 py-1 bg-slate-100 text-slate-700 border border-slate-200 rounded-md font-mono text-xs"
                >
                  {tool}
                </span>
              ))}
            </div>
          </div>

          {/* Countermeasures & Hardening */}
          <div className="bg-emerald-50/50 border border-emerald-200 p-4 rounded-xl">
            <h3 className="text-xs font-bold uppercase tracking-widest text-emerald-900 mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-700" />
              Prescribed Defensive Countermeasures & Hardening
            </h3>
            <ul className="space-y-1.5 text-xs text-emerald-800 list-disc pl-4 leading-relaxed">
              {activeModule.countermeasures.map((cm, idx) => (
                <li key={idx}>{cm}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
