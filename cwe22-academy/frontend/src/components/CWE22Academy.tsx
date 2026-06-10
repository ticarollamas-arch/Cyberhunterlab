// STANDALONE FRONTEND COMPONENT DELIVERABLE - CWE-22 ACADEMY WORKSPACE
import React, { useState, useEffect } from 'react';
import { 
  BookOpen, 
  Code2, 
  Terminal as TerminalIcon, 
  Play, 
  RotateCcw, 
  CheckCircle2, 
  AlertTriangle, 
  Folder, 
  File, 
  ChevronRight, 
  ChevronDown, 
  FileCheck, 
  Download, 
  Copy, 
  RefreshCw,
  Database
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';

// Mock Virtual File System types and templates
interface VfsNode {
  name: string;
  type: 'file' | 'directory';
  path: string;
  content?: string;
  isSensitive?: boolean;
  children?: VfsNode[];
}

const DEFAULT_VFS_MOCK: VfsNode[] = [
  {
    name: 'app',
    type: 'directory',
    path: '/app',
    children: [
      {
        name: 'public',
        type: 'directory',
        path: '/app/public',
        children: [
          { name: 'logo.png', type: 'file', path: '/app/public/logo.png', content: 'PNG_BINARY_IMAGE_DATA_504PX' },
          { name: 'index.html', type: 'file', path: '/app/public/index.html', content: '<h1>Welcome to node server</h1>' }
        ]
      },
      { name: 'server.js', type: 'file', path: '/app/server.js' }
    ]
  },
  {
    name: 'etc',
    type: 'directory',
    path: '/etc',
    children: [
      { name: 'passwd', type: 'file', path: '/etc/passwd', content: 'root:x:0:0:root:/root:/bin/bash\nsandbox:x:1000:1000:VulnerableAcademyGuest:/home/sandbox:/bin/bash', isSensitive: true },
      { name: 'hosts', type: 'file', path: '/etc/hosts', content: '127.0.0.1\tlocalhost', isSensitive: true }
    ]
  }
];

export function CWE22AcademyWorkspaceStandalone() {
  const [activeLang, setActiveLang] = useState<'node' | 'python' | 'go'>('node');
  const [codeValue, setCodeValue] = useState<string>('// insira o código aqui...');
  const [terminalLogs, setTerminalLogs] = useState<string[]>(['⚡ [CWE-22 ACADEMY] - Carregado.']);
  const [isVerifying, setIsVerifying] = useState(false);
  const [expandedNodes, setExpandedNodes] = useState<Record<string, boolean>>({ '/app': true, '/etc': true });

  const runLocalVerification = () => {
    setIsVerifying(true);
    setTerminalLogs(prev => [...prev, '⚡ [RUNNING] Verifying updated logic against fuzzer...']);
    setTimeout(() => {
      setIsVerifying(false);
    }, 1000);
  };

  return (
    <div className="p-6 bg-[#0a0a0a] min-h-screen text-zinc-300">
      <h2 className="text-2xl font-bold text-white">CWE-22 Academy Standalone Component</h2>
      <p className="text-xs text-zinc-500 mb-6">Componente simplificado de workspace do aluno pronto para Next.js.</p>
    </div>
  );
}
