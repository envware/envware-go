'use client'

import Link from 'next/link'
import { Github, LayoutDashboard, TerminalSquare } from 'lucide-react'
import { useI18n } from '@/components/I18nProvider'

export function Header() {
  const { t } = useI18n()

  return (
    <header className="sticky top-0 z-50 border-b border-zinc-800 bg-[#0a0c10]/80 backdrop-blur-xl">
      <div className="mx-auto flex h-18 max-w-7xl items-center justify-between px-6 lg:px-10">
        <Link href="/" className="flex items-center gap-3 text-white">
          <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/10 p-2 text-emerald-300">
            <TerminalSquare size={18} />
          </div>
          <div>
            <div className="font-mono text-sm text-zinc-400">git-envware</div>
            <div className="text-sm font-semibold tracking-wide text-zinc-200">CLI for envs, secrets, and access</div>
          </div>
        </Link>

        <nav className="hidden items-center gap-7 text-sm font-medium text-zinc-400 md:flex">
          <Link href="/docs" className="transition hover:text-white">{t.Nav.docs}</Link>
          <Link href="/simulador" className="transition hover:text-white">{t.Nav.simulator}</Link>
          <Link href="/dashboard" className="inline-flex items-center gap-1.5 transition hover:text-white">
            <LayoutDashboard size={14} />
            Dashboard
          </Link>
          <a
            href="https://github.com/envware/envware-go"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 transition hover:text-white"
          >
            <Github size={16} />
            GitHub
          </a>
          <Link href="/docs" className="rounded-xl border border-emerald-400/20 bg-emerald-400/10 px-4 py-2 text-emerald-300 transition hover:border-emerald-300/40 hover:bg-emerald-400/15">
            Start
          </Link>
        </nav>

        <Link
          href="/dashboard"
          className="inline-flex items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm font-medium text-zinc-300 transition hover:border-zinc-700 hover:text-white md:hidden"
        >
          <LayoutDashboard size={16} />
          Dashboard
        </Link>
      </div>
    </header>
  )
}