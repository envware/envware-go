'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import {
  Check,
  Copy,
  Github,
  KeyRound,
  Lock,
  Play,
  Search,
  ShieldCheck,
  TerminalSquare,
  Workflow,
} from 'lucide-react'
import { toast } from 'sonner'
import { Header } from '@/components/Header'

export const dynamic = 'force-dynamic'

const terminalScenarios = {
  install: [
    '$ curl -fsSL https://www.envware.dev/install.sh | bash',
    '🔍 checking latest version...',
    '🚀 downloading envware...',
    '🔗 creating git-envware shortcut...',
    '✔ envware installed successfully',
  ],
  request: [
    '$ envw request my-team my-project developer',
    '🔐 authenticating with your SSH key...',
    '✔ request created',
    '✔ identity registered via SHA256 fingerprint',
  ],
  accept: [
    '$ envw accept req_9fj2k',
    '🔍 verifying requester identity...',
    '🛡️ approval recorded',
    '✔ access granted securely',
  ],
  encrypt: [
    '$ envw encrypt my-team my-project .env.production',
    '🔐 encrypting locally...',
    '✔ file saved as .env.production.crypto',
  ],
  gitPull: [
    '$ git envware pull',
    '🚀 syncing repository...',
    '🛡️ decrypting .env.crypto locally...',
    '✔ .env restored successfully',
  ],
  gitPush: [
    '$ git envware push',
    '🔐 updating .env.crypto...',
    '📦 staging encrypted changes...',
    '🚀 pushing code + encrypted envs...',
    '✔ everything synced',
  ],
} as const

const quickStart = [
  {
    title: '1. Install the CLI',
    command: 'curl -fsSL https://www.envware.dev/install.sh | bash',
    description: 'Install the main binary plus the git envware shortcut.',
    scenario: terminalScenarios.install,
  },
  {
    title: '2. Request or create access',
    command: 'envw request my-team my-project developer',
    description: 'Create a new project or request access using your SSH identity.',
    scenario: terminalScenarios.request,
  },
  {
    title: '3. Encrypt your first environment',
    command: 'envw encrypt my-team my-project .env.production',
    description: 'Encrypt locally before sharing or versioning anything.',
    scenario: terminalScenarios.encrypt,
  },
  {
    title: '4. Pull it back through the workflow',
    command: 'git envware pull',
    description: 'Restore the right environment locally through the same repeatable path.',
    scenario: terminalScenarios.gitPull,
  },
] as const

const commonWorkflows = [
  {
    title: 'Join an existing project',
    description: 'Request access, get approved, and pull the correct environment without chasing files in chat.',
    command: 'envw request my-team my-project developer',
    scenario: terminalScenarios.request,
  },
  {
    title: 'Approve access safely',
    description: 'Validate identity first, then approve. No vague “yeah, that is probably them”.',
    command: 'envw accept req_9fj2k',
    scenario: terminalScenarios.accept,
  },
  {
    title: 'Version encrypted envs with Git',
    description: 'Keep .env.crypto in the repo while real secrets stay protected locally.',
    command: 'git envware push',
    scenario: terminalScenarios.gitPush,
  },
  {
    title: 'Restore envs locally',
    description: 'Pull code and restore the right encrypted config through one predictable command.',
    command: 'git envware pull',
    scenario: terminalScenarios.gitPull,
  },
] as const

const commandGroups = [
  {
    title: 'Core commands',
    items: [
      {
        command: 'envw request <team> <project> <role>',
        description: 'Request access or create a new project.',
        scenario: terminalScenarios.request,
      },
      {
        command: 'envw accept <request-id>',
        description: 'Approve a pending request after validating identity.',
        scenario: terminalScenarios.accept,
      },
      {
        command: 'envw encrypt <team> <project> <env-file>',
        description: 'Encrypt a local env file into a .crypto version.',
        scenario: terminalScenarios.encrypt,
      },
      {
        command: 'envw decrypt <team> <project> <crypto-file>',
        description: 'Restore a .crypto file into a readable local env file.',
        scenario: [
          '$ envw decrypt my-team my-project .env.production.crypto',
          '🔓 decrypting locally...',
          '✔ secrets restored',
        ],
      },
      {
        command: 'envw fingerprint',
        description: 'Show the SHA256 fingerprint of your SSH identity.',
        scenario: [
          '$ envw fingerprint',
          '💻 fingerprint: SHA256:7N2pr...',
          '✔ share this for approval verification',
        ],
      },
      {
        command: 'envw status',
        description: 'Show your current teams, projects, and auth context.',
        scenario: [
          '$ envw status',
          '👤 authenticated user found',
          '🏢 teams found: 1',
          '📦 available projects: 3',
        ],
      },
    ],
  },
  {
    title: 'Git integration',
    items: [
      {
        command: 'git envware checkout <repo-url>',
        description: 'Clone a repository and try to resolve the Envware project automatically.',
        scenario: [
          '$ git envware checkout https://github.com/acme/api.git',
          '🚀 cloning repository...',
          '🔍 resolving Envware context...',
          '✔ project linked to Git workflow',
        ],
      },
      {
        command: 'git envware pull',
        description: 'Pull the repo and restore encrypted env files locally.',
        scenario: terminalScenarios.gitPull,
      },
      {
        command: 'git envware push',
        description: 'Update encrypted env files and push them with the code.',
        scenario: terminalScenarios.gitPush,
      },
    ],
  },
] as const

const securityPrinciples = [
  'Secrets are encrypted locally before leaving the machine.',
  'Access is approved with SSH-key-based identity.',
  'Production, staging, and development can be isolated by environment.',
  'The server stores encrypted blobs, not the plain-text secret.',
] as const

const useCases = [
  'Solo developer who wants Git-friendly encrypted envs',
  'Small teams onboarding new developers without passing files around',
  'Agencies managing separate client projects and access boundaries',
  'CI and AI-assisted execution that should follow the same env workflow',
] as const

export default function DocsPage() {
  const [search, setSearch] = useState('')
  const [terminalLines, setTerminalLines] = useState<string[]>([...terminalScenarios.install])
  const [isTyping, setIsTyping] = useState(false)

  useEffect(() => {
    fetch('/api/v2/analytics?event=docs_view', { method: 'POST' }).catch(() => {})
  }, [])

  const filteredGroups = useMemo(() => {
    return commandGroups
      .map((group) => ({
        ...group,
        items: group.items.filter((item) => {
          const q = search.toLowerCase()
          return item.command.toLowerCase().includes(q) || item.description.toLowerCase().includes(q)
        }),
      }))
      .filter((group) => group.items.length > 0)
  }, [search])

  async function runScenario(lines: readonly string[]) {
    if (isTyping) return
    setIsTyping(true)
    setTerminalLines([])

    for (const line of lines) {
      setTerminalLines((prev) => [...prev, line])
      await new Promise((resolve) => setTimeout(resolve, 220))
    }

    setIsTyping(false)
  }

  function copy(text: string) {
    navigator.clipboard.writeText(text)
    toast.success('Command copied 🌸')
  }

  return (
    <main className="min-h-screen bg-[#0b0d12] text-zinc-100 selection:bg-emerald-300 selection:text-black">
      <Header />

      <section className="border-b border-zinc-800 bg-[radial-gradient(circle_at_top,rgba(16,185,129,0.10),transparent_30%)]">
        <div className="mx-auto max-w-7xl px-6 py-16 lg:px-10 lg:py-20">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.22em] text-emerald-300">
              <TerminalSquare size={14} />
              Learn the workflow in minutes
            </div>
            <h1 className="mt-6 text-4xl font-black tracking-[-0.04em] text-white md:text-6xl">
              Docs built for activation, not admiration.
            </h1>
            <p className="mt-5 max-w-2xl text-lg leading-8 text-zinc-400">
              Install Envware, encrypt your first environment, and start using a safer workflow for secrets, access, and Git without reading a small novel first.
            </p>

            <div className="mt-8 flex flex-col gap-4 sm:flex-row">
              <a
                href="#quick-start"
                className="inline-flex items-center justify-center gap-2 rounded-2xl bg-emerald-300 px-6 py-4 font-semibold text-black transition hover:bg-emerald-200"
              >
                Open quick start
              </a>
              <a
                href="#cli-reference"
                className="inline-flex items-center justify-center gap-2 rounded-2xl border border-zinc-700 bg-zinc-950 px-6 py-4 font-semibold text-zinc-100 transition hover:border-zinc-500 hover:bg-zinc-900"
              >
                CLI reference
              </a>
              <a
                href="https://github.com/envware/envware-go"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center gap-2 rounded-2xl border border-zinc-700 bg-zinc-950 px-6 py-4 font-semibold text-zinc-100 transition hover:border-zinc-500 hover:bg-zinc-900"
              >
                <Github size={18} />
                GitHub
              </a>
            </div>
          </div>
        </div>
      </section>

      <section id="quick-start" className="border-b border-zinc-900 bg-[#0e1117]">
        <div className="mx-auto grid max-w-7xl gap-10 px-6 py-14 lg:grid-cols-[1.05fr_0.95fr] lg:px-10">
          <div className="rounded-[28px] border border-zinc-800 bg-zinc-950/70 p-8">
            <div className="mb-8">
              <p className="text-sm font-semibold uppercase tracking-[0.24em] text-emerald-300">Quick start</p>
              <h2 className="mt-3 text-3xl font-black tracking-[-0.03em] text-white">Get from zero to workflow fast</h2>
              <p className="mt-4 max-w-2xl leading-7 text-zinc-400">
                The goal of this page is simple: help you install Envware, run the core commands, and understand where it fits in your day-to-day workflow.
              </p>
            </div>

            <div className="space-y-5">
              {quickStart.map((step) => (
                <div key={step.command} className="rounded-3xl border border-zinc-800 bg-[#0c1016] p-5">
                  <div className="text-sm font-semibold uppercase tracking-[0.2em] text-zinc-500">{step.title}</div>
                  <div className="mt-3 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                    <code className="overflow-x-auto rounded-2xl border border-zinc-800 bg-black/30 px-4 py-3 font-mono text-sm text-emerald-300">
                      {step.command}
                    </code>
                    <div className="flex gap-2">
                      <button
                        onClick={() => copy(step.command)}
                        className="inline-flex items-center justify-center rounded-xl border border-zinc-700 px-3 py-2 text-zinc-300 transition hover:border-zinc-500 hover:text-white"
                      >
                        <Copy size={16} />
                      </button>
                      <button
                        onClick={() => runScenario(step.scenario)}
                        className="inline-flex items-center gap-2 rounded-xl bg-emerald-300 px-4 py-2 font-semibold text-black transition hover:bg-emerald-200"
                      >
                        <Play size={16} />
                        Preview
                      </button>
                    </div>
                  </div>
                  <p className="mt-3 leading-7 text-zinc-400">{step.description}</p>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="sticky top-24 overflow-hidden rounded-[28px] border border-zinc-800 bg-zinc-950 shadow-[0_20px_80px_rgba(0,0,0,0.45)]">
              <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
                <div className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded-full bg-red-400/80" />
                  <span className="h-3 w-3 rounded-full bg-yellow-400/80" />
                  <span className="h-3 w-3 rounded-full bg-emerald-400/80" />
                </div>
                <span className="text-xs uppercase tracking-[0.22em] text-zinc-500">preview</span>
              </div>
              <div className="min-h-[360px] space-y-2 p-6 font-mono text-sm leading-7 text-zinc-300">
                {terminalLines.map((line, index) => (
                  <div
                    key={`${line}-${index}`}
                    className={line.startsWith('$') ? 'text-emerald-300' : line.includes('✔') ? 'text-white' : 'text-zinc-400'}
                  >
                    {line}
                  </div>
                ))}
                {isTyping ? <div className="animate-pulse text-zinc-500">...</div> : null}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="border-b border-zinc-900 bg-[#0b0d12]">
        <div className="mx-auto max-w-7xl px-6 py-16 lg:px-10">
          <div className="mb-8 max-w-3xl">
            <p className="text-sm font-semibold uppercase tracking-[0.24em] text-emerald-300">Common workflows</p>
            <h2 className="mt-4 text-3xl font-black tracking-[-0.03em] text-white md:text-5xl">
              The flows people actually use
            </h2>
            <p className="mt-5 text-lg leading-8 text-zinc-400">
              Start with the basics, then reuse the same verbs everywhere: request, approve, encrypt, pull, push, protect. That is how tools become habit instead of decoration.
            </p>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            {commonWorkflows.map((item) => (
              <div key={item.title} className="rounded-3xl border border-zinc-800 bg-zinc-950/70 p-6">
                <div className="mb-4 inline-flex rounded-2xl border border-emerald-400/20 bg-emerald-400/10 p-3 text-emerald-300">
                  <Workflow size={20} />
                </div>
                <h3 className="text-2xl font-bold text-white">{item.title}</h3>
                <p className="mt-3 leading-7 text-zinc-400">{item.description}</p>
                <code className="mt-4 block overflow-x-auto rounded-2xl border border-zinc-800 bg-black/30 px-4 py-3 font-mono text-sm text-emerald-300">
                  {item.command}
                </code>
                <div className="mt-4 flex gap-2">
                  <button
                    onClick={() => copy(item.command)}
                    className="inline-flex items-center justify-center rounded-xl border border-zinc-700 px-3 py-2 text-zinc-300 transition hover:border-zinc-500 hover:text-white"
                  >
                    <Copy size={16} />
                  </button>
                  <button
                    onClick={() => runScenario(item.scenario)}
                    className="inline-flex items-center gap-2 rounded-xl border border-emerald-400/20 bg-emerald-400/10 px-4 py-2 font-semibold text-emerald-300 transition hover:border-emerald-300/40 hover:bg-emerald-400/15"
                  >
                    <Play size={16} />
                    Preview
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="border-b border-zinc-900 bg-[#0e1117]">
        <div className="mx-auto grid max-w-7xl gap-8 px-6 py-16 lg:grid-cols-[0.95fr_1.05fr] lg:px-10">
          <div className="rounded-[28px] border border-zinc-800 bg-zinc-950/70 p-8">
            <div className="mb-6 flex items-center gap-3 text-emerald-300">
              <ShieldCheck size={20} />
              <span className="text-sm font-semibold uppercase tracking-[0.22em]">Security model</span>
            </div>
            <div className="space-y-4">
              {securityPrinciples.map((principle) => (
                <div key={principle} className="flex gap-3 rounded-2xl border border-zinc-800 bg-black/20 p-4 text-zinc-300">
                  <Check size={18} className="mt-0.5 shrink-0 text-emerald-300" />
                  <span className="leading-7">{principle}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-[28px] border border-zinc-800 bg-zinc-950/70 p-8">
            <div className="mb-6 flex items-center gap-3 text-emerald-300">
              <Lock size={20} />
              <span className="text-sm font-semibold uppercase tracking-[0.22em]">Where it helps</span>
            </div>
            <h2 className="text-3xl font-black tracking-[-0.03em] text-white">Built for real operational mess</h2>
            <p className="mt-5 text-lg leading-8 text-zinc-400">
              Envware matters when access, environment drift, and secret sharing stop being a side quest and start becoming recurring pain.
            </p>
            <div className="mt-6 space-y-3">
              {useCases.map((item) => (
                <div key={item} className="flex gap-3 rounded-2xl border border-zinc-800 bg-black/20 p-4 text-zinc-300">
                  <Check size={18} className="mt-0.5 shrink-0 text-emerald-300" />
                  <span className="leading-7">{item}</span>
                </div>
              ))}
            </div>
            <div className="mt-8 rounded-3xl border border-amber-400/20 bg-amber-400/10 p-5 text-amber-100">
              <div className="flex items-center gap-3 text-sm font-semibold uppercase tracking-[0.2em]">
                <KeyRound size={16} />
                Fingerprint first, approval after
              </div>
              <p className="mt-3 leading-7 text-amber-50/85">
                Before approving access, validate the SSH fingerprint through a separate channel. Security is not just encryption — it is also clear identity boundaries.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section id="cli-reference" className="border-b border-zinc-900 bg-[#0b0d12]">
        <div className="mx-auto max-w-7xl px-6 py-16 lg:px-10">
          <div className="mb-8 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.24em] text-emerald-300">CLI reference</p>
              <h2 className="mt-4 text-3xl font-black tracking-[-0.03em] text-white md:text-5xl">Commands you will actually reach for</h2>
            </div>
            <div className="relative w-full max-w-md">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500" size={18} />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search command"
                className="w-full rounded-2xl border border-zinc-800 bg-zinc-950 py-3 pl-11 pr-4 text-sm text-white outline-none transition placeholder:text-zinc-500 focus:border-emerald-400/40"
              />
            </div>
          </div>

          <div className="space-y-10">
            {filteredGroups.map((group) => (
              <section key={group.title} className="space-y-4">
                <h3 className="text-2xl font-bold text-white">{group.title}</h3>
                <div className="grid gap-4">
                  {group.items.map((item) => (
                    <div key={item.command} className="rounded-3xl border border-zinc-800 bg-zinc-950/70 p-5">
                      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                        <div className="min-w-0 flex-1">
                          <code className="block overflow-x-auto rounded-2xl border border-zinc-800 bg-black/30 px-4 py-3 font-mono text-sm text-emerald-300">
                            {item.command}
                          </code>
                          <p className="mt-3 leading-7 text-zinc-400">{item.description}</p>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => copy(item.command)}
                            className="inline-flex items-center justify-center rounded-xl border border-zinc-700 px-3 py-2 text-zinc-300 transition hover:border-zinc-500 hover:text-white"
                          >
                            <Copy size={16} />
                          </button>
                          <button
                            onClick={() => runScenario(item.scenario)}
                            className="inline-flex items-center gap-2 rounded-xl border border-emerald-400/20 bg-emerald-400/10 px-4 py-2 font-semibold text-emerald-300 transition hover:border-emerald-300/40 hover:bg-emerald-400/15"
                          >
                            <Play size={16} />
                            Preview
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            ))}
          </div>
        </div>
      </section>

      <section className="bg-[#0e1117]">
        <div className="mx-auto max-w-7xl px-6 py-16 lg:px-10">
          <div className="rounded-[28px] border border-emerald-400/15 bg-[linear-gradient(180deg,rgba(16,185,129,0.12),rgba(16,185,129,0.03))] p-8">
            <p className="text-sm font-semibold uppercase tracking-[0.24em] text-emerald-200">Next step</p>
            <h2 className="mt-4 text-3xl font-black tracking-[-0.03em] text-white md:text-4xl">
              Use the docs to start. Use the workflow to stay.
            </h2>
            <p className="mt-5 max-w-3xl text-lg leading-8 text-zinc-200/80">
              The homepage should convince. These docs should activate. Once the commands become muscle memory, Envware stops feeling like a tool you discovered and starts feeling like infrastructure you depend on.
            </p>
            <div className="mt-8 flex flex-col gap-4 sm:flex-row">
              <a
                href="#quick-start"
                className="inline-flex items-center justify-center gap-2 rounded-2xl bg-emerald-300 px-6 py-4 font-semibold text-black transition hover:bg-emerald-200"
              >
                Start now
              </a>
              <Link
                href="/simulador"
                className="inline-flex items-center justify-center gap-2 rounded-2xl border border-white/10 bg-black/20 px-6 py-4 font-semibold text-white transition hover:border-white/20 hover:bg-black/30"
              >
                Open simulator
              </Link>
            </div>
          </div>
        </div>
      </section>
    </main>
  )
}
