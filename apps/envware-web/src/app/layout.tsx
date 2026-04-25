import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { Toaster } from 'sonner'
import { Analytics } from "@vercel/analytics/next"
import { I18nProvider } from '@/components/I18nProvider'

import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Git Envware',
  description: 'Operational workflow for environments, secrets, approvals, and access.',
  applicationName: 'Git Envware',
  manifest: '/manifest.webmanifest',
  appleWebApp: {
    capable: true,
    statusBarStyle: 'black-translucent',
    title: 'Git Envware',
  },
  icons: {
    icon: ['/logo.png'],
    apple: ['/logo.png'],
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <Analytics />
      <I18nProvider>
        <body className={`${inter.className} min-h-screen bg-[#0a0c10] text-zinc-100 antialiased`}>
          {children}
          <Toaster theme="dark" />
        </body>
      </I18nProvider>
    </html>
  )
}