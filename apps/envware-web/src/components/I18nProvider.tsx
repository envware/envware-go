'use client'

import { createContext, useContext, useState, useEffect } from 'react'
import { translations, detectLocale, Locale } from '@/lib/i18n'

const I18nContext = createContext<{
  locale: Locale
  t: typeof translations.en
}>({
  locale: 'en',
  t: translations.en
})

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocale] = useState<Locale>('en')

  useEffect(() => {
    setLocale(detectLocale())
  }, [])

  return (
    <I18nContext.Provider value={{ locale, t: translations[locale] }}>
      {children}
    </I18nContext.Provider>
  )
}

export function useI18n() {
  return useContext(I18nContext)
}