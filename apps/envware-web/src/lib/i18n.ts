// Simple manual i18n - no next-intl dependency
export const translations = {
  en: {
    Nav: {
      home: "Home",
      docs: "Docs",
      simulator: "Simulator",
      login: "Login",
      signup: "Sign Up"
    },
    Home: {
      hero: {
        title: "Git Envware",
        subtitle: "Secure environment variables directly in your Git workflow",
        cta: "Get Started",
        ctaSecondary: "View Pricing"
      },
      features: {
        title: "Why Git Envware?",
        secure: {
          title: "End-to-End Encrypted",
          description: "Your secrets never leave your machine unencrypted"
        },
        git: {
          title: "Git-Native",
          description: "Works with your existing Git workflow"
        },
        team: {
          title: "Team Management",
          description: "Control who accesses what environments"
        }
      }
    },
    Pricing: {
      title: "Simple, Transparent Pricing",
      free: {
        name: "Free",
        price: "$0",
        features: ["1 team", "3 projects", "3 users per project"]
      },
      premium: {
        name: "Premium",
        price: "$19",
        period: "/month",
        features: ["3 teams", "10 projects per team", "5 users per project", "Priority support"]
      },
      cta: "Start Free Trial"
    },
    Footer: {
      copyright: "© {year} Git Envware. All rights reserved.",
      built: "Built for developers, by developers."
    }
  },
  pt: {
    Nav: {
      home: "Início",
      docs: "Docs",
      simulator: "Simulador",
      login: "Entrar",
      signup: "Cadastrar"
    },
    Home: {
      hero: {
        title: "Git Envware",
        subtitle: "Variáveis de ambiente seguras direto no seu fluxo Git",
        cta: "Começar Agora",
        ctaSecondary: "Ver Preços"
      },
      features: {
        title: "Por que Git Envware?",
        secure: {
          title: "Criptografia End-to-End",
          description: "Seus segredos nunca saem da sua máquina descriptografados"
        },
        git: {
          title: "Nativo no Git",
          description: "Funciona com seu fluxo Git existente"
        },
        team: {
          title: "Gestão de Equipe",
          description: "Controle quem acessa quais ambientes"
        }
      }
    },
    Pricing: {
      title: "Preços Simples e Transparentes",
      free: {
        name: "Grátis",
        price: "R$0",
        features: ["1 equipe", "3 projetos", "3 usuários por projeto"]
      },
      premium: {
        name: "Premium",
        price: "R$99",
        period: "/mês",
        features: ["3 equipes", "10 projetos por equipe", "5 usuários por projeto", "Suporte prioritário"]
      },
      cta: "Começar Teste Grátis"
    },
    Footer: {
      copyright: "© {year} Git Envware. Todos os direitos reservados.",
      built: "Feito para desenvolvedores, por desenvolvedores."
    }
  }
};

export type Locale = keyof typeof translations;

export function detectLocale(): Locale {
  if (typeof window === 'undefined') return 'en';
  const lang = navigator.language || (navigator as any).userLanguage || 'en';
  if (lang.startsWith('pt')) return 'pt';
  return 'en';
}

export function getTranslation(locale: Locale) {
  return translations[locale] || translations.en;
}