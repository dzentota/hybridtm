import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'HybridTM',
  description: 'Threat modeling as code',
  base: '/',
  locales: {
    root: {
      label: 'English',
      lang: 'en',
      link: '/en/',
      themeConfig: {
        nav: [
          { text: 'Guide', link: '/en/guide/getting-started' },
          { text: 'Knowledge Base', link: '/en/guide/kb-authoring' },
          { text: 'API Reference', link: '/en/guide/api-reference' },
          { text: 'Migration', link: '/en/guide/migration' },
          { text: 'In-depth guides', link: '/en/new-projects' },
        ],
        sidebar: {
          '/en/guide/': [
            {
              text: 'Studio Guide',
              items: [
                { text: 'Getting Started', link: '/en/guide/getting-started' },
                { text: 'Knowledge Base Authoring', link: '/en/guide/kb-authoring' },
                { text: 'API Reference', link: '/en/guide/api-reference' },
                { text: 'Migrating from plain hybridtm', link: '/en/guide/migration' },
              ],
            },
          ],
          '/en/': [
            {
              text: 'Studio Guide',
              items: [
                { text: 'Getting Started', link: '/en/guide/getting-started' },
                { text: 'Knowledge Base Authoring', link: '/en/guide/kb-authoring' },
                { text: 'API Reference', link: '/en/guide/api-reference' },
                { text: 'Migrating from plain hybridtm', link: '/en/guide/migration' },
              ],
            },
            {
              text: 'Library In-Depth',
              items: [
                { text: 'New Projects Guide', link: '/en/new-projects' },
                { text: 'Enterprise Adoption Guide', link: '/en/enterprise-adoption' },
                { text: 'DSL / Attribute Reference', link: '/en/reference' },
                { text: 'The Recognizable DSL Subset (ADR-08)', link: '/en/dsl-subset' },
              ],
            },
          ],
        },
      },
    },
    ru: {
      label: 'Русский',
      lang: 'ru',
      link: '/ru/',
      themeConfig: {
        nav: [
          { text: 'Руководство', link: '/ru/guide/getting-started' },
          { text: 'База знаний', link: '/ru/guide/kb-authoring' },
          { text: 'API', link: '/ru/guide/api-reference' },
          { text: 'Миграция', link: '/ru/guide/migration' },
          { text: 'Подробные руководства', link: '/ru/new-projects' },
        ],
        sidebar: {
          '/ru/guide/': [
            {
              text: 'Руководство по Studio',
              items: [
                { text: 'Быстрый старт', link: '/ru/guide/getting-started' },
                { text: 'Наполнение базы знаний', link: '/ru/guide/kb-authoring' },
                { text: 'Справочник API', link: '/ru/guide/api-reference' },
                { text: 'Миграция с чистого hybridtm', link: '/ru/guide/migration' },
              ],
            },
          ],
          '/ru/': [
            {
              text: 'Руководство по Studio',
              items: [
                { text: 'Быстрый старт', link: '/ru/guide/getting-started' },
                { text: 'Наполнение базы знаний', link: '/ru/guide/kb-authoring' },
                { text: 'Справочник API', link: '/ru/guide/api-reference' },
                { text: 'Миграция с чистого hybridtm', link: '/ru/guide/migration' },
              ],
            },
            {
              text: 'Библиотека подробно',
              items: [
                { text: 'Руководство для новых проектов', link: '/ru/new-projects' },
                { text: 'Руководство по внедрению в enterprise', link: '/ru/enterprise-adoption' },
                { text: 'Справочник DSL / атрибутов', link: '/ru/reference' },
                { text: 'Распознаваемое подмножество DSL (ADR-08)', link: '/en/dsl-subset' },
              ],
            },
          ],
        },
      },
    },
  },
  themeConfig: {
    socialLinks: [{ icon: 'github', link: 'https://github.com/hybridtm/hybridtm' }],
  },
})
