import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'LanPanel',
  description: 'LanPanel product, operations, and qualification documentation',
  base: process.env.DOCS_BASE || '/',
  cleanUrls: true,
  lastUpdated: true,
  rewrites: {
    'README.md': 'index.md'
  },
  themeConfig: {
    nav: [
      { text: 'Documentation', link: '/' },
      { text: 'Qualification', link: '/qualification' }
    ],
    sidebar: [
      {
        text: 'LanPanel',
        items: [
          { text: 'Documentation', link: '/' },
          { text: 'GA Qualification Tooling', link: '/qualification' }
        ]
      }
    ],
    outline: {
      level: [2, 3],
      label: 'On this page'
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/simp-lee/lanpanel' }
    ]
  }
})
