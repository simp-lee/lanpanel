import { defineConfig } from 'vitepress'

export default defineConfig({
  lang: 'zh-CN',
  title: 'Lanpanel',
  description: 'Lanpanel 中文文档',
  srcDir: 'zh-CN',
  base: process.env.DOCS_BASE || '/',
  cleanUrls: true,
  lastUpdated: true,
  metaChunk: true,
  head: [
    ['meta', { name: 'theme-color', content: '#1f6feb' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'Lanpanel 中文文档' }],
    ['meta', { property: 'og:description', content: '单台服务器私有网络和应用发布工具的中文文档' }]
  ],
  themeConfig: {
    siteTitle: 'Lanpanel 文档',
    nav: [
      { text: '首页', link: '/' },
      {
        text: '快速开始',
        items: [
          { text: '部署私有网络', link: '/quickstart' },
          { text: '发布本机 App', link: '/app-quickstart' }
        ]
      },
      { text: 'GitHub', link: 'https://github.com/simp-lee/lanpanel' }
    ],
    sidebar: [
      {
        text: '开始',
        items: [
          { text: '中文文档首页', link: '/' },
          { text: '安装和升级', link: '/install' },
          { text: '快速开始：部署私有网络', link: '/quickstart' },
          { text: '快速开始：发布本机 App', link: '/app-quickstart' },
          { text: '核心概念', link: '/concepts' }
        ]
      },
      {
        text: '使用手册',
        items: [
          { text: 'UI 面板手册', link: '/ui' },
          { text: 'App 配置参考', link: '/app' },
          { text: 'CLI 运维手册', link: '/cli' }
        ]
      },
      {
        text: '运维',
        items: [
          { text: '服务器和客户端运维', link: '/operations' },
          { text: '常见问题和排障', link: '/troubleshooting' },
          { text: '安全边界', link: '/security' }
        ]
      },
      {
        text: '开发者',
        items: [
          { text: '开发和人工测试', link: '/development' }
        ]
      }
    ],
    outline: {
      level: [2, 3],
      label: '本页目录'
    },
    search: {
      provider: 'local',
      options: {
        locales: {
          root: {
            translations: {
              button: {
                buttonText: '搜索文档',
                buttonAriaLabel: '搜索文档'
              },
              modal: {
                displayDetails: '显示详情',
                resetButtonTitle: '清除搜索',
                backButtonTitle: '返回',
                noResultsText: '没有找到结果',
                footer: {
                  selectText: '选择',
                  navigateText: '切换',
                  closeText: '关闭'
                }
              }
            }
          }
        }
      }
    },
    docFooter: {
      prev: '上一页',
      next: '下一页'
    },
    lastUpdated: {
      text: '最后更新',
      formatOptions: {
        dateStyle: 'short',
        timeStyle: 'medium'
      }
    },
    darkModeSwitchLabel: '外观',
    sidebarMenuLabel: '菜单',
    returnToTopLabel: '回到顶部',
    langMenuLabel: '语言',
    externalLinkIcon: true
  }
})
