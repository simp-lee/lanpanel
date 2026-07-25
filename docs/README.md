# Lanpanel Docs Site

This directory contains the VitePress documentation site.

The published site source is `docs/zh-CN`. Other files under `docs/`, such as P0 notes or backups, are not part of the VitePress source because `docs/.vitepress/config.mts` sets:

```ts
srcDir: 'zh-CN'
```

## Local Preview

```bash
npm install
npm run docs:dev
```

The dev server listens on `127.0.0.1`.

## Build

```bash
npm run docs:build
```

The static output is written to:

```text
docs/.vitepress/dist
```

## GitHub Pages

The workflow is `.github/workflows/docs.yml`.

By default it builds with:

```text
DOCS_BASE=/lanpanel/
```

This matches GitHub project Pages:

```text
https://<owner>.github.io/lanpanel/
```

When publishing behind `docs.lanpanel.com` or `lanpanel.com`, change `DOCS_BASE` in the workflow to:

```text
/
```

Then configure the custom domain in GitHub Pages or the hosting provider.

