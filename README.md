# Mohamad Moukayed — Engineering Portfolio

A responsive portfolio built with HTML, CSS, JavaScript, and a small Node.js server. The admin board saves editable content to `content.json`.

```sh
npm install
npm start
```

Open the portfolio at http://localhost:3000 and the admin board at http://localhost:3000/admin.

## Personalize it

- Edit the introduction, featured chocolate printer, NYUAD competition details, and contact links in `/admin`.
- Replace the project media placeholders in `index.html` with your photographs, screenshots, or video embeds. The printer diagrams are illustrations, not photographs.
- Other project cards, skills, and profile sections can still be edited in `index.html`.

The local server listens on 127.0.0.1 by default so the content editor is only available on this computer.

## Deploying to Cloudflare Workers

The Worker uses `src/index.js`, serves built files from `public/`, and stores content, passkeys, sessions, and challenges in the `portfolio_admin` D1 binding. Copy `.dev.vars.example` to `.dev.vars` for local Worker development, then set a random `ADMIN_SETUP_TOKEN` and use `http://localhost:8787` as `ADMIN_ORIGIN` in that local file.

Run `npm run db:migrate:local` before local development. Run `npm run dev` to build the static files and start Wrangler. The Wrangler config already points to the production D1 database; run `npm run db:migrate:remote` once to create its tables and seed the current portfolio content. Set `ADMIN_SETUP_TOKEN` with `npx wrangler secret put ADMIN_SETUP_TOKEN`, then deploy with `npm run deploy`.

In Cloudflare Workers Builds, use the repository root as the root directory, leave the separate build command blank, and set the deploy command to `npm run deploy`. This deploy script builds the public assets before invoking Wrangler.

## Admin passkey

Open the localhost address printed by the server and visit `/admin`. On first use, create a passkey with your device or password manager. Add a second passkey from the admin page as a recovery option.

For a hosted site, serve the admin over HTTPS and configure its exact origin as `ADMIN_ORIGIN` and a random one-time setup token of at least 32 characters as `ADMIN_SETUP_TOKEN` before starting the server. Set the token through your host's secret settings.

Enter that token only during the first passkey setup, then remove it from the server environment. The server stores passkey public keys and counters in the private `.admin-auth.json` file; it never stores passkey secrets. Sessions expire after eight hours and are cleared when the server restarts. Keep a second passkey registered to avoid losing access. To reset a lost passkey, stop the server, remove `.admin-auth.json`, and repeat first-time setup. For a hosted site, you'll need the setup token again.
