/* Daderezo PWA Service Worker v4.2 — Résilience Hors-Ligne & Cache Intelligent */
const CACHE_SHELL = 'daderezo-shell-v4.2';
const CACHE_DATA = 'daderezo-telemetry-v4.2';

const SHELL_ASSETS = [
  '/',
  '/ui',
  '/offline.html',
  '/manifest.webmanifest',
  '/favicon.png',
  '/favicon.svg',
  '/logo-icon.png',
  '/icon-192.png',
  '/icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_SHELL).then((cache) => cache.addAll(SHELL_ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k !== CACHE_SHELL && k !== CACHE_DATA)
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Ne jamais mettre en cache les endpoints d'authentification privés
  if (url.pathname.startsWith('/auth/')) return;

  // 1. Assets visuels statiques -> Stale-While-Revalidate
  if (/\.(png|jpg|jpeg|svg|ico|webmanifest)$/.test(url.pathname)) {
    event.respondWith(
      caches.open(CACHE_SHELL).then(async (cache) => {
        const cached = await cache.match(req);
        const netFetch = fetch(req).then((res) => {
          if (res && res.ok) cache.put(req, res.clone());
          return res;
        }).catch(() => cached);
        return cached || netFetch;
      })
    );
    return;
  }

  // 2. Navigation HTML (/, /ui, /app) -> Network-First avec repli Console en cache ou /offline.html
  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(CACHE_SHELL).then((c) => c.put(req, copy));
          }
          return res;
        })
        .catch(async () => {
          const shell = await caches.open(CACHE_SHELL);
          return (
            (await shell.match(req)) ||
            (await shell.match('/ui')) ||
            (await shell.match('/offline.html'))
          );
        })
    );
    return;
  }

  // 3. Télémétrie lecture seule -> Network-First avec dernier état connu en cas de coupure FAI
  if (
    url.pathname === '/health' ||
    url.pathname === '/agents' ||
    url.pathname.startsWith('/dashboard/') ||
    url.pathname === '/supervisor/overview'
  ) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          if (res && res.ok && !req.headers.get('authorization')) {
            const copy = res.clone();
            caches.open(CACHE_DATA).then((c) => c.put(req, copy));
          }
          return res;
        })
        .catch(async () => {
          const dataCache = await caches.open(CACHE_DATA);
          const cached = await dataCache.match(req);
          if (cached) return cached;
          return new Response(JSON.stringify({ status: 'offline', offline_cached: true }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' }
          });
        })
    );
  }
});
