/* VaultPGP Service Worker — cache-first, no external requests */
const CACHE_NAME = 'vaultpgp-v0.7.4';
const CORE_ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './styles.css',
  './app.js',
  './worker.js',
  './openpgp.min.js',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/apple-touch-icon.png'
];

/* Install: pre-cache all core assets */
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(CORE_ASSETS))
      .then(() => self.skipWaiting())
  );
});

/* Activate: delete old caches */
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

/* Fetch: cache-first strategy, block all external requests */
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  /* Block any request that isn't same-origin */
  if (url.origin !== self.location.origin) {
    event.respondWith(new Response('Network access blocked by VaultPGP policy.', {
      status: 403,
      statusText: 'Blocked'
    }));
    return;
  }

  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      /* Not in cache — serve from network (only during install phase) */
      return fetch(event.request).then(response => {
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }
        const toCache = response.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(event.request, toCache));
        return response;
      });
    })
  );
});
