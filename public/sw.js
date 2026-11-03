/* Datensis Stock PWA: intentionally NO offline caching of confidential resources. */
self.addEventListener('install', event => {event.waitUntil(self.skipWaiting());});
self.addEventListener('activate', event => {event.waitUntil(self.clients.claim());});
self.addEventListener('fetch', event => {
  // Network-only request; never use CacheStorage or keep a secret in the worker.
  if (event.request.method !== 'GET' || new URL(event.request.url).origin !== self.location.origin) return;
  event.respondWith(fetch(event.request, {cache:'no-store'}));
});
