// BlokBot – service worker: appka se otevře i bez signálu (ukáže poslední stav po připojení).
var CACHE = 'blokbot-v1';
var SOUBORY = ['./', 'index.html', 'app.js', 'manifest.webmanifest', 'ikona-180.png', 'ikona-192.png', 'ikona-512.png'];

self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SOUBORY); }).then(function () { return self.skipWaiting(); }));
});
self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (k) {
    return Promise.all(k.filter(function (n) { return n !== CACHE; }).map(function (n) { return caches.delete(n); }));
  }).then(function () { return self.clients.claim(); }));
});
self.addEventListener('fetch', function (e) {
  var url = new URL(e.request.url);
  if (url.origin !== self.location.origin || e.request.method !== 'GET') return; // ntfy.sh jde vždy přímo
  // nejdřív síť (ať jsou vidět aktualizace), bez signálu z mezipaměti
  e.respondWith(fetch(e.request).then(function (r) {
    var kopie = r.clone();
    caches.open(CACHE).then(function (c) { c.put(e.request, kopie); });
    return r;
  }).catch(function () { return caches.match(e.request).then(function (r) { return r || caches.match('index.html'); }); }));
});
