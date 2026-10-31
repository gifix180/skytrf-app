// SkyTrf : appli hors ligne (27/10/2026) et alertes (28/10/2026, en bas). Réseau d'abord ; sans réseau, dernière copie gardée (page chiffrée, relevé
// chiffré pmu.enc, icônes). Rien n'est déchiffré ici : les fichiers restent chiffrés dans le cache du téléphone.
const CACHE = "skytrf-v1";
self.addEventListener("install", e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(["./", "manifest.webmanifest", "icone-192.png", "icone-512.png"])).catch(() => {}));
});
self.addEventListener("activate", e => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
  await self.clients.claim();
})()));
self.addEventListener("fetch", e => {
  const req = e.request, u = new URL(req.url);
  if (req.method !== "GET" || u.origin !== self.location.origin) return;
  const cle = req.mode === "navigate" ? "./" : u.pathname.endsWith("/pmu.enc") ? "pmu.enc" : req;
  e.respondWith(fetch(req, {cache: "no-store"}).then(r => {
    if (r.ok) { const copie = r.clone(); caches.open(CACHE).then(c => c.put(cle, copie)); }
    return r;
  }).catch(async () => (await caches.match(cle, {ignoreSearch: true})) || Response.error()));
});
// Alertes avant les courses sûres (« web push », 28/10/2026) : le message arrive chiffré pour cet appareil ; le
// navigateur le déchiffre et le service l'affiche. Toucher l'alerte ouvre (ou ramène au premier plan) SkyTrf.
self.addEventListener("push", e => {
  let m = {};
  try { m = e.data ? e.data.json() : {}; } catch (x) { m = {body: e.data ? e.data.text() : ""}; }
  e.waitUntil(self.registration.showNotification(m.title || "SkyTrf", {
    body: m.body || "", tag: m.tag || "skytrf", renotify: true, icon: "icone-192.png", badge: "icone-192.png",
    data: {url: m.url || "./"}}));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || "./", self.registration.scope).href;
  e.waitUntil((async () => {
    for (const c of await self.clients.matchAll({type: "window", includeUncontrolled: true})) {
      if (c.url.startsWith(self.registration.scope) && "focus" in c) return c.focus();
    }
    return self.clients.openWindow(url);
  })());
});
