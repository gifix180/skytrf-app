# hgb-pages

Pages privées du projet HGB, protégées par mot de passe.

- `index.html` : page « Montes et partants », **chiffrée** (AES-256-GCM, clé tirée du mot de passe). Déposée par le
  dépôt privé du projet après chaque passage du suivi.
- `pmu.enc` : relevé PMU du jour (données publiques du PMU), **chiffré** de la même façon ; mis à jour toutes les
  30 minutes pendant les courses par `releve.py` (`.github/workflows/releve.yml`).

Ce dépôt ne contient aucune donnée en clair : sans le mot de passe, la page n'affiche qu'un champ « mot de passe ».
L'historique est volontairement réduit à un seul commit (les fichiers sont remplacés à chaque mise à jour).
- `alertes.py` : alertes sur le téléphone avant les courses sûres (« web push »), appelé par `releve.py`. Lit
  `alertes.enc` (liste du jour, **chiffrée**) et les abonnements des appareils (secrets `ALERTES_1` … `ALERTES_5`) ; le
  message est chiffré pour l'appareil. `alertes_envoyees.json` : empreintes des alertes déjà envoyées (illisibles).
  Essai : Actions → « Alerte d'essai » → Run workflow.
- `releve.yml` tourne jour et nuit (pas de relevé de 23 h à 8 h) et lance le matin (8 h 55, puis 10 h 05) le suivi du dépôt
  privé, dont GitHub retarde les horaires (secret `SUIVI_TOKEN` : clé limitée au dépôt privé, droit Actions seulement).
  `suivi_lance.txt` : jours où le suivi a été lancé.
