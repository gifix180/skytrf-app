"""Alertes SkyTrf sur le téléphone avant les courses sûres (« web push », 28/10/2026, demande du propriétaire).

Appelé par releve.py après chaque relevé (toutes les 15 min) :
- lit alertes.enc (courses du jour et notre 1er, déposé chiffré par le dépôt privé avec la page) ;
- recalcule le niveau de chaque course comme la page (notre 1er = favori unique du moment à moins de 2,
  12 partants au plus → « Très sûre » ; table de croisement → « Sûre ») ;
- envoie une alerte aux appareils abonnés pour les courses qui partent dans 30 minutes au plus.

Abonnements : secrets ALERTES_1 … ALERTES_5 (texte copié depuis le bouton « Alertes » de la page, un par appareil).
Clé d'envoi (VAPID) : dérivée du mot de passe (secret HGB_MOT_DE_PASSE), aucune autre clé à garder.
Le message est chiffré pour l'appareil (RFC 8291) : Apple / Google le transportent sans pouvoir le lire.
Le journal de GitHub (public) n'affiche que des nombres, jamais une course.
Mémoire des alertes envoyées : alertes_envoyees.json (empreintes illisibles sans le mot de passe).

    HGB_MOT_DE_PASSE=… ALERTES_1=… python alertes.py --essai     # alerte d'essai à tous les appareils
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

TOURS = 600_000
SEL = b"hgb-pages-sel-v1"
SEL_VAPID = b"skytrf-vapid-v1"      # même calcul dans le dépôt privé (tools/page/libre/alertes.py) : ne pas changer
SUJET = "https://gifix180.github.io/skytrf-app/"
AVANCE_MIN = 30                     # alerte quand le départ est dans 30 min au plus (relevé toutes les 15 min)
MEMOIRE = "alertes_envoyees.json"
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
NIV = {3: "Très sûre", 2: "Sûre"}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def d64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def cle_vapid(mdp):
    """Clé privée P-256 dérivée du mot de passe (PBKDF2, sel propre aux alertes)."""
    brut = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=SEL_VAPID, iterations=TOURS).derive(mdp.encode())
    return ec.derive_private_key(int.from_bytes(brut, "big") % (N_P256 - 1) + 1, ec.SECP256R1())


def publique(cle):
    return cle.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def jwt_vapid(cle, endpoint, duree=12 * 3600):
    u = urllib.parse.urlsplit(endpoint)
    entete = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    corps = b64u(json.dumps({"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + duree, "sub": SUJET},
                            separators=(",", ":")).encode())
    r, s = decode_dss_signature(cle.sign(f"{entete}.{corps}".encode(), ec.ECDSA(hashes.SHA256())))
    return f"{entete}.{corps}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _hmac(k, m):
    return hmac.new(k, m, hashlib.sha256).digest()


def chiffrer_push(texte, p256dh, auth, sel=None, ephemere=None):
    """Chiffrement « aes128gcm » du message pour l'appareil (RFC 8291 + RFC 8188, un seul bloc)."""
    ua_pub = d64u(p256dh)
    ua = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_pub)
    as_priv = ephemere or ec.generate_private_key(ec.SECP256R1())
    as_pub = publique(as_priv)
    secret = as_priv.exchange(ec.ECDH(), ua)
    ikm = _hmac(_hmac(d64u(auth), secret), b"WebPush: info\x00" + ua_pub + as_pub + b"\x01")
    sel = sel or os.urandom(16)
    prk = _hmac(sel, ikm)
    cek = _hmac(prk, b"Content-Encoding: aes128gcm\x00\x01")[:16]
    nonce = _hmac(prk, b"Content-Encoding: nonce\x00\x01")[:12]
    ct = AESGCM(cek).encrypt(nonce, texte.encode("utf-8") + b"\x02", None)
    return sel + struct.pack("!IB", 4096, len(as_pub)) + as_pub + ct


def envoyer(cle, abo, message, ttl=1800):
    """Envoie un message à un appareil. Rend le code HTTP (201 = accepté ; 404 / 410 = abonnement expiré)."""
    corps = chiffrer_push(json.dumps(message, ensure_ascii=False), abo["keys"]["p256dh"], abo["keys"]["auth"])
    req = urllib.request.Request(abo["endpoint"], data=corps, method="POST", headers={
        "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", "TTL": str(ttl), "Urgency": "high",
        "Authorization": f"vapid t={jwt_vapid(cle, abo['endpoint'])}, k={b64u(publique(cle))}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def abonnements():
    """Secrets ALERTES_1 … ALERTES_5 : {"niveau": 3 ou 2, "endpoint": …, "keys": {"p256dh": …, "auth": …}}."""
    L = []
    for i in range(1, 6):
        t = (os.environ.get(f"ALERTES_{i}") or "").strip()
        if not t:
            continue
        try:
            a = json.loads(t)
            assert a["endpoint"].startswith("https://") and a["keys"]["p256dh"] and a["keys"]["auth"]
            L.append({"i": i, "niveau": 2 if a.get("niveau") == 2 else 3, "endpoint": a["endpoint"], "keys": a["keys"]})
        except Exception:
            print(f"::warning::ALERTES_{i} illisible (recopier le texte du bouton « Alertes »)")
    return L


def dechiffrer(fichier, mdp):
    with open(fichier) as f:
        d = json.load(f)
    cle = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SEL, iterations=TOURS).derive(mdp.encode())
    return json.loads(AESGCM(cle).decrypt(base64.b64decode(d["iv"]), base64.b64decode(d["ct"]), None))


def bande(n):
    return "5-7" if n <= 7 else "8-9" if n <= 9 else "10-12" if n <= 12 else "13+"


def niveau_du_moment(c, participants, croise):
    """Même calcul que la page (surCourse) : favori et partants du moment ; sinon niveau du matin."""
    o = {"niveau": c["niveau"], "partants": c["partants"], "fav": None}
    if not participants:
        return o
    act = [p for p in participants if p.get("statut") == "PARTANT"]
    rap = lambda p: (p.get("dernierRapportDirect") or {}).get("rapport") or 0
    wc = [p for p in act if rap(p) > 1]
    if act:
        o["partants"] = len(act)
    if not act or len(wc) != len(act):
        return o
    mn = min(rap(p) for p in wc)
    f = [p for p in wc if rap(p) == mn]
    if len(f) != 1:
        return o
    accord = f[0].get("numPmu") == c["t1"][0]
    o["fav"] = [f[0].get("numPmu"), mn]
    place1, g4 = c.get("place1") or 0, c.get("g4") or 0
    k = f"{bande(o['partants'])}|{'oui' if accord else 'non'}|{'<2' if mn < 2 else '2-3' if mn < 3 else '3+'}"
    if k in croise:
        place1, g4 = croise[k][0], croise[k][1]
    o["niveau"] = 3 if (accord and mn < 2 and o["partants"] <= 12) else 2 if (place1 >= 0.65 or g4 >= 0.85) else 1
    return o


def cote(v):
    return f"{v:.1f}".replace(".", ",")


def message(c, o, hippo, h):
    t = f"{NIV[o['niveau']]} · R{c['r']} C{c['n']} · {h}"
    b = f"{hippo} · notre 1er n°{c['t1'][0]} {c['t1'][1]}".strip()
    if o["fav"]:
        b += f" · favori n°{o['fav'][0]} à {cote(o['fav'][1])}"
    b += f" · {o['partants']} partants"
    return {"title": t, "body": b, "tag": f"skytrf-{c['r']}-{c['n']}", "url": "./"}


def lire_memoire(jour):
    try:
        with open(MEMOIRE) as f:
            m = json.load(f)
    except Exception:
        m = {}
    if m.get("jour") != jour:
        m = {"jour": jour, "envoyees": [], "abonnes": m.get("abonnes") or []}
    return m


def apres_releve(jour, data, base, d, mdp, maintenant_ms=None):
    """Appelé par releve.py avec les données du relevé. Ne lève jamais d'erreur (le relevé passe avant)."""
    try:
        abos = abonnements()
        if not abos:
            return
        if not os.path.exists("alertes.enc"):
            print("alertes : pas de liste du jour (alertes.enc absent)")
            return
        A = dechiffrer("alertes.enc", mdp)
        if A.get("date") != jour:
            print("alertes : liste d'un autre jour (page du jour pas encore déposée)")
            return
        cle = cle_vapid(mdp)
        tag = lambda s: _hmac(cle.private_numbers().private_value.to_bytes(32, "big"), s.encode()).hex()[:20]
        m = lire_memoire(jour)
        maintenant = maintenant_ms if maintenant_ms is not None else time.time() * 1000
        prog = {(r["numOfficiel"], c["numOrdre"]): (r, c) for r in data[base + d]["programme"]["reunions"] for c in r["courses"]}
        nb, expires = 0, set()
        # nouvel appareil : message de bienvenue (vérifie toute la chaîne)
        for a in abos:
            t = tag("abo|" + a["endpoint"])
            if t not in m["abonnes"]:
                code = envoyer(cle, a, {"title": "SkyTrf · alertes activées ✓", "body": f"Vous serez prévenu environ 15 à 30 min avant chaque course {'Très sûre ou Sûre' if a['niveau'] == 2 else 'Très sûre'}.", "tag": "skytrf-bienvenue", "url": "./"})
                if code in (200, 201, 202):
                    m["abonnes"].append(t)
                print(f"alertes : bienvenue appareil {a['i']} → {code}")
        for c in A.get("courses") or []:
            rc = prog.get((c["r"], c["n"]))
            if not rc or not rc[1].get("heureDepart") or rc[1].get("ordreArrivee"):
                continue
            reste = (rc[1]["heureDepart"] - maintenant) / 60000
            if not (0 < reste <= AVANCE_MIN):
                continue
            j = data.get(f"{base}{d}/R{c['r']}/C{c['n']}/participants") or {}
            o = niveau_du_moment(c, j.get("participants"), A.get("croise") or {})
            if o["niveau"] < 2:
                continue
            h = datetime.fromtimestamp(rc[1]["heureDepart"] / 1000, ZoneInfo("Europe/Paris")).strftime("%H:%M")
            msg = message(c, o, ((rc[0].get("hippodrome") or {}).get("libelleCourt") or "").title(), h)
            for a in abos:
                if o["niveau"] < a["niveau"]:
                    continue
                t = tag(f"{jour}|{c['r']}|{c['n']}|{a['endpoint']}")
                if t in m["envoyees"]:
                    continue
                code = envoyer(cle, a, msg)
                if code in (200, 201, 202):
                    m["envoyees"].append(t); nb += 1
                elif code in (404, 410):
                    expires.add(a["i"])
                else:
                    print(f"alertes : appareil {a['i']} → réponse {code}")
        for i in sorted(expires):
            print(f"::warning::ALERTES_{i} expiré (réactiver les alertes sur l'appareil et recopier le texte)")
        with open(MEMOIRE, "w") as f:
            json.dump(m, f)
        print(f"alertes : {nb} envoyée(s), {len(abos)} appareil(s)")
    except Exception as e:  # jamais bloquant ; pas de détail de course dans le journal public
        print(f"::warning::alertes : erreur {type(e).__name__}")


def essai():
    mdp = os.environ["HGB_MOT_DE_PASSE"]
    cle, abos = cle_vapid(mdp), abonnements()
    if not abos:
        sys.exit("aucun abonnement (secrets ALERTES_1 … ALERTES_5 vides)")
    for a in abos:
        code = envoyer(cle, a, {"title": "SkyTrf · essai ✓", "body": "Les alertes arrivent bien sur cet appareil.", "tag": "skytrf-essai", "url": "./"})
        print(f"appareil {a['i']} → {code}{' (accepté)' if code in (200, 201, 202) else ' (expiré : réactiver et recopier)' if code in (404, 410) else ''}")


if __name__ == "__main__":
    if "--essai" in sys.argv:
        essai()
    elif "--cle" in sys.argv:
        print(b64u(publique(cle_vapid(os.environ["HGB_MOT_DE_PASSE"]))))
