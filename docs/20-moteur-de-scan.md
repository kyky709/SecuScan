# 20 — Le moteur de scan

> Ce qui se passe entre la réception d'une adresse et la production du rapport.
> Fichiers : `src/lib/scanner/scan.ts` (orchestrateur), `target.ts`, `network/*`, `checks/html.ts`.

## 1. Les six étapes de `scanSite(input)`

```
saisie ──► 1. normalizeTarget ──► 2. pré-contrôle DNS ──► 3. sondes ──► 4. contexte ──► 5. contrôles ──► 6. note
```

### Étape 1 — Normaliser la saisie (`target.ts`)

L'utilisateur peut taper `example.com`, `HTTPS://Example.com:443/page#ancre` ou `exemple.рф`.
`normalizeTarget` produit une cible unique (`ScanTarget`) et refuse ce qui ne doit pas être analysé :

| Règle | Exemple refusé | Code |
|---|---|---|
| URL lisible (parseur WHATWG, celui des navigateurs) | `http://exa mple.com` | `INVALID_URL` |
| Schéma `http` ou `https` uniquement | `file:///etc/passwd`, `javascript:…` | `UNSUPPORTED_PROTOCOL` |
| Pas d'identifiants dans l'adresse (ils seraient envoyés au site) | `user:pw@example.com` | `CREDENTIALS_IN_URL` |
| Ports 80 et 443 uniquement (sinon : outil de scan de ports) | `example.com:8080` | `FORBIDDEN_PORT` |
| Nom public : pas de `localhost`, `.local`, `.internal`, `.home.arpa`… | `metadata.google.internal` | `TARGET_NOT_ALLOWED` |
| IP littérale publique (toutes les écritures : `0x7f.1`, `2130706433`, `[::ffff:127.0.0.1]`…) | `169.254.169.254` | `TARGET_NOT_ALLOWED` |

L'URL analysée est toujours en **HTTPS**, sans fragment ni port ; le nom d'hôte est en minuscules,
sans point final, internationalisé en punycode.

### Étape 2 — Pré-contrôle DNS

`resolveHost` résout le nom et vérifie **toutes** ses adresses. Un nom introuvable donne `DNS_FAILURE`
(message clair) ; un nom qui pointe vers une adresse privée donne `TARGET_NOT_ALLOWED`. Ce contrôle sert
à expliquer les refus ; la vraie protection est revérifiée à **chaque** connexion (étape 3).

### Étape 3 — Six sondes en parallèle

Elles partent en même temps (le scan dure le temps de la plus lente) et partagent un signal
d'annulation : au-delà de **20 s** (`SCAN_TIMEOUT_MS`), tout ce qui est encore en cours est arrêté.

| Sonde | Requête | Corps lu | Sert à |
|---|---|---|---|
| `https` | `GET https://hôte/chemin`, redirections suivies | HTML, 2 Mio max | En-têtes, cookies, HTML, certificat de l'hôte final |
| `http` | `GET http://hôte/chemin`, redirections suivies | non | Redirection vers HTTPS, cookies déposés en clair |
| `tls` | Négociation TLS sur le port 443, puis TLS 1.0 et 1.1 | — | Certificat, version, anciens protocoles |
| `securityTxt` | `GET /.well-known/security.txt`, 3 redirections max | 64 Kio max | Contrôle security.txt |
| `cors` | `GET` avec `Origin: https://secuscan-cors-probe.invalid` | non | Contrôle CORS |
| `caa` | Requêtes DNS CAA, en remontant vers les domaines parents | — | Contrôle CAA |

Au total, une analyse ouvre généralement **6 à 8 connexions** vers le site (dont les redirections et
les trois négociations TLS) et quelques requêtes DNS. Le scanner s'identifie par son User-Agent :
`Mozilla/5.0 (compatible; SecuScan/1.0.0[; +adresse de contact])`.

**Résilience.**
- Une sonde coupée par le serveur (`CONNECTION_RESET`) est **retentée une fois** après 500 ms :
  certains serveurs coupent les connexions simultanées d'un même client (constaté sur badssl.com).
  Les autres échecs (refus, délai, erreur TLS) sont stables et ne sont pas retentés.
- La sonde TLS teste TLS 1.0 et 1.1 **après** la négociation principale, et seulement si elle a
  réussi, pour ne pas ouvrir trois connexions à la fois.
- Si la sonde TLS échoue mais que la connexion HTTPS a abouti, le contrôle du certificat s'appuie sur
  la validation faite pendant cette connexion (`HttpResponse.tls`).

Si **ni HTTPS ni HTTP** ne répondent, il n'y a rien à analyser : le scan s'arrête avec
`TARGET_UNREACHABLE` (ou `TIMEOUT`, ou `TARGET_NOT_ALLOWED` si une redirection menait vers une adresse
interne). Toute autre sonde en échec rend seulement « Non vérifié » les contrôles qui en dépendent.

### Étape 4 — Construire le `ScanContext`

La **réponse analysée** est la réponse HTTPS finale, ou à défaut la réponse HTTP (site sans HTTPS).
Si c'est du HTML et que le corps a été lu, `extractHtmlInfo` (`checks/html.ts`) en extrait, comme un
navigateur : scripts exécutables (pas les blocs JSON-LD), feuilles de style, images, cadres, objets,
formulaires, CSP et Referrer-Policy en `<meta>`, en résolvant les URL relatives avec le premier
`<base href>`. Le contenu des commentaires et des `<template>` est ignoré. Le parcours de l'arbre est
itératif (pas de débordement de pile sur une page de 100 000 `<div>` imbriqués).

### Étape 5 — Évaluer les 18 contrôles

`CHECKS.map(evaluate)` : des fonctions pures, voir [21-controles.md](21-controles.md). Chaque appel est
protégé : un contrôle qui lèverait une exception passe en « Non vérifié » sans gêner les autres.

### Étape 6 — Noter et assembler le rapport

`computeScore` applique la méthode de [22-notation.md](22-notation.md). Le `ScanReport` contient aussi
les chaînes de redirections, les en-têtes bruts de la réponse analysée, les détails TLS et la liste
des sondes en échec (pour expliquer les « Non vérifié »).

## 2. La couche réseau anti-SSRF (`network/`)

Pourquoi ne pas utiliser `fetch()` ? Il ne permet pas de contrôler **l'adresse réellement contactée**,
ni de lire la réponse d'un site au certificat invalide, ni de récupérer les en-têtes dupliqués.
SecuScan utilise donc `node:http`, `node:https` et `node:tls` avec des réglages précis.

| Fichier | Rôle |
|---|---|
| `ip.ts` | Politique d'adresses : seules les adresses publiques « unicast » sont autorisées (IPv6 dans `2000::/3`) ; NAT64, 6to4 et Teredo, qui peuvent cacher une IPv4 interne, sont refusés |
| `safe-lookup.ts` | Fonction `lookup` donnée à Node.js : résout le nom et refuse s'**une seule** adresse est interdite. Elle est appelée **au moment de chaque connexion** : un changement de réponse DNS entre deux étapes (*DNS rebinding*) est donc intercepté |
| `http-client.ts` | Client HTTP(S) : `agent: false`, redirections suivies à la main et revalidées, délais, taille de corps bornée, décompression, encodages |
| `tls-probe.ts` | Négociation TLS directe : certificat, chaîne, protocole, ALPN, anciens protocoles |
| `dns.ts` | Recherche des enregistrements CAA (RFC 8659), avec remontée vers les domaines parents |

Les pièges découverts par expérience sur Node.js 24 (voir [journal.md](journal.md)) :

- une connexion réutilisée (*keep-alive*) **ne repasse pas** par `lookup` : d'où `agent: false` ;
- Node.js n'appelle pas `lookup` pour une IP littérale : elle est vérifiée à part ;
- quand la chaîne de certificats est invalide, Node.js ne signale plus l'erreur de nom d'hôte : elle
  est vérifiée séparément (`checkServerIdentity`) ;
- `message.headers` fusionne ou supprime certains en-têtes dupliqués : SecuScan lit `headersDistinct` ;
- l'option `timeout` de Node.js ne détecte qu'une inactivité : le délai total est imposé par un
  `AbortSignal` ;
- la taille maximale d'un corps est vérifiée **après** décompression (bombe de décompression).

## 3. Réglages (`src/lib/config.ts`)

| Réglage | Valeur | Pourquoi |
|---|---|---|
| `REQUEST_TIMEOUT_MS` | 8 s | Délai total d'une requête, redirections comprises |
| `TLS_TIMEOUT_MS` | 6 s | Négociation TLS |
| `DNS_TIMEOUT_MS` | 4 s | Résolution DNS |
| `SCAN_TIMEOUT_MS` | 20 s | Délai global ; la fonction Vercel a 30 s (`maxDuration`) |
| `MAX_REDIRECTS` | 10 | Au-delà : `TOO_MANY_REDIRECTS` (boucle détectée plus tôt) |
| `MAX_BODY_BYTES` | 2 Mio | Taille de page analysée |
| `MAX_SECURITY_TXT_BYTES` | 64 Kio | Taille de security.txt analysée |
| `ALLOWED_PORTS` | 80, 443 | Pas de scan de ports |
| `RATE_LIMIT_PER_CLIENT` | 10 / minute | Par adresse IP (hachée) du visiteur |
| `RATE_LIMIT_PER_TARGET` | 6 / minute | Par site analysé : SecuScan ne sert pas à harceler un site |

## 4. Performances

Mesures sur des sites réels (novembre 2026) : 0,6 s (github.com) à 8 s (serveurs lents ou qui coupent
les connexions). Le pire cas est borné par le délai global de 20 s. Les analyseurs (CSP, cookies,
srcset, security.txt…) sont **linéaires** : une page piégée de 2 Mio est traitée en moins d'une seconde
(voir la section ReDoS de [30-securite.md](30-securite.md)).
