# 10 — Architecture

> Vue d'ensemble : comment les morceaux de SecuScan s'emboîtent, du formulaire jusqu'au rapport.
> Pour le détail du moteur, lire ensuite [20-moteur-de-scan.md](20-moteur-de-scan.md).

## 1. En une image

```
Navigateur (React)                         Serveur (fonction Vercel, Node.js 24)
──────────────────                         ─────────────────────────────────────────────────────
ScanForm ──► api.ts ── POST /api/scan ──►  route.ts : origine · corps JSON (zod) · limite de débit
   ▲          {url}                            │
   │                                           ▼
   │                                       scanSite(url)                    src/lib/scanner/scan.ts
   │                                           │ 1. normalizeTarget          target.ts (1re barrière SSRF)
   │                                           │ 2. pré-contrôle DNS         network/safe-lookup.ts
   │                                           │ 3. 6 sondes en parallèle    network/* (délai global 20 s)
   │                                           │      https · http · tls · security.txt · cors · caa
   │                                           │ 4. ScanContext + HTML       checks/html.ts
   │                                           │ 5. 18 contrôles purs        checks/<id>.ts
   │                                           │ 6. computeScore             scoring.ts
   │                                           ▼
ReportView ◄──────── ScanReport (JSON) ◄──────┘
```

Une seule application **Next.js 16 (App Router)** contient l'interface et l'API : un seul projet, un
seul déploiement Vercel. L'analyse tourne **côté serveur**, pour deux raisons : un navigateur ne peut
ni lire les en-têtes d'un autre site (politique CORS), ni inspecter une négociation TLS.

## 2. Le principe clé : « cœur fonctionnel, coquille impérative »

Le moteur sépare strictement deux mondes :

| | Coquille impérative | Cœur fonctionnel |
|---|---|---|
| Fichiers | `scan.ts`, `network/*` | `checks/*`, `scoring.ts` |
| Rôle | Ouvrir des connexions, attendre, gérer les erreurs et les délais | Interpréter des faits, décider d'un verdict |
| Caractère | Lent, faillible, difficile à tester | Instantané, déterministe, testé sans réseau |
| Entrée → sortie | URL → `ScanContext` (faits bruts) | `ScanContext` → `CheckOutcome` (verdict) |

Conséquences concrètes :

- **Un contrôle ne fait jamais de requête.** Il reçoit des réponses déjà collectées. Ajouter un
  contrôle ne rend donc pas le scan plus lent, et chaque contrôle se teste avec un contexte fabriqué
  à la main (`test/helpers/context.ts`), sans Internet.
- **Les sondes sont partagées.** Une seule requête HTTPS sert à huit contrôles d'en-têtes.
- **Les erreurs sont des valeurs.** Les sondes renvoient un `Result<T>` (`{ ok: true, value }` ou
  `{ ok: false, error }`) au lieu de lever des exceptions : chaque contrôle est obligé de traiter le
  cas « sonde en échec » (statut *Non vérifié*, 0 point).

## 3. Arborescence

```
src/
├── app/                          Pages et routes (App Router)
│   ├── layout.tsx                Squelette HTML, polices, en-tête/pied de page, nonce CSP
│   ├── page.tsx                  Accueil : formulaire + rapport (?url= relance une analyse)
│   ├── methodologie/page.tsx     Méthode et grilles, générées depuis le registre des contrôles
│   ├── a-propos/page.tsx         Projet, technologies, données, limites
│   ├── api/scan/route.ts         POST /api/scan : filtre, limite, traduit les erreurs
│   ├── api/health/route.ts       GET /api/health : supervision
│   ├── error.tsx, not-found.tsx  Pages d'erreur
│   └── robots.ts, sitemap.ts     Référencement
├── components/
│   ├── scan/                     Formulaire, appel de l'API, carte de chargement
│   ├── report/                   Rapport : note, filtres, cartes de contrôle, panneaux TLS/redirections
│   ├── layout/                   En-tête, pied de page, lien d'évitement
│   └── ui/                       Petits composants réutilisables (bouton copier, lien externe)
├── lib/
│   ├── config.ts                 Tous les réglages : délais, tailles, User-Agent, limites de débit
│   ├── rate-limit.ts             Limitation de débit (mémoire ou Upstash Redis)
│   ├── site.ts                   Nom, adresse publique, dépôt
│   ├── security/csp.ts           CSP stricte à nonce de SecuScan lui-même
│   └── scanner/
│       ├── index.ts              Point d'entrée serveur (« server-only »)
│       ├── types.ts              LE contrat : tout le modèle de données
│       ├── target.ts             Normalisation et validation de la saisie
│       ├── scan.ts               Orchestrateur
│       ├── scoring.ts            Score et note
│       ├── errors.ts             ScanError et codes → statuts HTTP
│       ├── labels.ts             Familles et libellés de statut (partagés avec l'interface)
│       ├── references.ts         Catalogue des références OWASP/MDN/RFC vérifiées
│       ├── network/              Couche réseau anti-SSRF (HTTP, TLS, DNS)
│       └── checks/               Les 18 contrôles + analyseurs (CSP, cookies, security.txt, HTML)
└── proxy.ts                      Pose la CSP à nonce sur chaque page (ex-« middleware »)
```

## 4. Le modèle de données (`types.ts`)

C'est le premier fichier à lire. Les types principaux, dans l'ordre du flux :

| Type | Rôle |
|---|---|
| `ScanTarget` | Saisie normalisée : URL en HTTPS, nom d'hôte en minuscules et punycode |
| `HttpResponse` | Une réponse telle que reçue : statut, en-têtes (minuscules), `Set-Cookie` séparés, corps, IP, infos TLS |
| `FetchSuccess` | Réponse finale + chaîne complète des redirections |
| `TlsInfo` | Protocole, suite, certificat (`CertificateInfo`), anciens protocoles acceptés |
| `HtmlInfo` | Scripts, styles, ressources, formulaires, CSP et Referrer en `<meta>` |
| `ScanContext` | **L'entrée unique des contrôles** : le résultat de chaque sonde + réponse analysée + HTML |
| `CheckDefinition` | Un contrôle : métadonnées (titre, description, références, grille) + `evaluate()` |
| `CheckOutcome` / `CheckResult` | Le verdict d'un contrôle (statut, points, constat, preuve, conseils) |
| `ScoreBreakdown` | Base, pénalités, bonus, bonus appliqués ou non, score, note |
| `ScanReport` | Le JSON renvoyé par l'API (`schemaVersion: 1`) |

## 5. Frontière serveur / navigateur

- `src/lib/scanner/index.ts` commence par `import "server-only"` : si un composant client
  l'importait par erreur, la compilation échouerait. Le moteur (sockets, DNS) ne part jamais dans le
  JavaScript envoyé au navigateur.
- L'interface n'importe que des **types** (`types.ts`), les **libellés** (`labels.ts`) et le
  **registre** pour la page Méthodologie (rendue côté serveur).
- Le navigateur ne parle qu'à `POST /api/scan` (`src/components/scan/api.ts`), qui transforme chaque
  réponse d'erreur en message français.

## 6. Rendu et sécurité de l'application

Les pages sont rendues **dynamiquement** à chaque requête : `src/proxy.ts` tire un **nonce** aléatoire,
l'ajoute à la CSP de la réponse, et Next.js le recopie sur ses propres balises `<script>`. Une page
pré-rendue au moment du build ne pourrait pas porter ce nonce : le *Partial Prerendering*
(`cacheComponents`) est donc désactivé. Les autres en-têtes de sécurité (HSTS, nosniff,
X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP) sont fixes et posés par
`next.config.ts`. SecuScan applique ainsi tout ce qu'il recommande : une fois déployé, il doit
obtenir A+ en analysant son propre domaine (vérification décrite dans
[50-deploiement.md](50-deploiement.md)). Détails dans [30-securite.md](30-securite.md).

## 7. Gestion des erreurs

| Où | Mécanisme | Effet |
|---|---|---|
| Sonde réseau | `Result` + `NetworkErrorCode` (`TIMEOUT`, `BLOCKED_ADDRESS`…) | Le contrôle concerné passe en *Non vérifié* (0 point) |
| Contrôle | Fonction pure, appel protégé par `try/catch` dans `scan.ts` | Un bogue n'affecte que ce contrôle |
| HTML pathologique | `extractHtmlInfo` ne lève jamais | La page est traitée comme non HTML |
| Saisie refusée, site injoignable | `ScanError` avec un code stable | L'API répond `{ error: { code, message } }` avec le statut HTTP prévu |

Codes d'erreur de l'API (`errors.ts`) : `INVALID_REQUEST` 400, `FORBIDDEN_ORIGIN` 403,
`PAYLOAD_TOO_LARGE` 413, `INVALID_URL` / `UNSUPPORTED_PROTOCOL` / `FORBIDDEN_PORT` /
`CREDENTIALS_IN_URL` 400, `TARGET_NOT_ALLOWED` / `DNS_FAILURE` 422, `RATE_LIMITED` 429,
`TARGET_UNREACHABLE` 502, `TIMEOUT` 504, `INTERNAL_ERROR` 500.

## 8. Une seule source de vérité

| Information | Source unique | Utilisée par |
|---|---|---|
| Liste et ordre des contrôles | `checks/index.ts` (`CHECKS`) | Orchestrateur, page Méthodologie, tests |
| Grille d'un contrôle | `scoring` de sa `CheckDefinition` | Page Méthodologie, test d'invariants, ce dossier |
| Références OWASP/MDN/RFC | `references.ts` (`REFS`) | Tous les contrôles (un test refuse toute autre source) |
| Réglages (délais, tailles, limites) | `lib/config.ts` | Réseau, API, documentation |
| Familles et statuts | `labels.ts` | Moteur et interface |
