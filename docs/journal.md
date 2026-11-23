# Journal

Ce qui a été fait, dans l'ordre, avec ce qu'on en a appris. Les décisions structurantes sont dans
[decisions.md](decisions.md).

## 2026-11-15 — Jalon 0 : cadrage

- Cahier des charges rédigé ([00-cadrage.md](00-cadrage.md)) : 18 contrôles en 5 familles, note de A+ à F,
  références OWASP, déploiement Vercel.
- Recherche documentaire avant d'écrire du code, sur sources primaires (pages officielles, code source,
  expériences sur la machine) :
  - **OWASP** : le Top 10:2025 est l'édition finale ; ASVS 5.0.0 ; identifiants vérifiés un par un ;
  - **MDN HTTP Observatory** : barème exact de l'algorithme v6 (septembre 2026), lu dans son code source et
    confirmé par son API ;
  - **Node.js 24** : comportement réel de la résolution DNS, des URL et de TLS, testé contre badssl.com ;
  - **Next.js 16.4 / Vercel** : documentation fournie dans `node_modules/next/dist/docs/`, limites des fonctions ;
  - **Standards** : RFC 6797 (HSTS), CSP Level 3, spécifications HTML et Fetch, RFC 9116, RFC 8659.
- Enseignements marquants :
  - une connexion HTTP réutilisée (*keep-alive*) **ne repasse pas** par la vérification DNS : il faut
    `agent: false`, sinon la protection anti-SSRF peut être contournée ;
  - quand la chaîne de certificats est invalide, Node **ne signale plus** une erreur de nom d'hôte : il faut
    la vérifier séparément ;
  - `message.headers` de Node **supprime** certains en-têtes dupliqués (`server`, `content-type`…) :
    utiliser `headersDistinct` ;
  - le *Partial Prerendering* de Next.js 16 est **incompatible** avec une CSP à nonce.

## 2026-11-15 — Jalon 1 : initialisation

- Projet créé avec `create-next-app@16.4.6` (TypeScript, Tailwind, Biome, App Router, `src/`), Git initialisé.
- Outillage : TypeScript plus strict (`noUncheckedIndexedAccess`…), Biome (largeur 100), Vitest avec deux
  environnements (Node pour le moteur, jsdom pour les composants), scripts `check` / `typecheck` / `lint`.
- Sécurité de l'application elle-même : CSP stricte à nonce (`src/proxy.ts`), en-têtes HSTS, nosniff,
  Referrer-Policy, Permissions-Policy, COOP/CORP, suppression de `X-Powered-By` (`next.config.ts`).
- CI GitHub Actions (types, lint, tests avec couverture, build), CodeQL, Dependabot.
- Contrats partagés écrits avant le code : modèle de données (`types.ts`), configuration, erreurs, libellés,
  références OWASP vérifiées, utilitaires de test.

## 2026-11-15 → 16 — Jalon 2 : implémentation

- Recherche documentaire synthétisée en un cahier des charges technique (grille de chaque contrôle,
  pièges de Node.js), puis implémentation bloc par bloc : couche réseau anti-SSRF,
  contrôles d'en-têtes (CSP, clickjacking…), contrôles de transport (redirection, certificat, TLS,
  HSTS…), contrôles de contenu (cookies, SRI, contenu mixte, CORS, security.txt, CAA), cœur et API
  (normalisation, orchestrateur, notation, limitation de débit), interface.
- Écarts assumés consignés dans [decisions.md](decisions.md).
- Les contrôles de contenu ont d'abord été écrits sans leurs tests : couverture globale à 71 %, sous
  le seuil de 80 % de la CI (rattrapé au jalon 3).

## 2026-11-19 → 20 — Jalon 3 : tests, revue de sécurité, corrections

- **Tests manquants écrits** à partir des spécifications (HTML, SRI, contenu mixte, cookies, CORS,
  security.txt, CAA), plus trois tests transversaux : invariants du registre, robustesse des 18 contrôles
  sur ~400 contextes piégés, non-régression de sécurité. Couverture : 71 % → 98,5 % ; 1 635 tests.
- **Revue adverse anti-SSRF** : plus de 40 tentatives de contournement (encodages d'IP, IPv6, NAT64,
  noms piégés, redirections, en-têtes `Location` malformés) ; aucune connexion interne obtenue.
- **Failles trouvées et corrigées** :
  - **ReDoS** : cinq expressions régulières au coût quadratique (CSP, srcset, version dans `Server`,
    Permissions-Policy, security.txt) ; une page piégée bloquait le serveur 13 s, désormais 2 ms.
    Test de non-régression vérifié par mutation ;
  - **fuite du DNS interne** : les messages de blocage citaient l'adresse privée résolue pour un nom
    interne vers lequel un site piégé redirigeait ;
  - un en-tête valant `constructor` faisait afficher du code JavaScript dans le rapport (recherche
    dans un objet littéral) ; des valeurs de 60 Ko étaient recopiées dans les constats.
- **Justesse des verdicts** :
  - un cookie anti-CSRF (`XSRF-TOKEN`) était pris pour un cookie de session et pénalisé faute de
    `HttpOnly`, alors que JavaScript doit pouvoir le lire ;
  - CAA : `issuewild` seul n'encadre que les certificats génériques, le constat le dit désormais ;
  - message trompeur pour `user:pw@example.com` (« protocole user ») remplacé par le refus des
    identifiants.
- **Validation sur sites réels** : scores identiques à MDN Observatory pour github.com (115),
  developer.mozilla.org (110), mozilla.org (80), owasp.org (75) ; écarts restants expliqués par les
  contrôles propres à SecuScan. Verdicts TLS confrontés à `openssl s_client` (example.com accepte bien
  TLS 1.0).
- **Résilience**, après les coupures de connexion observées sur badssl.com : une nouvelle tentative
  unique après `ECONNRESET`, anciens protocoles TLS testés après la négociation principale, certificat
  jugé d'après la connexion HTTPS quand la sonde TLS échoue (`expired.badssl.com` : « non vérifié » →
  « expiré », −50).
- Enseignements :
  - un test de performance doit utiliser une entrée assez grande pour révéler un coût quadratique,
    mais assez petite pour **finir** : avec 2 Mio, une régression bloquerait la CI au lieu d'échouer ;
  - des tests calqués sur le code reproduisent ses erreurs : les invariants transversaux et la
    comparaison avec une référence externe (Observatory, OpenSSL) ont trouvé ce que les tests
    unitaires n'avaient pas vu.

## 2026-11-20 → 23 — Jalon 4 : documentation

- README réécrit (fonctionnalités, API, architecture, sécurité, documentation) avec capture d'écran.
- Documents : architecture, moteur de scan, contrôles, notation (grilles tirées du registre),
  sécurité (modèle de menaces, attaques testées, limites), tests, déploiement Vercel, guide pas à
  pas (dont un tutoriel « ajouter un contrôle »).
- Les grilles de notation sont rassemblées dans `docs/22-notation.md`, que citent les commentaires du
  code.

## 2026-11-23 — Jalon 5 : publication

- Dépôt publié sur GitHub, historique découpé en commits thématiques.
- À suivre : déploiement Vercel et vérifications de [50-deploiement.md](50-deploiement.md).
