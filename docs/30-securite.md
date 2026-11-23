# 30 — Sécurité de SecuScan lui-même

> Un scanner de sécurité est une cible : il accepte une adresse quelconque et ouvre des connexions
> pour le compte d'inconnus. Ce document décrit les menaces, les protections en place, ce qui a été
> testé, et les limites connues. Référence : exigence NF1 du [cadrage](00-cadrage.md).

## 1. Modèle de menaces

| # | Menace | Exemple d'attaque | Impact | Protection |
|---|---|---|---|---|
| M1 | **SSRF** : faire contacter au serveur une adresse interne | Analyser `169.254.169.254` (métadonnées cloud), `localhost:6379` (Redis) | Lecture de secrets, accès au réseau interne | § 2 |
| M2 | **Harcèlement d'un site tiers** via SecuScan | Lancer des milliers d'analyses du même site | SecuScan complice d'un déni de service | § 4 |
| M3 | **Déni de service de SecuScan** | Site piégé lent, énorme, ou aux en-têtes pathologiques | Fonction bloquée, coûts | § 3 |
| M4 | **Fuite d'informations** | Messages d'erreur révélant des adresses internes, valeurs de cookies | Cartographie interne, vol de session | § 5 |
| M5 | **XSS dans l'interface** | En-tête malveillant affiché dans le rapport | Exécution de script chez le visiteur | § 6 |
| M6 | **CSRF / abus de l'API** | Un site fait lancer des analyses par les navigateurs de ses visiteurs | Consommation de leur quota | § 4 |
| M7 | **Chaîne d'approvisionnement** | Dépendance ou action GitHub compromise | Code malveillant déployé | § 7 |

## 2. Anti-SSRF : une défense en profondeur (M1)

Approche « liste de blocage » du cas 2 de l'[OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
(l'application doit pouvoir contacter n'importe quelle adresse externe : une liste d'autorisation est
impossible pour un scanner).

1. **Saisie** (`target.ts`) : schémas `http`/`https`, ports 80/443, pas d'identifiants, noms réservés
   refusés (`localhost`, `.local`, `.internal`, `.home.arpa`…), IP littérales vérifiées sous toutes
   leurs écritures.
2. **Pré-contrôle DNS** : toutes les adresses du nom doivent être publiques.
3. **À chaque connexion** (`safe-lookup.ts`) : la fonction `lookup` passée à Node.js revérifie les
   adresses **au moment de se connecter** ; un changement de réponse DNS (*DNS rebinding*) est bloqué.
4. **Pas de réutilisation de connexion** (`agent: false`) : une connexion *keep-alive* ne repasse pas
   par `lookup` (contournement démontré par expérience).
5. **Chaque redirection est revalidée** : schéma, port, identifiants, adresse.
6. **Politique d'adresses** (`ip.ts`) : seules les adresses publiques « unicast » passent ; NAT64,
   6to4 et Teredo sont refusés car ils peuvent encapsuler une IPv4 interne.

### Attaques testées et bloquées (revue du 19-20 novembre 2026)

Plus de 40 tentatives, **aucune connexion interne obtenue** :

| Catégorie | Exemples | Résultat |
|---|---|---|
| IPv4 sous toutes ses formes | `127.1`, `0177.0.0.1`, `0x7f.1`, `2130706433`, `0`, `0.0.0.0` | Refusé (bouclage / non spécifiée) |
| Plages spéciales | `10/8`, `172.16/12`, `192.168/16`, `100.64/10` (CGNAT), `169.254/16`, `192.0.0/24`, `198.18/15`, `240/4`, `255.255.255.255`, plages de documentation | Refusé |
| IPv6 | `[::1]`, `[::]`, `[::ffff:127.0.0.1]`, `[::127.0.0.1]`, `[fc00::1]`, `[fd00:ec2::254]` (AWS), `[fe80::1]`, `[ff02::1]`, `[2001:db8::1]` | Refusé |
| IPv4 encapsulée | NAT64 `[64:ff9b::7f00:1]`, `[64:ff9b:1::1]`, 6to4 `[2002:7f00:1::1]`, Teredo `[2001::1]` | Refusé |
| Noms | `localhost.`, `LOCALHOST`, `x.localhost`, `ⓛⓞⓒⓐⓛⓗⓞⓢⓣ`, `localhost%2e`, `metadata.google.internal`, `nas.local`, `x.home.arpa`, `localtest.me`, `127.0.0.1.nip.io`, `169.254.169.254.nip.io` | Refusé |
| Ports | `example.com:8080`, `:8443`, redirection vers un port interne | Refusé |
| Redirections | Vers `127.0.0.1`, `[::1]`, `//[::1]`, `/\[::1]`, nom interne, `file:`, `ftp:`, `gopher:`, `data:`, `javascript:`, `ws:`, avec identifiants, avec CRLF ou caractère NUL | Refusé (`BLOCKED_ADDRESS`, `INVALID_REDIRECT` ou `PROTOCOL_ERROR`) |
| En-têtes `Location` piégés | Doublés, repliés, avec espaces | Refusé ou seule la première valeur suivie, puis revalidée |
| Sonde TLS | `localhost`, `127.0.0.1`, `[::1]`, `localtest.me` | Refusé avant toute connexion |

Ces cas sont couverts par des tests de non-régression (`test/lib/scanner/network/`,
`test/lib/scanner/target.test.ts`).

## 3. Résistance au déni de service (M3)

| Risque | Protection |
|---|---|
| Serveur lent (*slowloris*) | Délai total par requête (8 s) et global (20 s), imposés par `AbortSignal` |
| Corps énorme / bombe de décompression | 2 Mio maximum, mesurés **après** décompression |
| En-têtes géants | 64 Kio maximum (`maxHeaderSize`) |
| Boucle de redirections | 10 au plus, boucle détectée dès qu'une URL revient |
| HTML profondément imbriqué | Parcours itératif, pas de récursion |
| **Expressions régulières au coût quadratique (ReDoS)** | Analyseurs linéaires, testés (voir ci-dessous) |

### La faille ReDoS corrigée

La revue de sécurité a trouvé **cinq** expressions régulières dont le temps d'exécution croissait comme
le carré de la taille de l'entrée. Un site piégé pouvait ainsi bloquer le serveur, car ce calcul est
synchrone : le délai global du scan ne peut pas l'interrompre.

| Analyseur | Entrée piégée | Avant | Après |
|---|---|---|---|
| CSP (`stripAsciiWhitespace`) | `<meta>` CSP de 80 000 espaces | 13 s | 2 ms |
| CSP en en-tête | 60 000 espaces | 7,3 s | 1 ms |
| srcset (`withoutTrailingCommas`) | 80 000 virgules | 2,5 s | 3 ms |
| Version dans `Server` (`/\d+\.\d+/`) | 60 000 chiffres | 1,4 s | 1 ms |
| Permissions-Policy | `camera=(` + 60 000 espaces | 1,4 s | 2 ms |
| security.txt (`\s*(.*)$`) | Espaces + retour chariot isolé | 1,6 s | 1 ms |

Correctif : remplacer ces expressions par des boucles ou par des expressions sans retour arrière
ambigu (`/\d\.\d/` détecte exactement les mêmes versions que `/\d+\.\d+/`). Le test
`test/lib/scanner/security-regressions.test.ts` impose moins de 1,5 s par analyse sur ces entrées. Il a
été vérifié **par mutation** : avec l'ancienne expression remise en place, il échoue (24 s et 40 s).

## 4. Abus et limitation de débit (M2, M6)

- **Par client** : 10 analyses par minute et par adresse IP ; **par site analysé** : 6 par minute
  (SecuScan ne peut pas servir à harceler un site). En mémoire par défaut, partagé entre toutes les
  instances avec **Upstash Redis** si les variables d'environnement existent.
- Réponses 429 avec `Retry-After` et en-têtes `RateLimit-*` (quota restant).
- **Vérification de l'origine** (`route.ts`) : un navigateur joint toujours `Origin` à un POST ; une
  requête venue d'un autre site est refusée (403). C'est une protection anti-CSRF, pas une
  authentification : un script sans navigateur (curl) n'envoie pas d'`Origin` et reste soumis aux
  limites de débit.
- Corps de requête limité à 4 Kio, validé par **zod**.
- **Analyse passive** : SecuScan consulte la page comme un navigateur (6 à 8 connexions), s'identifie
  par son User-Agent et rappelle de n'analyser que des sites autorisés.

**Hypothèse de déploiement.** L'adresse du client est lue dans `x-real-ip`, puis `x-forwarded-for`.
Sur Vercel, ces en-têtes sont écrits par la plateforme et ne peuvent pas être falsifiés. Hébergé
ailleurs sans proxy de confiance, un client pourrait les falsifier pour contourner la limite *par
client* (la limite *par site* resterait en place).

## 5. Données personnelles et fuites d'informations (M4)

- **Aucune donnée conservée** : ni compte, ni cookie, ni historique ; le rapport n'existe que dans la
  réponse et dans le navigateur du visiteur.
- **Adresse IP** : utilisée seulement comme clé de limitation, après hachage SHA-256, et oubliée à la
  fin de la fenêtre d'une minute ; jamais journalisée. Le hachage n'est pas un anonymat absolu (une
  IPv4 peut être retrouvée en essayant les 2³² valeurs) : l'amélioration possible est un HMAC avec une
  clé secrète partagée entre les instances.
- **Journaux** : un événement par analyse (`host`, note, score, durée), sans IP ni URL complète (sa
  partie requête peut contenir un jeton collé par l'utilisateur).
- **Valeurs de cookies** jamais affichées (`nom=***`), y compris dans la preuve et l'export JSON.
- **Pas de fuite du DNS interne** (correctif du 20 novembre 2026). Auparavant, un site piégé qui
  redirigeait ses sondes vers `db.interne` faisait afficher l'adresse privée associée par le DNS de
  l'hébergeur (`« db.interne » pointe vers 10.20.30.40`). Désormais seule la catégorie est citée
  (« pointe vers une adresse non publique : réseau privé »). Un test de non-régression le vérifie.
- **Erreurs internes** : message générique côté client, détail seulement dans les journaux.

## 6. Sécurité de l'interface (M5)

- React échappe tout texte affiché : les valeurs d'en-têtes, de cookies ou d'URL venues du site analysé
  ne sont jamais interprétées comme du HTML (aucun `dangerouslySetInnerHTML`).
- **CSP stricte à nonce** posée par `src/proxy.ts` sur chaque page :
  `default-src 'none'; script-src 'self' 'nonce-…' 'strict-dynamic'; style-src 'self' 'nonce-…';
  img-src 'self' data: blob:; object-src 'none'; base-uri 'none'; form-action 'self';
  frame-ancestors 'none'; upgrade-insecure-requests`. Le nonce (128 bits aléatoires) change à chaque
  requête. L'API a sa propre CSP `default-src 'none'`.
- Autres en-têtes (`next.config.ts`) : HSTS deux ans avec préchargement, `nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`
  restrictive, COOP et CORP `same-origin` ; `X-Powered-By` supprimé.
- Les valeurs recopiées dans les phrases du rapport sont raccourcies (120 caractères) ; une valeur
  d'en-tête comme `constructor` ne peut plus faire afficher de code JavaScript (recherche limitée aux
  propriétés propres des tables, `lookup()`).

## 7. Chaîne d'approvisionnement (M7)

- Actions GitHub **épinglées par SHA** de commit (une étiquette `@v7` peut être déplacée).
- **Dependabot** (npm et actions) et **CodeQL** (analyse statique) chaque semaine.
- Dépendances d'exécution peu nombreuses et répandues : `next`, `react`, `zod`, `ipaddr.js`,
  `node-html-parser`, `lucide-react`, `@upstash/*`.
- `npm ci` en CI (versions exactes du fichier de verrouillage).

## 8. Limites connues

| Limite | Conséquence | Piste |
|---|---|---|
| Révocation des certificats non vérifiée (OCSP/CRL) | Un certificat révoqué paraît valide | Non fourni par Node.js ; hors périmètre |
| Hachage d'IP sans clé secrète | Pseudonymisation, pas anonymisation | HMAC avec une variable d'environnement secrète |
| Confiance dans `x-real-ip` | Contournement de la limite par client hors Vercel | Lire l'IP du socket quand aucun proxy n'est configuré |
| Réseaux IPv6 seuls avec NAT64 | SecuScan ne pourrait pas y analyser de sites IPv4 | Choix assumé : sécurité d'abord |
| Limiteur en mémoire | Approximatif avec plusieurs instances | Activer Upstash Redis en production |
