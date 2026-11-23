# 40 — Tests et qualité

> Comment SecuScan est vérifié, comment lancer les tests et comment en écrire de nouveaux.

## 1. En chiffres (23 novembre 2026)

| Indicateur | Valeur |
|---|---|
| Fichiers de test | 48 |
| Tests | 1 639, sans aucun accès à Internet |
| Couverture (`src/lib/**`) | 98,5 % des instructions, 93 % des branches, 99 % des fonctions et des lignes |
| Seuils imposés par la CI | 80 % lignes, fonctions et instructions ; 75 % branches |
| Durée | 3 à 15 s selon la machine |

## 2. Les commandes

```bash
npm test                 # toute la suite (Vitest)
npm run test:watch       # relance à chaque modification
npm run test:coverage    # avec la couverture (rapport HTML dans coverage/)
npm run check            # types + lint + tests : à lancer avant chaque commit
npx vitest run test/lib/scanner/checks/hsts.test.ts   # un seul fichier
npx vitest run -t "préchargement"                      # les tests dont le nom contient ce texte
```

## 3. Stratégie : une pyramide adaptée à l'architecture

L'architecture « cœur fonctionnel, coquille impérative » ([10-architecture.md](10-architecture.md))
dicte la stratégie : le cœur se teste en masse, simplement ; la coquille avec de vrais serveurs locaux.

| Niveau | Quoi | Comment | Exemples |
|---|---|---|---|
| **Unitaires purs** (la majorité) | Les 18 contrôles, les analyseurs (CSP, cookies, security.txt, HTML), la notation | Un `ScanContext` fabriqué à la main → on vérifie le verdict | `checks/hsts.test.ts`, `checks/csp-parser.test.ts`, `scoring.test.ts` |
| **Réseau** | Client HTTP, sonde TLS, DNS, politique d'adresses | Vrais serveurs `node:http`/`https`/`tls` lancés sur `127.0.0.1` par le test, DNS simulé | `network/http-client.test.ts`, `network/tls-probe.test.ts` |
| **Orchestration** | `scanSite` | Toutes les dépendances injectées (doublures) | `scan.test.ts` |
| **API** | `POST /api/scan`, `GET /api/health` | Appel direct du gestionnaire de route avec une `Request` | `app/api/scan.route.test.ts` |
| **Interface** | Formulaire, rapport, chargement | React Testing Library dans jsdom | `components/report/report-view.test.tsx` |
| **Transversaux** | Invariants, robustesse, sécurité, documentation | Voir § 4 | `checks/robustness.test.ts`, `security-regressions.test.ts`, `docs/documentation.test.ts` |

Vitest exécute deux « projets » (`vitest.config.mts`) : `node` pour les fichiers `*.test.ts`,
`dom` (jsdom) pour les composants `*.test.tsx`.

### Les fabriques de test (`test/helpers/context.ts`)

`makeContext()` construit un site **exemplaire par défaut** (HTTPS valide, redirection HTTP → HTTPS,
TLS 1.3) ; chaque test ne change que ce qu'il étudie :

```ts
const outcome = hstsCheck.evaluate(
  makeContext({ headers: { "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload" } }),
);
expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
```

Autres fabriques : `makeResponse`, `makeRedirect`, `fetched` (succès avec chaîne), `failure` (échec de
sonde), `makeTlsInfo`, `makeHtmlInfo`, `makeTarget`.

## 4. Les tests transversaux

### Grille de chaque contrôle

Chaque fichier de contrôle teste **chaque ligne de sa grille** (statut et points), la règle « le plus
grave l'emporte », les échecs de sonde, et vérifie que `scoring` déclare tous les modificateurs.

### Invariants du registre (`checks/index.test.ts`)

18 contrôles dans l'ordre d'affichage, regroupés par famille ; titres uniques ; chaque référence
appartient au catalogue vérifié `REFS` et utilise HTTPS ; `getCheck("__proto__")` renvoie `undefined`.

### Robustesse (`checks/robustness.test.ts`)

Les 18 contrôles sont évalués sur environ 400 contextes dégradés ou piégés : toutes les sondes en échec
(chaque code d'erreur), réponse absente, en-têtes vides, géants (60 000 caractères), contenant des
caractères de contrôle ou des mots « magiques » (`__proto__`, `constructor`), statuts 204/304/404/500…
Pour chaque cas : aucune exception, statut valide, **modificateur présent dans la grille déclarée**,
aucun « undefined », « NaN » ou « [native code] » dans les textes, phrases de longueur raisonnable.

Ce test a révélé de vrais bogues, corrigés le 20 novembre 2026 : un en-tête
`Referrer-Policy: constructor` faisait afficher le code source d'une fonction JavaScript dans le rapport,
et des en-têtes de 60 Ko étaient recopiés tels quels dans les constats.

### Non-régression de sécurité (`security-regressions.test.ts`)

- **ReDoS** : un scan complet d'un site piégé (serveur local) doit durer moins de 1,5 s pour chaque
  entrée qui coûtait auparavant plusieurs secondes. Vérifié par mutation : en remettant l'ancienne
  expression régulière, le test échoue.
- **Fuite du DNS interne** : un site qui redirige vers `db.internal.corp` ne doit pas faire apparaître
  l'adresse privée correspondante dans le rapport.

### Documentation (`test/docs/documentation.test.ts`)

Chaque lien relatif du README et de `docs/` doit mener à un fichier existant ; chaque contrôle du
registre doit être décrit dans [21-controles.md](21-controles.md) et noté dans
[22-notation.md](22-notation.md), dont les seuils de notes doivent être ceux de `scoring.ts`. Ajouter
un contrôle sans le documenter fait échouer la CI.

## 5. Validation sur des sites réels

Les tests automatiques n'utilisent jamais Internet (ils seraient lents et instables). La validation sur
de vrais sites se fait à la main, avec le serveur de production local :

```bash
npm run build && npx next start -p 3123
curl -s -X POST http://localhost:3123/api/scan \
  -H "Content-Type: application/json" -H "Origin: http://localhost:3123" \
  -d '{"url":"github.com"}' | jq '.score'
```

Corpus utilisé (novembre 2026) :

- **badssl.com**, conçu pour tester les clients TLS : certificat expiré, auto-signé, mauvais nom,
  chaîne incomplète, contenu mixte… Chaque verdict a été confronté à `openssl s_client`.
- **Sites connus** comparés à **MDN HTTP Observatory** (`POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=…`) :
  scores identiques pour github.com (115), developer.mozilla.org (110), mozilla.org (80) et owasp.org
  (75) ; les autres écarts s'expliquent tous par les contrôles propres à SecuScan (TLS, divulgation de
  version). Tableau complet dans [22-notation.md](22-notation.md).

Enseignements tirés de cette validation : badssl.com coupe les connexions simultanées, ce qui a conduit
à retenter une fois les connexions coupées, à tester les anciens protocoles TLS après la négociation
principale, et à juger le certificat d'après la connexion HTTPS quand la sonde TLS échoue.

## 6. Intégration continue (`.github/workflows/ci.yml`)

À chaque push sur `main` et à chaque pull request : `npm ci` → types (`tsc`) → lint et format
(`biome ci`) → tests avec couverture (seuils bloquants) → build de production. Le rapport de
couverture est publié comme artefact. CodeQL analyse le code chaque semaine.

## 7. Écrire un test

1. Créer `test/<même chemin que src>/<fichier>.test.ts` ; commencer par un commentaire qui dit ce qui
   est testé et pourquoi.
2. Écrire les tests **à partir de la règle** (spécification, RFC, grille), pas à partir du code : un
   test recopié sur l'implémentation reproduit ses erreurs.
3. Noms de tests en français, à la forme active : « échoue (−20) quand l'en-tête est absent ».
4. Un test = un comportement ; `it.each` pour les variantes d'une même règle.
5. Pour une règle non évidente, citer la source en commentaire (« RFC 6797 § 6.1 »).
6. `npm run check` avant de valider.
