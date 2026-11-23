# 60 — Guide pas à pas

> Installer le projet, le comprendre dans le bon ordre, puis le faire évoluer (ajouter un contrôle,
> modifier la notation). À lire après [10-architecture.md](10-architecture.md).

## 1. Installer et lancer

Prérequis : **Node.js 24** (fichier `.nvmrc`) et npm.

```bash
git clone https://github.com/kyky709/SecuScan.git
cd SecuScan
nvm use            # Node.js 24
npm ci             # installe exactement les versions du package-lock.json
npm run dev        # http://localhost:3000
```

Les variables d'environnement sont toutes facultatives (voir `.env.example`). En développement, la CSP
est assouplie (`'unsafe-eval'` pour React, styles en ligne pour le rechargement à chaud) ; jamais en
production.

> ⚠️ En local, SecuScan refuse d'analyser `localhost` ou une adresse privée : c'est la protection
> anti-SSRF, pas un bogue. Analysez un site public (`github.com`, `example.com`).

| Commande | Rôle |
|---|---|
| `npm run dev` | Serveur de développement |
| `npm run build` puis `npm start` | Version de production en local |
| `npm run check` | Types + lint + tests : **à lancer avant chaque commit** |
| `npm run lint:fix` | Corrige le formatage et l'ordre des imports (Biome) |
| `npm run test:coverage` | Tests avec couverture |

## 2. Lire le code dans le bon ordre

Chaque fichier commence par un commentaire qui explique son rôle, pourquoi il existe et sa place dans
l'architecture. Parcours conseillé, du contrat vers les détails :

1. **`src/lib/scanner/types.ts`** : tout le modèle de données. Comprendre `ScanContext`,
   `CheckDefinition` et `ScanReport` rend le reste lisible.
2. **`src/lib/scanner/scan.ts`** : l'orchestrateur, en six étapes numérotées dans le code.
3. **Un contrôle simple** : `checks/content-type-options.ts` (trois lignes de grille), puis
   `checks/hsts.ts` (analyse d'un en-tête selon une RFC).
4. **`src/lib/scanner/scoring.ts`** : 30 lignes pour la note.
5. **`src/lib/scanner/target.ts`** puis **`network/ip.ts`** et **`network/safe-lookup.ts`** : la
   protection anti-SSRF.
6. **`network/http-client.ts`** : le plus technique ; lire d'abord son commentaire d'en-tête.
7. **`src/app/api/scan/route.ts`** : la route, étape par étape.
8. **`src/components/scan/scan-app.tsx`** puis **`components/report/report-view.tsx`** : l'interface.

Pour chaque fichier, lire en parallèle son test (`test/` reproduit l'arborescence de `src/`) : les
noms des tests décrivent le comportement attendu en français.

## 3. Tutoriel : ajouter un contrôle

Exemple : vérifier l'en-tête **`X-Permitted-Cross-Domain-Policies`**, que l'OWASP Secure Headers
Project recommande de fixer à `none` (il empêche les anciens clients Flash/PDF de charger des données
du site). C'est un exemple pédagogique : il ne fait pas partie des 18 contrôles.

### Étape 1 — Choisir l'identifiant et la famille

Ajouter l'identifiant à l'union `CheckId` de `src/lib/scanner/types.ts` :

```ts
export type CheckId =
  | "https-redirect"
  // …
  | "cross-domain-policies"
  | "caa";
```

### Étape 2 — Ajouter la référence au catalogue

Toutes les sources sont centralisées dans `src/lib/scanner/references.ts` (un test refuse toute autre
source). Vérifier l'URL dans un navigateur avant de l'ajouter :

```ts
secureHeaders: {
  // …
  crossDomainPolicies: ref(
    "owasp-secure-headers",
    "OWASP Secure Headers Project – X-Permitted-Cross-Domain-Policies",
    "https://secure-headers-project.owasp.org/response-headers/#x-permitted-cross-domain-policies",
  ),
},
```

### Étape 3 — Écrire le contrôle

Créer `src/lib/scanner/checks/cross-domain-policies.ts`. Une grille, une fonction pure :

```ts
/**
 * Contrôle « cross-domain-policies » : en-tête X-Permitted-Cross-Domain-Policies.
 *
 * Rôle : vérifier que le site interdit aux anciens clients (Flash, Acrobat) de lire ses données
 * via un fichier crossdomain.xml. Place dans l'architecture : contrôle pur de la famille « headers ».
 */
import { REFS } from "@/lib/scanner/references";
import type { CheckDefinition } from "@/lib/scanner/types";
import { getHeader, notApplicable, probeErrorOutcome, shorten } from "./helpers";

export const crossDomainPoliciesCheck: CheckDefinition = {
  id: "cross-domain-policies",
  category: "headers",
  title: "X-Permitted-Cross-Domain-Policies",
  description:
    "Cet en-tête indique aux anciens clients Flash et PDF s'ils peuvent lire les données du site depuis un autre domaine. La valeur none les en empêche.",
  references: [REFS.secureHeaders.crossDomainPolicies],
  scoring: [
    { outcome: "none", modifier: 0 },
    { outcome: "Absent ou autre valeur", modifier: 0 },
  ],
  evaluate(context) {
    const response = context.response;
    if (!response) {
      return context.https.ok
        ? notApplicable("Aucune réponse HTTP n'a pu être analysée.")
        : probeErrorOutcome(context.https.error, "l'en-tête X-Permitted-Cross-Domain-Policies");
    }
    const value = getHeader(response, "x-permitted-cross-domain-policies")?.trim() ?? null;
    if (value?.toLowerCase() === "none") {
      return {
        status: "pass",
        scoreModifier: 0,
        summary: "X-Permitted-Cross-Domain-Policies vaut none.",
        evidence: value,
        recommendation: null,
      };
    }
    return {
      status: "info",
      scoreModifier: 0,
      summary:
        value === null
          ? "L'en-tête X-Permitted-Cross-Domain-Policies est absent."
          : `X-Permitted-Cross-Domain-Policies vaut « ${shorten(value)} ».`,
      evidence: value,
      recommendation: "Ajoutez X-Permitted-Cross-Domain-Policies: none.",
      examples: [
        {
          label: "Nginx",
          language: "nginx",
          code: 'add_header X-Permitted-Cross-Domain-Policies "none" always;',
        },
      ],
    };
  },
};
```

Règles à respecter (vérifiées par les tests transversaux) :

- `evaluate` ne fait **aucune** requête et ne lève **jamais** d'exception ;
- chaque `scoreModifier` renvoyé figure dans `scoring` ;
- une valeur venue du site est raccourcie (`shorten`) avant d'être citée dans une phrase ;
- une recherche dans une table utilise `lookup()`, pas `table[valeur]` ;
- textes en français, exemples Nginx / Apache / Next.js pour un en-tête à poser.

### Étape 4 — Enregistrer le contrôle

Dans `src/lib/scanner/checks/index.ts`, l'importer et l'insérer **à sa place dans sa famille** (la
liste `CHECKS` fixe l'ordre d'affichage). La page Méthodologie l'affiche aussitôt, sans autre
modification.

### Étape 5 — Tester

Créer `test/lib/scanner/checks/cross-domain-policies.test.ts` : un test par ligne de grille, plus les
cas limites (casse, espaces, en-tête dupliqué). Mettre à jour la liste attendue dans
`test/lib/scanner/checks/index.test.ts` (19 contrôles). Le test de robustesse évalue automatiquement le
nouveau contrôle sur les ~400 contextes piégés. Puis :

```bash
npm run check
```

### Étape 6 — Documenter

Ajouter la grille dans [22-notation.md](22-notation.md), un paragraphe dans
[21-controles.md](21-controles.md), une ligne datée dans [decisions.md](decisions.md) si un choix a
été fait, et une entrée dans [journal.md](journal.md).

## 4. Modifier la notation

- **Seuils des notes ou règle des bonus** : `src/lib/scanner/scoring.ts` (`GRADE_THRESHOLDS`,
  `BONUS_THRESHOLD`) ; mettre à jour `test/lib/scanner/scoring.test.ts` et
  [22-notation.md](22-notation.md).
- **Points d'un contrôle** : dans sa grille (`GRID` ou `scoring` du fichier du contrôle) ; les tests du
  contrôle et le tableau de 22-notation.md doivent suivre.
- **Délais, tailles, limites de débit** : `src/lib/config.ts`, et nulle part ailleurs.

## 5. Déboguer une analyse

1. Lancer la version de production en local (`npm run build && npm start`) et appeler l'API :
   ```bash
   curl -s -X POST http://localhost:3000/api/scan -H "Content-Type: application/json" \
     -H "Origin: http://localhost:3000" -d '{"url":"example.com"}' | jq '.checks[] | {id, status, scoreModifier, summary}'
   ```
2. Regarder `probeErrors` dans le rapport : une sonde en échec explique les contrôles « Non vérifié ».
3. Comparer avec la réalité : `curl -sI https://site/`, `openssl s_client -connect site:443 -servername site`,
   `dig CAA site`.
4. Reproduire le cas dans un test avec `makeContext(...)` avant de corriger : le bogue ne reviendra pas.

## 6. Méthode de travail

- **Avant d'écrire du code** : relire le [cadrage](00-cadrage.md) (le besoin est-il dans le périmètre ?)
  et, pour Next.js, le guide correspondant dans `node_modules/next/dist/docs/` (Next.js 16 diffère des
  versions précédentes).
- **Un commit par jalon**, au message explicite (voir le [journal](journal.md)).
- **Toute décision structurante** (choix technique, écart avec une norme) : une ligne datée dans
  [decisions.md](decisions.md), avec la raison et les options écartées.
- **Branche et pull request** pour chaque évolution : la CI vérifie types, lint, tests, couverture et
  build avant la fusion.
