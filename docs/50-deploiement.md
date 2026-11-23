# 50 — Déploiement sur Vercel

> Mettre SecuScan en ligne gratuitement (offre Hobby de Vercel), puis vérifier que tout fonctionne.

## 1. Ce qui est déjà configuré dans le dépôt

| Fichier | Réglage | Pourquoi |
|---|---|---|
| `package.json` | `"engines": { "node": "24.x" }` | Vercel déploierait sinon la dernière version de Node.js ; le code a été vérifié sur Node 24 |
| `.nvmrc` | `24` | Même version en local et en CI |
| `vercel.json` | `"regions": ["cdg1"]` | Fonctions exécutées à Paris, au plus près des sites et des visiteurs français |
| `src/app/api/scan/route.ts` | `export const maxDuration = 30` | Le scan est borné à 20 s ; 30 s laissent la marge de la validation et de la réponse |
| `next.config.ts` | En-têtes de sécurité, `poweredByHeader: false` | Le site applique ce qu'il recommande |
| `src/proxy.ts` | CSP à nonce | Pages rendues dynamiquement, nonce renouvelé à chaque requête |

## 2. Variables d'environnement (toutes facultatives)

Modèle : [`.env.example`](../.env.example). En local, copier ce fichier en `.env.local` ; sur Vercel,
les saisir dans **Project Settings → Environment Variables**.

| Variable | Rôle | Valeur par défaut |
|---|---|---|
| `NEXT_PUBLIC_SITE_URL` | Adresse publique (métadonnées, sitemap) | Adresse de production fournie par Vercel |
| `NEXT_PUBLIC_REPOSITORY_URL` | Lien vers le dépôt affiché dans l'interface | `https://github.com/kyky709/SecuScan` |
| `SCANNER_CONTACT_URL` | Ajoutée au User-Agent pour que les sites analysés sachent qui les contacte | aucune |
| `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` | Limitation de débit partagée entre toutes les instances | Limiteur en mémoire, par instance |

## 3. Mise en ligne, pas à pas

1. **Publier le dépôt sur GitHub** :
   ```bash
   git remote add origin git@github.com:kyky709/SecuScan.git
   git push -u origin main
   ```
   La CI GitHub Actions se lance : vérifier qu'elle est verte (onglet **Actions**).
2. **Importer le projet** sur [vercel.com/new](https://vercel.com/new) : choisir le dépôt ; Vercel
   détecte Next.js (commande `next build`, aucun réglage à changer).
3. **(Recommandé) Limitation de débit partagée** : dans l'onglet **Storage** du projet, ajouter
   l'intégration **Upstash for Redis** (offre gratuite) ; elle crée les deux variables `UPSTASH_*`.
   Sans elle, chaque instance compte de son côté : la limite reste effective, mais approximative.
4. **Variables** : ajouter `SCANNER_CONTACT_URL` (par exemple l'adresse du dépôt ou de la page
   « À propos »), et `NEXT_PUBLIC_SITE_URL` si vous utilisez un domaine personnalisé.
5. **Déployer** (bouton *Deploy*). Chaque push sur `main` redéploie ensuite la production ; chaque
   pull request obtient un déploiement de prévisualisation.

## 4. Vérifier le déploiement

```bash
SITE=https://secuscan.vercel.app   # à remplacer par votre adresse

# 1. L'application répond
curl -s $SITE/api/health
# {"status":"ok","name":"SecuScan","version":"1.0.0"}

# 2. Les en-têtes de sécurité sont présents (HSTS, CSP à nonce, nosniff…)
curl -sI $SITE | grep -iE "strict-transport|content-security|x-content-type|x-frame|referrer|permissions|cross-origin"

# 3. Une analyse aboutit
curl -s -X POST $SITE/api/scan -H "Content-Type: application/json" \
  -d '{"url":"github.com"}' | jq '.score.grade'

# 4. Les cibles internes sont refusées
curl -s -X POST $SITE/api/scan -H "Content-Type: application/json" \
  -d '{"url":"169.254.169.254"}' | jq '.error.code'
# "TARGET_NOT_ALLOWED"
```

5. **Le test ultime** : analyser SecuScan avec SecuScan (saisir l'adresse du déploiement dans le
   formulaire). Avec les en-têtes de `next.config.ts` et la CSP à nonce, la note attendue est **A+**.
6. **Vérifier les anciens protocoles TLS en production** : les tests locaux ont été faits avec
   OpenSSL 4.1 (Node.js de Homebrew), alors que Vercel utilise l'OpenSSL fourni avec Node.js 24. Analyser
   `example.com` (qui accepte TLS 1.0 et 1.1) doit donner « TLS 1.0 ou TLS 1.1 encore acceptés » ; si
   le contrôle répond « test non concluant », l'OpenSSL de la plateforme refuse ces versions même au
   niveau de sécurité 0, et la documentation devra le mentionner.

## 5. Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| Erreur 504 sur `/api/scan` | La fonction a dépassé `maxDuration` | Vérifier la région et les journaux ; le scan lui-même est borné à 20 s |
| 429 `RATE_LIMITED` | Limite par client (10/min) ou par site (6/min) | Attendre (`Retry-After`) ; ajuster `RATE_LIMIT_*` dans `src/lib/config.ts` si besoin |
| 403 `FORBIDDEN_ORIGIN` | Requête lancée depuis une autre origine que le site | Normal : seul le site SecuScan peut lancer une analyse depuis un navigateur |
| Page blanche, erreurs CSP dans la console | Script ou style sans nonce | Ne jamais ajouter de `<script>` en ligne ; passer par les composants Next.js |
| Build en échec sur Vercel mais pas en local | Version de Node.js différente | Vérifier `engines` et la version affichée dans les journaux de build |

## 6. Coûts

L'offre **Hobby** (gratuite, usage personnel et non commercial) et l'offre gratuite d'Upstash suffisent
pour un projet personnel comme celui-ci. SecuScan ne stocke rien et ne fait aucun calcul lourd : chaque analyse
dure de 1 à 10 secondes.
