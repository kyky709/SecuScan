# 22 — Notation

> Comment SecuScan transforme les verdicts des 18 contrôles en un score et une note de **A+ à F**.
> Le code de référence est `src/lib/scanner/scoring.ts` ; les grilles ci-dessous sont celles déclarées
> par chaque contrôle (`scoring` dans `src/lib/scanner/checks/<id>.ts`), affichées aussi sur la page
> **Méthodologie** du site. Un test (`test/lib/scanner/checks/robustness.test.ts`) vérifie que
> chaque contrôle ne renvoie jamais un modificateur absent de sa grille.

## 1. Le calcul en quatre étapes

La méthode reprend celle de [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory/docs/scoring)
(algorithme v6, lu dans son code source) :

1. **On part de 100 points.**
2. **On additionne toutes les pénalités** (modificateurs négatifs) : c'est le score « sans bonus ».
3. **Si ce score atteint 90, on ajoute tous les bonus** (modificateurs positifs) ; sinon, aucun.
   C'est du *tout ou rien* : un bonus ne doit jamais masquer un vrai problème. Une excellente CSP
   (+10) ne compense pas un cookie de session envoyé en clair (−40).
4. **Le score ne descend pas sous 0 mais n'a pas de plafond** : 115/100 est possible et vaut A+.

Chaque contrôle fournit **un seul** modificateur, celui de son constat le plus grave : les pénalités
d'un même contrôle ne se cumulent jamais (un site sans HSTS et sans `includeSubDomains` perd 20 points,
pas 30). Les autres constats deviennent des détails du rapport.

Un contrôle qui n'a pas pu être réalisé (sonde réseau en échec, statut « Non vérifié ») vaut **0** :
on ne pénalise pas ce qu'on n'a pas pu observer.

## 2. Les notes

| Note | Score minimal | Lecture |
|---|---|---|
| **A+** | 100 | Exemplaire : aucune pénalité notable et des protections avancées |
| **A** | 85 | Très bonne configuration |
| **B** | 70 | Bonne base, quelques protections manquantes |
| **C** | 55 | Plusieurs protections importantes manquent |
| **D** | 40 | Configuration faible |
| **E** | 25 | Configuration très faible |
| **F** | 0 | Problèmes graves (HTTPS absent, certificat invalide, cookies de session exposés…) |

SecuScan utilise **7 lettres** (comme securityheaders.com) plutôt que les 13 niveaux d'Observatory
(A+, A, A−, B+…) : le cahier des charges demande une note « de A à F » et une échelle courte se lit
mieux. Les seuils restent proches de ceux d'Observatory.

### Exemples

| Situation | Pénalités | Bonus | Score sans bonus | Bonus appliqués ? | Score | Note |
|---|---|---|---|---|---|---|
| github.com (novembre 2026) | −5 (SRI) | +20 | 95 | oui (≥ 90) | **115** | A+ |
| mozilla.org | −20 (CSP `'unsafe-inline'`) | +15 | 80 | non (< 90) | **80** | B |
| Pénalités −15, bonus +10 | −15 | +10 | 85 | non | **85** | A |
| Pénalités −10, bonus +10 | −10 | +10 | 90 | oui | **100** | A+ |
| example.com | −110 | 0 | −10 | non | **0** (plancher) | F |

## 3. Grille de chaque contrôle

Le modificateur est ajouté au score de base. « 0 » signifie : aucun effet sur la note, mais un constat
et souvent un conseil dans le rapport.

### Chiffrement et transport

**Redirection HTTP → HTTPS** (`https-redirect`)

| Constat | Points |
|---|---|
| HTTP injoignable (port 80 fermé) alors que HTTPS répond | 0 |
| HTTPS indisponible alors que HTTP répond | −20 |
| Contenu servi en HTTP clair, sans redirection | −20 |
| Redirection invalide ou trop de redirections | −20 |
| La chaîne de redirections se termine en HTTP | −20 |
| Première redirection vers une autre adresse en HTTP | −10 |
| Première redirection vers HTTPS sur un autre hôte | −5 |
| Première redirection vers HTTPS sur le même hôte | 0 |

**Certificat TLS** (`tls-certificate`)

| Constat | Points |
|---|---|
| Connexion TLS impossible : pas de HTTPS | −30 |
| Sonde TLS en échec pour une autre raison (non vérifié) | 0 |
| Certificat invalide (expiré, pas encore valide, auto-signé, autorité inconnue, nom non couvert…) | −50 |
| Certificat invalide sur l'hôte final atteint après redirection | −50 |
| Chaîne de certificats incomplète | −10 |
| Clé trop faible (RSA < 2048 bits, EC < 256 bits) | −10 |
| Expiration proche, renouvellement en retard | 0 |
| Certificat valide | 0 |

Si la sonde TLS dédiée échoue mais que la connexion HTTPS de l'analyse a abouti, le verdict s'appuie
sur la validation faite pendant cette connexion (voir [20-moteur-de-scan.md](20-moteur-de-scan.md)).

**Version de TLS** (`tls-protocol`)

| Constat | Points |
|---|---|
| Sonde TLS en échec (déjà pénalisé par le contrôle du certificat) | 0 |
| Protocole négocié antérieur à TLS 1.2 | −30 |
| TLS 1.0 ou TLS 1.1 encore acceptés | −20 |
| TLS 1.2 négocié, TLS 1.3 non proposé | 0 |
| TLS 1.3 négocié | 0 |

**HTTP Strict Transport Security** (`hsts`)

| Constat | Points |
|---|---|
| Site non accessible en HTTPS | −20 |
| En-tête absent | −20 |
| En-tête invalide ou `max-age=0` | −20 |
| `max-age` inférieur à 15 552 000 s (180 jours) | −10 |
| `max-age` d'au moins 180 jours | 0 |
| Éligible au préchargement (`max-age` ≥ 31 536 000, `includeSubDomains`, `preload`) | +5 |

### En-têtes de sécurité

**Content Security Policy** (`csp`)

| Constat | Points |
|---|---|
| Aucune CSP appliquée (ni en-tête ni `<meta>` ; une politique *Report-Only* seule ne compte pas) | −25 |
| CSP invalide (illisible, ou directive répétée dans une même politique) | −25 |
| Scripts non restreints : ni `script-src` ni `default-src`, `'unsafe-inline'` effectif (sans nonce ni empreinte), `data:` ou source trop large (`*`, `http:`, `https:`…) ; ou `object-src` absente (sans `default-src`) ou trop large | −20 |
| Source en schéma non sécurisé (`http:` ou `http://…`) pour les scripts ou les objets | −20 |
| `'unsafe-eval'` dans `script-src` ou `style-src` | −10 |
| Schéma non sécurisé seulement pour du contenu passif (`img-src`, `media-src`) | −10 |
| Seul `style-src` est faible (`'unsafe-inline'`, `data:` ou source trop large) | 0 |
| Aucune source dangereuse | +5 |
| Aucune source dangereuse et `default-src 'none'` | +10 |

**Protection contre le clickjacking** (`clickjacking`)

| Constat | Points |
|---|---|
| CSP `frame-ancestors` restrictive, envoyée en en-tête (`'none'`, `'self'` ou liste d'origines) | +5 |
| `X-Frame-Options` `DENY` ou `SAMEORIGIN` | +5 |
| `X-Frame-Options` `ALLOW-FROM` (ignoré des navigateurs actuels) ou valeur invalide | −20 |
| Aucune protection | −20 |

**X-Content-Type-Options** (`content-type-options`)

| Constat | Points |
|---|---|
| `nosniff` | 0 |
| Absent | −5 |
| Valeur invalide | −5 |

**Referrer-Policy** (`referrer-policy`)

| Constat | Points |
|---|---|
| Politique stricte : `no-referrer`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin` | +5 |
| Politique permissive : `no-referrer-when-downgrade`, `origin`, `origin-when-cross-origin`, `unsafe-url` | −5 |
| Valeur invalide | −5 |
| Absente (le navigateur applique `strict-origin-when-cross-origin`) | 0 |

**Permissions-Policy** (`permissions-policy`) : toujours 0 (présent, invalide, ancien
`Feature-Policy` ou absent) ; seul le constat change. Observatory ne la note pas non plus.

**Isolation entre origines** (`cross-origin-isolation`)

| Constat | Points |
|---|---|
| Valeur invalide (inconnue ou en-tête dupliqué) pour COOP, COEP ou CORP | −5 |
| COOP isolant : `same-origin`, `same-origin-allow-popups` ou `noopener-allow-popups` | +5 |
| COOP absent ou `unsafe-none` | 0 |

**X-XSS-Protection** (`xss-protection`) : toujours 0. L'en-tête est obsolète (auditeur XSS retiré des
navigateurs) ; le rapport conseille de le supprimer ou de le mettre à `0`.

### Cookies

**Attributs des cookies** (`cookies`) — la règle enfreinte la plus grave l'emporte.

| Constat | Points |
|---|---|
| Aucun cookie | 0 |
| Cookie de session sans `Secure` | −40 |
| Cookie de session sans `HttpOnly` | −30 |
| Cookie sans `Secure` | −20 |
| `SameSite` invalide, ou `SameSite=None` sans `Secure` | −20 |
| Cookie anti-CSRF sans `SameSite` | −20 |
| Cookie de session sans `Secure` mais protégé par HSTS | −10 |
| Cookie sans `Secure` mais protégé par HSTS | −5 |
| Préfixe `__Secure-` / `__Host-` dont les règles ne sont pas respectées | −5 |
| Tous `Secure`, sessions `HttpOnly`, mais `SameSite` manquant sur certains | 0 |
| Tous `Secure`, sessions `HttpOnly`, tous avec `SameSite` valide | +5 |

Un cookie « de session » est reconnu à son nom (`sess`, `sid`, `auth`, `token`, `jwt`, `PHPSESSID`…),
sauf s'il s'agit d'un cookie anti-CSRF (`csrf`, `xsrf`) : dans le schéma « double soumission »,
JavaScript doit justement pouvoir le lire.

### Contenu et ressources

**Intégrité des scripts tiers** (`sri`)

| Constat | Points |
|---|---|
| Réponse non HTML | 0 |
| Aucun script tiers | 0 |
| Tous les scripts tiers ont un attribut `integrity` | +5 |
| Script(s) tiers sans `integrity` | −5 |

**Contenu mixte** (`mixed-content`)

| Constat | Points |
|---|---|
| Page non HTML ou servie en HTTP (sans objet) | 0 |
| Ressource « bloquable » en `http://` : script, feuille de style, iframe/frame, object, embed | −20 |
| Formulaire dont l'action envoie en `http://` | −10 |
| Ressource passive en `http://` (img, audio, video, source, track) | −5 |
| Aucune ressource en `http://` | 0 |

**Partage entre origines** (`cors`)

| Constat | Points |
|---|---|
| Sonde en échec | 0 |
| Pas d'`Access-Control-Allow-Origin` (ou valeur invalide) | 0 |
| ACAO reflète l'origine sondée **et** `Access-Control-Allow-Credentials: true` | −50 |
| ACAO `null` avec credentials | −50 |
| ACAO reflète l'origine sondée (ou vaut `null`) sans credentials : équivaut à `*` | 0 |
| ACAO `*` (contenu public) | 0 |
| ACAO limité à une origine précise | 0 |

### Exposition et bonnes pratiques

**Divulgation d'informations techniques** (`information-disclosure`)

| Constat | Points |
|---|---|
| Version logicielle exposée (ex. `Apache/2.4.41`, `PHP/8.1`) | −5 |
| Technologie exposée sans version (ex. `Server: nginx`) | 0 |
| Seul l'hébergeur ou le CDN est nommé (ex. `Server: cloudflare`) | 0 |
| Rien d'exposé | 0 |

**Fichier security.txt** (`security-txt`) et **Enregistrements DNS CAA** (`caa`) : toujours 0. Ce
sont de bonnes pratiques recommandées par l'OWASP, mais leur absence n'expose pas les visiteurs.

## 4. Écarts assumés avec MDN HTTP Observatory

Chaque problème est compté une seule fois, à l'endroit le plus parlant, et les verdicts suivent le
comportement réel des navigateurs. Les décisions sont datées dans [decisions.md](decisions.md).

| Sujet | Observatory v6 | SecuScan | Pourquoi |
|---|---|---|---|
| TLS | Non testé | Certificat (−50/−30/−10) et versions (−30/−20) | Le cahier des charges inclut le transport ; un certificat invalide est le défaut le plus visible |
| Divulgation de version | Non testée | −5 | Une version précise aide à cibler une faille connue (OWASP A02:2025) |
| COOP / COEP / CORP | Un test par en-tête | Un seul contrôle, +5 pour COOP | Trois en-têtes liés, présentés ensemble |
| Scripts en `http://` | Comptés par SRI | Comptés par « contenu mixte » | Pas de double pénalité |
| `X-Frame-Options: ALLOW-FROM` | Toléré | Traité comme absent (−20) | Plus aucun navigateur ne le prend en charge |
| En-têtes dupliqués | Règles historiques | Règles des spécifications (comme les navigateurs) | Le verdict reflète ce que fait le navigateur |
| `frame-ancestors` permissive (`*`) | +5 | −20 (aucune protection) | Elle n'empêche rien, même si `X-Frame-Options` est présent |
| Préchargement HSTS | Liste réelle de Chromium | Estimé d'après l'en-tête | Pas d'accès à la liste en temps réel ; le rapport le précise |
| HSTS sur un certificat invalide | Pénalité HSTS (`hsts-invalid-cert`) | Seul le certificat est pénalisé ; HSTS le signale en détail | Un même défaut n'est compté qu'une fois |

### Comparaison sur des sites réels (20 novembre 2026)

| Site | SecuScan | Observatory | Écart expliqué par |
|---|---|---|---|
| github.com | A+ (115) | A+ (115) | — |
| developer.mozilla.org | A+ (110) | A+ (110) | — |
| mozilla.org | B (80) | B+ (80) | Échelle de lettres seulement |
| owasp.org | B (75) | B (75) | — |
| securityheaders.com | A+ (110) | A+ (115) | Divulgation de version (`X-Powered-By`, −5) |
| wikipedia.org | D (45) | C (50) | Divulgation de version (`Server`, −5) |
| example.com | F (0) | F (10) | TLS 1.0/1.1 acceptés (−20, vérifié avec OpenSSL) |
