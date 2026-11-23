# 21 — Les 18 contrôles

> Ce que vérifie chaque contrôle, pourquoi, et selon quelles règles. Les barèmes sont dans
> [22-notation.md](22-notation.md) ; les sources complètes (OWASP, MDN, RFC) sont affichées dans le
> rapport et sur la page **Méthodologie**, générée à partir du même registre
> (`src/lib/scanner/checks/index.ts`).

Chaque contrôle est une **fonction pure** `ScanContext → CheckOutcome` : il ne fait aucune requête,
il lit les faits collectés par les sondes (voir [20-moteur-de-scan.md](20-moteur-de-scan.md)). Son
verdict contient un statut (*Conforme*, *À améliorer*, *À corriger*, *Information*, *Non vérifié*),
un effet sur le score, un constat, des détails, la valeur observée (preuve), une recommandation et
des exemples de configuration Nginx, Apache et Next.js.

| Famille | Contrôles |
|---|---|
| Chiffrement et transport | `https-redirect`, `tls-certificate`, `tls-protocol`, `hsts` |
| En-têtes de sécurité | `csp`, `clickjacking`, `content-type-options`, `referrer-policy`, `permissions-policy`, `cross-origin-isolation`, `xss-protection` |
| Cookies | `cookies` |
| Contenu et ressources | `sri`, `mixed-content`, `cors` |
| Exposition et bonnes pratiques | `information-disclosure`, `security-txt`, `caa` |

---

## Chiffrement et transport

### Redirection HTTP → HTTPS (`https-redirect`)

**Risque.** Un visiteur qui tape `example.com` arrive d'abord en HTTP clair. Sans redirection immédiate
vers HTTPS, un attaquant sur le réseau (Wi-Fi public) peut intercepter ou modifier cette première page.

**Ce qui est observé.** La sonde HTTP (`http://hôte/`, redirections suivies une à une).

**Règles.** La *première* redirection compte : elle doit mener en HTTPS **sur le même hôte**, sinon le
navigateur ne peut pas mémoriser HTTPS pour l'hôte saisi (HSTS). Une chaîne qui finit en HTTP, une
boucle ou une redirection invalide est un échec. Un port 80 fermé alors que HTTPS répond est
acceptable. Les codes 301/308 (permanents) sont conseillés plutôt que 302/307.

**Sources.** OWASP TLS Cheat Sheet, Top 10:2025 A04, ASVS 12.2.1, WSTG-CRYP-01.

### Certificat TLS (`tls-certificate`)

**Risque.** Un certificat invalide déclenche une alerte que les visiteurs apprennent à ignorer, ce qui
ouvre la porte aux attaques de l'homme du milieu.

**Ce qui est observé.** La sonde TLS (négociation directe sur le port 443) ; à défaut, la validation
faite pendant la connexion HTTPS de l'analyse.

**Règles.** Expiré, pas encore valide, auto-signé, autorité inconnue, nom d'hôte non couvert → −50.
Quand la chaîne est en erreur, Node.js ne vérifie plus le nom d'hôte : SecuScan le vérifie lui-même
(joker `*.example.com` sur un seul niveau). Chaîne incomplète (les navigateurs savent souvent la
compléter, pas les autres clients) ou clé faible → −10. Expiration à moins de 14 jours avec moins d'un
tiers de la durée de vie restante → avertissement sans pénalité. Le certificat de l'hôte final atteint
après redirection est aussi vérifié. **Limite** : la révocation (OCSP/CRL) n'est pas vérifiée, Node.js
ne la fournit pas.

**Sources.** OWASP TLS Cheat Sheet, Top 10:2025 A04, ASVS 12.2.2, WSTG-CRYP-01.

### Version de TLS (`tls-protocol`)

**Risque.** TLS 1.0 et 1.1 sont abandonnés (RFC 8996) : leurs faiblesses (BEAST, absence d'AEAD…)
permettent des attaques par rétrogradation.

**Règles.** La version négociée doit être au moins TLS 1.2 (1.3 recommandé). SecuScan tente en plus
deux négociations limitées à TLS 1.0 puis TLS 1.1 : si le serveur les accepte → −20. Un test non
concluant (coupure, délai) n'est pas pénalisé.

**Sources.** OWASP TLS Cheat Sheet, ASVS 12.1.1, RFC 8996.

### HTTP Strict Transport Security (`hsts`)

**Risque.** Sans HSTS, chaque visite qui commence en HTTP peut être interceptée (attaque *SSL
stripping*). L'en-tête demande au navigateur de n'utiliser que HTTPS pendant `max-age` secondes.

**Règles (RFC 6797).** Directives insensibles à la casse, `max-age` éventuellement entre guillemets,
directive répétée = en-tête invalide. Seul le premier en-tête compte s'il est envoyé plusieurs fois.
180 jours minimum, un an et plus avec `includeSubDomains` et `preload` pour le bonus. HSTS reçu en
HTTP clair est ignoré par les navigateurs (signalé) ; HSTS ne s'applique pas à une adresse IP.

**Sources.** OWASP HSTS Cheat Sheet, ASVS 3.4.1 et 3.7.4, WSTG-CONF-07, RFC 6797, hstspreload.org.

---

## En-têtes de sécurité

### Content Security Policy (`csp`)

**Risque.** La CSP est la meilleure défense en profondeur contre le XSS : elle dit au navigateur
quels scripts il a le droit d'exécuter. Une politique avec `'unsafe-inline'` laisse passer un script
injecté.

**Ce qui est observé.** Les en-têtes `Content-Security-Policy` (et `-Report-Only`, qui n'applique
rien) et les balises `<meta http-equiv>` de la page.

**Règles (CSP Level 3).** Analyseur conforme à la spécification (`csp-parser.ts`) : plusieurs politiques
séparées par des virgules, directives en minuscules, première occurrence retenue, chaînes de repli
(`script-src` → `default-src`), `'unsafe-inline'` neutralisé par un nonce ou une empreinte,
`'strict-dynamic'`. Plusieurs politiques s'appliquent toutes : la plus stricte détermine le verdict. En
`<meta>`, `frame-ancestors`, `report-uri` et `sandbox` sont ignorées. Détails sans points :
`object-src`, `base-uri`, `form-action`, `frame-ancestors` manquants.

**Sources.** OWASP CSP Cheat Sheet, Secure Headers Project, Top 10:2025 A05, ASVS 3.4.3, WSTG-CONF-12,
web.dev (CSP stricte).

### Protection contre le clickjacking (`clickjacking`)

**Risque.** Un site malveillant affiche la page dans un cadre invisible et fait cliquer le visiteur
à son insu.

**Règles.** `frame-ancestors` (en en-tête uniquement) l'emporte sur `X-Frame-Options`. L'analyse de
`X-Frame-Options` suit l'algorithme de la spécification HTML (valeurs jointes, `ALLOW-FROM` ignoré,
valeurs contradictoires = blocage). Une `frame-ancestors` qui autorise tout le monde (`*`) n'est pas une
protection.

**Sources.** OWASP Clickjacking Defense Cheat Sheet, ASVS 3.4.6, WSTG-CLNT-09, RFC 7034.

### X-Content-Type-Options (`content-type-options`)

**Risque.** Sans `nosniff`, le navigateur peut « deviner » qu'un fichier texte est un script et
l'exécuter.

**Règle (spécification Fetch).** Seule la première valeur compte, insensible à la casse.

### Referrer-Policy (`referrer-policy`)

**Risque.** L'adresse complète des pages (qui peut contenir un jeton, un identifiant) fuit vers les
sites tiers via l'en-tête `Referer`.

**Règles.** La **dernière** valeur reconnue l'emporte (une liste permet un repli pour les vieux
navigateurs) ; une balise `<meta name="referrer">` valide est appliquée après l'en-tête.

### Permissions-Policy (`permissions-policy`)

**Rôle.** Désactiver les fonctionnalités sensibles (caméra, micro, géolocalisation, paiement) que le
site n'utilise pas. La syntaxe (dictionnaire de champs structurés, RFC 8941) est vérifiée et l'ancienne
syntaxe `Feature-Policy` est reconnue. Sans effet sur la note, comme chez Observatory.

### Isolation entre origines (`cross-origin-isolation`)

**Rôle.** `Cross-Origin-Opener-Policy` coupe le lien entre la page et les fenêtres d'autres origines
(attaques XS-Leaks) ; COEP et CORP complètent l'isolation. Les valeurs sont sensibles à la casse et
un COOP envoyé en HTTP clair est ignoré par les navigateurs.

### X-XSS-Protection (`xss-protection`)

**Rôle.** En-tête **obsolète** : l'auditeur XSS a été retiré des navigateurs et pouvait lui-même créer
des failles. Absent ou `0` est le bon réglage ; `1; mode=block` est signalé.

---

## Cookies

### Attributs des cookies (`cookies`)

**Risque.** Un cookie de session sans `Secure` peut être volé sur le réseau, sans `HttpOnly` par un
script (XSS), sans `SameSite` il accompagne les requêtes d'autres sites (CSRF).

**Ce qui est observé.** Tous les `Set-Cookie` des réponses HTTPS **et** HTTP, redirections comprises,
lus par un analyseur conforme à la RFC 6265bis (`cookie-parser.ts`) : attributs insensibles à la casse,
dernière occurrence retenue, en-tête ignoré s'il contient un caractère de contrôle.

**Règles.** Cookie de session reconnu à son nom ; cookie anti-CSRF (`csrf`, `xsrf`) exclu de cette
catégorie car JavaScript doit le lire. HSTS atténue l'absence de `Secure`. Un cookie dont le préfixe
`__Secure-` / `__Host-` n'est pas respecté est rejeté par le navigateur : seule cette règle s'applique
alors. Les cookies supprimés (`Max-Age=0`, date passée) ne sont pas évalués. **Confidentialité** :
la valeur d'un cookie n'apparaît jamais dans le rapport (`nom=***`).

**Sources.** OWASP Session Management et CSRF Prevention Cheat Sheets, ASVS 3.3.1 à 3.3.4, WSTG-SESS-02.

---

## Contenu et ressources

### Intégrité des scripts tiers — SRI (`sri`)

**Risque.** Un script chargé depuis un CDN s'exécute avec tous les droits de la page : si le CDN est
compromis, tous les visiteurs exécutent le code modifié (attaque de la chaîne d'approvisionnement).

**Règles.** Script « tiers » = hôte différent de celui de la page (règle d'Observatory, un sous-domaine
compte). Jeton `integrity` utilisable : `sha256`, `sha384` ou `sha512` suivi d'une empreinte base64.
`integrity` sans `crossorigin` fait bloquer le script (signalé). Les scripts en `http://` relèvent du
contenu mixte.

**Sources.** OWASP Third Party JavaScript Management Cheat Sheet, Top 10:2025 A03 et A08, ASVS 3.6.1.

### Contenu mixte (`mixed-content`)

**Risque.** Une page HTTPS qui charge un script en `http://` redevient modifiable par un attaquant
sur le réseau.

**Règles (W3C Mixed Content).** Ressources « bloquables » (scripts, styles, cadres, objets,
préchargements) → −20 ; formulaires envoyés en `http://` → −10 ; ressources « passives » (images,
médias, icônes), que Chrome et Firefox passent automatiquement en HTTPS → −5. La directive CSP
`upgrade-insecure-requests` est signalée mais ne dispense pas de corriger les adresses.

**Écart connu.** La spécification Mixed Content Level 2 range `<track>` parmi les ressources bloquables ;
SecuScan le compte pour l'instant comme passif (−5 au lieu de −20) ; c'est une amélioration prévue.

### Partage entre origines — CORS (`cors`)

**Risque.** Si le serveur recopie n'importe quelle origine dans `Access-Control-Allow-Origin` **et**
autorise les cookies, n'importe quel site peut lire les données du visiteur connecté.

**Ce qui est observé.** Une requête envoyée avec l'origine fictive `https://secuscan-cors-probe.invalid`
(domaine `.invalid` réservé : il n'appartient à personne).

**Règles (spécification Fetch).** Comparaison exacte de l'origine ; `Access-Control-Allow-Credentials`
compte seulement s'il vaut exactement `true` ; `*` est incompatible avec les cookies ; plusieurs valeurs
= accès refusé ; une origine recopiée sans `Vary: Origin` est signalée (cache partagé).

**Sources.** OWASP HTML5 Security Cheat Sheet, Top 10:2025 A01, ASVS 3.4.2, WSTG-CLNT-07.

---

## Exposition et bonnes pratiques

### Divulgation d'informations techniques (`information-disclosure`)

**Risque.** `Server: Apache/2.4.41` ou `X-Powered-By: PHP/8.1` indiquent à un attaquant quelles failles
connues essayer. Une version précise (« majeure.mineure ») coûte −5 ; un simple nom de technologie ou
de CDN est informatif.

**Sources.** OWASP Secure Headers Project, ASVS 13.4.6, WSTG-INFO-02 et INFO-08.

### Fichier security.txt (`security-txt`)

**Rôle (RFC 9116).** Indiquer aux chercheurs en sécurité comment signaler une faille
(`/.well-known/security.txt`, champs `Contact` et `Expires` obligatoires). SecuScan reconnaît les
« faux 200 » (page HTML renvoyée pour toute adresse inconnue), les fichiers signés OpenPGP et vérifie
le format des dates. Sans effet sur la note.

### Enregistrements DNS CAA (`caa`)

**Rôle (RFC 8659).** Lister les autorités autorisées à émettre des certificats pour le domaine (la
recherche remonte aux domaines parents). Sans `issue`, `issuewild` n'encadre que les certificats
génériques. Les navigateurs ne les lisent pas : sans effet sur la note.
