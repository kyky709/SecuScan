# 00 — Cadrage du projet

> Ce document fixe **pourquoi** SecuScan existe, **ce qu'il doit faire** et **ce qu'il ne fera pas**.
> C'est la référence à relire avant toute nouvelle fonctionnalité.

## 1. Contexte

SecuScan est un projet personnel, mené par intérêt pour deux domaines :
le **développement web moderne** (Next.js, TypeScript, déploiement serverless) et la **sécurité des
applications web** (en-têtes HTTP, TLS, cookies, référentiels OWASP).

Le principe reprend celui d'outils réels comme [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory)
(ex-Mozilla Observatory) et [securityheaders.com](https://securityheaders.com) : on saisit l'adresse d'un site,
l'outil analyse sa configuration de sécurité, attribue une note et explique comment corriger chaque point.

## 2. Objectifs

| # | Objectif | Indicateur de réussite |
|---|---|---|
| O1 | Analyser la configuration de sécurité d'un site à partir de son adresse | 18 contrôles exécutés en moins de 20 s |
| O2 | Donner une note claire et justifiée | Note de A+ à F, score détaillé (pénalités, bonus) |
| O3 | Expliquer et aider à corriger | Pour chaque problème : constat, recommandation, exemples Nginx/Apache/Next.js |
| O4 | S'appuyer sur des références reconnues | Chaque contrôle cite l'OWASP (Top 10:2025, ASVS 5.0, Cheat Sheets, WSTG) |
| O5 | Être soi-même exemplaire en sécurité | Protection anti-SSRF testée, CSP stricte, limitation de débit |
| O6 | Être professionnel et compréhensible | Code commenté, tests automatisés, CI, documentation, déploiement Vercel |

## 3. Périmètre

### Inclus

- Analyse **passive** d'une page (celle de l'URL saisie), comme une visite de navigateur :
  - **Transport** : redirection HTTP → HTTPS, certificat TLS, versions de TLS, HSTS ;
  - **En-têtes de sécurité** : Content-Security-Policy, protection anti-clickjacking (X-Frame-Options /
    frame-ancestors), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP,
    X-XSS-Protection (obsolète) ;
  - **Cookies** : Secure, HttpOnly, SameSite, préfixes `__Secure-` / `__Host-` ;
  - **Contenu** : Subresource Integrity, contenu mixte, CORS ;
  - **Exposition** : en-têtes qui divulguent des versions, fichier `security.txt`, enregistrements DNS CAA.
- Note de **A+ à F** inspirée de la méthode publique de MDN HTTP Observatory.
- Rapport web détaillé, lien partageable (`?url=`), export JSON.
- API JSON (`POST /api/scan`) utilisable sans l'interface.
- Page « Méthodologie » générée à partir du catalogue des contrôles (une seule source de vérité).

### Exclus (hors périmètre)

- Toute action **intrusive** : recherche de failles (injections, XSS…), force brute, exploration du site
  (crawl), test de ports, test de charge. SecuScan n'est pas un outil de test d'intrusion.
- L'analyse de plusieurs pages ou d'un site entier.
- Les comptes utilisateurs, l'historique des analyses, la surveillance planifiée.
- La vérification de révocation des certificats (OCSP/CRL), non fournie par Node.js.

## 4. Exigences

### Fonctionnelles

| Id | Exigence |
|---|---|
| F1 | Accepter une adresse avec ou sans `https://`, avec ou sans chemin, et la normaliser |
| F2 | Refuser les adresses locales, privées ou réservées, les ports non standard et les identifiants dans l'URL |
| F3 | Exécuter les sondes réseau en parallèle avec un délai global |
| F4 | Produire pour chaque contrôle : statut, effet sur le score, constat, preuve, recommandation, exemples, références |
| F5 | Calculer le score et la note selon la grille documentée (`docs/22-notation.md`) |
| F6 | Afficher le rapport, permettre de le partager et de l'exporter |
| F7 | Expliquer la méthode de notation et chaque contrôle sur une page dédiée |

### Non fonctionnelles

| Id | Exigence |
|---|---|
| NF1 | **Sécurité** : protection anti-SSRF à chaque connexion (y compris après redirection), CSP stricte à nonce, en-têtes de sécurité, limitation de débit, aucune donnée personnelle conservée |
| NF2 | **Performance** : rapport en moins de 20 s dans le pire cas (délais bornés) |
| NF3 | **Qualité** : TypeScript strict, lint et formatage Biome, tests unitaires et d'intégration (Vitest), CI GitHub Actions |
| NF4 | **Accessibilité** : interface utilisable au clavier, contrastes suffisants, thème clair et sombre |
| NF5 | **Pédagogie** : chaque fichier explique son rôle ; documentation en français |
| NF6 | **Responsabilité** : le scanner s'identifie (User-Agent), fait peu de requêtes (6 à 8 connexions par analyse) et rappelle de n'analyser que des sites autorisés |

## 5. Contraintes

- Hébergement **Vercel** (offre gratuite Hobby) : fonctions serverless Node.js 24, durée limitée,
  plusieurs instances possibles (d'où une limitation de débit partageable via Redis).
- Pas de base de données : tout est calculé à la demande.
- Budget : nul (services gratuits uniquement).

## 6. Livrables

1. Application déployée sur Vercel.
2. Code source documenté (dépôt Git), tests et CI.
3. Documentation : ce cadrage, architecture, moteur de scan, contrôles, notation, sécurité, tests,
   déploiement, guide pas à pas, journal et décisions.

## 7. Risques

| Risque | Parade |
|---|---|
| Le scanner sert à attaquer un réseau interne (SSRF) | Validation de chaque adresse au moment de la connexion, ports 80/443, tests de non-régression |
| Le scanner sert à harceler un site | Limitation de débit par client **et** par site analysé |
| Faux positifs / négatifs | Règles fondées sur les spécifications et sur Observatory, tests par cas, comparaison avec des sites de référence |
| Évolution des référentiels (OWASP, navigateurs) | Références centralisées dans un seul fichier (`references.ts`), dates de vérification notées |
| Durée d'exécution serverless dépassée | Délais par requête et délai global, sondes en parallèle |
