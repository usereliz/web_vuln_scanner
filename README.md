# Scanner de Vulnérabilités Web

**Outil éducatif** pour détecter les vulnérabilités OWASP Top 10 dans les applications web.

## ⚠️ AVERTISSEMENT LÉGAL

**Utilisez uniquement sur des applications que vous possédez ou pour lesquelles vous avez une autorisation écrite explicite.** Le scanning non autorisé est illégal et contraire à l'éthique.

## Fonctionnalités

- ✅ Vérification des en-têtes de sécurité (X-Content-Type-Options, CSP, HSTS, X-Frame-Options)
- ✅ Détection d'injections SQL (basée sur le temps et les erreurs)
- ✅ Détection des redirections non sécurisées (open redirect)
- ✅ Affichage terminal coloré
- ✅ Génération de rapport JSON avec mapping OWASP

## Installation

```bash
git clone https://github.com/usereliz/web_vuln_scanner.git
cd web_vuln_scanner
pip install -r requirements.txt"# web_vuln_scanner" 
