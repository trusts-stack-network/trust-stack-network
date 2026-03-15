# Configuration DNS Cloudflare — trusts-network.com

## Enregistrements DNS Requis

### A Records

### CNAME Records

### Page Rules (Cloudflare)
1. **Always HTTPS** : `http://*trusts-network.com/*` → `https://$1`
2. **WWW redirect** : `trusts-network.com/*` → `https://www.trusts-network.com/$1`

### SSL/TLS
- Mode : Full (strict)
- Certificat SSL : Cloudflare généré automatiquement
- TLS 1.3 : Activé

### Sécurité
- Firewall : Bloquer les IPs suspectes automatiquement
- Rate limiting : 100 req/min par IP sur /api/*
- Bot Fight Mode : Activé

### CDN
- Caching level : Standard
- Browser cache TTL : 4 heures
- Always Online : Activé