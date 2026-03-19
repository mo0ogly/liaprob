# Ameliorations pour Waves 3-6

## 1. Corrections pipeline de conversion (avant Wave 3)

### A. Validation RE2 dans le convertisseur
Le script de conversion (nmap/recog/nuclei/wappalyzer -> lia-fingerprint-v1) doit :
- Tester chaque regex avec `regexp.Compile()` AVANT ecriture du JSON
- Remplacer les backreferences par des groupes non-capturants ou des alternatives
- Signaler les regex incompatibles dans un rapport

**Effort :** 2h | **Impact :** Elimine les 35 matchers disabled a la source

### B. Confidence calibrage dans le convertisseur
Le convertisseur doit :
- Calculer `max_achievable = base + sum(deltas)` pour chaque pattern
- Si `max_achievable < threshold` -> ajuster automatiquement
- Pour les patterns avec 1 seul matcher : `delta >= threshold`

**Effort :** 2h | **Impact :** Elimine les 239 patterns unreachable

### C. Deduplication matchers probe/banner
Les patterns nmap ont les matchers dupliques dans `banner_matchers` et `probes[0].matchers`.
Ajouter une passe de deduplication au chargement.

**Effort :** 1h | **Impact :** Performance matcher -50% temps CPU sur nmap patterns

---

## 2. Ameliorations tests (Wave 3+)

### A. Banners reelles depuis le Discovery Lab
Ne plus inventer de banners dans les tests. Workflow :
1. Demarrer le service dans le Discovery Lab Docker
2. Capturer la banner avec netcat/nmap
3. Copier dans le test
Priorite : wappalyzer (HTTP headers/body) et recog (equipements reseau)

**Effort :** 4h (setup lab + capture 50 banners) | **Impact :** Tests realistes, zero faux positifs

### B. Tests negatifs systematiques
Chaque Wave doit inclure des tests negatifs :
- Banner SSH ne doit pas matcher un pattern HTTP
- Banner MySQL ne doit pas matcher PostgreSQL
- Header Apache ne doit pas matcher Nginx

**Effort :** 2h par wave | **Impact :** Detection faux positifs

### C. Test de performance Wave 6
Benchmark : temps de matching pour 1000 ports x 16K patterns.
Cible : < 5s sur un single thread.

**Effort :** 3h | **Impact :** Go/no-go production

---

## 3. Ameliorations loader (avant Wave 3)

### A. Support UDP natif pour SNMP/mDNS
274 patterns recog ciblent SNMP mais le matcher ne supporte pas UDP nativement en mode test.
Ajouter `UDPResponses` dans les tests Wave 4.

**Effort :** 3h | **Impact :** 274 patterns recog SNMP activables

### B. Port inference pour patterns sans default_ports
2 843 patterns nmap n'ont pas de `default_ports`. Ajouter une table de mapping service -> ports par defaut dans le normalizer.

**Effort :** 4h | **Impact :** 2 843 patterns indexables par port

### C. Nettoyage port explosion
Certains patterns wappalyzer ont 100+ ports. Limiter a 20 ports max par pattern (top ports du service).

**Effort :** 1h | **Impact :** Index ByPort plus performant

---

## 4. Quick wins pour Wave 3

| Quick win | Effort | Impact | Wave |
|-----------|--------|--------|------|
| Tester 10 CMS wappalyzer (WordPress, Drupal, Joomla) | 1h | Valide 30% des patterns wappalyzer | W3 |
| Tester 5 frameworks JS (React, Angular, Vue, jQuery) | 1h | Valide 20% des patterns wappalyzer | W3 |
| Capturer headers HTTP reels du lab (nginx, Apache, IIS) | 30min | Banners realistes | W3 |
| Ajouter test priorite LIA > wappalyzer sur meme service | 30min | Regression guard | W3 |
| Deduplication matchers dans normalizePattern | 1h | Performance | W3-W6 |

---

## 5. Objectifs Wave 3

- **Scope :** wappalyzer (5 164 patterns) - technologies web
- **Score cible :** 50 technos web detectees (headers + body)
- **Focus areas :**
  - CMS : WordPress, Drupal, Joomla, Magento, Shopify (header + body)
  - Frameworks : React, Angular, Vue, jQuery, Bootstrap (body patterns)
  - Serveurs : nginx, Apache via wappalyzer vs LIA (priorite test)
- **Risques :**
  - 7 patterns wappalyzer avec lookaheads disabled -> peuvent impacter des technos majeures
  - Port explosion sur les patterns HTTP (80, 443 = 10K+ patterns)
  - Body matching plus lent que banner matching (HTML parsing implicite)
- **Quality gate :** 40/50 top technos matchees = PASS

---

## 6. Objectifs Wave 4-6

### Wave 4 : recog (2 396 patterns)
- Top 30 equipements reseau : Cisco, Juniper, HP, Dell, Fortinet
- Banners SNMP, SSH, FTP industrielles
- Necessite : support UDP test + banners lab

### Wave 5 : nuclei (908 patterns)
- Panels admin : phpMyAdmin, Grafana, Jenkins (via nuclei vs LIA)
- Technologies cloud : AWS, Azure, GCP signatures
- APIs exposees

### Wave 6 : Integration
- Multi-source priority test (meme service, 5 sources -> LIA gagne)
- Performance benchmark (< 5s / 1000 ports)
- Zero regression suite complete (47 LIA + 20 Wave2)
