# Audit technique de la plateforme Aeria

Date : 12 novembre 2026. Auditeur : BRINIS Aya. Outils : nmap 7.95 (embarqué dans Varys), Varys
(règles de risque réseau et preuves chaînées), client Mosquitto, scripts maison
([`scripts/web_checks.py`](../scripts/web_checks.py), [`scripts/osv_scan.py`](../scripts/osv_scan.py)),
Wazuh 4.14.9.

## 1. Périmètre et règles d'engagement

| Inclus | Exclu |
|---|---|
| Réseau Docker `aeria_default` (172.21.0.0/28) : broker MQTT, PostgreSQL | les autres appareils du réseau domestique |
| Le poste de l'auteur, vu depuis son adresse Wi-Fi (192.168.1.6/32) | tout système tiers ou en ligne |
| Back-office (8084) et API de prévision (8083) en local | — |
| Dépendances logicielles des modules 1 à 4 | — |

Seule la plateforme de l'auteur, déployée sur son propre poste, a été testée. Le test de devinette de mot de
passe a visé le compte de démonstration. Les règles Wazuh ont été chargées dans un manager **jetable**
(même image 4.14.9), pas dans le laboratoire Wazuh existant.

## 2. Synthèse des constats

| N° | Constat | Gravité | Source | Statut |
|---|---|---|---|---|
| F1 | Back-office à l'écoute sur toutes les interfaces, en HTTP : identifiants et cookie de session circulent en clair sur le Wi-Fi | **élevée** | nmap 03, netstat | **corrigé** : écoute sur la boucle locale, vérifiée par nmap 08 ; HTTPS par proxy à mettre en place |
| F2 | Broker MQTT en accès anonyme : n'importe qui peut publier des mesures au nom de n'importe quel capteur | **élevée** | test 02 | **corrigé** pour la production : `mosquitto.prod.conf`, test 07 réussi à 4/4 |
| F3 | Aucune protection contre la devinette de mot de passe (20 essais, ni blocage ni ralentissement) | moyenne | web 06 | **corrigé** : verrouillage après 5 échecs, vérifié par web 09 |
| F4 | Dépendances Java vieilles d'un an : 69 (module 1) et 76 (module 4) vulnérabilités connues, dont des critiques (Tomcat, Thymeleaf, Spring Security) | **élevée** | OSV 11 | **corrigé** : 2 restantes, non exploitables ici (§5) |
| F5 | API de prévision sans en-têtes de sécurité, bannière `uvicorn` | faible | web 06 | **corrigé** (web 09) |
| F6 | Back-office sans `Referrer-Policy` ni `Permissions-Policy` | faible | web 06 | **corrigé** |
| F7 | Aucun événement de sécurité journalisé : Wazuh n'aurait rien à détecter | moyenne | revue de code | **corrigé** : journal `AERIA-SECURITY` et règles Wazuh, 15/15 |
| F8 | Identifiants de base de données par défaut faibles dans les fichiers compose (`aeria/aeria`) | moyenne | revue | accepté en développement ; variables obligatoires en production |
| F9 | Cookie de session sans l'attribut `Secure` | faible | web 09 | dépend de HTTPS (`COOKIE_SECURE=true` derrière le proxy) |
| F10 | Varys ne signale pas un HTTP en clair sur un port non standard (8084) | info | comparaison nmap / Varys | limite de l'outil remontée : règle NET-HTTP-CLEARTEXT limitée aux ports 80 et 8080 |

## 3. Vue réseau

### 3.1 Réseau interne Aeria (nmap -sV -p-)

```
172.21.0.2  1883/tcp  open  mqtt
172.21.0.3  5432/tcp  open  postgresql  PostgreSQL DB 9.6.0 or later
```

Surface minimale : un port par service, rien d'autre sur les 65 535. PostgreSQL ouvert sur le réseau
applicatif est attendu ; Varys le signale (NET-DATABASE), c'est un risque accepté, l'accès étant
authentifié et limité au réseau Docker. Sortie complète :
[`raw/01-nmap-reseau-interne-avant.txt`](audit/raw/01-nmap-reseau-interne-avant.txt).

### 3.2 Poste vu depuis le Wi-Fi

| Port | Avant | Après | Service |
|---|---|---|---|
| 8084 | **open** (Apache Tomcat) | closed | back-office Aeria (F1) |
| 1883 | filtered | closed | MQTT, publié sur 127.0.0.1 uniquement |
| 5440 | filtered | closed | PostgreSQL Aeria, publié sur 127.0.0.1 |
| 8083 | filtered | closed | API de prévision, démarrée sur 127.0.0.1 |

Sorties : [`03-nmap-poste-lan-avant.txt`](audit/raw/03-nmap-poste-lan-avant.txt),
[`08-nmap-poste-lan-apres.txt`](audit/raw/08-nmap-poste-lan-apres.txt).

### 3.3 Accès anonyme au broker

```
Client null sending CONNECT
Client null received CONNACK (0)                     <- accepté sans identifiant
Client null sending PUBLISH (… 'aeria/sensors/AUDIT-TEST/measurements' …)
Client null received PUBACK (Mid: 1, RC:0)           <- publication acceptée
```

La configuration de production a été vérifiée dans le conteneur du broker, par une seconde instance
([`07-mqtt-config-prod-apres.txt`](audit/raw/07-mqtt-config-prod-apres.txt)) :

```
PASS  anonymous client refused
PASS  wrong password refused
PASS  sensor can publish its own topic
PASS  sensor cannot publish as another sensor
```

À noter : en MQTT 3.1.1, le broker accuse réception (PUBACK) d'une publication refusée par l'ACL sans la
transmettre. Le refus ne se voit donc qu'à la réception, ce que vérifie le 4ᵉ test.

## 4. Audit Varys

Deux campagnes, avec les ports d'Aeria ajoutés à la liste par défaut :

| Campagne | Cible | Hôtes | Ports ouverts | Preuves | Conformes | Non conformes |
|---|---|---|---|---|---|---|
| 42 | 172.21.0.0/28 | 4 | 7 | 48 | 44 | 4 |
| 43 | 192.168.1.6/32 | 1 | 9 | 12 | 8 | 4 |

Chaque preuve est un enregistrement en insertion seule, horodaté et chaîné par empreintes
(`prev_hash` → `content_hash`, SHA-256). Exemple : `ev_001639`, `sha256:f084e28f…86a9`. Export complet :
[`05-varys-preuves-avant.json`](audit/raw/05-varys-preuves-avant.json).

Non-conformités relevées :

- **172.21.0.3** (PostgreSQL Aeria) : NET-DATABASE, risque accepté (§3.1).
- **172.21.0.1**, la passerelle du réseau Docker, c'est-à-dire l'hôte : 9200 (indexeur Wazuh), 111 (rpcbind),
  8080 (HTTP). Un conteneur Aeria compromis pourrait donc atteindre des services d'autres projets
  hébergés sur le poste. Recommandation : publier ces services sur 127.0.0.1, ou filtrer le trafic des réseaux
  Docker vers l'hôte.
- **192.168.1.6** : SMB et NetBIOS, RPC, PostgreSQL natif (5432), indexeur Wazuh (9200), HTTP 8080. Ce sont des
  services du poste hors Aeria, détaillés au §6.

Limite constatée (F10) : la règle de Varys sur le HTTP en clair ne regarde que les ports 80 et 8080. Le
back-office sur 8084 n'a été repéré que par nmap. Il faudrait l'élargir à tout service identifié comme
`http` par la détection de version.

## 5. Dépendances (osv.dev)

| Module | Paquets | Avant (Spring Boot 3.5.7) | Spring Boot 3.5.16 | Final (+ Tomcat 10.1.61, Jackson 2.21.8, pgjdbc 42.7.14, log4j 2.25.5) |
|---|---|---|---|---|
| aeria-iot-sensors | 77 Maven | 69 (dont 9 critiques) | 22 (7 critiques) | **2** |
| aeria-backoffice | 66 Maven | 76 (dont 16 critiques) | 22 (7 critiques) | **2** |
| aeria-forecast | 9 PyPI | 0 | — | 0 |
| aeria-data-pipeline | 8 PyPI | 0 | — | 0 |

La mise à jour de Spring Boot n'a pas suffi. Elle laissait des failles critiques de Tomcat (contournement
d'authentification, contrôle d'accès), corrigées seulement dans des versions plus récentes que celles du BOM
Spring Boot. Elles ont été forcées par les propriétés Maven `tomcat.version`, `jackson-bom.version` et
`postgresql.version` et `log4j2.version`. Les 24 tests du back-office et les 16 du module 1 passent avec ces versions.

**Vulnérabilités résiduelles** (rapports : [`11-osv-dependances.json`](audit/raw/11-osv-dependances.json),
[`12-osv-dependances-apres.json`](audit/raw/12-osv-dependances-apres.json),
[`13-osv-dependances-final.json`](audit/raw/13-osv-dependances-final.json)) :

| Avis | Composant | Pourquoi il ne s'applique pas à Aeria |
|---|---|---|
| GHSA-pc63-qcmh-9cmg (critique) | spring-webmvc 6.2.19 : `XsltView` | aucune vue XSLT : rendu Thymeleaf et JSON uniquement |
| GHSA-j9f9-w8pj-32f8 (critique) | spring-webmvc 6.2.19 : fragments en *Server-Sent Events* | aucun flux SSE |

Les deux avis critiques ne sont corrigés qu'en Spring Framework 7 (Spring Boot 4). La migration est inscrite au
PACS. L'analyse OSV tourne chaque semaine en CI pour signaler toute nouvelle vulnérabilité.

## 6. Observations sur le poste (hors périmètre Aeria)

| Service | Exposition | Recommandation |
|---|---|---|
| PostgreSQL natif Windows (5432) | toutes interfaces, visible du Wi-Fi | `listen_addresses = 'localhost'` dans `postgresql.conf`, ou désinstaller s'il ne sert plus |
| Laboratoire Wazuh (443, 1514, 1515, 9200, 55000) | toutes interfaces | publier sur 127.0.0.1 sauf 1514/1515 si des agents externes doivent s'y connecter |
| Varys (8080, 8443) | toutes interfaces | 127.0.0.1 hors démonstration |
| SMB / NetBIOS / RPC (445, 139, 135) | réseau Wi-Fi | profil réseau « Public » sur les Wi-Fi non maîtrisés ; désactiver le partage si inutile |
| Manager Wazuh du laboratoire | `wazuh-analysisd` ne répond plus sur son socket depuis le redémarrage brutal de Docker : les événements ne sont plus analysés | `docker restart single-node-wazuh.manager-1` |

## 7. Contrôles applicatifs

| Contrôle | Back-office avant | après | API de prévision avant | après |
|---|---|---|---|---|
| CSP / X-Frame-Options / X-Content-Type-Options | oui / oui / oui | oui | non / non / non | oui |
| Referrer-Policy / Permissions-Policy | non / non | oui / oui | non | oui |
| HSTS | non (pas de TLS) | non (pas de TLS) | non | non |
| Bannière serveur | aucune | aucune | `uvicorn` | aucune |
| Cookie de session | HttpOnly, SameSite=Lax, sans Secure | idem (F9) | — | — |
| Actuator | seul `/health` public | idem | — | — |
| Accès anonyme | redirection 302, API 401 | idem | public (données ouvertes) | idem |
| 20 mots de passe faux | aucun blocage | **compte verrouillé** | — | — |
| Limitation de débit | — | — | aucune | à confier au proxy inverse |

Sorties : [`06-web-avant.json`](audit/raw/06-web-avant.json), [`09-web-apres.json`](audit/raw/09-web-apres.json).
