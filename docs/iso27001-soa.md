# Déclaration d'applicabilité (extrait) — ISO/IEC 27001:2022, annexe A

Périmètre : la plateforme Aeria (modules 1 à 6) et sa chaîne de développement. L'extrait couvre les mesures
pertinentes pour une petite plateforme de données environnementales. Les mesures non citées (sécurité des
ressources humaines à l'embauche, locaux, supports amovibles…) relèvent de l'organisation qui exploiterait
Aeria.

Statuts :

- **Appliquée** : en place, avec une preuve dans les dépôts ;
- **Partielle** : en place mais incomplète ;
- **Planifiée** : inscrite au PACS (mesures M1 à M13 de l'EBIOS RM) ;
- **N/A** : non applicable à ce périmètre.

| Mesure | Intitulé | Statut | Mise en œuvre et preuve |
|---|---|---|---|
| 5.1 | Politiques de sécurité de l'information | Partielle | analyse de risques et rapport de ce module ; politique formelle à rédiger par l'exploitant |
| 5.9 | Inventaire des informations et autres actifs | Appliquée | parc de capteurs (module 4 : modèle, n° de série, site, statut) ; inventaire des biens supports (EBIOS, atelier 1) |
| 5.12 | Classification de l'information | Appliquée | besoins DICT par valeur métier (EBIOS, atelier 1) ; mesures publiques, données des techniciens confidentielles |
| 5.15 | Contrôle d'accès | Appliquée | deux rôles, contrôle d'appartenance des interventions (module 4, RG16), API authentifiée |
| 5.17 | Informations d'authentification | Appliquée | BCrypt ; verrouillage après 5 échecs (M3) ; un compte MQTT par capteur (M1) |
| 5.19 | Sécurité dans les relations fournisseurs | Partielle | cartographie de l'écosystème (EBIOS, atelier 3) ; exigences contractuelles envers les mairies à définir |
| 5.21 | Sécurité dans la chaîne d'approvisionnement des TIC | Appliquée | versions épinglées ; analyse OSV hebdomadaire (M6) ; actions GitHub épinglées par empreinte SHA (M13) |
| 5.23 | Sécurité des services en nuage | Partielle | GitHub : dépôts publics sans secret ; secret scanning et Dependabot à activer |
| 5.24 | Planification de la gestion des incidents | Partielle | règles Wazuh qualifiées par niveau ; procédure de réponse décrite dans le rapport |
| 5.25 | Évaluation des événements de sécurité | Appliquée | règles corrélées (force brute puis succès : niveau 12) ; 15 scénarios testés |
| 5.28 | Collecte des preuves | Appliquée | preuves Varys horodatées et chaînées par empreintes SHA-256 ; sorties brutes de l'audit archivées |
| 5.30 | Préparation des TIC à la continuité | Planifiée | sauvegardes chiffrées et test de restauration (M10) |
| 5.34 | Vie privée et protection des données personnelles | Appliquée | données personnelles minimales (nom, e-mail, téléphone pro des techniciens) ; démo sur données fictives |
| 6.3 | Sensibilisation, formation | Planifiée | MOOC SecNumacadémie de l'ANSSI (à suivre par l'auteur) |
| 7.8 | Emplacement et protection du matériel | Partielle | capteurs sur la voie publique : boîtiers IP65, fixation sur mât ; anti-vandalisme renforcé (M12) |
| 8.1 | Terminaux des utilisateurs | Partielle | poste audité : services exposés hors périmètre Aeria signalés (voir `audit.md` §6) |
| 8.2 | Droits d'accès privilégiés | Appliquée | actions sensibles réservées au responsable ; MFA planifiée (M11) |
| 8.5 | Authentification sécurisée | Partielle | formulaire et jeton CSRF, verrouillage ; MFA et HTTPS (M2, M11) restants |
| 8.8 | Gestion des vulnérabilités techniques | Appliquée | analyse OSV des dépendances (Maven et PyPI) ; mise à jour en Spring Boot 3.5.16 ; analyse hebdomadaire en CI |
| 8.9 | Gestion des configurations | Appliquée | infrastructure décrite en code (compose, Dockerfiles) ; configuration MQTT de production versionnée |
| 8.13 | Sauvegarde des informations | Planifiée | M10 |
| 8.15 | Journalisation | Appliquée | journal `AERIA-SECURITY` normalisé, anti-injection (M4) ; journal des statuts de ticket en base (RG12) |
| 8.16 | Activités de surveillance | Appliquée | règles Wazuh (M5) ; supervision des capteurs muets ou dérivants (RG14) |
| 8.20 | Sécurité des réseaux | Partielle | services sur la boucle locale ; MQTT TLS 8883 en production ; proxy HTTPS restant |
| 8.21 | Sécurité des services réseau | Partielle | ACL MQTT par capteur ; en-têtes de sécurité HTTP |
| 8.22 | Cloisonnement des réseaux | Partielle | réseaux Docker par module ; constat : la passerelle Docker expose des services d'autres projets (`audit.md` §6) |
| 8.24 | Utilisation de la cryptographie | Partielle | BCrypt, TLS MQTT ; HTTPS du back-office restant ; chiffrement de la flash ESP32 (M9) |
| 8.25 | Cycle de vie de développement sécurisé | Appliquée | intégration continue sur tous les modules ; règles métier en base ; revue de sécurité (ce module) |
| 8.26 | Exigences de sécurité des applications | Appliquée | CSRF, CSP, X-Frame-Options, verrouillage, contrôle d'appartenance |
| 8.28 | Codage sécurisé | Appliquée | requêtes SQL paramétrées (JdbcTemplate), échappement Thymeleaf, neutralisation des journaux |
| 8.29 | Tests de sécurité | Appliquée | tests automatisés de sécurité (module 4 : 12 tests) ; audit nmap, Varys, contrôles web ; scénarios Wazuh |
| 8.31 | Séparation des environnements | Partielle | profils demo / test / prod ; base de test distincte ; pas d'environnement de préproduction |
| 8.32 | Gestion des changements | Appliquée | Git, intégration continue obligatoire, historique des corrections de l'audit (commits liés aux constats) |
| 8.33 | Informations de test | Appliquée | jeux de démonstration synthétiques, aucune donnée personnelle réelle |
| 8.34 | Protection des SI en cours d'audit | Appliquée | périmètre limité à la plateforme et au poste de l'auteur ; manager Wazuh jetable ; aucun scan du réseau domestique |

**Bilan** : 35 mesures examinées, dont 20 appliquées, 12 partielles et 3 planifiées. Les mesures partielles et
planifiées correspondent aux mesures M2 et M8 à M13 du PACS.
