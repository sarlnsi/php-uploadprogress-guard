# hp_uploadprogress_guard

Extension PHP native visant à **réduire certains chemins d’exploitation de CVE-2026-109618 et CVE-2026-109619**, sans reconstruire tout PHP.

**Version : `3.1.0-fork2`. Profils testés : PHP 7.3.33 et 7.4.33 NTS non-debug, Linux, Apache mod_php/prefork, Debian 10 en conteneurs.** La version précédente a aussi été testée en PHP 7.4.33 sur Debian 11. Ce fork reste une mitigation expérimentale : il ne certifie pas l’application du correctif complet au moteur PHP.

## CVE visées

| CVE | Problème que le module essaie de mitiger | Référence officielle |
| --- | --- | --- |
| **CVE-2026-109618** | Un échec d’allocation mémoire peut interrompre PHP alors que des structures de requête sont partiellement initialisées. Leur traitement ultérieur peut mener à une corruption mémoire et à une exécution de code à distance. | [RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) |
| **CVE-2026-109619** | Un worker conserve des références à de la mémoire appartenant à une requête terminée. Une opération ultérieure peut réutiliser cet état périmé : use-after-free et possibilité d’exécution de code à distance. | [RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) |

## Corrections apportées au fork

Comparaison avec l’amont `85fdda078eaccc94e3c8e7dce64f51d99f4c8dd5` :

| Changement | Comportement obtenu | CVE principalement concernée |
| --- | --- | --- |
| Élargissement de l’arrêt sur erreur d’allocation | Quand le diagnostic atteint le callback, le worker quitte immédiatement, y compris pendant le code applicatif. L’amont limitait cet arrêt aux moments où aucun script n’était en cours. | 109618 |
| Suppression du nettoyage dans le chemin OOM | Aucun parcours de la table des uploads potentiellement incomplète avant `_exit(137)` ; aucun shutdown applicatif n’est appelé. | 109618, réduction d’un risque de traitement d’état invalide |
| Gestion des débordements de taille d’allocation | Les diagnostics d’overflow d’allocation empruntent aussi ce chemin d’arrêt. Les erreurs fatales ordinaires et les timeouts gardent leur traitement normal. | 109618 |
| Réinitialisation SAPI avancée | Les pointeurs déjà libérés sont remis à `NULL` avant le callback SAPI suivant, au lieu de le faire après son exécution. | 109619 |
| Rejet des formulaires dépassant les limites | En PHP 7.3 et 7.4 : HTTP 413 et abandon des données partielles en cas de dépassement du nombre de parties, de la taille POST déclarée/réelle ou des limites du parseur. | 109618, durcissement du traitement multipart |
| Calcul mémoire sans débordement de `size_t` | Les additions et l’arrondi du garde-fou ne peuvent plus se transformer en une acceptation par débordement arithmétique. | 109618, durcissement du garde-fou |
| Configuration et compilation contrôlées | Mode inconnu et profil ZTS non corrigé refusés ; parseur sélectionné selon la branche ; absence de réutilisation d’un ancien binaire après échec de build. | Fiabilité du déploiement |
| Diagnostic dans le worker réel | `hp_uploadprogress_guard_status()` et la sonde vérifient l’identité des hooks, le fichier chargé et son SHA256. | Vérification de la mitigation des deux CVE |

Le fork conserve aussi les protections de l’amont : retrait du callback de progression des uploads, verrouillage de `session.upload_progress.enabled=0`, copie durcie du parseur multipart et remises à zéro de fin de requête. Les sessions et les uploads ordinaires restent utilisables ; le suivi de progression via les sessions PHP est neutralisé.

## Installation

Essayer d’abord sur un clone de l’application. Prérequis : Python >= 3.7, GCC/make/autoconf/binutils et **les outils/en-têtes de développement correspondant exactement au PHP installé**. Le script ne change aucun dépôt APT et n’installe pas de dépendances automatiquement.

| Branche | Compilation | Installation | API | INI Apache par défaut |
| --- | --- | --- | --- | --- |
| PHP 7.3.x | `tools/build_php73.py` | `tools/install_php73.py` | 20180731 | `/etc/php/7.3/apache2/conf.d/99-hp-guard.ini` |
| PHP 7.4.33 | `tools/build_php74.py` | `tools/install_php74.py` | 20190902 | `/etc/php/7.4/apache2/conf.d/99-hp-guard.ini` |

PHP 7.3.x : validation complète sur **7.3.33**. D’autres versions 7.3.x sont acceptées si les outils de développement, le CLI et le PHP web correspondent exactement, suffixe fournisseur compris ; elles n’ont pas toutes été testées et doivent être validées sur clone. Un binaire 7.4 n’est jamais accepté par l’installateur 7.3, ni inversement.

### PHP 7.3 : construire puis charger

En compte non root, dans le checkout complet :

```sh
python3 tools/build_php73.py \
  --php /usr/bin/php7.3 \
  --phpize /usr/bin/phpize7.3 \
  --php-config /usr/bin/php-config7.3 \
  --output /var/tmp/hp-guard-build73
```

Examiner le plan, puis appliquer pendant une maintenance avec les mêmes chemins adaptés au site :

```sh
python3 tools/install_php73.py install \
  --build /var/tmp/hp-guard-build73 \
  --probe-url https://VOTRE_SITE/hp-guard-probe.php \
  --probe-file /var/www/VOTRE_SITE/hp-guard-probe.php

sudo python3 tools/install_php73.py install \
  --build /var/tmp/hp-guard-build73 \
  --probe-url https://VOTRE_SITE/hp-guard-probe.php \
  --probe-file /var/www/VOTRE_SITE/hp-guard-probe.php \
  --apply
```

Le CLI par défaut est `/usr/bin/php7.3`. La sonde est une page temporaire protégée par jeton, créée puis supprimée automatiquement : elle observe le module et ses hooks dans Apache, sans attaque. Sauvegarde, arrêt/redémarrage d’Apache et retour arrière suivent la même procédure qu’en 7.4 ci-dessous. Pour retirer cette installation :

```sh
sudo python3 tools/install_php73.py rollback \
  --transaction /var/backups/hp-guard/TRANSACTION \
  --apply
```

### PHP 7.4.33

#### 1. Construire en utilisateur non root

```sh
python3 tools/build_php74.py \
  --php /usr/bin/php7.4 \
  --phpize /usr/bin/phpize7.4 \
  --php-config /usr/bin/php-config7.4 \
  --output /var/tmp/hp-guard-build
```

Cette commande produit le `.so`, son manifeste et le journal, sans installation. Elle vérifie l’API, le chargement CLI et les symboles glibc compatibles avec Debian 10. Ne pas réutiliser un binaire construit pour une autre installation.

#### 2. Examiner le plan

Adapter l’URL HTTPS et le chemin local d’une **nouvelle** sonde dans le DocumentRoot du même backend :

```sh
python3 tools/install_php74.py install \
  --build /var/tmp/hp-guard-build \
  --probe-url https://VOTRE_SITE/hp-guard-probe.php \
  --probe-file /var/www/VOTRE_SITE/hp-guard-probe.php
```

Sans `--apply`, aucun INI ni service n’est modifié. L’empreinte du build et les chemins prévus sont affichés ; les contrôles du serveur web sont effectués lors de l’application.

#### 3. Appliquer pendant une maintenance

```sh
sudo python3 tools/install_php74.py install \
  --build /var/tmp/hp-guard-build \
  --probe-url https://VOTRE_SITE/hp-guard-probe.php \
  --probe-file /var/www/VOTRE_SITE/hp-guard-probe.php \
  --apply
```

L’installateur :

1. Vérifie le build, le CLI, le PHP réellement servi par Apache et le profil de configuration.
2. Prépare une sonde et un jeton temporaires ; refuse d’écraser un fichier existant.
3. Sauvegarde la configuration dans `/var/backups/hp-guard/<transaction>/` et place le module sous `/opt/hp-guard/3.1.0-fork2/<empreinte>/`.
4. Arrête Apache, crée son nouvel INI, vérifie la configuration et redémarre le service.
5. Contrôle le `.so` chargé, son empreinte et les hooks actifs par une requête HTTP administrative.
6. Retire la sonde et le jeton, puis conserve l’état et les journaux de la transaction.

Un échec après le début du changement déclenche un retour arrière. Une installation identique déjà observée évite un nouveau redémarrage. Le script refuse une ancienne configuration étrangère ou modifiée, un pool FPM actif de la branche ciblée, un runtime différent, ainsi que les écarts au profil strict (`memory_limit=-1`, retour au parseur natif multibyte). Il ne modifie pas automatiquement ces réglages.

Une ancienne installation `fork1` n’est pas écrasée. Pour la remplacer, planifier le retour arrière de sa transaction puis construire/installer `fork2`. Un ancien manifeste n’est pas réutilisable avec cette révision.

Options utiles : `--php /chemin/php7.4`, `--ini-file /chemin/conf.d/99-hp-guard.ini`, `--web-group www-data`. Les valeurs Debian par défaut sont documentées dans [PROCEDURE.txt](PROCEDURE.txt).

#### Retour arrière

Utiliser la transaction affichée par l’installateur :

```sh
sudo python3 tools/install_php74.py rollback \
  --transaction /var/backups/hp-guard/TRANSACTION \
  --apply
```

Le retour arrière retire uniquement l’INI créé par cette transaction et redémarre Apache. Il refuse d’effacer une modification administrateur ultérieure. Les sauvegardes et le binaire conservé permettent l’analyse ; le reste de la configuration n’est pas restauré aveuglément.

## Limites et effets

- Le module intervient par des callbacks, **après certaines opérations internes du moteur**. Il ne remplace pas l’allocateur Zend ; les remises à zéro restent parfois plus tardives que dans le correctif officiel.
- `mbstring.encoding_translation=On` entraîne un retour au parseur natif. Le profil strict de l’installateur et du vérificateur refuse ce cas.
- Un OOM intercepté termine le worker et peut couper la réponse HTTP courante. Des temporaires d’upload peuvent rester ; leur expiration doit être gérée hors de ce chemin d’erreur.
- Une empreinte cohérente ou un symbole détecté ne constitue pas une certification du correctif complet. Le build et le checkout exécutés avec `sudo` doivent provenir d’une source de confiance.

Le [rétroportage officiel pour PHP 7.4](https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2) reste la référence de remédiation. Les réserves détaillées figurent dans [AUDIT.txt](AUDIT.txt). Aucun gain de couverture complète des deux CVE n’est annoncé sur la seule base des tests.

## Tests et rapports

- Module `fork2` : **103 contrôles PHP 7.3.33 et 103 contrôles PHP 7.4.33** sur Debian 10/mod_php ; 10 000 cas d’arithmétique mémoire pour chacun des deux parseurs.
- Installateur : transactions, échecs, nettoyage, préservation des fichiers existants et retour arrière testés ; rapports dans [audit/](audit/).
- Les laboratoires sont jetables, sans réseau externe ni port publié. Aucun exploit RCE ni test de panne n’est envoyé à un serveur de production.
- Pour l’installateur en conteneur, Apache et les fichiers sont réels ; `systemctl` est remplacé par une simulation utilisant `apache2ctl`. Le comportement d’une unité systemd de production reste à vérifier sur clone.

```sh
python3 -m unittest discover -s test -p 'test_*.py' -v
python3 tools/lab_php74.py --help
python3 tools/lab_php73.py --help
python3 tools/lab_installer.py --help
```

Windows, FPM, ZTS et les branches autres que 7.3/7.4 ne font pas partie du profil validé. Pour l’extension expérimentale, aucun binaire précompilé approuvé n’est distribué. Conserver tout le répertoire `tools/` : les points d’entrée 7.3 et 7.4 partagent des contrôles internes.

## Paquets de remplacement du moteur PHP

Les [outils de paquets DEB](packaging/php-core-debs/PROCEDURE.txt) préparent et vérifient des remplacements du moteur pour PHP 7.3/7.4, Debian 10/11 et Ubuntu 20.04/22.04, amd64/arm64. Ils utilisent les sources corrigées du fournisseur, indépendamment de ce module expérimental. Les livraisons sont organisées en huit archives par OS et architecture, chacune contenant les deux branches. Une livraison complète exige 16 lots validés : 21 contrôles par lot, correspondance des empreintes des moteurs installés avec les `.deb`, et vérification des sources corrigées avant/après compilation locale. Deux tests de remplacement depuis les PHP stock vérifient aussi la conservation des INI et de Redis.

Le plan d’installation ne change aucun service et sélectionne les paquets PHP déjà installés ; ses 22 tests couvrent les erreurs de plate-forme, les empreintes, les remplaçants manquants et les rapports de tests modifiés. Apache/mod_php, CLI et FPM sont inclus ; LiteSpeed est exclu des reconstructions Debian 10/Ubuntu 20.04. Les deux CVE sont la portée du correctif, sans renouvellement du support général de ces versions anciennes. Les archives validées et leurs sommes SHA256 sont destinées aux Releases de ce dépôt, qui reste privé.

## Origine et licences

Dérivé de [HOSTED-POWER/php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard). L’historique Git est conservé. Module d’origine : [MIT](LICENSE). Copies du parseur : [PHP License 3.01](PHP-LICENSE.txt). [UPSTREAM_README.md](UPSTREAM_README.md) conserve la documentation historique de l’amont.
