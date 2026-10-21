# hp_uploadprogress_guard — fork expérimental pour PHP 7.4.33

Dépôt privé d’étude, dérivé de [HOSTED-POWER/php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard), commit `85fdda078eaccc94e3c8e7dce64f51d99f4c8dd5`.
Version du module : **3.1.0-fork1**. Ne pas assimiler cette extension au correctif complet du moteur PHP.

Le profil étudié est **Linux, PHP 7.4.33 NTS non-debug, Apache mod_php/prefork**.
Les anciens fichiers binaires et le workflow Windows de l’amont ont été retirés de cette branche : reconstruire le module pour le PHP cible. L’historique et les licences de l’amont sont conservés.

## Ce qui a changé

- Arrêt immédiat quand une erreur d’allocation atteint le callback, y compris pendant le code applicatif et sur un débordement de taille d’allocation.
- Aucune tentative de parcourir la table des uploads dans ce chemin d’erreur : elle peut être incomplète. Des fichiers temporaires peuvent rester après cet arrêt.
- Réinitialisation des pointeurs SAPI libérés **avant** le callback de désactivation suivant.
- En PHP 7.4, réponse HTTP 413 et abandon des données partielles pour dépassement du nombre de parties, de la taille POST déclarée ou réellement lue, et du budget mémoire du parseur.
- Calcul du budget mémoire sans débordement de `size_t`.
- Refus d’un mode inconnu et du profil ZTS non corrigé ; sélection systématique du parseur correspondant à la branche de compilation.
- Diagnostic `hp_uploadprogress_guard_status()` dans le worker réel et sonde administrative temporaire protégée par jeton.

## Limites de sécurité

L’extension **n’intercepte pas directement l’allocateur Zend**. Par exemple, `zend_error_va_list()` peut traiter un état d’exception avant d’appeler le callback sur lequel repose cette mitigation. Les remises à zéro de fin de requête restent plus tardives que celles du correctif interne. Des tests réussis ne prouvent pas la couverture de tous les producteurs et consommateurs de la seconde CVE.

Avec `mbstring.encoding_translation=On`, le module repasse par le parseur natif ; la sonde refuse ce cas dans son profil strict. Un autre module peut aussi remplacer les points d’accroche : le diagnostic vérifie leur identité dans le worker observé.

Le [rétroportage officiel PHP 7.4](https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2) reste la référence. La détection d’un symbole du correctif par le module est un indice, pas une attestation de l’intégralité des sources/binaries.

## Construction et essai sur clone

Lire [PROCEDURE.txt](PROCEDURE.txt) avant déploiement. La compilation ne requiert pas root et n’installe rien :

```sh
python3 tools/build_php74.py \
  --php /usr/bin/php7.4 \
  --phpize /usr/bin/phpize7.4 \
  --php-config /usr/bin/php-config7.4 \
  --output /var/tmp/hp-guard-build
```

Les trois outils doivent correspondre à la même installation PHP 7.4.33. Le script vérifie l’API des en-têtes, le chargement du nouveau module et les symboles glibc ; il refuse un binaire nécessitant une glibc plus récente que celle de Debian 10.

## Validation reproductible

Le laboratoire n’accepte aucune cible distante. Il utilise des conteneurs jetables sans réseau externe ni port publié. Les seules pannes provoquées sont des allocations bornées et des entrées de formulaire dans ces workers privés ; aucun exploit de RCE n’est exécuté.

```sh
python3 -m unittest discover -s test -p test_headroom.py -v

docker pull php:7.4-apache-buster@sha256:54ab36b44088c9baa82213e8bbb54802e1c12e620afbfbf64f41e2e9b8f01211
python3 tools/lab_php74.py --output /var/tmp/hp-guard-lab \
  --image php:7.4-apache-buster@sha256:54ab36b44088c9baa82213e8bbb54802e1c12e620afbfbf64f41e2e9b8f01211
```

Le laboratoire reconstruit aussi l’amont d’origine pour comparaison : garder l’historique Git, ou récupérer le commit de référence. `--python-runtime /chemin/prefixe-python-portable` ajoute le test du vérificateur HTTP à l’intérieur des conteneurs ; il attend `bin/python3` et un runtime compatible avec leur glibc.

Les résultats datés et leur périmètre figurent dans [AUDIT.txt](AUDIT.txt) et `audit/`. Les versions Windows, ZTS, FPM et les autres branches PHP ne font pas partie de la validation de ce fork.

## Licences

Le module d’origine est sous licence MIT : [LICENSE](LICENSE). Les copies du parseur PHP sont soumises à la [PHP License 3.01](PHP-LICENSE.txt). `UPSTREAM_README.md` conserve la documentation historique de l’amont ; ses affirmations de couverture ne sont pas une certification de ce fork.
