# Vérification indépendante de la racine de Merkle

Ce document explique, en clair, comment la "racine" de chaque maillon ADN
est calculée, et donne un **second programme, écrit indépendamment**, que
n'importe qui peut utiliser pour vérifier que `archiveur.py` ne triche pas.

## Pourquoi un second programme ?

`archiveur.py` (publié dans ce dépôt) contient déjà les fonctions qui
calculent la racine de Merkle de chaque jour. Mais demander à quelqu'un de
vérifier un calcul avec le programme qui a produit ce même calcul n'apporte
aucune garantie : s'il y avait une erreur (ou une malhonnêteté) dans
`archiveur.py`, se vérifier soi-même ne la révélerait jamais.

`merkle_independant.py`, dans ce même dossier, est donc une **réécriture
complète et indépendante** des mêmes fonctions, à partir de la seule
spécification publique (ci-dessous) — sans importer une seule ligne
d'`archiveur.py`. Si les deux programmes donnent le même résultat sur les
mêmes données, c'est une vraie preuve, pas une simple relecture.

## La spécification (RFC 9162, SHA-256)

- **Feuille** : `SHA-256(0x00 || donnees)` — les octets exacts de la donnée
  (fichier, ligne, etc.), précédés d'un seul octet `0x00`.
- **Nœud** : `SHA-256(0x01 || gauche || droite)` — deux empreintes de 32
  octets, précédées d'un seul octet `0x01`.
- **Racine à 1 feuille** : c'est la feuille elle-même, non re-hachée.
- **Forme de l'arbre** : pas de duplication du dernier élément quand le
  nombre de feuilles est impair. Le sous-arbre de gauche est toujours de
  taille "ronde" (la plus grande puissance de 2 inférieure au total), le
  reste part à droite.

## Les feuilles d'un jour

Un jour complet compte **environ 21 000 feuilles** (21 007 le 26/10/2026).
Une feuille = un élément, dans cet ordre :

| Position | Type | Contenu haché |
|---|---|---|
| 0 | `veille` | `adn/1 veille <racine du maillon de la veille>` (`aucune` le premier jour) |
| 1 | `empreinte` | `adn/1 empreinte` + le fichier d'empreinte TRACKYZZ du jour, octet pour octet |
| 2 … | `releve HH` | `adn/1 releve` + **chaque ligne** du registre du jour (un bloc par paire et par minute, plus les cours et les oracles), `HH` = heure UTC d'écriture |
| puis | `incident` | `adn/1 incident` + `concerne AAAA-MM-JJ` + la ligne d'incident, telle qu'archivée |
| enfin | `gene <nom>` | `adn/1 gene <nom>` + la valeur du gène en JSON canonique (clés triées, sans espaces) |

Les préfixes exacts et le saut de ligne qui les suit sont décrits en tête de
[`adn.py`](./adn.py). Les relevés sont environ 1 440 par paire suivie et par
jour : ce ne sont **pas** 24 « relevés horaires » (une version précédente de
ce document le disait à tort).

### Les gènes

Jusqu'à sept gènes, toujours dans cet ordre : `code` (empreintes des
programmes), `horloge` (écart de l'horloge du serveur), `bloc` (dernier bloc
Bitcoin avant minuit UTC), `temoin`, `astra`, **`tours`** depuis le
28/10/2026, et **`bce`** (taux de change de la Banque centrale européenne).
Un nouveau gène s'ajoute toujours à la fin : les maillons plus anciens ont
4, 5 ou 6 gènes et restent valables tels quels.

Le gène `tours` décrit les **incidents de la collecte** du jour, recalculés
depuis les relevés scellés : minutes sans aucun bloc écrit, minutes de cours
écrites plus de 180 s après leur fin (rattrapées en retard), créneaux de
5 minutes sans lecture d'oracle. Un incident n'est pas une falsification :
c'est une trace honnête d'un trou, scellée le jour même au lieu d'être
cachée. Exemple de valeur :

```json
{"statut": "mesure", "minutes_sans_bloc": 1, "plages_sans_bloc": ["13:00"],
 "minutes_en_retard": 1, "plages_en_retard": ["12:57"], "retard_max_s": 200,
 "seuil_retard_s": 180, "oracles_perdus": 1, "creneaux_oracles_perdus": ["13:00"],
 "source": "releves scelles du jour"}
```

Le gène `bce` enregistre le **taux de change de référence officiel** de la
Banque centrale européenne pour le jour scellé, afin de pouvoir plus tard
convertir des cours en euros de façon vérifiable.

- **D'où vient le taux** : d'une source unique, la publication quotidienne
  de la BCE (`https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml`),
  mise en ligne vers 16 h (heure de Paris) les jours ouvrés. Aucun autre site,
  aucune estimation. Le fichier reçu est conservé tel quel, octet pour octet
  (`bce-AAAA-MM-JJ.xml`), et le gène contient son empreinte SHA-256, la date
  de publication indiquée par la BCE et le taux EUR/USD tel qu'il y est écrit.
- **Jours sans taux** : le week-end et les jours où la BCE ne publie pas
  (jours fériés), le gène vaut `sans_publication`, sans taux ; si la BCE n'a
  pas pu être jointe, il vaut `indisponible`. Le taux de la veille n'est
  **jamais** recopié.
- **Ce qu'il prouve** : le fichier de la BCE conservé n'a pas changé depuis
  le scellement, et il existait au plus tard au bloc Bitcoin de l'ancrage.
- **Ce qu'il ne prouve pas** : la BCE ne signe pas son fichier ; l'empreinte
  seule ne prouve donc pas qu'il vient d'elle. `verify.py` recoupe le taux
  avec le fichier historique publié par la BCE (`eurofxref-hist.xml`) : un
  écart y est signalé en ATTENTION, à vérifier à la main. C'est un taux de
  **référence** de la BCE, publié une fois par jour, pas un cours de marché :
  il ne dit rien des cours relevés par TRACKYZZ.

Exemple de valeur :

```json
{"statut": "mesure", "version": "bce/1", "date_publication": "2026-10-29",
 "eur_usd": "1.0832", "fichier": "bce/bce-2026-10-29.xml",
 "fichier_sha256": "…", "conserve_le": "2026-10-29T15:50:03Z",
 "source": "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"}
```

## Ce qui est publié

- `adn-AAAA-MM-JJ.json` : le maillon (racine, racine de la veille, comptes
  de feuilles, valeur des gènes), sur trackyzz.com. Ancré dans Bitcoin par
  OpenTimestamps (`.json.ots`, puis `.json.bitcoin.ots`).
- `feuilles-AAAA-MM-JJ.txt.gz` : **l'empreinte SHA-256 de chaque feuille**,
  dans l'ordre, dans un dépôt séparé par année (`scelyans-feuilles-<année>`,
  environ 0,9 Mo par jour). Disponible pour tous les jours depuis le premier
  maillon (09/10/2026). Format, une ligne par feuille après 4 lignes d'en-tête :

  ```
  adn-scelyans-feuilles/1
  jour 2026-10-26
  racine 29d34a5d22a700df9976ba896166f1072fd9636f5ec692b7b623156a10c1f05b
  feuilles 21007
  0 veille 928f27dce249fcb698601f5785d91616cfc0fdd257a45dc95f4b2a3be199bbe6
  1 empreinte d04848a1ee83be876d91f6dcec0e70c8d139061e4a2d7ebfea03283521683b04
  2 releve 00 d748f329c145a9144b1c2aa0d223372797b28cdf1dc4e6e09b60a5b1cf29e352
  …
  21006 gene astra f91287158c215c0844ab5d2d8102ab6e5d6de0b024c9fa8b12908553033d2eea
  ```

  (Ce jour-là, scellé avant le gène `tours`, la dernière feuille est le gène `astra`.)

- Le fichier d'empreinte TRACKYZZ du jour (dépôt `trackyzz-empreintes`).

Les fichiers BCE conservés (`bce-AAAA-MM-JJ.xml`) ne sont **pas encore**
publiés : en attendant, `verify.py` signale leur empreinte en ATTENTION
(non vérifiable), jamais en ECHEC.

**Aucun relevé ni aucun prix n'est publié.** Une empreinte SHA-256 ne permet
pas de retrouver la ligne hachée : chaque ligne contient, en plus des prix,
des empreintes et une signature impossibles à deviner. Avant chaque
publication, chaque ligne du fichier est contrôlée : tout ce qui n'est pas
« position, type, empreinte » est refusé.

## Ce que l'on peut vérifier seul

Avec les seuls fichiers publics, sans rien demander à TRACKYZZ :

1. **La racine** : recalculée sur les ~21 000 empreintes, elle doit être
   identique au champ `"racine"` du maillon.
2. **La feuille de la veille** : recalculée depuis `"racine_veille"`.
3. **Les feuilles des gènes** : recalculées depuis les valeurs publiées
   dans le maillon. Un gène modifié après coup ne redonne plus sa feuille.
4. **La feuille d'empreinte** : recalculée depuis le fichier d'empreinte
   TRACKYZZ publié.
5. **Les comptes** : autant de lignes `releve`, `incident` et `gene` que
   le maillon en annonce, positions continues de 0 à N−1.

Comme la racine est elle-même ancrée dans Bitcoin, personne (y compris
TRACKYZZ) ne peut changer après coup une seule de ces ~21 000 feuilles sans
que la racine change.

Ce que l'on ne peut **pas** vérifier seul : le contenu d'un relevé précis
(il contient des prix). Pour cela, TRACKYZZ remet sur demande une preuve
d'inclusion (`adn.py preuve`), vérifiable avec `adn.py verifier-preuve` et
le seul maillon publié.

## Utiliser les programmes

Trois façons, de la plus indépendante à la plus complète :

```bash
# 1. Ce programme seul (aucun code du projet) : vérifie l'implémentation, puis un vrai jour
python3 merkle_independant.py --autotest          # dont un arbre de 21 006 feuilles
python3 merkle_independant.py --feuilles feuilles-2026-10-26.txt.gz --adn adn-2026-10-26.json

# 2. Le programme du projet : racine, veille, gènes et empreinte TRACKYZZ
python3 adn.py verifier-feuilles --feuilles feuilles-2026-10-26.txt.gz --adn adn-2026-10-26.json \
        --empreinte 2026-10-26.txt

# 3. Le vérificateur public complet : bloc Bitcoin, OpenTimestamps, code, veille, gène tours, feuilles, gène bce
python3 verify.py adn-2026-10-26.json --feuilles feuilles-2026-10-26.txt.gz [--bce bce-2026-10-26.xml]
```

`verify.py` cherche le `.bitcoin.ots`, le maillon de la veille, le fichier
des feuilles et le fichier BCE à côté du maillon ; la veille est ensuite cherchée sur
trackyzz.com. Ce qu'il ne peut pas vérifier (pas d'internet, fichier
absent) est affiché en ATTENTION, jamais en ECHEC ; seule une contradiction
est un ECHEC. Pour OpenTimestamps, il utilise la bibliothèque
`opentimestamps` si elle est installée (`pip install opentimestamps-client`).

Résultat attendu (26/10/2026) : les trois programmes retrouvent la racine
`29d34a5d22a700df9976ba896166f1072fd9636f5ec692b7b623156a10c1f05b` sur
21 007 feuilles.

Code source : [`merkle_independant.py`](./merkle_independant.py),
[`adn.py`](./adn.py), [`verify.py`](./verify.py).
