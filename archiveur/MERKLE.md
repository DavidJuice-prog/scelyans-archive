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

Chaque jour, les feuilles sont, dans cet ordre : la racine de la veille, puis
l'empreinte TRACKYZZ du jour, puis chaque relevé horaire (24 au total), puis
les incidents du jour, puis jusqu'à 5 "gènes" (code, horloge, bloc Bitcoin,
témoin, ASTRA-M).

## Ce qui manque aujourd'hui pour une vérification 100% publique

Le fichier `adn-AAAA-MM-JJ.json` publié chaque jour contient la racine
(`"racine"`) mais **pas** les feuilles elles-mêmes — seulement un compteur
(`"feuilles": {"total": ..., ...}`). Recalculer la vraie racine d'un jour
réel suppose donc de disposer, en plus du maillon publié :

1. le fichier d'empreinte TRACKYZZ du jour (`empreintes/<jour>.txt`) ;
2. les 24 relevés horaires bruts de ce jour ;
3. les lignes d'incidents/trous concernant ce jour ;
4. les 5 gènes du jour.

Tant que ces éléments ne sont pas publiés (ou fournis au cas par cas), ce
programme ne peut être exercé que sur des exemples faits à la main — c'est
ce que fait `--autotest` : vérifier que l'implémentation est correcte, sans
dépendre de données réelles.

**Prochaine étape pour une transparence complète** : publier (ou documenter
où trouver) les relevés horaires et les empreintes quotidiennes, pour que
`merkle_independant.py --racine <feuille1> <feuille2> ...` puisse
reconstituer et vérifier la vraie racine d'un jour donné.

## Utiliser le programme

```bash
# Vérifie que l'implémentation elle-même est correcte (exemples faits main)
python3 merkle_independant.py --autotest

# Calcule la racine à partir de fichiers réels, dans le bon ordre
python3 merkle_independant.py --racine veille.txt empreinte.txt releve_00.txt ... --attendu <racine publiée en hex>
```

Code source : [`merkle_independant.py`](./merkle_independant.py).
