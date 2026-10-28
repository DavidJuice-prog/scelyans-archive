#!/usr/bin/env python3
"""
merkle_independant.py — Réimplémentation indépendante du Merkle ADN (Scelyans)

Pourquoi ce fichier existe
--------------------------
archiveur.py (publié sur github.com/DavidJuice-prog/scelyans-archive) contient
déjà les fonctions qui construisent l'arbre de Merkle de chaque maillon ADN
(feuille, noeud, racine_merkle, chemin_merkle, verifier_chemin). Mais un
auditeur qui veut vérifier que ces fonctions font bien ce qu'elles prétendent
faire ne devrait pas avoir à FAIRE CONFIANCE à ce code-là : il doit pouvoir
comparer son résultat à une SECONDE implémentation, écrite indépendamment, à
partir de la seule spécification publique (le docstring d'adn.py et le champ
"algorithme" des maillons : "RFC 9162 SHA-256 (feuille 0x00 || donnees,
noeud 0x01 || gauche || droite)").

C'est exactement ce que fait ce fichier : aucune dépendance à archiveur.py,
aucun import du projet, uniquement la bibliothèque standard Python.

Spécification (RFC 9162 §2.1, telle que déclarée par Scelyans)
----------------------------------------------------------------
- Hachage : SHA-256 partout.
- Feuille  : SHA-256(0x00 || donnees)                  — donnees = octets bruts
- Noeud    : SHA-256(0x01 || gauche || droite)          — gauche, droite = 32 octets
- Forme de l'arbre : pas d'arbre binaire équilibré classique avec duplication
  du dernier élément impair. La coupure gauche/droite au niveau n est
  toujours la plus grande puissance de 2 strictement inférieure à n
  (fonction _coupure). Le sous-arbre gauche est donc toujours de taille
  "ronde" (puissance de 2), et le reste va à droite. Un nœud non apparié
  à un niveau donné est simplement promu tel quel au niveau supérieur,
  jamais dupliqué.
- Racine à 1 feuille : la racine EST la feuille elle-même (pas re-hachée).
- Encodage : les valeurs sont manipulées en octets bruts (bytes) partout en
  interne ; seule la sérialisation finale (JSON, fichiers texte) utilise de
  l'hexadécimal minuscule (.hex()).

Les feuilles d'un jour réel
----------------------------
Une feuille par élément, dans cet ordre (voir adn.py) :
  1. la veille (« adn/1 veille <racine de la veille> »),
  2. l'empreinte TRACKYZZ du jour (empreintes/<jour>.txt),
  3. CHAQUE LIGNE du registre du jour (un bloc par paire et par minute,
     plus les cours et les oracles) : environ 21 000 feuilles par jour
     complet — et non 24 « relevés horaires » ;
  4. les incidents constatés ce jour-là,
  5. les gènes du jour : code, horloge, bloc, témoin, astra, et tours
     (incidents de la collecte, depuis le 28/10/2026).
Les relevés contiennent des prix : ils ne sont pas publiés. Ce qui est
publié, c'est feuilles-AAAA-MM-JJ.txt.gz : l'empreinte SHA-256 de chaque
feuille, une par ligne (« <position> <type> <empreinte> »). Ce script en
recalcule la racine (option --feuilles), sans aucun code du projet, et la
compare au champ "racine" du maillon publié.

Usage
-----
    python3 merkle_independant.py --autotest
        Fait tourner une batterie de tests sur des exemples faits à la main
        (y compris l'exemple à 3 feuilles documenté : racine =
        noeud(noeud(f0, f1), f2)) et affiche PASS/FAIL pour chacun.

    python3 merkle_independant.py --racine FICHIER1 FICHIER2 ...
        Calcule la racine de Merkle sur les fichiers donnés, dans l'ordre
        donné (chaque fichier = une feuille, ses octets exacts). Affiche la
        racine en hexadécimal minuscule, comparable au champ "racine" d'un
        maillon ADN si on lui a donné les bonnes feuilles dans le bon ordre.

    python3 merkle_independant.py --racine FICHIER1 ... --attendu HEX
        Comme ci-dessus, mais compare aussi au hex attendu et sort avec le
        code 0 (identique) ou 2 (différent).

    python3 merkle_independant.py --feuilles feuilles-AAAA-MM-JJ.txt.gz [--adn adn-AAAA-MM-JJ.json | --attendu HEX]
        Recalcule la racine d'un jour réel depuis les empreintes publiées de
        ses ~21 000 feuilles, et la compare à celle du maillon (code 0 ou 2).
"""

import sys
import gzip
import json
import re
import hashlib
import argparse


# ---------------------------------------------------------------------------
# Primitives (RFC 9162 §2.1)
# ---------------------------------------------------------------------------

def feuille(donnees: bytes) -> bytes:
    """SHA-256(0x00 || donnees) -> 32 octets bruts."""
    if not isinstance(donnees, (bytes, bytearray)):
        raise TypeError("feuille() attend des octets (bytes), pas du texte")
    return hashlib.sha256(b"\x00" + bytes(donnees)).digest()


def noeud(gauche: bytes, droite: bytes) -> bytes:
    """SHA-256(0x01 || gauche || droite) -> 32 octets bruts."""
    for nom, v in (("gauche", gauche), ("droite", droite)):
        if not isinstance(v, (bytes, bytearray)) or len(v) != 32:
            raise ValueError(f"{nom} doit être exactement 32 octets (un digest SHA-256)")
    return hashlib.sha256(b"\x01" + bytes(gauche) + bytes(droite)).digest()


def _coupure(n: int) -> int:
    """Plus grande puissance de 2 strictement inférieure à n (n >= 2)."""
    if n < 2:
        raise ValueError("_coupure() suppose n >= 2")
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def racine_merkle(feuilles: list) -> bytes:
    """
    Racine de l'arbre de Merkle d'une liste de feuilles déjà hachées
    (chacune = 32 octets, résultat de feuille()).

    Pas de duplication du dernier élément impair : le sous-arbre gauche est
    toujours de taille ronde (puissance de 2), le reste va à droite.
    """
    n = len(feuilles)
    if n == 0:
        raise ValueError("racine_merkle() ne gère pas une liste vide")
    for i, f in enumerate(feuilles):
        if not isinstance(f, (bytes, bytearray)) or len(f) != 32:
            raise ValueError(f"feuilles[{i}] doit être 32 octets (sortie de feuille())")
    if n == 1:
        return bytes(feuilles[0])
    k = _coupure(n)
    return noeud(racine_merkle(feuilles[:k]), racine_merkle(feuilles[k:]))


def chemin_merkle(m: int, feuilles: list) -> list:
    """
    Chemin d'inclusion (liste de frères, du bas de l'arbre vers le haut)
    pour la feuille d'indice m (0-based) dans la liste donnée.
    """
    n = len(feuilles)
    if not (0 <= m < n):
        raise ValueError("indice m hors limites")
    if n == 1:
        return []
    k = _coupure(n)
    if m < k:
        return chemin_merkle(m, feuilles[:k]) + [racine_merkle(feuilles[k:])]
    else:
        return chemin_merkle(m - k, feuilles[k:]) + [racine_merkle(feuilles[:k])]


def verifier_chemin(index: int, taille: int, f: bytes, chemin: list, racine: bytes) -> bool:
    """
    Vérifie qu'une feuille f, d'indice `index` parmi `taille` feuilles,
    appartient bien à l'arbre dont la racine est `racine`, via le `chemin`
    d'inclusion fourni (RFC 9162 §2.1.3.2).
    """
    if index >= taille:
        return False
    for i, p in enumerate(chemin):
        if not isinstance(p, (bytes, bytearray)) or len(p) != 32:
            raise ValueError(f"chemin[{i}] doit être 32 octets")

    fn, sn, r = index, taille - 1, bytes(f)
    for p in chemin:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = noeud(bytes(p), r)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = noeud(r, bytes(p))
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == bytes(racine)


# ---------------------------------------------------------------------------
# Auto-test : exemples faits à la main, aucune dépendance aux données réelles
# ---------------------------------------------------------------------------

def _h(donnees: bytes) -> bytes:
    return feuille(donnees)


def autotest() -> bool:
    ok_total = True

    def check(nom, condition):
        nonlocal ok_total
        statut = "PASS" if condition else "FAIL"
        if not condition:
            ok_total = False
        print(f"[{statut}] {nom}")

    # 1 feuille : la racine est la feuille elle-même, non re-hachée.
    f0 = _h(b"exemple")
    check("racine a 1 feuille == la feuille elle-meme", racine_merkle([f0]) == f0)

    # 2 feuilles : racine = noeud(f0, f1)
    f1 = _h(b"deuxieme feuille")
    attendu2 = noeud(f0, f1)
    check("racine a 2 feuilles == noeud(f0, f1)", racine_merkle([f0, f1]) == attendu2)

    # 3 feuilles (exemple documenté) : racine = noeud(noeud(f0, f1), f2)
    f2 = _h(b"troisieme feuille")
    attendu3 = noeud(noeud(f0, f1), f2)
    check("racine a 3 feuilles == noeud(noeud(f0,f1), f2) [exemple documente]",
          racine_merkle([f0, f1, f2]) == attendu3)

    # 4 feuilles : racine = noeud(noeud(f0,f1), noeud(f2,f3))
    f3 = _h(b"quatrieme feuille")
    attendu4 = noeud(noeud(f0, f1), noeud(f2, f3))
    check("racine a 4 feuilles == arbre complet equilibre",
          racine_merkle([f0, f1, f2, f3]) == attendu4)

    # 5 feuilles : coupure(5) = 4, donc racine = noeud(racine([f0..f3]), f4)
    f4 = _h(b"cinquieme feuille")
    attendu5 = noeud(attendu4, f4)
    check("racine a 5 feuilles == noeud(racine(f0..f3), f4)",
          racine_merkle([f0, f1, f2, f3, f4]) == attendu5)

    # Vérification croisée feuille par feuille, sur les 5 feuilles ci-dessus.
    feuilles5 = [f0, f1, f2, f3, f4]
    racine5 = racine_merkle(feuilles5)
    for i in range(5):
        chemin = chemin_merkle(i, feuilles5)
        resultat = verifier_chemin(i, 5, feuilles5[i], chemin, racine5)
        check(f"chemin d'inclusion verifie pour la feuille d'indice {i} (sur 5)", resultat)

    # Un chemin altéré doit être rejeté.
    chemin0 = chemin_merkle(0, feuilles5)
    if chemin0:
        chemin_altere = list(chemin0)
        chemin_altere[0] = _h(b"valeur bidon")
        resultat = verifier_chemin(0, 5, feuilles5[0], chemin_altere, racine5)
        check("un chemin d'inclusion altere est bien rejete", resultat is False)

    # Une feuille erronée doit être rejetée.
    resultat = verifier_chemin(0, 5, _h(b"pas la bonne feuille"), chemin0, racine5)
    check("une feuille erronee est bien rejetee", resultat is False)

    # Taille réelle d'un jour ADN : 21 006 feuilles (veille, empreinte, ~21 000
    # lignes du registre, gènes). La racine récursive doit égaler un calcul
    # par niveaux (nœud sans frère promu tel quel), et les chemins d'inclusion
    # doivent tenir aux bords et au milieu de l'arbre.
    n = 21006
    feuilles_jour = [_h(f"feuille {i}".encode()) for i in range(n)]
    racine_jour = racine_merkle(feuilles_jour)
    check(f"racine sur {n} feuilles == calcul par niveaux", racine_jour == _racine_par_niveaux(feuilles_jour))
    indices = [0, 1, 2, n // 2, 16383, 16384, n - 2, n - 1]
    check(f"chemins d'inclusion sur {n} feuilles (indices {indices})",
          all(verifier_chemin(i, n, feuilles_jour[i], chemin_merkle(i, feuilles_jour), racine_jour) for i in indices))
    check(f"une feuille déplacée sur {n} change la racine",
          racine_merkle(feuilles_jour[:5] + [feuilles_jour[6], feuilles_jour[5]] + feuilles_jour[7:]) != racine_jour)

    # Lecture d'un fichier de feuilles publié (format feuilles-AAAA-MM-JJ.txt.gz).
    texte = "\n".join(["adn-scelyans-feuilles/1", "jour 2026-10-15", f"racine {attendu5.hex()}", "feuilles 5"]
                      + [f"{i} releve 00 {f.hex()}" for i, f in enumerate(feuilles5)]) + "\n"
    check("racine lue depuis un fichier de feuilles == racine attendue",
          racine_fichier_feuilles(gzip.compress(texte.encode()))[0] == attendu5)
    try:
        racine_fichier_feuilles(texte.replace("1 releve", "2 releve").encode())
        check("un fichier de feuilles hors d'ordre est refuse", False)
    except ValueError:
        check("un fichier de feuilles hors d'ordre est refuse", True)

    return ok_total


def _racine_par_niveaux(feuilles: list) -> bytes:
    """Seconde façon de calculer la même racine : on assemble les paires niveau par niveau."""
    h = list(feuilles)
    while len(h) > 1:
        h = [noeud(h[i], h[i + 1]) if i + 1 < len(h) else h[i] for i in range(0, len(h), 2)]
    return h[0]


def racine_fichier_feuilles(octets: bytes):
    """(racine, en-tête) d'un fichier feuilles-AAAA-MM-JJ.txt(.gz). Positions contrôlées une à une ; le nombre de
    feuilles annoncé doit être le nombre lu. ValueError sinon."""
    if octets[:2] == b"\x1f\x8b":
        octets = gzip.decompress(octets)
    lignes = octets.decode("ascii").splitlines()
    if len(lignes) < 5 or lignes[0] != "adn-scelyans-feuilles/1":
        raise ValueError("ce n'est pas un fichier de feuilles ADN")
    tete = dict(l.split(" ", 1) for l in lignes[1:4])
    feuilles = []
    for k, l in enumerate(lignes[4:]):
        m = re.fullmatch(r"(\d+) [a-z]+(?: [a-z0-9]+)? ([0-9a-f]{64})", l)
        if not m or int(m.group(1)) != k:
            raise ValueError(f"ligne {k + 5} illisible ou hors d'ordre")
        feuilles.append(bytes.fromhex(m.group(2)))
    if int(tete.get("feuilles", -1)) != len(feuilles):
        raise ValueError(f"{len(feuilles)} feuilles lues, {tete.get('feuilles')} annoncées")
    return racine_merkle(feuilles), tete


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Réimplémentation indépendante du Merkle ADN (Scelyans), RFC 9162 SHA-256."
    )
    parser.add_argument("--autotest", action="store_true",
                         help="Lance la batterie de tests sur des exemples faits à la main.")
    parser.add_argument("--racine", nargs="+", metavar="FICHIER",
                         help="Calcule la racine de Merkle sur ces fichiers, dans l'ordre donné "
                              "(chaque fichier = une feuille).")
    parser.add_argument("--attendu", metavar="HEX",
                         help="Racine attendue en hexadécimal, à comparer avec --racine ou --feuilles.")
    parser.add_argument("--feuilles", metavar="FICHIER",
                         help="Fichier feuilles-AAAA-MM-JJ.txt.gz publié : recalcule la racine du jour.")
    parser.add_argument("--adn", metavar="MAILLON",
                         help="Maillon adn-AAAA-MM-JJ.json publié : sa racine est la valeur attendue.")
    args = parser.parse_args()

    if args.feuilles:
        with open(args.feuilles, "rb") as fh:
            racine, tete = racine_fichier_feuilles(fh.read())
        print(f"Racine calculee ({tete['feuilles']} feuilles, jour {tete.get('jour')}) : {racine.hex()}")
        attendu = args.attendu
        if args.adn:
            with open(args.adn, encoding="utf-8") as fh:
                maillon = json.load(fh)
            if maillon.get("jour") != tete.get("jour"):
                print("CONCLUSION : le maillon et le fichier de feuilles ne sont pas du même jour.")
                sys.exit(2)
            attendu = maillon.get("racine")
        if attendu:
            identique = racine == bytes.fromhex(attendu.strip().lower())
            print("CONCLUSION : identique a la valeur attendue." if identique
                  else "CONCLUSION : DIFFERENTE de la valeur attendue — ne pas faire confiance.")
            sys.exit(0 if identique else 2)
        sys.exit(0)

    if args.autotest:
        ok = autotest()
        print()
        print("RESULTAT : tout est passe." if ok else "RESULTAT : au moins un test a échoué.")
        sys.exit(0 if ok else 1)

    if args.racine:
        feuilles = []
        for chemin_fichier in args.racine:
            with open(chemin_fichier, "rb") as fh:
                feuilles.append(feuille(fh.read()))
        racine = racine_merkle(feuilles)
        print(f"Racine calculee ({len(feuilles)} feuilles) : {racine.hex()}")
        if args.attendu:
            attendu_bytes = bytes.fromhex(args.attendu.strip().lower())
            if racine == attendu_bytes:
                print("CONCLUSION : identique a la valeur attendue.")
                sys.exit(0)
            else:
                print("CONCLUSION : DIFFERENTE de la valeur attendue — ne pas faire confiance.")
                sys.exit(2)
        sys.exit(0)

    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
