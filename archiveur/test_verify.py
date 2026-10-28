"""Tests de verify.py (vérificateur public) sur des maillons produits par le vrai adn.py, réseau simulé.

    python -m unittest -v test_verify
"""
import contextlib, gzip, io, json, os, shutil, tempfile, unittest, unittest.mock, urllib.error
from pathlib import Path

import adn
import archiveur as ar
import test_adn
import verify
from test_archiveur import FauxHorodateurs

J1, J2 = test_adn.J1, test_adn.J2
SITE = Path.home() / "trackyzz-site-depot" / "adn"


def injoignable(url, timeout=10):
    """Sources Bitcoin simulées qui confirment le bloc des faux gènes (hash bb…) ; tout le reste hors ligne."""
    if "/block-height/" in url:
        return "bb" * 32
    raise urllib.error.URLError("hors ligne (test)")


def lancer(*args, http=injoignable):
    sortie = io.StringIO()
    with unittest.mock.patch.object(verify, "http_get_json", http), contextlib.redirect_stdout(sortie):
        code = verify.main(list(args))
    return code, sortie.getvalue()


class MaillonsReels(unittest.TestCase):
    """J1 et J2 scellés par le vrai adn.py (gènes simulés + vrai gène tours), feuilles comprises."""

    @classmethod
    def setUpClass(cls):
        class Fabrique(test_adn.TestADN):               # définie ici : jamais collectée comme série de tests
            def runTest(self):
                pass
        cls.f = Fabrique()
        cls.f.setUp()
        fin = cls.f.jours(J1, J2)
        tours = lambda c, j, n: {**test_adn.faux_genes(c, j, n), "tours": adn.gene_tours(c, j)}
        adn.executer(cls.f.conf, now_s=fin, horo=FauxHorodateurs(), genes=tours)
        cls.d = cls.f.dest / "adn"

    @classmethod
    def tearDownClass(cls):
        cls.f.tearDown()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def copie(self, *noms):
        for n in noms:
            shutil.copy(self.d / n, self.tmp / n)
            os.chmod(self.tmp / n, 0o666)
        return str(self.tmp / noms[0])

    def test_maillon_complet_hors_ligne(self):
        m = self.copie(f"adn-{J2}.json", f"adn-{J1}.json", f"feuilles-{J2}.txt.gz")
        code, out = lancer(m)
        self.assertEqual(code, 0, out)
        self.assertIn("feuilles : ", out)
        self.assertRegex(out, r"racine recalculée sur les \d+ feuilles : identique")
        self.assertIn("feuille veille recalculée depuis racine_veille", out)
        self.assertIn("correspond bien à la racine du maillon précédent", out)
        self.assertIn(f"adn-{J1}.json", out)                              # veille trouvée à côté
        self.assertIn("(+ tours)", out)
        self.assertNotIn("\033[", out)                                     # pas de couleurs dans un fichier

    def test_feuille_modifiee_echec(self):
        m = self.copie(f"adn-{J2}.json", f"adn-{J1}.json")
        lignes = gzip.decompress((self.d / f"feuilles-{J2}.txt.gz").read_bytes()).decode().splitlines()
        h = lignes[100].rsplit(" ", 1)[1]
        lignes[100] = lignes[100][:-64] + ("1" if h[0] == "0" else "0") + h[1:]
        f = self.tmp / "autre.txt"
        f.write_text("\n".join(lignes) + "\n", encoding="ascii")
        code, out = lancer(m, "--feuilles", str(f))
        self.assertEqual(code, 2)
        self.assertIn("racine recalculée DIFFÉRENTE", out)

    def test_gene_publie_modifie_detecte_par_les_feuilles(self):
        m = self.copie(f"adn-{J2}.json", f"adn-{J1}.json", f"feuilles-{J2}.txt.gz")
        p = Path(m)
        p.write_text(p.read_text("utf-8").replace('"hauteur":1', '"hauteur":7'), encoding="utf-8")
        code, out = lancer(m)
        self.assertEqual(code, 2)
        self.assertIn("feuille gene bloc différente de la valeur publiée", out)

    def test_veille_absente_puis_telechargee(self):
        m = self.copie(f"adn-{J2}.json")
        code, out = lancer(m)
        self.assertEqual(code, 0)
        self.assertIn(f"maillon de la veille ({J1}) introuvable", out)       # ATTENTION, jamais ECHEC
        veille = (self.d / f"adn-{J1}.json").read_text("utf-8")
        vues = []

        def site(url, timeout=10):
            vues.append(url)
            if url == verify.ADN_URL.format(jour=J1):
                return veille
            return injoignable(url)
        code, out = lancer(m, http=site)
        self.assertEqual(code, 0)
        self.assertIn(verify.ADN_URL.format(jour=J1), vues)
        self.assertIn("correspond bien à la racine du maillon précédent", out)

    def test_veille_d_un_autre_jour_ou_fichier_fourni_absent(self):
        m = self.copie(f"adn-{J2}.json")
        code, out = lancer(m, m, m)                                        # « veille » = le maillon lui-même
        self.assertEqual(code, 2)
        self.assertIn(f"porte le jour {J2}, et non {J1}", out)
        code, out = lancer(m, m, str(self.tmp / "absent.json"))
        self.assertEqual(code, 2)
        self.assertIn("fichier introuvable", out)

    def test_jour_veille_qui_n_est_pas_la_veille(self):
        m = self.copie(f"adn-{J2}.json")
        p = Path(m)
        p.write_text(p.read_text("utf-8").replace(f'"jour_veille":"{J1}"', '"jour_veille":"2026-10-01"'), encoding="utf-8")
        code, out = lancer(m)
        self.assertEqual(code, 2)
        self.assertIn("n'est pas la veille", out)

    def test_premier_maillon(self):
        m = self.copie(f"adn-{J1}.json")
        code, out = lancer(m)
        self.assertEqual(code, 0)
        self.assertIn("premier maillon de la chaîne", out)


class GeneTours(unittest.TestCase):
    BASE = {"statut": "mesure", "source": "releves scelles du jour", "seuil_retard_s": 180,
            "minutes_sans_bloc": 3, "plages_sans_bloc": ["09:08-09:09", "13:00"],
            "minutes_en_retard": 1, "plages_en_retard": ["09:06"], "retard_max_s": 200,
            "oracles_perdus": 1, "creneaux_oracles_perdus": ["13:00"]}

    def statut(self, tours):
        d = {"genes": {} if tours is None else {"tours": tours}}
        with contextlib.redirect_stdout(io.StringIO()) as s:
            r = verify.verifier_gene_tours(d)
        return r, s.getvalue()

    def test_incidents_affiches_sans_echec(self):
        r, out = self.statut(dict(self.BASE))
        self.assertIs(r, True)
        self.assertIn("3 minute(s) sans aucun bloc (UTC) : 09:08-09:09, 13:00", out)
        self.assertIn("ce n'est pas une falsification", out)

    def test_jour_sans_incident(self):
        t = dict(self.BASE, minutes_sans_bloc=0, plages_sans_bloc=[], minutes_en_retard=0, plages_en_retard=[],
                 retard_max_s=0, oracles_perdus=0, creneaux_oracles_perdus=[])
        r, out = self.statut(t)
        self.assertIs(r, True)
        self.assertIn("aucun tour manqué", out)

    def test_comptes_incoherents_echec(self):
        for faux in ({"minutes_sans_bloc": 2}, {"oracles_perdus": 0}, {"plages_en_retard": []},
                     {"retard_max_s": 100}, {"plages_sans_bloc": "09:08"}):
            r, _ = self.statut(dict(self.BASE, **faux))
            self.assertIs(r, False, faux)

    def test_absent_ou_indisponible(self):
        self.assertIsNone(self.statut(None)[0])
        self.assertIsNone(self.statut({"statut": "indisponible", "raison": "x"})[0])


class Couleurs(unittest.TestCase):
    def test_jamais_dans_un_fichier_ni_avec_no_color(self):
        self.assertFalse(verify.activer_couleurs(io.StringIO()))

        class Terminal(io.StringIO):
            def isatty(self):
                return True
        with unittest.mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(verify.activer_couleurs(Terminal()))
        with unittest.mock.patch.object(verify, "COULEURS", False):
            self.assertEqual(verify._c(92, "[OK]"), "[OK]")
        with unittest.mock.patch.object(verify, "COULEURS", True):
            self.assertEqual(verify._c(92, "[OK]"), "\033[92m[OK]\033[0m")


@unittest.skipUnless((verify.TRACKYZZ_DEFAUT / "app" / "ancrage.py").exists() and SITE.exists(),
                     "dossier TRACKYZZ ou dépôt du site absent")
class OpenTimestampsSansInstallation(unittest.TestCase):
    JOUR = "2026-10-20"

    def setUp(self):
        self.lib = verify.bibliotheque_ots()
        self.assertIsNotNone(self.lib)
        lire, BBHA, _ = self.lib
        f = lire(SITE / f"adn-{self.JOUR}.json.bitcoin.ots")
        self.racines = {a.height: m[::-1].hex() for m, a in f.timestamp.all_attestations() if isinstance(a, BBHA)}

    def mempool(self, racine):
        def http(url, timeout=10):
            if "/block-height/" in url:
                return "hash-du-bloc"
            return json.dumps({"merkle_root": racine})
        return http

    def verifier(self, json_path, racine):
        with unittest.mock.patch.object(verify, "http_get_json", self.mempool(racine)), \
                contextlib.redirect_stdout(io.StringIO()) as s:
            r = verify.verifier_opentimestamps(str(json_path), str(SITE / f"adn-{self.JOUR}.json.bitcoin.ots"))
        return r, s.getvalue()

    def test_origine_de_la_bibliotheque(self):
        try:
            import opentimestamps  # noqa: F401
            self.assertIn("installée", self.lib[2])
        except ImportError:
            self.assertIn("ancrage.py", self.lib[2])                       # aucune installation sur ce PC
        self.assertIsNone(verify.bibliotheque_ots(tempfile.gettempdir()) if "ancrage" in self.lib[2] else None)

    def test_vrai_ots_confirme_puis_alterations_refusees(self):
        (h, racine), = self.racines.items()
        r, out = self.verifier(SITE / f"adn-{self.JOUR}.json", racine)
        self.assertIs(r, True, out)
        self.assertIn(f"attestation Bitcoin confirmée au bloc {h}", out)
        r, out = self.verifier(SITE / f"adn-{self.JOUR}.json", "00" * 32)
        self.assertIs(r, False)
        with tempfile.TemporaryDirectory() as d:
            faux = Path(d) / f"adn-{self.JOUR}.json"
            faux.write_bytes((SITE / f"adn-{self.JOUR}.json").read_bytes().replace(b'"jour"', b'"jour" '))
            r, out = self.verifier(faux, racine)
        self.assertIs(r, False)
        self.assertIn("a été modifié depuis son scellement", out)


if __name__ == "__main__":
    unittest.main()
