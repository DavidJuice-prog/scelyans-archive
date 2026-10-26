# Installer l'archiveur sur le collecteur Oracle — À NE LANCER QU'APRÈS ACCORD EXPLICITE

Rien de ce fichier n'a été exécuté. Aucune commande ne touche aux fichiers, à la configuration ni aux services de
TRACKYZZ : l'archiveur lit `/var/lib/trackyzz` et n'écrit que dans `/var/lib/archiveur`.

## 1. Copier les fichiers (depuis le PC, PowerShell)

```powershell
scp C:\Users\lumia\ARCHIVE_PROJET\archiveur\archiveur.py C:\Users\lumia\ARCHIVE_PROJET\archiveur\deploy\archiveur.service C:\Users\lumia\ARCHIVE_PROJET\archiveur\deploy\archiveur.timer C:\Users\lumia\ARCHIVE_PROJET\archiveur\deploy\archiveur.conf.exemple trackyzz:~/
```

## 2. Installer (sur le serveur)

```bash
sudo useradd --system --home-dir /var/lib/archiveur --create-home --shell /usr/sbin/nologin archiveur
sudo install -d -o root -g root -m 755 /opt/archiveur
sudo install -o root -g root -m 644 ~/archiveur.py /opt/archiveur/archiveur.py
sudo install -d -o root -g archiveur -m 750 /etc/archiveur
sudo install -o root -g archiveur -m 640 ~/archiveur.conf.exemple /etc/archiveur/archiveur.conf
sudo install -m 644 ~/archiveur.service ~/archiveur.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

## 3. Premier passage à la main, puis vérification

```bash
sudo systemctl start archiveur.service          # reprise du passé depuis le 09/10 : quelques minutes
journalctl -u archiveur -n 5 --no-pager
sudo -u archiveur python3 /opt/archiveur/archiveur.py verifier --config /etc/archiveur/archiveur.conf
```

Attendu : « archive intègre », `incidents: []`, chaque jour terminé concorde avec TRACKYZZ.

## 4. Mise en route automatique (toutes les 5 minutes)

```bash
sudo systemctl enable --now archiveur.timer
```

Retour en arrière (n'efface aucune donnée) : `sudo systemctl disable --now archiveur.timer`.

## 5. Plus tard, avec un accord séparé : ancrage OpenTimestamps et RFC 3161

Installe le client officiel OpenTimestamps dans un environnement propre à l'archiveur (téléchargement depuis PyPI),
puis renseigne `ots` et `tsa_url` dans `/etc/archiveur/archiveur.conf` (relu à chaque passage) :

```bash
sudo python3 -m venv /opt/archiveur/venv
sudo /opt/archiveur/venv/bin/pip install opentimestamps-client==0.7.2
#   ots     = /opt/archiveur/venv/bin/ots
#   tsa_url = https://freetsa.org/tsr
```
