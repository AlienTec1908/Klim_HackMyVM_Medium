# Klim - HackMyVM (Medium)

![Klim.png](Klim.png)

## Übersicht

*   **VM:** Klim
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Klim)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 06. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Klim_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Klim" zu erlangen. Der initiale Zugriff erfolgte über die Entdeckung von WordPress-Anmeldeinformationen, die mittels Steganographie in einem Bild auf der Webseite versteckt waren. Mit diesen Credentials wurde der WordPress-Admin-Bereich betreten und eine Theme-Datei (`404.php`) modifiziert, um eine Webshell zu platzieren und so Remote Code Execution (RCE) als Benutzer `www-data` zu erreichen. Die erste Rechteausweitung zum Benutzer `klim` gelang durch Ausnutzung einer unsicheren `sudo`-Regel, die es `www-data` erlaubte, ein Tool als `klim` auszuführen, um dessen privaten SSH-Schlüssel zu lesen. Die finale Eskalation zu Root erfolgte durch die Identifizierung und Ausnutzung eines schwachen SSH-Schlüssels für den Root-Benutzer, der auf die Debian OpenSSL Predictable PRNG Schwachstelle (CVE-2008-0166) zurückzuführen war.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wpscan`
*   `hydra`
*   `nikto`
*   `curl`
*   `stegseek`
*   `nc` (netcat)
*   `python3`
*   `stty`
*   `sudo`
*   `chmod`
*   `ssh`
*   `find`
*   `uname`
*   `env`
*   `ss`
*   `mysql`
*   `ssh-keygen`
*   `wget`
*   `tar`
*   `python2`
*   Standard Linux-Befehle (`cat`, `ls`, `cd`, `id`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Klim" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration (Port 80 - Wordpress):**
    *   IP-Adresse des Ziels (192.168.2.115) mit `arp-scan` identifiziert.
    *   `nmap`-Scan offenbarte SSH (Port 22, OpenSSH 7.9p1) und HTTP (Port 80, Apache 2.4.38).
    *   `gobuster` fand ein `/wordpress`-Verzeichnis auf Port 80.
    *   `wpscan` wurde auf die WordPress-Installation angewendet und identifizierte:
        *   WordPress Version 6.1.
        *   Theme "twentytwenty" Version 1.8 (veraltet).
        *   Benutzer `klim`.
    *   Brute-Force-Versuche auf das WordPress-Login für `klim` mit `wpscan` und `hydra` (auch gegen SSH) blieben erfolglos. SSH unterstützte keine Passwort-Authentifizierung.

2.  **Steganographie & Info Leak (WordPress Credentials):**
    *   Ein Bild (`image.jpg`, vermutlich von der WordPress-Seite) wurde mit `stegseek` und der `rockyou.txt`-Liste analysiert.
    *   Das Steghide-Passwort `ichliebedich` wurde gefunden.
    *   Eine versteckte Datei (`dump`, extrahiert als `image.jpg.out`) enthielt einen Netzwerk-Capture-Ausschnitt.
    *   Dieser Capture zeigte einen HTTP-POST-Request an `/wordpress/wp-login.php` mit den Credentials: `klim`:`ss7WhrrnnHZC#9bQn`.

3.  **RCE via Wordpress Theme Edit (Initial Access als `www-data`):**
    *   Login in das WordPress-Admin-Panel (`/wordpress/wp-admin/`) mit den gefundenen Credentials (`klim`:`ss7WhrrnnHZC#9bQn`).
    *   Über den Theme-Editor wurde die Datei `404.php` des aktiven Themes ("Twenty Nineteen") bearbeitet und eine PHP-Webshell (`system($_GET['cmd']);`) eingefügt.
    *   RCE als `www-data` wurde durch Aufrufen der modifizierten `404.php` mit dem `cmd`-Parameter bestätigt.
    *   Eine Reverse Shell wurde zum Angreifer-System (lauschender Netcat-Listener) als `www-data` aufgebaut. Die Shell wurde stabilisiert.

4.  **Privilege Escalation (von `www-data` zu `klim`):**
    *   In `/var/www/html/wordpress/wp-config.php` wurden die Datenbank-Credentials `wordpress_user:Tropicano123!` gefunden.
    *   `sudo -l` als `www-data` zeigte, dass der Befehl `/home/klim/tool` als Benutzer `klim` ohne Passwort ausgeführt werden durfte: `(klim) NPASSWD: /home/klim/tool`.
    *   Durch Ausführen von `sudo -u klim /home/klim/tool /home/klim/.ssh/id_rsa` wurde der private SSH-Schlüssel des Benutzers `klim` ausgelesen.

5.  **SSH Access (klim) & Enumeration:**
    *   Login per SSH als `klim` mit dem extrahierten privaten Schlüssel.
    *   `sudo -l` als `klim` erforderte ein Passwort.
    *   Die User-Flag wurde in `/home/klim/user.txt` gefunden.
    *   In `/opt/` wurde ein öffentlicher SSH-Schlüssel (`id_rsa.pub`) gefunden, der `root@klim` gehörte. Der Fingerprint wurde extrahiert.

6.  **Privilege Escalation (von `klim` zu `root` via Weak SSH Key):**
    *   Die Vermutung entstand, dass der Root-SSH-Schlüssel aufgrund der Debian OpenSSL Predictable PRNG Schwachstelle (CVE-2008-0166) schwach sein könnte.
    *   Das Archiv `5622.tar.bz2` (mit bekannten schwachen SSH-Schlüsseln) wurde von Exploit-DB heruntergeladen und entpackt.
    *   Ein Python-Skript (`opensslHack.py`) wurde verwendet, um die schwachen RSA-2048-Bit-Schlüssel aus dem Archiv gegen den SSH-Server des Ziels (als `root`) zu testen.
    *   Das Skript fand erfolgreich einen passenden privaten Schlüssel (`rsa/2048/54701a3b124be15d4c8d3cf2da8f0139-2005`).
    *   Login per SSH als `root` mit dem gefundenen schwachen privaten Schlüssel.
    *   Die Root-Flag wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Steganographie:** Verstecken von Informationen (hier: WordPress-Credentials in einem Netzwerk-Capture) in einer Bilddatei.
*   **WordPress Theme-Editor Missbrauch:** Ausnutzung der Berechtigung zum Bearbeiten von Theme-Dateien, um eine PHP-Webshell zu platzieren und RCE zu erlangen.
*   **Unsichere `sudo`-Regel:** Eine Regel erlaubte `www-data`, ein benutzerdefiniertes Tool als `klim` auszuführen, was zum Auslesen von dessen privatem SSH-Schlüssel missbraucht wurde, da das Tool als Dateileser fungierte.
*   **Debian OpenSSL Predictable PRNG (CVE-2008-0166):** Ausnutzung eines schwachen SSH-Schlüssels des Root-Benutzers, der aufgrund dieser alten Schwachstelle vorhersehbar generiert wurde. Dies ermöglichte den direkten SSH-Login als Root.
*   **Informationslecks:** WordPress-Datenbank-Credentials in `wp-config.php`.
*   **WordPress Enumeration:** Identifizierung von Benutzern, Themes und potenziellen Angriffsvektoren mittels `wpscan`.

## Flags

*   **User Flag (`/home/klim/user.txt`):** `2fbef74059deaea1e5e11cff5a65b68e`
*   **Root Flag (`/root/root.txt`):** `60667e12c8ea62295de82d053d950e1f`

## Tags

`HackMyVM`, `Klim`, `Medium`, `WordPress`, `Steganography`, `Theme Editor RCE`, `sudo Exploit`, `CVE-2008-0166`, `Weak SSH Key`, `Linux`, `Web`, `Privilege Escalation`
