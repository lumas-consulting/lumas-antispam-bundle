# lumas-antispam
Contao Antispam includes honeypot, Session und IP Blocking, stop words detection for different languages, time based blocking.



LUMAS AntiSpam Bundle for Contao

Eine einfache aber wirkungsvolle, vollständig integrierte Anti-Spam-Erweiterung für Contao 5  .
Das Bundle schützt Formulare vor Spam, Bots und Missbrauch – ohne externe Dienste, granular konfigurierbar.

## Features
Formularbasierter Spam-Schutz
- Zeitbasierte Heuristik (Mindest-Ausfüllzeit)
- Inhaltsanalyse
- Mindestlänge
- Stopwort-Erkennung mit Sprachauswahl
- Maximal erlaubte Links
- Honeypot-Feld
- Session-basierte Sperren
- Globale IP-Reputation
- Eskalierende Sperrdauer
- Whitelist & Hard-Block
- Zentrales Spam-Log
- Root-Page-Defaults + Formular-Overrides
- Backend-Module zur Verwaltung
- Composer / Packagist ready

## Installation
composer require lumas/antispam-bundle

Danach:
- Contao Manager / Setup ausführen
- Cache leeren
- Backend neu laden

Die Datenbanktabellen werden automatisch angelegt.

## Backend-Module
Nach der Installation erscheint im Backend eine eigene Rubrik:
- LUMAS AntiSpam
- IP-Sperrliste
- Blockierte IPs
- Reputation / Eskalationsstufe
- Whitelist & permanente Sperren
- Spam-Log
- Alle blockierten Formularversuche
- Grund, Formular, Details (JSON)

Benutzer müssen die Module ggf. in den Backend-Rechten aktivieren.

## Konfiguration
- Globale Defaults (Root-Seite)
Auf der Root-Seite können Standardwerte für die gesamte Domain definiert werden:
IP-Reputations-Sperre aktivieren
Globale IP-Sperrdauer
Mindest-Ausfüllzeit
Session-Sperrdauer
Sprache für Stopwort-Analyse
Text-Mindestlänge
Max. Links
Stopwort-Schwelle
Diese Werte gelten für alle Formulare, sofern sie nicht überschrieben werden.

## Formular-spezifische Einstellungen
In jedem Formular:
1.) AntiSpam aktivieren
2.) Formulartemplate ändern form_wrapper_lumas_antispam.html5
3.) Falls Text-Area Feld im Formular verwendet wird, dieses "message", "nachricht" oder "comment" nennen damit Textprüfung greift.

Optionale Overrides:
- IP-Sperre aktivieren/deaktivieren
- Zeit- & Text-Heuristik
- Sprache
- Nicht gesetzte Werte erben automatisch die Root-Defaults.

## Funktionsweise (vereinfacht)

Formular wird aufgerufen → Startzeit wird gespeichert

Beim Absenden:
- Honeypot prüfen
- Mindest-Zeit von Seitenaufruf bis Absenden prüfen
- Textlänge & Sprache prüfen

Bei Verstoß:
- Formular wird nach x-tem Fehlversuch blockiert (Session Sperre)
- Session-Fehlversuche gezählt
- IP-Negativ Reputation erhöht -> 24h Sperre für IP
- Log-Eintrag geschrieben

Ab bestimmten Schwellen:
- Session-Sperre
- Globale IP-Sperre mit eskalierender Dauer
- Eskalationslogik (IP-Reputation)
Verstöße	IP-Sperre
5	24 h
10	120 h
15	240 h
20	360 h
+120 h je 5 weitere

## Template-Integration

Formular-Wrapper-Template:
- form_wrapper_lumas_antispam.html5

Funktionen:
- Automatisches Honeypot-Feld
- Zeitstempel (form_start)
- AJAX-Support
- Automatisches Scrollen bei Fehlern

## Kompatibilität
- Contao 5.3+
- Contao 6.x
- PHP 8.2 – 8.4
- Keine externen APIs

## work in progress
Weitere Ideen Änderungen gerne hier oder in eigener Branch. 

MIT License
© LUMAS Consulting