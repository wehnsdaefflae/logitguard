# LogitGuard

**Eine Sicherheitsschranke im Dekodierschritt lokaler Sprachmodelle.**

Ein Sprachmodell unterscheidet nicht zwischen der Anweisung des Betreibers und dem Text,
den es gerade verarbeitet. Wer eine Rechnung, eine Bewerbung oder eine Mail an eine
Behörde schickt, kann darin einen Befehl verstecken. Die verbreitete Gegenmaßnahme ist ein
zweites Modell, das mitliest und bewertet — angreifbar mit denselben Mitteln wie das
erste.

LogitGuard setzt eine Stelle früher an. Vor jedem Wort berechnet ein Sprachmodell
Wahrscheinlichkeiten über sein Vokabular. Wer dort eingreift, muss nichts erkennen: Ein
Token, dessen Wahrscheinlichkeit auf null gesetzt ist, kann nicht erzeugt werden.

> **Stand: Prinzipbeweis.** Dieses Repository zeigt den Mechanismus an einem
> Spielzeug-Vokabular, ohne Modell und ohne GPU. Der produktive Teil — Regel-Compiler,
> Rust-Maskenmaschine über PyO3, Adapter für `HuggingFace Transformers`, `vLLM` und
> `llama.cpp`, `FastAPI`-Proxy — ist Gegenstand der Bewerbung beim Prototype Fund,
> Jahrgang 03.

## Ausprobieren

Keine Abhängigkeiten, Python 3.11 genügt:

```
python3 logitguard.py            # Vorführung
python3 logitguard.py --selftest # Tests
```

## Was die Vorführung zeigt

Ausgabe eines echten Durchlaufs (14.10.2026):

```
Regel: erlaubte Domains = api.intern, cdn.intern · verbotene Senke = send(

1) Das Modell will eine erlaubte Adresse schreiben:
   -> GET https:// api.intern /status
2) Das Modell will exfiltrieren — evil.example ist nicht erlaubt:
   -> POST https:// <eos> /daten
   evil.example wurde nicht erzeugt. Statt der Zieladresse kam das
   zweitbeste erlaubte Token (<eos>) — die Anfrage bleibt unvollständig,
   und genau das ist gewollt: kein Abfluss, auch nicht teilweise.
3) Markierte Eingabedaten dürfen nicht in send( :
   -> send( <eos>
   'geheim' stammt aus unsicherer Eingabe und ist in der Senke gesperrt.
4) Rückfallebene — bleibt nichts erlaubt, wird abgebrochen:
   kontrollierter Abbruch: keine erlaubte Fortsetzung

Prinzip gezeigt: Die Schranke wirkt im Dekodierschritt, nicht danach.
```

Im zweiten Fall *will* das simulierte Modell `evil.example` schreiben — dieses Token hat
das höchste Logit. Es entsteht trotzdem nicht. Kein Filter greift danach ein; die
Alternative war nie verfügbar.

## Wie es funktioniert

Eine Regel nennt, was erlaubt ist:

```python
regel = Regel(
    erlaubte_domains=frozenset({"api.intern", "cdn.intern"}),
    verbotene_senken=frozenset({"send("}),
)
```

Daraus entsteht pro Dekodierschritt eine Maske über dem Vokabular. Drei Dinge prüft der
Prinzipbeweis:

| | Regelart | Was verhindert wird |
|---|---|---|
| 1 | Zieladressen | Nach einem Schema (`https://`) darf nur eine freigegebene Domain folgen |
| 2 | Herkunftsmarkierung | Ein Token aus unsicherer Eingabe darf nicht in einen Funktionsaufruf wandern |
| 3 | Rückfallebene | Bleibt nichts Erlaubtes übrig, bricht die Generierung ab statt zu raten |

Die Maske wird **vor** der Tokenwahl berechnet, allein aus Regel und Automatenzustand. Im
produktiven Entwurf ist sie ein Bitvektor in Vokabulargröße, erzeugt in Rust; der
Aufschlag pro Token liegt damit deutlich unter einer Millisekunde und ist unabhängig von
der Antwortlänge.

## Herkunft

LogitGuard ist das Gegenstück zu
[LLMSecTest](https://github.com/wehnsdaefflae/llmsectest) (Prototype Fund, Jahrgang 02):
Dort suche ich Lücken, hier sollen sie geschlossen werden. Von 52 mit LLMSecTest
geprüften Anwendungen gaben 32 ein hinterlegtes Geheimnis heraus, weil im Eingabetext
danach gefragt wurde. Befunde aus LLMSecTest liegen als SARIF vor und sollen künftig
direkt zu LogitGuard-Regeln werden.

## Lizenz

MIT — siehe [LICENSE](LICENSE).
