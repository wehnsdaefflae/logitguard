"""logitguard — Prinzipbeweis: Sicherheitsregeln als Maske über dem Vokabular.

Dieses Modul zeigt das Prinzip von LogitGuard an einem Spielzeug-Vokabular, ohne
Sprachmodell und ohne GPU: Eine Regel wird vorab in einen Automaten übersetzt, dessen
Zustände Bitmasken über dem Vokabular sind. Bei jedem Dekodierschritt wird die Maske auf
die Logits gelegt, bevor das nächste Token gewählt wird. Ein verbotenes Token erhält
Wahrscheinlichkeit Null und kann deshalb nicht erzeugt werden — es wird nicht nachträglich
erkannt und gefiltert.

Gezeigt werden drei Dinge:

1. **Zieladressen.** Nur freigegebene Domains dürfen entstehen. Das Modell "will"
   `evil.example` schreiben und kann es nicht.
2. **Herkunftsmarkierung (Taint).** Tokens, die aus unsicherer Eingabe stammen, dürfen
   nicht in einen Funktionsaufruf wandern.
3. **Rückfallebene.** Bleibt nach der Maskierung kein Token übrig, bricht die Generierung
   kontrolliert ab, statt irgendetwas zu erzeugen.

Ausführen:   python3 logitguard.py
Tests:       python3 -m pytest tests/ -q   (oder python3 logitguard.py --selftest)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

# --- Ein Spielzeug-Vokabular. Ein echtes Modell hat 32k-128k Tokens; am Prinzip
#     ändert das nichts, die Maske ist dort ein Bitvektor derselben Länge. -----------

VOCAB: list[str] = [
    "<eos>", "GET", "POST", "http://", "https://",
    "api.intern", "cdn.intern", "evil.example", "pastebin.example",
    "/daten", "/status", "?q=", "send(", "log(", "geheim", "hallo", "welt",
]
TOKEN_ID = {t: i for i, t in enumerate(VOCAB)}


class Abbruch(Exception):
    """Keine erlaubte Fortsetzung — die Generierung bricht kontrolliert ab."""


@dataclass
class Regel:
    """Eine Sicherheitsregel, wie sie in LogitGuard als Pydantic-Modell beschrieben wird.

    erlaubte_domains: nur diese dürfen nach einem Schema-Token stehen.
    verbotene_senken: Funktionen, in die markierte (unsichere) Daten nicht fließen dürfen.
    """

    erlaubte_domains: frozenset[str] = frozenset()
    verbotene_senken: frozenset[str] = frozenset()


@dataclass
class Zustand:
    """Der Automatenzustand während des Dekodierens."""

    letztes: str | None = None
    in_senke: bool = False
    markiert: frozenset[str] = frozenset()
    erzeugt: list[str] = field(default_factory=list)


SCHEMATA = ("http://", "https://")
DOMAINS = ("api.intern", "cdn.intern", "evil.example", "pastebin.example")


def maske(regel: Regel, z: Zustand) -> list[bool]:
    """Erlaubt-Maske über dem Vokabular für den NÄCHSTEN Schritt.

    Das ist der Kern: die Entscheidung fällt VOR der Tokenwahl, allein aus Regel und
    Zustand — nicht aus dem fertigen Text.
    """
    erlaubt = [True] * len(VOCAB)

    for i, tok in enumerate(VOCAB):
        # 1. Nach einem Schema darf nur eine freigegebene Domain folgen.
        if z.letztes in SCHEMATA and tok in DOMAINS:
            if tok not in regel.erlaubte_domains:
                erlaubt[i] = False
        # 2. Eine Domain darf nur direkt nach einem Schema stehen.
        if tok in DOMAINS and z.letztes not in SCHEMATA:
            erlaubt[i] = False
        # 3. In einer verbotenen Senke kein markiertes Token.
        if z.in_senke and tok in z.markiert:
            erlaubt[i] = False

    return erlaubt


def schritt(regel: Regel, z: Zustand, logits: list[float]) -> str:
    """Ein Dekodierschritt: maskieren, dann das wahrscheinlichste erlaubte Token wählen."""
    if len(logits) != len(VOCAB):
        raise ValueError(f"logits müssen {len(VOCAB)} Werte haben, nicht {len(logits)}")

    m = maske(regel, z)
    # Ein Token ist nur Kandidat, wenn die Regel es erlaubt UND das Modell es für
    # möglich hält. -inf heißt: kommt für das Modell nicht in Frage.
    kandidaten = [(w, i) for i, (w, gut) in enumerate(zip(logits, m))
                  if gut and w != float("-inf")]
    if not kandidaten:
        raise Abbruch("keine erlaubte Fortsetzung")

    _, best = max(kandidaten)
    tok = VOCAB[best]

    z.letztes = tok
    z.erzeugt.append(tok)
    if tok in regel.verbotene_senken:
        z.in_senke = True
    return tok


def erzeuge(regel: Regel, wunsch: list[str], markiert: frozenset[str] = frozenset(),
            max_schritte: int = 24) -> list[str]:
    """Simuliert ein Modell, das `wunsch` schreiben WILL, unter der Schranke `regel`.

    Der Wunsch wird als Logits ausgedrückt: das gewünschte Token bekommt den höchsten
    Wert. Was die Maske verbietet, kann es trotzdem nicht werden.
    """
    z = Zustand(markiert=markiert)
    for ziel in wunsch[:max_schritte]:
        logits = [0.0] * len(VOCAB)
        logits[TOKEN_ID[ziel]] = 10.0          # das Modell "will" dieses Token
        # Ein zweitbester Kandidat, damit eine echte Wahl existiert:
        logits[TOKEN_ID["<eos>"]] = 1.0
        schritt(regel, z, logits)
    return z.erzeugt


def vorfuehrung() -> int:
    regel = Regel(
        erlaubte_domains=frozenset({"api.intern", "cdn.intern"}),
        verbotene_senken=frozenset({"send("}),
    )

    print("Regel: erlaubte Domains = api.intern, cdn.intern · verbotene Senke = send(")
    print()

    print("1) Das Modell will eine erlaubte Adresse schreiben:")
    got = erzeuge(regel, ["GET", "https://", "api.intern", "/status"])
    print("   ->", " ".join(got))
    assert "api.intern" in got

    print("2) Das Modell will exfiltrieren — evil.example ist nicht erlaubt:")
    got = erzeuge(regel, ["POST", "https://", "evil.example", "/daten"])
    print("   ->", " ".join(got))
    assert "evil.example" not in got, "die Schranke hat versagt"
    print("   evil.example wurde nicht erzeugt. Statt der Zieladresse kam das")
    print("   zweitbeste erlaubte Token (<eos>) — die Anfrage bleibt unvollständig,")
    print("   und genau das ist gewollt: kein Abfluss, auch nicht teilweise.")

    print("3) Markierte Eingabedaten dürfen nicht in send( :")
    got = erzeuge(regel, ["send(", "geheim"], markiert=frozenset({"geheim"}))
    print("   ->", " ".join(got))
    assert "geheim" not in got
    print("   'geheim' stammt aus unsicherer Eingabe und ist in der Senke gesperrt.")

    print("4) Rückfallebene — bleibt nichts erlaubt, wird abgebrochen:")
    z = Zustand(letztes="https://")
    streng = Regel(erlaubte_domains=frozenset())
    logits = [0.0] * len(VOCAB)
    for d in DOMAINS:
        logits[TOKEN_ID[d]] = 10.0
    for i, t in enumerate(VOCAB):
        if t not in DOMAINS:
            logits[i] = float("-inf")
    try:
        schritt(streng, z, logits)
        print("   FEHLER: hätte abbrechen müssen")
        return 1
    except Abbruch as e:
        print(f"   kontrollierter Abbruch: {e}")

    print()
    print("Prinzip gezeigt: Die Schranke wirkt im Dekodierschritt, nicht danach.")
    return 0


def selftest() -> int:
    ok = True

    def expect(c: bool, m: str) -> None:
        nonlocal ok
        if not c:
            ok = False
            print(f"FAIL: {m}", file=sys.stderr)

    regel = Regel(erlaubte_domains=frozenset({"api.intern"}),
                  verbotene_senken=frozenset({"send("}))

    expect("api.intern" in erzeuge(regel, ["GET", "https://", "api.intern"]),
           "erlaubte Domain kommt durch")
    expect("evil.example" not in erzeuge(regel, ["GET", "https://", "evil.example"]),
           "verbotene Domain wird nicht erzeugt")
    expect("cdn.intern" not in erzeuge(regel, ["GET", "https://", "cdn.intern"]),
           "nicht freigegebene Domain wird nicht erzeugt")
    expect("geheim" not in erzeuge(regel, ["send(", "geheim"],
                                   markiert=frozenset({"geheim"})),
           "markiertes Token nicht in der Senke")
    expect("geheim" in erzeuge(regel, ["log(", "geheim"],
                               markiert=frozenset({"geheim"})),
           "ausserhalb der Senke ist das Token erlaubt")
    expect("api.intern" not in erzeuge(regel, ["GET", "api.intern"]),
           "Domain ohne Schema wird nicht erzeugt")

    try:
        schritt(regel, Zustand(), [0.0])
        expect(False, "falsche Logit-Laenge muss auffallen")
    except ValueError:
        pass

    print("selftest: PASS" if ok else "selftest: FAIL", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else vorfuehrung())
