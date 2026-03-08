# Vorschläge aus Codebasis-Review

## 1) Aufgabe: Tippfehler/Benennungsfehler in CLI-Hilfe korrigieren
**Problem:** In der Hilfe wird der Befehl als `network-transparency` angezeigt. Das ist inkonsistent zur Projekt-/Assembly-Benennung `NetworkTransparency` und kann für Nutzer wie ein Tippfehler wirken.

**Betroffene Stelle:** `src/NetworkTransparency/Program.cs` (`PrintHelp()`).

**Vorschlag:**
- Entweder den tatsächlichen Binärnamen dynamisch ausgeben (z. B. via `AppDomain.CurrentDomain.FriendlyName`) oder die Hilfe an die reale Startweise angleichen (`dotnet run --project ... -- <command>`).

**Akzeptanzkriterien:**
- Hilfe zeigt einen ausführbaren, konsistenten Aufruf.
- README und CLI-Hilfe verwenden dieselbe Befehlsform.

## 2) Aufgabe: Programmierfehler in `CliOptions.Parse` beheben
**Problem:** `CliOptions` verwendet `init`-Properties, die in `Parse()` nach `new CliOptions()` gesetzt werden. Das ist in C# nicht zulässig und führt zu einem Compilerfehler (CS8852).

**Betroffene Stelle:** `src/NetworkTransparency/Program.cs` (`CliOptions`).

**Vorschlag:**
- Variante A: `init` auf `set` ändern.
- Variante B (sauberer): während des Parsens lokale Variablen sammeln und am Ende per Objektinitialisierung ein `CliOptions`-Objekt erzeugen.

**Akzeptanzkriterien:**
- Projekt kompiliert ohne CS8852.
- Vorhandenes Verhalten der Argumentverarbeitung bleibt erhalten.

## 3) Aufgabe: Dokumentations-Unstimmigkeit beheben
**Problem:** Die README-Sektion „Repository layout“ nennt nur `src/NetworkTransparency` und `scripts/`, obwohl ein Testprojekt unter `src/NetworkTransparency.Tests` existiert.

**Betroffene Stelle:** `README.md` („Repository layout“).

**Vorschlag:**
- Layout um das Testprojekt ergänzen.
- Optional: kurze Erklärung, was dort getestet wird.

**Akzeptanzkriterien:**
- README spiegelt die tatsächliche Struktur des Repositories wider.
- Neue Entwickler finden den Testcode direkt.

## 4) Aufgabe: Tests verbessern (Klassifizierungslogik)
**Problem:** Aktuell werden nur service-basierte, case-insensitive Klassifizierungen getestet. DNS-basierte Pfade und Prioritäten/Präzedenz sind ungetestet.

**Betroffene Stelle:** `src/NetworkTransparency.Tests/ClassifierTests.cs`.

**Vorschlag:**
- Zusätzliche Tests für:
  - DNS-Heuristiken (`windowsupdate`, `update.microsoft`, `telemetry`, `data.microsoft`).
  - Priorität von Service-basierten Regeln gegenüber DNS-Treffern.
  - Fallback auf `Other` bei nicht passenden Eingaben.

**Akzeptanzkriterien:**
- Tests decken alle wesentlichen Entscheidungszweige in `Classifier.Classify` ab.
- Änderungen an Heuristiken verursachen nachvollziehbare Testfehler statt stiller Regressionen.
