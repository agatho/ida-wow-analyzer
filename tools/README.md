# Wire-Extraktionswerkzeuge — Build 12.1.0.69382

Pipeline zur Rekonstruktion des JAM-Drahtformats aus `wow_dump.bin.i64`.
Alle Skripte laufen headless: `idat.exe -A "-SC:/dumps/<skript>.py" C:\dumps\wow_dump.bin.i64`.

## Empfangsseite (SMSG)

| Skript | Zweck |
|---|---|
| `dump_family_wire.py` | Familien-Dispatcher + Reader transitiv (Tiefe 3) dekompilieren. `TC_FAMS=0x65,0x67,...` |
| `dump_fam45.py` | Sonderfall `0x45` (903 Cases, 62-KB-Dispatcher) |
| `dump_fam45_readers.py` | Massenlauf über die Reader-/Dispatch-Paare von `0x45` |
| `find_small_dispatchers.py` | Familien ≤ 5 Opcodes: GetMsgId-Thunk → Vtable-Slot → Vtable-Basis → Dispatcher |
| `find_opcode_sites.py` | Opcode-Immediates im Code suchen (Vergleichsketten statt Sprungtabelle) |

## Sendeseite (CMSG)

| Skript | Zweck |
|---|---|
| `dump_cmsg_family.py` | Immediate-Site → Writer-Funktion, transitiv. `TC_CFAMS=0x43,0x3D,...` |
| `dump_subwriters.py` | Nachlauf: gezielt einzelne Serializer, die `dump_cmsg_family.py` an seiner 700-Funktionen-Grenze verloren hat. Zielliste in `C:/dumps/subwriter_targets.json` |
| `dump_primitives.py` | die drei RVA-Bänder der Lese-/Schreibprimitiven vollständig dekompilieren |

## Konsumenten

| Skript | Zweck |
|---|---|
| `dump_hook_registry.py` | Handler-Hook-Tabelle scannen + Registrare dekompilieren; löst `global = handler` auch bei NULL-Zeigern auf |
| `dump_handlers_w1.py` | gezielte Handler-Dekompilierung + zweite Hook-Tabelle (Event-Objekte) |
| `dump_4D_deep.py`, `dump_4D_hooks.py` | Erstanalyse Familie `0x4D` (Vtables, RTTI-Versuch, Hook-Umfeld) |

## Auswertung (läuft lokal, nicht in IDA)

| Skript | Zweck |
|---|---|
| `famtab2.py <fam>` | SMSG-Opcode-Tabelle: Case, Name, Hook-Zustand, Handler, Sniff, Lesefolge |
| `cmsgtab.py <fam>` | CMSG-Opcode-Tabelle: Writer, Schreibfolge, Sniff |
| `show.py <fam> c<case>|<funcname>` | einzelne Case-Bodies / Funktionen ausgeben |
| `showc.py <fam> <funcname>` | dasselbe für CMSG-Dumps |
| `wseq.py <writer-rva>` | Schreibfolge einer Writer-Funktion; kennt die Bit-Leitern, erkennt eingebettete Bit-Akkumulatoren und klammert Schleifenrümpfe als `[…]*` |

## Primitive (Build 12.1.0.69382, RVA)

Vollständig aufgelöst — Herleitung und Beweis in `BEFUND_wire_primitiven_69382.md`.

**Feste Breite, lesen:** `0x35AF050` u8 · `0x35AF0F0` u16 · `0x35AF190` u32 · `0x35AF230` u64 ·
`0x35AF730` Rohzeiger · `0x35AF7D0` ReadBytes · `0x35AF9E0` Rest ·
`0x36012B0` ReadPackedGuid (→ `0x3602D40`) · `0x347D750` ReadDynString (Länge inkl. NUL)

**Feste Breite, schreiben:** `0x35AFB40` u8 · `0x35AFBC0` **u16** · `0x35AFC40` u32 ·
`0x35AFCC0` **float** · `0x35AFD40` **double** · `0x35AFDC0` u64 ·
`0x35AFE40` WriteBytes (`0x35B01C0` ist ein Thunk darauf) · `0x35B01D0` Puffer reservieren ·
`0x36012E0` WritePackedGuid

**Bit-Sektionen, lesen:** `0x5D4FD0` 2 · `0x5D5080` 3 · `0x5D5130` 4 · `0x5D51E0` 5 ·
`0x5D5290` 6 · `0x5D5340` 7 · `0x613AC0` 24 · `0x5D53F0` Flush

**Bit-Sektionen, schreiben:** `0x5D4A20` 2 · `0x5D4AE0` 3 · `0x5D4BA0` 4 · `0x5D4C60` 5 ·
`0x5D4D20` 6 · `0x5D4DE0` 7 · `0x613670` 24 · `0x5D4EA0` Flush

Ein einzelnes Bit hat **keine** eigene Funktion — `WriteBits(1)` ist immer eingebettet.

**Keine Draht-Operation:** `0x3543700` ist der Deallokator, nicht ein Array-Primitiv. Die
`T:X`-Angaben in den Lesefolgen stammen aus seinen `WowGetRawTypeName<X>`-Debug-Namen und
belegen den *Elementtyp* eines wachsenden Arrays — nicht eine Leseoperation. Ebenso ohne
Draht-Wirkung: `0x35AFA60`, `0x3542440`, `0x3542CB0`, `0x3542930`, `0x3542710`.

## Formatregeln

Siehe `BEFUND_ai_debug_kanal_4D_69382.md`, Abschnitt 3 — MSB-first-Bit-Sektionen mit Flush,
Stringlänge als `bits<ceil(log2(Puffergröße))>`, Array-Count an Deklarationsposition mit
Deferred-Payload, Packed-GUID identisch zu TrinityCores `ByteBuffer`.
