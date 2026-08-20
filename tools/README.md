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
| `dump_cmsg_family.py` | Immediate-Site → Writer-Funktion, transitiv |

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

## Primitive (Build 12.1.0.69382, RVA)

**Lesen:** `0x35AF050` u8 · `0x35AF0F0` u16 · `0x35AF190` u32 · `0x35AF230` u64 ·
`0x36012B0` PackedGuid · `0x35AF7D0` Bytes · `0x35AF730` Rohzeiger ·
`0x5D5340` ReadBits(7) · `0x5D5080` ReadBits(3) · `0x613AC0` ReadBits(24) ·
`0x347D750` DynString (Länge inkl. NUL)

**Schreiben:** `0x35AFC40` u32 (erster Aufruf = Opcode) · `0x35AFB40` u8 · `0x35AFDC0` u64 ·
`0x36012E0` PackedGuid · `0x35B01C0` Bytes · `0x5D4EA0` FlushBits · `0x613670` WriteBits(24)

## Formatregeln

Siehe `BEFUND_ai_debug_kanal_4D_69382.md`, Abschnitt 3 — MSB-first-Bit-Sektionen mit Flush,
Stringlänge als `bits<ceil(log2(Puffergröße))>`, Array-Count an Deklarationsposition mit
Deferred-Payload, Packed-GUID identisch zu TrinityCores `ByteBuffer`.
