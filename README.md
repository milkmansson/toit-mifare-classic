# MIFARE Classic

MIFARE Classic cards (sectors, access bits, Crypto1 authentication) on top
of the [toit-nfc](https://github.com/milkmansson/toit-nfc) `Reader`/`Target`
interface. Works with any reader chip that exposes raw-frame access; see
below for what that excludes.

## Authentication is done entirely in software

Both reader chips commonly used with this package can run MIFARE Classic's
Crypto1 authentication in their own hardware: the MFRC522 has an `MFAuthent`
command, and the PN532's firmware runs it behind `InDataExchange`. This
package uses neither. All Crypto1 authentication here runs in software
(`src/crypto1.toit`), driven over a reader's raw ISO 14443-3 frames
(`RawFrameTarget` from toit-nfc).

Why:

- **A hardware fast path and a software path would both need maintaining,
  for no functional gain.** A chip's own `MFAuthent`-style command can't do
  nested authentication — it never exposes the raw nonce exchange once its
  internal crypto unit takes over. Nested authentication is required for
  Crypto1 key-recovery attacks (darkside, nested, mfkey-style), which is a
  planned feature of this package. Since the software path is needed
  anyway for that, keeping a separate hardware-only fast path for plain
  reads/writes would be pure added complexity, with two subtly different
  code paths to test and debug, for a speed difference that doesn't matter
  at MIFARE Classic's data rates.
- **It keeps the abstraction honest.** A reader-chip-native fast path only
  works on chips that have one shaped like MIFARE Classic's; it wouldn't
  generalize to other reader chips this family might add later. Software
  Crypto1 over raw frames is the one thing that's actually portable across
  any raw-frame-capable reader.
- **It's what nested authentication and key recovery need anyway**, so
  building on it now means that feature has no separate integration step
  later.

The practical consequence: **this package only works with readers that
implement `RawFrameTarget`** (`ReaderCapabilities.supports-raw-frames`).
`toit-mfrc522` does; `toit-pn53x` does not, because the PN532 doesn't expose
raw frames at all — its firmware handles anticollision and framing
internally. A `ClassicCard` can still be constructed over a PN532 `Target`
to read blocks that don't need a key (eg. block 0), but `authenticate` will
throw a clear error rather than silently falling back to a hardware path
that wouldn't support key recovery.

## Status

`ClassicCard` (sectors, blocks, authenticate, read, write, dump,
`write-to-stdout`), `AccessBits` and `MifareException` are moved over from
`toit-mfrc522` and built against the `Reader`/`Target` interface. Crypto1
key recovery (darkside/nested/mfkey-style attacks against your own cards)
is a planned v1 feature, not yet implemented.
