// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import nfc.card-type show CardType
import nfc.crc show crc-a check-crc-a
import nfc.reader show Target RawFrameTarget
import .access-bits show AccessBits
import .crypto1 show MifareCryptoReader
import .mifare-exception show MifareException

// https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf

/**
A MIFARE Classic card, built on top of a $Target from any toit-nfc reader.

Authentication (and, later, key recovery) is done entirely in software,
  using Crypto1 run over raw ISO 14443-3 frames; see this package's
  README for why. This means $authenticate (and therefore $read/$write of
  any block that needs a key) requires a reader that implements
  $RawFrameTarget; a reader without raw-frame access (such as the PN532)
  can still be used to read unencrypted blocks (eg. block 0), but not to
  authenticate.
*/
class ClassicCard:
  /**
  The first block of a Mifare card contains the manufacturer data.
  It is generally read-only (except for "magic" cards).
  */
  static MANUFACTURER-BLOCK ::= 0

  static MIFARE-READ_ ::= 0x30
  static MIFARE-WRITE_ ::= 0xA0
  static ACK_ ::= #[0x0A]
  static AUTHENT-KEY-A-COMMAND_ ::= 0x60
  static AUTHENT-KEY-B-COMMAND_ ::= 0x61

  /** Default (factory/transport configuration) key for Mifare Classic cards. */
  static DEFAULT-KEY := #[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

  target/Target
  crypto_/MifareCryptoReader? := null

  constructor .target:

  /** The UID of the underlying $target. */
  uid -> ByteArray: return target.uid

  /** The $CardType of the underlying $target. */
  type -> int: return target.type

  /**
  Authenticates for $block using $key.

  Returns whether authentication succeeded.

  Throws if $target does not implement $RawFrameTarget, since this
    authentication is always done in software over raw frames; see this
    package's README.
  */
  authenticate --block/int key/ByteArray=DEFAULT-KEY --is-key-a/bool=true -> bool:
    if target is not RawFrameTarget:
      throw "MIFARE Classic authentication requires a raw-frame-capable reader (see ReaderCapabilities.supports-raw-frames); not supported by this reader"
    raw := target as RawFrameTarget

    successful := false
    try:
      // Crypto1 only works with a 4-byte UID; for longer UIDs, only the
      // last 4 (cascade-level) bytes are used.
      crypto-uid := uid.size == 4 ? uid : uid[uid.size - 4 ..]
      if not crypto_:
        crypto_ = MifareCryptoReader --uid=crypto-uid
      crypto_.start-authentication --key=key

      // See MIFARE Classic EV1 1K spec, section 9.1.
      command-bytes := #[is-key-a ? AUTHENT-KEY-A-COMMAND_ : AUTHENT-KEY-B-COMMAND_, block]
      crc := crc-a command-bytes
      command-bytes += #[crc & 0xFF, (crc >> 8) & 0xFF]

      nonce-tag-frame := raw.transceive-raw (crypto_.encrypt command-bytes)
      if not nonce-tag-frame: return false
      nonce-tag := crypto_.decrypt nonce-tag-frame

      // In theory this should be a random number.
      nonce-reader := #[0x00, 0x00, 0x00, 0x00]

      sleep --ms=10
      challenge-response := crypto_.generate-challenge-response
          --nonce-tag=nonce-tag
          --nonce-reader=nonce-reader

      tag-response-frame := raw.transceive-raw (crypto_.encrypt challenge-response)
      if not tag-response-frame: return false
      tag-response := crypto_.decrypt tag-response-frame

      successful = crypto_.compare-tag-response tag-response
      return successful
    finally:
      // Make sure we don't leave the crypto in a bad state. If we are not
      // successful, the communication is pretty much broken anyway.
      if not successful: crypto_ = null

  /** Whether this card is currently authenticated for some sector. */
  is-authenticated -> bool:
    return crypto_ != null

  /** Stops using Crypto1 for further $read/$write calls. */
  deauthenticate -> none:
    crypto_ = null

  /**
  Transceives $bytes with the card, transparently en/decrypting them with
    Crypto1 if $is-authenticated, the same way a chip's own hardware
    Crypto1 unit would do invisibly.
  */
  transceive_ bytes/ByteArray --check-crc/bool=false --add-crc/bool=true -> ByteArray?:
    if not crypto_:
      return target.transceive bytes --check-crc=check-crc

    raw := target as RawFrameTarget
    to-send := bytes
    if add-crc:
      crc := crc-a bytes
      to-send = bytes + #[crc & 0xFF, (crc >> 8) & 0xFF]

    result-frame := raw.transceive-raw (crypto_.encrypt to-send)
    if not result-frame: return null
    decrypted := crypto_.decrypt result-frame
    if not check-crc: return decrypted
    check-crc-a decrypted
    return decrypted[..decrypted.size - 2]

  read --block/int -> ByteArray?:
    if not 0 <= block < total-block-count: throw "INVALID_ARGUMENT"
    return transceive_ #[MIFARE-READ_, block] --check-crc

  /**
  Writes $bytes to a given block.

  Checks that the data is valid for block 0 (the UUID), that the sector trailer's access
    bits are correct, and that they don't lock out the user from modifying the access
    bits in the future.
  If $force is true, writes the data, without doing any check.
  If $force-lockout is true, verifies that the data is correct, but allows to
    lock out the user from modifying the access bits in the future. The parameter
    $force implies $force-lockout.
  The $force and $force-lockout flags only verify the data in the $bytes array. They
    don't check that the user is allowed to write to the block.
  */
  write --block/int bytes/ByteArray --force/bool=false --force-lockout/bool=false -> none:
    if not 0 <= block < total-block-count: throw "INVALID_ARGUMENT"
    if bytes.size != 16: throw "ClassicCard.write: bytes must be 16 bytes long"
    if block == MANUFACTURER-BLOCK and not force: check-manufacturer-data_ bytes
    if is-trailer-block block and not force: check-trailer-data_ bytes --allow-lockout=(not force-lockout)

    response := transceive_ #[MIFARE-WRITE_, block]
    if response != ACK_: throw (MifareException.from-response response)
    response = transceive_ bytes
    if response != ACK_: throw (MifareException.from-response response)

  /** Deauthenticates and halts the underlying $target. */
  close -> none:
    deauthenticate
    target.close

  is-trailer-block block/int -> bool:
    if block < (32 * 4):
      return block % 4 == 3
    return block % 16 == 15

  is-first-block-in-sector block/int -> bool:
    if block < (32 * 4):
      return block % 4 == 0
    return block % 16 == 0

  sectors-count -> int:
    if type == CardType.MIFARE-MINI:
      return 5
    else if type == CardType.MIFARE-1K or type == CardType.MIFARE-PLUS-DESFIRE:
      return 16
    else if type == CardType.MIFARE-4K:
      return 40
    throw "Unknown card"

  total-block-count -> int:
    sectors := sectors-count
    if sectors <= 32: return sectors * 4
    return 32 * 4 + (sectors - 32) * 16

  /** The size of the given sector in blocks. */
  sector-size-in-blocks sector/int -> int:
    if sector < 32: return 4
    return 16

  check-keys_ keys/List:
    keys.do:
      if it.size != 6: throw "Keys must be 6 bytes long"

  dump --keys/List=(List sectors-count: DEFAULT-KEY) -> ByteArray:
    check-keys_ keys
    result := ByteArray total-block-count * 16
    sector-counter := 0
    key/ByteArray? := null
    for i := 0; i < total-block-count; i++:
      if is-first-block-in-sector i:
        // Set the key so we can update the trailer block later.
        key = keys[sector-counter]
        authenticated := authenticate --block=i key
        if not authenticated: throw (MifareException.from-code MifareException.AUTHENTICATION-FAILED)
        sector-counter++
      block-bytes := read --block=i
      if is-trailer-block i: block-bytes.replace 0 key
      result.replace (i * 16) block-bytes
    return result

  /**
  Dumps the content of the card to stdout.

  If a sector's authentication fails, prints that it is encrypted and skips
    to the next sector, rather than trying to recover the connection: unlike
    the chip-specific driver this card is built on, this class has no way
    to re-poll for the card itself.
  */
  write-to-stdout --keys/List=(List sectors-count: DEFAULT-KEY) --print-last-first/bool=true:
    check-keys_ keys
    sector-counter := 0
    key/ByteArray? := null
    block := 0
    while block < total-block-count:
      if is-first-block-in-sector block:
        if block != 0: print
        print "Sector $sector-counter:"
        // Set the key so we can update the trailer block later.
        key = keys[sector-counter]
        authenticated := authenticate --block=block key
        if not authenticated:
          print "  encrypted"
          deauthenticate
          // Skip over the remaining blocks in this sector.
          block += sector-size-in-blocks sector-counter
          sector-counter++
          continue

      blocks := []
      sector-size := sector-size-in-blocks sector-counter
      for j := 0; j < sector-size; j++:
        block-bytes := read --block=block
        if is-trailer-block block: block-bytes.replace 0 key
        blocks.add block-bytes
        block++

      access-bits := AccessBits.from-trailer blocks.last
      for i := 0; i < blocks.size; i++:
        block-bytes := blocks[i]
        block-str := ""
        block-bytes.do: block-str += "$(%02x it)"
        area/int := ?
        if sector-size == 4:
          area = i
        else:
          if i < 5: area = 0
          else if i < 10: area = 1
          else if i < 15: area = 2
          else: area = 3

        legend := access-bits.stringify --area=area

        print "  $block-str ($legend)"

      sector-counter++

  check-manufacturer-data_ bytes/ByteArray:
    // We assume that the UID must be of the same size as the current UID.
    // Magic cards generally don't allow to switch UID size.
    new-uid-bytes := bytes[..uid.size]
    bcc := 0
    new-uid-bytes.do: bcc ^= it
    if bcc != bytes[uid.size]: throw (MifareException.from-code MifareException.INVALID-UID-BCC)

  check-trailer-data_ byte/ByteArray --allow-lockout/bool:
    access-bits := AccessBits.from-trailer byte
    if allow-lockout: return
    if not access-bits.can-write-access-bits --with-key-a --with-key-b:
      throw (MifareException.from-code MifareException.ACCESS-BITS-LOCKOUT)
