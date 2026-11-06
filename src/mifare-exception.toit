// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

class MifareException:
  static INVALID-OPERATION-VALID-BUFFER ::= 0x00
  static PARITY-OR-CRC-ERROR-VALID-BUFFER ::= 0x01
  static INVALID-OPERATION-INVALID-BUFFER ::= 0x04
  static PARITY-OR-CRC-ERROR-INVALID-BUFFER ::= 0x05

  /**
  The card did not return an ACK, but the response did not match any known error code
    or format.
  */
  static INVALID-ERROR-RESPONSE ::= -1
  /**
  When writing the manufacturer block, the BCC (block check character) was found to be
    invalid.
  A BCC is a checksum over the UID bytes, and an invalid BCC can brick magic cards.
  */
  static INVALID-UID-BCC ::= -2
  /**
  Invalid access bits.

  Normaly, the access bits of a trailer block are duplicated in such a way that
    each bit has a corresponding inverted bit. This error is used when that's
    not the case.
  */
  static INVALID-ACCESS-BITS ::= -3

  /**
  The Mifare authentication failed.
  */
  static AUTHENTICATION-FAILED ::= -4

  /**
  Dangerous access bits.

  This code is used when a user tries to write a trailer block with access bits
    that would lock out the owner of the card.
  */
  static ACCESS-BITS-LOCKOUT ::= -5

  /** The received data, if any. */
  response/ByteArray?

  /**
  The code of the error.

  Codes $INVALID-OPERATION-VALID-BUFFER, $PARITY-OR-CRC-ERROR-VALID-BUFFER, $INVALID-OPERATION-INVALID-BUFFER and
    $PARITY-OR-CRC-ERROR-INVALID-BUFFER are responses from the Mifare card. Other codes are defined by this library.
  */
  code/int

  constructor.from-response .response/ByteArray:
    if response.size != 1: code = INVALID-ERROR-RESPONSE
    if response[0] != INVALID-OPERATION-VALID-BUFFER and response[0] != PARITY-OR-CRC-ERROR-VALID-BUFFER and
        response[0] != INVALID-OPERATION-INVALID-BUFFER and response[0] != PARITY-OR-CRC-ERROR-INVALID-BUFFER:
      code = INVALID-ERROR-RESPONSE
    else:
      code = response[0]

  constructor.from-code .code:
    response = null

  stringify -> string:
    if code == INVALID-OPERATION-VALID-BUFFER: return "Invalid operation (valid buffer)"
    if code == PARITY-OR-CRC-ERROR-VALID-BUFFER: return "Parity or CRC error (valid buffer)"
    if code == INVALID-OPERATION-INVALID-BUFFER: return "Invalid operation (invalid buffer)"
    if code == PARITY-OR-CRC-ERROR-INVALID-BUFFER: return "Parity or CRC error (invalid buffer)"
    if code == INVALID-ERROR-RESPONSE: return "Invalid response: $response"
    if code == INVALID-UID-BCC: return "Invalid UID BCC"
    if code == INVALID-ACCESS-BITS: return "Invalid access bits"
    if code == AUTHENTICATION-FAILED: return "Authentication failed"
    return "Unknown error code: $code"
