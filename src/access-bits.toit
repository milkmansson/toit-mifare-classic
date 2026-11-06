// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import .mifare-exception show MifareException

/**
Access bits of a Mifare card.

A trailer block encodes 4 integers, each between 0 and 7.
The first three integers provide the access bits for the data blocks.
The list integer provides the access bits for the trailer block itself.

When a sector has more than 3 data blocks (Mifare 4K), then the access bits are
  applied as follows:
  * b0 (the first byte), applies to blocks 0-4
  * b1 (the second byte), applies to blocks 5-9
  * b2 (the third byte), applies to blocks 10-14

b3 is always the access bits for the trailer block.

The meaning of the access bits for data blocks is as follows:
```
        read write increment decrement/transfer/restore
0b000:   AB   AB      AB       AB    # Transport configuration
0b010:   AB   --      --       --    # read/write block
0b100:   AB    B      --       --    # read/write block
0b110:   AB    B       B       AB    # value block
0b001:   AB   --      --       AB    # value block
0b011:    B    B      --       --    # read/write block
0b101:    B   --      --       --    # read/write block
0b111:   --   --      --       --    # read/write block
```

The meaning of the access bits for the trailer block is as follows.
```
        Key A, Access bits, Key B
0b000: Aw   ,  Ar        , Arw      # Key B is readable.
0b010:      ,  Ar        , Ar       # Key B is readable.
0b100:    Bw,  Ar  Br    ,     Bw
0b110:      ,  Ar  Br    ,
0b001: Aw   ,  Arw       , Arw      # Transport configuration. Key B is readable.
0b011:    Bw,  Ar  Brw   ,     Bw
0b101:      ,  Ar  Brw   ,
0b111:      ,  Ar  Br    ,
```
*/
class AccessBits:
  /**
  Constructs the access bits for a data area.

  Not all combinations of $key-a-read, $key-b-read, $key-a-write, $key-b-write,
    $key-a-increment, $key-b-increment, $key-a-decrement, $key-b-decrement are possible.
  */
  static build-data-area-bits -> int
      --key-a-read/bool --key-b-read/bool
      --key-a-write/bool --key-b-write/bool
      --key-a-increment/bool --key-b-increment/bool
      --key-a-decrement/bool --key-b-decrement/bool:
    if key-a-read and key-b-read and
        key-a-write and key-b-write and
        key-a-increment and key-b-increment and
        key-a-decrement and key-b-decrement:
      return 0b000
    if key-a-read and key-b-read and
        not key-a-write and not key-b-write and
        not key-a-increment and not key-b-increment and
        not key-a-decrement and not key-b-decrement:
      return 0b010
    if key-a-read and key-b-read and
        not key-a-write and key-b-write and
        not key-a-increment and not key-b-increment and
        not key-a-decrement and not key-b-decrement:
      return 0b100
    if key-a-read and key-b-read and
        not key-a-write and key-b-write and
        not key-a-increment and key-b-increment and
        key-a-decrement and key-b-decrement:
      return 0b110
    if key-a-read and key-b-read and
        not key-a-write and not key-b-write and
        not key-a-increment and not key-b-increment and
        key-a-decrement and key-b-decrement:
      return 0b001
    if not key-a-read and key-b-read and
        not key-a-write and key-b-write and
        not key-a-increment and not key-b-increment and
        not key-a-decrement and not key-b-decrement:
      return 0b011
    if not key-a-read and key-b-read and
        not key-a-write and not key-b-write and
        not key-a-increment and not key-b-increment and
        not key-a-decrement and not key-b-decrement:
      return 0b101
    if not key-a-read and not key-b-read and
        not key-a-write and not key-b-write and
        not key-a-increment and not key-b-increment and
        not key-a-decrement and not key-b-decrement:
      return 0b111
    throw "INVALID_ARGUMENT"

  /**
  Constructs the access bits for a trailer area.

  Not all combinations of
    $read-key-b-with-key-a,
    $write-key-a-with-key-a, $write-key-a-with-key-b,
    $write-key-b-with-key-a, $write-key-b-with-key-b,
    $read-access-bits-with-key-a, $read-access-bits-with-key-b,
    $write-access-bits-with-key-a, $write-access-bits-with-key-b are possible.
  */
  static build-trailer-bits -> int
      --read-key-b-with-key-a/bool
      --write-key-a-with-key-a/bool --write-key-a-with-key-b/bool
      --write-key-b-with-key-a/bool --write-key-b-with-key-b/bool
      --read-access-bits-with-key-a/bool --read-access-bits-with-key-b/bool
      --write-access-bits-with-key-a/bool --write-access-bits-with-key-b/bool:
    if read-key-b-with-key-a and
        write-key-a-with-key-a and not write-key-a-with-key-b and
        write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and not read-access-bits-with-key-b and
        not write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b000
    if read-key-b-with-key-a and
        not write-key-a-with-key-a and not write-key-a-with-key-b and
        not write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and not read-access-bits-with-key-b and
        not write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b010
    if not read-key-b-with-key-a and
        not write-key-a-with-key-a and write-key-a-with-key-b and
        not write-key-b-with-key-a and write-key-b-with-key-b and
        read-access-bits-with-key-a and read-access-bits-with-key-b and
        not write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b100
    if not read-key-b-with-key-a and
        not write-key-a-with-key-a and not write-key-a-with-key-b and
        not write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and read-access-bits-with-key-b and
        not write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b110
    if read-key-b-with-key-a and
        write-key-a-with-key-a and not write-key-a-with-key-b and
        write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and not read-access-bits-with-key-b and
        write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b001
    if not read-key-b-with-key-a and
        not write-key-a-with-key-a and write-key-a-with-key-b and
        not write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and read-access-bits-with-key-b and
        not write-access-bits-with-key-a and write-access-bits-with-key-b:
      return 0b011
    if not read-key-b-with-key-a and
        not write-key-a-with-key-a and not write-key-a-with-key-b and
        not write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and read-access-bits-with-key-b and
        not write-access-bits-with-key-a and write-access-bits-with-key-b:
      return 0b101
    if not read-key-b-with-key-a and
        not write-key-a-with-key-a and not write-key-a-with-key-b and
        not write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and read-access-bits-with-key-b and
        not write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b111
    throw "INVALID_ARGUMENT"

  b0 /int
  b1 /int
  b2 /int
  b3 /int

  constructor.from-trailer bytes/ByteArray:
    if bytes.size != 16: throw "INVALID_ARGUMENT"
    c1 := bytes[7] >> 4
    c2 := bytes[8] & 0xf
    c3 := bytes[8] >> 4
    c1_ := bytes[6] & 0xf
    c2_ := bytes[6] >> 4
    c3_ := bytes[7] & 0xf

    // cX_ should always be the inverted version of cX.
    if c1_ != 0xf - c1 or c2_ != 0xf - c2 or c3_ != 0xf - c3:
      throw (MifareException.from-code MifareException.INVALID-ACCESS-BITS)
    else:
      b0 = (c1 & 0b0001) << 2 | (c2 & 0b0001) << 1 | (c3 & 0b0001) << 0
      b1 = (c1 & 0b0010) << 1 | (c2 & 0b0010) << 0 | (c3 & 0b0010) >> 1
      b2 = (c1 & 0b0100) << 0 | (c2 & 0b0100) >> 1 | (c3 & 0b0100) >> 2
      b3 = (c1 & 0b1000) >> 1 | (c2 & 0b1000) >> 2 | (c3 & 0b1000) >> 3

  /**
  Builds a instance with the given access bits for each area.
  */
  constructor .b0 .b1 .b2 .b3:
    if not 0 <= b0 <= 7: throw "INVALID_ARGUMENT"
    if not 0 <= b1 <= 7: throw "INVALID_ARGUMENT"
    if not 0 <= b2 <= 7: throw "INVALID_ARGUMENT"
    if not 0 <= b3 <= 7: throw "INVALID_ARGUMENT"

  /**
  Returns whether it is possible to read the blocks covered by the given $area with
    key A (if $with-key-a is true) and/or key B (if $with-key-b is true).

  The $area must be in range 0-2, as this function only covers the access bits for
    data blocks.
  */
  can-read-data --area/int --with-key-a/bool --with-key-b/bool -> bool:
    bits := area-to-bits_ area

    if with-key-a:
      if bits == 0b000 or bits == 0b010 or bits == 0b100 or bits == 0b110 or bits == 0b001: return true
    if with-key-b:
      if bits != 0b111: return true
    return false

  /**
  Returns whether it is possible to write the blocks covered by the given $area with
    key A (if $with-key-a is true) and/or key B (if $with-key-b is true).

  The $area must be in range 0-2, as this function only covers the access bits for
    data blocks.
  */
  can-write-data --area/int --with-key-a/bool --with-key-b/bool -> bool:
    bits := area-to-bits_ area

    if with-key-a and bits == 0b000: return true
    if with-key-b:
      if bits == 0b000 or bits == 0b100 or bits == 0b110 or bits == 0b011: return true
    return false

  /**
  Returns whether is is possible increment the blocks covered by the given $area with
    key A (if $with-key-a is true) and/or key B (if $with-key-b is true).

  The $area must be in range 0-2, as this function only covers the access bits for
    data blocks.
  */
  can-increment-data --area/int --with-key-a/bool --with-key-b/bool -> bool:
    bits := area-to-bits_ area

    if with-key-a and bits == 0b000: return true
    if with-key-b and bits == 0b000 or bits == 0b110: return true
    return false

  /**
  Returns whether is is possible decrement the blocks covered by the given $area with
    key A (if $with-key-a is true) and/or key B (if $with-key-b is true).

  The $area must be in range 0-2, as this function only covers the access bits for
    data blocks.
  */
  can-decrement-data --area/int --with-key-a/bool --with-key-b/bool -> bool:
    bits := area-to-bits_ area

    if not with-key-a and not with-key-b: return false
    return bits == 0b000 or bits == 0b110 or bits == 0b001

  /**
  Returns whether it is possible to read key B of the trailer block with key A.

  Note: there is no `can_read_key_a` as key A is never readable.
  */
  can-read-key-b -> bool:
    return b3 == 0b000 or b3 == 0b010 or b3 == 0b001

  /**
  Whether it is possible to write key A or B of the trailer block with key
    A (if $with-key-a is true) and/or key B (if $with-key-b is true).
  */
  can-write-key --with-key-a/bool --with-key-b/bool -> bool:
    if with-key-a:
      if b3 == 0b000 or b3 == 0b001: return true
    if with-key-b:
    if b3 == 0b100 or b3 == 0b011: return true
    return false

  /**
  Whether it is possible to read the access bits of the trailer block with key B.

  Note: key A can always read the access bits.
  */
  can-read-access-bits --with-key-b/bool -> bool:
    if not with-key-b: return false
    return b3 == 0b100 or b3 == 0b110 or b3 == 0b011 or b3 == 0b101 or b3 == 0b111

  /**
  Whether it is possible to write the access bits of the trailer block with key A
    (if $with-key-a is true) and/or key B (if $with-key-b is true).
  */
  can-write-access-bits --with-key-a/bool --with-key-b/bool -> bool:
    if with-key-a and b3 == 0b001: return true
    if with-key-b:
      if b3 == 0b011 or b3 == 0b101: return true
    return false

  /**
  Writes the access bits into the given $bytes trailer.

  This modifies bytes 6, 7 and 8 of the $bytes.
  */
  write-into-trailer bytes/ByteArray:
    if bytes.size != 16: throw "INVALID_ARGUMENT"

    c1 := (b0 >> 2) & 0b0001 | (b1 >> 1) & 0b0010 | (b2 >> 0) & 0b0100 | (b3 << 1) & 0b1000
    c2 := (b0 >> 1) & 0b0001 | (b1 >> 0) & 0b0010 | (b2 << 1) & 0b0100 | (b3 << 2) & 0b1000
    c3 := (b0 >> 0) & 0b0001 | (b1 << 1) & 0b0010 | (b2 << 2) & 0b0100 | (b3 << 3) & 0b1000
    c1_ := 0xf - c1
    c2_ := 0xf - c2
    c3_ := 0xf - c3
    bytes[6] = (c2_ << 4) | c1_
    bytes[7] = (c1 << 4) | c3_
    bytes[8] = (c3 << 4) | c2

  stringify -> string:
    return """
      $(data-access-bits-to-string b0)
      $(data-access-bits-to-string b1)
      $(data-access-bits-to-string b2)
      $(trailer-access-bits-to-string b3)
      """

  area-to-bits_ area/int -> int:
    if not 0 <= area <= 3: throw "INVALID_ARGUMENT"
    if area == 0: return b0
    else if area == 1: return b1
    else if area == 2: return b2
    return b3

  /**
  Stringifies the access bits for the given $area.

  The $area value must be in range 0-3.
  For Mifare 1K, the $area value is equivalent to the block in the sector.
  For Mifare 4K, the $area value may cover multiple blocks.
  */
  stringify --area/int:
    if not 0 <= area <= 3: throw "INVALID_ARGUMENT"
    if area == 0: return data-access-bits-to-string b0
    if area == 1: return data-access-bits-to-string b1
    if area == 2: return data-access-bits-to-string b2
    return trailer-access-bits-to-string b3

  /**
  Returns a string representation of the access bits of a data block ($b0, $b1, or $b2).
  */
  data-access-bits-to-string area/int -> string:
    if area == 0b000:
      return "000 - read:AB, write:AB, increment:AB, decrement:AB"
    if area == 0b010:
      return "010 - read:AB"
    if area == 0b100:
      return "100 - read:AB, write:B"
    if area == 0b110:
      return "110 - read:AB, write:B, increment:B, decrement:AB"
    if area == 0b001:
      return "001 - read:AB, decrement:AB"
    if area == 0b011:
      return "011 - read:B, write:B"
    if area == 0b101:
      return "101 - read:B"
    if area == 0b111:
      return "111 - no access"
    unreachable

  /**
  Returns a string representation of the access bits of the trailer block ($b3).
  */
  trailer-access-bits-to-string bits/int -> string:
    if bits == 0b000:
      return "000 - Key A: Aw, Bits: Ar, Key B: Arw"
    if bits == 0b010:
      return "010 - Bits: Ar, Key B: Ar"
    if bits == 0b100:
      return "100 - Key A: Bw, Bits: Ar Br,  Key B: Bw"
    if bits == 0b110:
      return "110 - Bits: Ar Br"
    if bits == 0b001:
      return "001 - Key A: Aw, Bits: Arw, Key B: Arw"
    if bits == 0b011:
      return "011 - Key A: Bw, Bits: Ar Brw, Key B: Bw"
    if bits == 0b101:
      return "101 - Bits: Ar Brw"
    if bits == 0b111:
      return "111 - Bits: Ar Br"
    unreachable
