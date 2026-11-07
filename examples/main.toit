// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

/**
Hardware test for $ClassicCard over a PN532 (I2C).

The PN532 has no raw-frame access, so $ClassicCard.authenticate is
  expected to throw here -- this example demonstrates and confirms that
  boundary rather than hiding it. What it *does* prove: plain block 0
  reads work over the ISO 14443-3 layer end to end, and card
  detection/typing is correct for a real MIFARE Classic card.

Authenticated read/write (and the still-open nested-authentication
  bug) need a raw-frame-capable reader -- `toit-mfrc522`, over SPI, not
  this I2C harness. See that package's own example for that test.
*/

import gpio
import i2c
import mifare-classic show ClassicCard
import nfc.card-type show CardType
import pn53x show Pn53x

// I2C test harness (2026-11-07); keep in sync with
// toit-pn53x/examples/main.toit if the wiring changes. IRQ/RESET are
// both optional -- see that file's comment -- and unset here since
// only VCC/GND/SDA/SCL are wired so far.
SDA ::= 19
SCL ::= 20
IRQ-PIN/int? ::= null
RESET-PIN/int? ::= null

main:
  sda := gpio.Pin SDA
  scl := gpio.Pin SCL
  irq := IRQ-PIN and (gpio.Pin IRQ-PIN)
  reset := RESET-PIN and (gpio.Pin RESET-PIN)

  bus := i2c.Bus --sda=sda --scl=scl --frequency=100_000
  device := bus.device Pn53x.I2C-ADDRESS
  pn53x := Pn53x.i2c device --irq=irq --reset=reset

  pn53x.on
  print "Firmware: $pn53x.miscellaneous.firmware-version"
  print "Waiting for a MIFARE Classic card..."

  target := null
  while not target:
    target = pn53x.poll
    if not target: sleep --ms=200

  print "Found: $target"
  is-classic := target.type == CardType.MIFARE-MINI or target.type == CardType.MIFARE-1K or
      target.type == CardType.MIFARE-4K or target.type == CardType.MIFARE-PLUS-DESFIRE
  if not is-classic:
    print "Not a MIFARE Classic card (type=$target.type) -- stopping."
    return

  card := ClassicCard target
  print "UID: $card.uid"

  block0 := card.read --block=ClassicCard.MANUFACTURER-BLOCK
  print "Block 0 (plain read): $block0"
  if block0:
    print "PASS: plain read works over PN532."
  else:
    print "FAIL: expected block 0 data, got null -- check wiring/antenna before anything else."

  print "Attempting authenticate --block=4 (expected to throw: no raw-frame access on PN532)..."
  exception := catch:
    card.authenticate --block=4 ClassicCard.DEFAULT-KEY
  if exception:
    print "Got exception as expected: $exception"
    print "PASS: confirms the documented PN532 limitation."
  else:
    print "UNEXPECTED: authenticate did not throw -- toit-mifare-classic's raw-frame requirement may have changed; check RawFrameTarget before trusting Classic auth over I2C."

  pn53x.off
  device.close
  bus.close
  if irq: irq.close
  if reset: reset.close
  scl.close
  sda.close
