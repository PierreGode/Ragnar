#!/usr/bin/env python3
# i2c_bus.py — one process-wide lock for I2C bus 1 on the CardputerZero.
#
# Bus 1 (SDA=GPIO2, SCL=GPIO3) carries three chips Ragnar talks to from
# different threads: the M5IOE1 expander (0x4F: LCD backlight/reset + the 5 V
# rails), the BQ27220 fuel gauge (0x55), and — read for the hardware panel —
# the rail state again through the expander. The kernel serialises each single
# transaction, but several of ours are read-modify-write (the expander's GPIO
# output registers hold the backlight-reset bit *and* the rail-enable bits in
# one byte). Two threads doing RMW on that byte at once can lose an update —
# e.g. a Grove-rail toggle clobbering the LCD reset bit. One lock around every
# bus-1 operation keeps each read-modify-write atomic against the others.
#
# It is an RLock so a caller that already holds it (the expander methods take it
# too) can nest without deadlocking. Holding it does not fix a flaky bus; it
# only stops *our own* threads from piling onto it or racing a RMW.

import threading

_LOCK = threading.RLock()


def lock():
    """The shared re-entrant lock for I2C bus 1. Use as ``with i2c_bus.lock():``
    around a bus-1 transaction (or a multi-step read-modify-write)."""
    return _LOCK
