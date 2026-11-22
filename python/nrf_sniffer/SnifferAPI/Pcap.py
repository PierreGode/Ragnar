#!/usr/bin/env python3

# Copyright (c) Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form, except as embedded into a Nordic
#    Semiconductor ASA integrated circuit in a product or a software update for
#    such product, must reproduce the above copyright notice, this list of
#    conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of Nordic Semiconductor ASA nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# 4. This software, with or without modification, must only be used with a
#    Nordic Semiconductor ASA integrated circuit.
#
# 5. Any software provided in binary form under this license must not be reverse
#    engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import struct


# See:
# - https://github.com/pcapng/pcapng
# - https://www.tcpdump.org/linktypes/LINKTYPE_NORDIC_BLE.html
PACKET_HEADER = struct.Struct("<LLLL")
GLOBAL_HEADER = struct.pack("<LHHIILL",
                            0xa1b2c3d4,  # PCAP magic number
                            2,           # PCAP major version
                            4,           # PCAP minor version
                            0,           # Reserved
                            0,           # Reserved
                            0x0000ffff,  # Max length of capture frame
                            272)         # Nordic BLE link type


def get_global_header():
    """Get the PCAP global header."""
    return GLOBAL_HEADER


def create_packet(packet: bytes, timestamp_seconds: float):
    """Create a PCAP packet.

    Args:
        packet (bytes): Packet in the Nordic BLE packet format.
        timestamp_seconds (float): a relative timestamp in seconds.

    Returns:
        bytes: a PCAP formatted packet.
    """
    timestamp_floor = int(timestamp_seconds)
    timestamp_offset_us = int((timestamp_seconds - timestamp_floor) * 1_000_000)

    return struct.pack("<LLLL",
                       timestamp_floor,
                       timestamp_offset_us,
                       len(packet),
                       len(packet)) + packet
