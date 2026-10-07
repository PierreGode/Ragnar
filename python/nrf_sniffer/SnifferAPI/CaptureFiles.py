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


import time, os, logging
from . import Logger
from . import Pcap


DEFAULT_CAPTURE_FILE_DIR = Logger.DEFAULT_LOG_FILE_DIR
DEFAULT_CAPTURE_FILE_NAME = "capture.pcap"


def get_capture_file_path(capture_file_path=None):
    default_path = os.path.join(DEFAULT_CAPTURE_FILE_DIR, DEFAULT_CAPTURE_FILE_NAME)
    if capture_file_path is None:
        return default_path
    if os.path.splitext(capture_file_path)[1] != ".pcap":
        return default_path
    return os.path.abspath(capture_file_path)


class CaptureFileHandler:
    def __init__(self, capture_file_path=None, clear=False):
        filename = get_capture_file_path(capture_file_path)
        if not os.path.isdir(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        self.filename = filename
        self.backupFilename = self.filename+".1"
        if not os.path.isfile(self.filename):
            self.startNewFile()
        elif os.path.getsize(self.filename) > 20000000:
            self.doRollover()
        if clear:
            #clear file
            self.startNewFile()

    def startNewFile(self):
        with open(self.filename, "wb") as f:
            f.write(Pcap.get_global_header())

    def doRollover(self):
        try:
            os.remove(self.backupFilename)
        except:
            logging.exception("capture file rollover remove backup failed")
        try:
            os.rename(self.filename, self.backupFilename)
            self.startNewFile()
        except:
            logging.exception("capture file rollover failed")

    def writePacket(self, packet):
        with open(self.filename, "ab") as f:
            packet = Pcap.create_packet(
                bytes([packet.boardId] + packet.getList()),
                packet.time)
            f.write(packet)
