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

import collections
import logging
import serial
from threading import Thread, Event

import serial.tools.list_ports as list_ports

from . import Exceptions
from . import Packet
from . import Filelock

import os
if os.name == "posix":
    import termios

SNIFFER_OLD_DEFAULT_BAUDRATE = 460800
# Baudrates that should be tried (add more if required)
SNIFFER_BAUDRATES = [1000000, 460800]


def find_sniffer(write_data=False):
    open_ports = list_ports.comports()

    sniffers = []
    for port in [x.device for x in open_ports]:
        for rate in SNIFFER_BAUDRATES:
            reader = None
            l_errors = [serial.SerialException, ValueError, Exceptions.LockedException, OSError]
            if os.name == 'posix':
                l_errors.append(termios.error)
            try:
                reader = Packet.PacketReader(portnum=port, baudrate=rate)
                try:
                    if write_data:
                        reader.sendPingReq()
                        _ = reader.decodeFromSLIP(0.1, complete_timeout=0.1)
                    else:
                        _ = reader.decodeFromSLIP(0.3, complete_timeout=0.3)

                    # FIXME: Should add the baud rate here, but that will be a breaking change
                    sniffers.append(port)
                    break
                except (Exceptions.SnifferTimeout, Exceptions.UARTPacketError):
                    pass
            except tuple(l_errors):
                continue
            finally:
                if reader is not None:
                    reader.doExit()
    return sniffers


def find_sniffer_baudrates(port, write_data=False):
    for rate in SNIFFER_BAUDRATES:
        reader = None
        try:
            reader = Packet.PacketReader(portnum=port, baudrate=rate)
            try:
                if write_data:
                    reader.sendPingReq()
                    _ = reader.decodeFromSLIP(0.1, complete_timeout=0.1)
                else:
                    _ = reader.decodeFromSLIP(0.3, complete_timeout=0.3)

                # TODO: possibly include additional rates based on protocol version
                return {"default": rate, "other": []}
            except (Exceptions.SnifferTimeout, Exceptions.UARTPacketError):
                pass
        finally:
            if reader is not None:
                reader.doExit()
    return None


class Uart:
    def __init__(self, portnum=None, baudrate=None):
        self.ser = None
        try:
            if baudrate is not None and baudrate not in SNIFFER_BAUDRATES:
                raise Exception("Invalid baudrate: " + str(baudrate))

            logging.info('Opening serial port {}'.format(portnum))

            self.portnum = portnum
            if self.portnum:
                Filelock.lock(portnum)

            self.ser = serial.Serial(
                port=portnum,
                baudrate=9600,
                rtscts=True,
                exclusive=True
            )
            self.ser.baudrate = baudrate

        except Exception:
            if self.ser:
                self.ser.close()
                self.ser = None
            raise

        self.read_queue = collections.deque()
        self.read_queue_has_data = Event()

        self.worker_thread = Thread(target=self._read_worker)
        self.reading = True
        self.worker_thread.setDaemon(True)
        self.worker_thread.start()

    def _read_worker(self):
        self.ser.reset_input_buffer()
        while self.reading:
            try:
                # Read any data available, or wait for at least one byte
                data_read = self.ser.read(self.ser.in_waiting or 1)
                #logging.info('type: {}'.format(data_read.__class__))
                self._read_queue_extend(data_read)
            except serial.SerialException as e:
                logging.info("Unable to read UART: %s" % e)
                self.reading = False
                return

    def close(self):
        if self.ser:
            logging.info("closing UART")
            self.reading = False
            # Wake any threads waiting on the queue
            self.read_queue_has_data.set()
            if hasattr(self.ser, "cancel_read"):
                self.ser.cancel_read()
                self.worker_thread.join()
                self.ser.close()
            else:
                self.ser.close()
                self.worker_thread.join()
            self.ser = None

        if self.portnum:
            Filelock.unlock(self.portnum)

    def __del__(self):
        self.close()

    def switchBaudRate(self, newBaudRate):
        self.ser.baudrate = newBaudRate

    def readByte(self, timeout=None):
        r = self._read_queue_get(timeout)
        return r

    def writeList(self, array):
        try:
            self.ser.write(array)
        except serial.SerialTimeoutException:
            logging.info("Got write timeout, ignoring error")

        except serial.SerialException as e:
            self.ser.close()
            raise e

    def _read_queue_extend(self, data):
        if len(data) > 0:
            self.read_queue.extend(data)
            self.read_queue_has_data.set()

    def _read_queue_get(self, timeout=None):
        data = None
        if self.read_queue_has_data.wait(timeout):
            self.read_queue_has_data.clear()
            try:
                data = self.read_queue.popleft()
            except IndexError:
                # This will happen when the class is destroyed
                return None
            if len(self.read_queue) > 0:
                self.read_queue_has_data.set()
        return data


def list_serial_ports():
    # Scan for available ports.
    return list_ports.comports()

if __name__ == "__main__":
    import time
    t_start = time.time()
    s = find_sniffer()
    tn = time.time()
    print(s)
    print("find_sniffer took %f seconds" % (tn - t_start))
    for p in s:
        t = time.time()
        print(find_sniffer_baudrates(p))
        tn = time.time()
        print("find_sniffer_baudrate took %f seconds" % (tn - t))
    tn = time.time()
    print("total runtime %f" % (tn - t_start))
