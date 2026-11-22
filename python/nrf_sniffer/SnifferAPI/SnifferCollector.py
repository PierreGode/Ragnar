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

from . import Packet, Exceptions, CaptureFiles, Devices, Notifications
import time, sys, threading, subprocess, os, logging, copy
from serial import SerialException
from .Types import *

STATE_INITIALIZING = 0
STATE_SCANNING = 1
STATE_FOLLOWING = 2

class SnifferCollector(Notifications.Notifier):
    def __init__(self, portnum=None, baudrate=None, *args, **kwargs):
        Notifications.Notifier.__init__(self, *args, **kwargs)
        self._portnum = portnum
        self._fwversion = "Unknown version"
        self._setState(STATE_INITIALIZING)
        self._captureHandler = CaptureFiles.CaptureFileHandler(capture_file_path=kwargs.get("capture_file_path", None))
        self._exit = False
        self._connectionAccessAddress = None
        self._packetListLock = threading.RLock()
        with self._packetListLock:
            self._packets = []

        self._packetReader = Packet.PacketReader(self._portnum, baudrate=baudrate,
                                                 callbacks=[("*", self.passOnNotification)])
        self._devices = Devices.DeviceList(callbacks=[("*", self.passOnNotification)])

        self._missedPackets = 0
        self._packetsInLastConnection = None
        self._connectEventPacketCounterValue = None
        self._inConnection = False
        self._currentConnectRequest = None

        self._nProcessedPackets = 0

        self._switchingBaudRate = False

        self._attemptedBaudRates = []

        self._last_time = None
        self._last_timestamp = 0
        self._boardId = self._makeBoardId()

    def __del__(self):
        self._doExit()

    def _setup(self):
        self._packetReader.setup()

    def _makeBoardId(self):
        try:
            if sys.platform == 'win32':
                boardId = int(self._packetReader.portnum.split("COM")[1])
                logging.info("board ID: %d" % boardId)
            elif sys.platform == 'linux':
                boardId = int(self._packetReader.portnum.split("ttyACM")[1])
                logging.info("board ID: %d" % boardId)
            else:
                # Generate a random boardID
                raise IndexError()
        except (IndexError, AttributeError):
            import random
            random.seed()
            boardId = random.randint(0,255)
            logging.info("board ID (random): %d" % boardId)

        return boardId

    @property
    def state(self):
        return self._state

    def _setState(self, newState):
        self._state = newState
        self.notify("STATE_CHANGE", newState)

    def _switchBaudRate(self, newBaudRate):
        if newBaudRate in self._packetReader.uart.ser.BAUDRATES:
            self._packetReader.sendSwitchBaudRate(newBaudRate)
            self._switchingBaudRate = True
            self._proposedBaudRate = newBaudRate
            self._attemptedBaudRates.append(newBaudRate)

    def _addDevice(self, device):
        self._devices.appendOrUpdate(device)

    def _processBLEPacket(self, packet):
        packet.boardId = self._boardId

        if packet.protover >= PROTOVER_V3:
            if self._last_time is None:
                # Timestamp from Host
                packet.time = time.time()
            else:
                # Timestamp using reference and packet timestamp diff
                if packet.timestamp < self._last_timestamp:
                    time_diff = (1 << 32) - (self._last_timestamp - packet.timestamp)
                else:
                    time_diff = (packet.timestamp - self._last_timestamp)

                packet.time = self._last_time + (time_diff / 1_000_000)

                self._last_time = packet.time
                self._last_timestamp = packet.timestamp
        else:
            # Timestamp from Host
            packet.time = time.time()

        self._appendPacket(packet)

        self.notify("NEW_BLE_PACKET", {"packet": packet})
        self._captureHandler.writePacket(packet)

        self._nProcessedPackets += 1
        if packet.OK:
            try:
                if packet.blePacket.type == PACKET_TYPE_ADVERTISING:

                    if self.state == STATE_FOLLOWING and packet.blePacket.advType == 5:
                        self._connectionAccessAddress = packet.blePacket.accessAddress

                    if self.state == STATE_FOLLOWING and packet.blePacket.advType == 4:
                        newDevice = Devices.Device(address=packet.blePacket.advAddress, name=packet.blePacket.name, RSSI=packet.RSSI)
                        self._devices.appendOrUpdate(newDevice)

                    if self.state == STATE_SCANNING:
                        if (packet.blePacket.advType in [0, 1, 2, 4, 6, 7] and
                            packet.blePacket.advAddress != None and
                            packet.crcOK and
                            not packet.direction
                           ):
                            newDevice = Devices.Device(address=packet.blePacket.advAddress, name=packet.blePacket.name, RSSI=packet.RSSI)
                            self._devices.appendOrUpdate(newDevice)

            except Exception as e:
                logging.exception("packet processing error %s" % str(e))
                self.notify("PACKET_PROCESSING_ERROR", {"errorString": str(e)})

    def _continuouslyPipe(self):
        while not self._exit:
            try:
                packet = self._packetReader.getPacket(timeout=12)
                if packet == None or not packet.valid:
                    raise Exceptions.InvalidPacketException("")
            except Exceptions.SnifferTimeout as e:
                logging.info(str(e))
                packet = None
            except (SerialException, ValueError):
                logging.exception("UART read error")
                logging.error("Lost contact with sniffer hardware.")
                self._doExit()
            except Exceptions.InvalidPacketException:
                pass
            else:
                if packet.id == EVENT_PACKET_DATA_PDU or packet.id == EVENT_PACKET_ADV_PDU:
                    self._processBLEPacket(packet)
                elif packet.id == EVENT_FOLLOW:
                    # This packet has no value for the user.
                    pass
                elif packet.id == EVENT_CONNECT:
                    self._connectEventPacketCounterValue = packet.packetCounter
                    self._inConnection = True
                     # copy it because packets are eventually deleted
                    self._currentConnectRequest = copy.copy(self._findPacketByPacketCounter(self._connectEventPacketCounterValue-1))
                elif packet.id == EVENT_DISCONNECT:
                    if self._inConnection:
                        self._packetsInLastConnection = packet.packetCounter - self._connectEventPacketCounterValue
                        self._inConnection = False
                elif packet.id == SWITCH_BAUD_RATE_RESP and self._switchingBaudRate:
                    self._switchingBaudRate = False
                    if (packet.baudRate == self._proposedBaudRate):
                        self._packetReader.switchBaudRate(self._proposedBaudRate)
                    else:
                        self._switchBaudRate(packet.baudRate)
                elif packet.id == PING_RESP:
                    if hasattr(packet, 'version'):
                        versions = { 1116: '3.1.0',
                                     1115: '3.0.0',
                                     1114: '2.0.0',
                                     1113: '2.0.0-beta-3',
                                     1112: '2.0.0-beta-1' }
                        self._fwversion = versions.get(packet.version, 'SVN rev: %d' % packet.version)
                        logging.info("Firmware version %s" % self._fwversion)
                elif packet.id == RESP_VERSION:
                    self._fwversion = packet.version
                    logging.info("Firmware version %s" % self._fwversion)
                elif packet.id == RESP_TIMESTAMP:
                    # Use current time as timestamp reference
                    self._last_time = time.time()
                    self._last_timestamp = packet.timestamp

                    lt = time.localtime(self._last_time)
                    usecs = int((self._last_time - int(self._last_time)) * 1_000_000)
                    logging.info(f'Firmware timestamp {self._last_timestamp} reference: '
                                 f'{time.strftime("%b %d %Y %X", lt)}.{usecs} {time.strftime("%Z", lt)}')
                else:
                    logging.info("Unknown packet ID")

    def _findPacketByPacketCounter(self, packetCounterValue):
        with self._packetListLock:
            for i in range(-1, -1-len(self._packets), -1):
            # iterate backwards through packets
                if self._packets[i].packetCounter == packetCounterValue:
                    return self._packets[i]
        return None

    def _startScanning(self, findScanRsp = False, findAux = False, scanCoded = False):
        logging.info("starting scan")

        if self.state == STATE_FOLLOWING:
            logging.info("Stopped sniffing device")

        self._setState(STATE_SCANNING)
        self._packetReader.sendScan(findScanRsp, findAux, scanCoded)
        self._packetReader.sendTK([0])

    def _doExit(self):
        self._exit = True
        self.notify("APP_EXIT")
        self._packetReader.doExit()
        # Clear method references to avoid uncollectable cyclic references
        self.clearCallbacks()
        self._devices.clearCallbacks()

    def _startFollowing(self, device, followOnlyAdvertisements = False, followOnlyLegacy = False, followCoded = False):
        self._devices.setFollowed(device)
        logging.info("Sniffing device " + str(self._devices.index(device)) + ' - "'+device.name+'"')
        self._packetReader.sendFollow(device.address, followOnlyAdvertisements, followOnlyLegacy, followCoded)
        self._setState(STATE_FOLLOWING)

    def _clearDevices(self):
        self._devices.clear()

    def _appendPacket(self, packet):
        with self._packetListLock:
            if len(self._packets) > 100000:
                self._packets = self._packets[20000:]
            self._packets.append(packet)

    def _getPackets(self, number = -1):
        with self._packetListLock:
            returnList = self._packets[0:number]
            self._packets = self._packets[number:]
        return returnList

    def _clearPackets(self):
        with self._packetListLock:
            del self._packets[:]
