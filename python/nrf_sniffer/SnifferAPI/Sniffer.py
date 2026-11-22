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

import logging
from . import Logger
from . import UART

from .Types import *
try:
    from .version import VERSION_STRING
except:
    VERSION_STRING = "Unknown Version"


def initLog():
    Logger.initLogger()

    logging.info("--------------------------------------------------------")
    logging.info("Software version: " + VERSION_STRING)


initLog()



import sys, os, threading
from . import SnifferCollector

class Sniffer(threading.Thread, SnifferCollector.SnifferCollector):

    # Sniffer constructor. portnum argument is optional. If not provided,
    # the software will try to locate the firwmare automatically (may take time).
    # NOTE: portnum is 0-indexed, while Windows names are 1-indexed
    def __init__(self, portnum=None, baudrate=UART.SNIFFER_OLD_DEFAULT_BAUDRATE, **kwargs):
        threading.Thread.__init__(self)
        SnifferCollector.SnifferCollector.__init__(self, portnum, baudrate=baudrate, **kwargs)
        self.daemon = True

        self.subscribe("COMPORT_FOUND", self.comPortFound)

    # API STARTS HERE


    # Get [number] number of packets since last fetch (-1 means all)
    # Note that the packet buffer is limited to about 80000 packets.
    # Returns: A list of Packet objects
    def getPackets(self, number=-1):
        return self._getPackets(number)

    # Get a list of devices which are advertising in range of the Sniffer.
    # Returns: A DeviceList object.
    def getDevices(self):
        return self._devices

    # Add a new device to the list of devices
    def addDevice(self, device):
        self._addDevice(device)

    # Signal the Sniffer firmware to sniff a specific device.
    # "device" argument is of type Device
    # if "followOnlyAdvertisements" is True, the sniffer will not follow the device into a connection.
    # Returns nothing
    def follow(self, device=None, followOnlyAdvertisements = False, followOnlyLegacy = False, followCoded = False):
        self._startFollowing(device, followOnlyAdvertisements, followOnlyLegacy, followCoded)

    # Clear the list of devices
    def clearDevices(self):
        self._clearDevices()

    # Signal the Sniffer to scan for advertising devices by sending the REQ_SCAN_CONT UART packet.
    # This will cause it to stop sniffing any device it is sniffing at the moment.
    # Returns nothing.
    def scan(self, findScanRsp = False, findAux = False, scanCoded = False):
        self._startScanning(findScanRsp, findAux, scanCoded)

    # Send a temporary key to the sniffer to use when decrypting encrypted communication.
    # Returns nothing.
    def sendTK(self, TK):
        self._packetReader.sendTK(TK)

    # Send Diffie-Hellman private key to the sniffer to use when decrypting encrypted communication.
    # Returns nothing.
    def sendPrivateKey(self, pk):
        self._packetReader.sendPrivateKey(pk)

    # Send Legacy Long Term Key (LTK) to the sniffer to use when decrypting encrypted communication.
    # Returns nothing.
    def sendLegacyLTK(self, ltk):
        self._packetReader.sendLegacyLTK(ltk)

    # Send LE Secure Connections (SC) Long Term Key (LTK) to the sniffer to use when decrypting encrypted communication.
    # Returns nothing.
    def sendSCLTK(self, ltk):
        self._packetReader.sendSCLTK(ltk)

    def sendIRK(self, irk):
        self._packetReader.sendIRK(irk)

    # Send a request for the sniffer version in the sniffer firmware.
    def getFirmwareVersion(self):
        self._packetReader.sendVersionReq()
        # Older versions of the firmware send the version in the PING response packet.
        self._packetReader.sendPingReq()

    def getTimestamp(self):
        self._packetReader.sendTimestampReq()

    # Set the preset COM port number. Only use this during startup. Set to None to search all ports.
    # Returns nothing.
    def setPortnum(self, portnum):
        self._portnum = portnum
        self._packetReader.portnum = portnum

    # Set the order in which the sniffer cycles through adv channels when following a device.
    # hopSequence must be a list of length 1, 2, or 3, and each item must be either 37, 38, or 39.
    # The same channel cannot occur more than once in the list.
    # Returns nothing.
    def setAdvHopSequence(self, hopSequence):
        self._packetReader.sendHopSequence(hopSequence)

    def setSupportedProtocolVersion(self, suportedProtocolVersion):
        self._packetReader.setSupportedProtocolVersion(suportedProtocolVersion)

    # Gracefully shut down the sniffer threads and connections.
    # If join is True, join the sniffer thread until it quits.
    # Returns nothing.
    def doExit(self, join=False):
        self._doExit()
        if join:
            self.join()

    # NOTE: Methods with decorator @property can be used as (read-only) properties
    # Example: mMissedPackets = sniffer.missedPackets

    # The number of missed packets over the UART, as determined by the packet counter in the header.
    @property
    def missedPackets(self):
        return self._missedPackets

    # The number of packets which were sniffed in the last BLE connection. From CONNECT_REQ until link loss/termination.
    @property
    def packetsInLastConnection(self):
        return self._packetsInLastConnection

    # The packet counter value of the last received connect request.
    @property
    def connectEventPacketCounterValue(self):
        return self._connectEventPacketCounterValue

    # A Packet object containing the last received connect request.
    @property
    def currentConnectRequest(self):
        return self._currentConnectRequest

    # A boolean indicating whether the sniffed device is in a connection.
    @property
    def inConnection(self):
        return self._inConnection

    # The internal state of the sniffer. States are defined in SnifferCollector module. Valid values are 0-2.
    @property
    def state(self):
        return self._state

    # The COM port of the sniffer hardware. During initialization, this value is a preset.
    @property
    def portnum(self):
        return self._portnum

    # The version number of the API software.
    @property
    def swversion(self):
        return VERSION_STRING

    # The version number of the sniffer firmware.
    @property
    def fwversion(self):
        return self._fwversion

    # API ENDS HERE

    # Private method
    def run(self):
        try:
            self._setup()
            self.runSniffer()
        except (KeyboardInterrupt) as e:
            _, _, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            lineno = exc_tb.tb_lineno
            logging.info("exiting ("+str(type(e))+" in "+fname+" at "+str(lineno)+"): "+str(e))
            self.goodExit = False
        except (BrokenPipeError, OSError):
            logging.info("capture pipe closed before sniffer thread was stopped")
            self.goodExit = True
        except Exception as e:
            import traceback
            logging.exception("CRASH: {}".format(e))
            logging.exception(traceback.format_exc())
            logging.exception('internal error: {}'.format(repr(e)))
            self.goodExit = False
        else:
            self.goodExit = True

    # Private method
    def comPortFound(self, notification):
        self._portnum = notification.msg["comPort"]
        self._boardId = self._makeBoardId()

    # Private method
    def runSniffer(self):
        if not self._exit:
            self._continuouslyPipe()
        else:
            self.goodExit = False
