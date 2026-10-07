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

from . import UART, Exceptions, Notifications
import time, logging, os, sys, serial
from .Types import *

ADV_ACCESS_ADDRESS = [0xD6, 0xBE, 0x89, 0x8E]

SYNCWORD_POS = 0
PAYLOAD_LEN_POS_V1 = 1
PAYLOAD_LEN_POS = 0
PROTOVER_POS = PAYLOAD_LEN_POS+2
PACKETCOUNTER_POS = PROTOVER_POS+1
ID_POS = PACKETCOUNTER_POS+2

BLE_HEADER_LEN_POS = ID_POS+1
FLAGS_POS = BLE_HEADER_LEN_POS+1
CHANNEL_POS = FLAGS_POS+1
RSSI_POS = CHANNEL_POS+1
EVENTCOUNTER_POS = RSSI_POS+1
TIMESTAMP_POS = EVENTCOUNTER_POS+2
BLEPACKET_POS = TIMESTAMP_POS+4
TXADD_POS = BLEPACKET_POS + 4
TXADD_MSK = 0x40
PAYLOAD_POS = BLE_HEADER_LEN_POS

HEADER_LENGTH = 6
BLE_HEADER_LENGTH = 10

VALID_ADV_CHANS = [37, 38, 39]

PACKET_COUNTER_CAP = 2**16


class PacketReader(Notifications.Notifier):
    def __init__(self, portnum=None, callbacks=[], baudrate=None):
        Notifications.Notifier.__init__(self, callbacks)
        self.portnum = portnum
        try:
            self.uart = UART.Uart(portnum, baudrate)
        except serial.SerialException as e:
            logging.exception("Error opening UART %s" % str(e))
            self.uart = UART.Uart()
        self.packetCounter = 0
        self.lastReceivedPacketCounter = 0
        self.lastReceivedPacket = None
        self.lastReceivedTimestampPacket = None
        self.supportedProtocolVersion = PROTOVER_V3

    def setup(self):
        pass

    def doExit(self):
        # This method will always join the Uart worker thread
        self.uart.close()
        # Clear method references to avoid uncollectable cyclic references
        self.clearCallbacks()

    # This function takes a byte list, encode it in SLIP protocol and return the encoded byte list
    def encodeToSLIP(self, byteList):
        tempSLIPBuffer = []
        tempSLIPBuffer.append(SLIP_START)
        for i in byteList:
            if i == SLIP_START:
                tempSLIPBuffer.append(SLIP_ESC)
                tempSLIPBuffer.append(SLIP_ESC_START)
            elif i == SLIP_END:
                tempSLIPBuffer.append(SLIP_ESC)
                tempSLIPBuffer.append(SLIP_ESC_END)
            elif i == SLIP_ESC:
                tempSLIPBuffer.append(SLIP_ESC)
                tempSLIPBuffer.append(SLIP_ESC_ESC)
            else:
                tempSLIPBuffer.append(i)
        tempSLIPBuffer.append(SLIP_END)
        return tempSLIPBuffer

    # This function uses getSerialByte() function to get SLIP encoded bytes from the serial port and return a decoded byte list  
    # Based on https://github.com/mehdix/pyslip/
    def decodeFromSLIP(self, timeout=None, complete_timeout=None):
        dataBuffer = []
        startOfPacket = False
        endOfPacket = False

        if complete_timeout is not None:
            time_start = time.time()

        while not startOfPacket and (complete_timeout is None or (time.time() - time_start < complete_timeout)):
            res = self.getSerialByte(timeout)
            startOfPacket = (res == SLIP_START)

        while not endOfPacket and (complete_timeout is None or (time.time() - time_start < complete_timeout)):
            serialByte = self.getSerialByte(timeout)
            if serialByte == SLIP_END:
                endOfPacket = True
            elif serialByte == SLIP_ESC:
                serialByte = self.getSerialByte(timeout)
                if serialByte == SLIP_ESC_START:
                    dataBuffer.append(SLIP_START)
                elif serialByte == SLIP_ESC_END:
                    dataBuffer.append(SLIP_END)
                elif serialByte == SLIP_ESC_ESC:
                    dataBuffer.append(SLIP_ESC)
                else:
                    dataBuffer.append(SLIP_END)
            else:
                 dataBuffer.append(serialByte)
        if not endOfPacket:
            raise Exceptions.UARTPacketError("Exceeded max timeout of %f seconds." % complete_timeout)
        return dataBuffer

    # This function read byte chuncks from the serial port and return one byte at a time
    # Based on https://github.com/mehdix/pyslip/
    def getSerialByte(self, timeout=None):
        serialByte = self.uart.readByte(timeout)
        if serialByte is None:
            raise Exceptions.SnifferTimeout("Packet read timed out.")
        return serialByte

    def handlePacketHistory(self, packet):
        # Reads and validates packet counter
        if self.lastReceivedPacket is not None \
                and packet.packetCounter != (self.lastReceivedPacket.packetCounter + 1) % PACKET_COUNTER_CAP \
                and self.lastReceivedPacket.packetCounter != 0:

            logging.info("gap in packets, between " + str(self.lastReceivedPacket.packetCounter) + " and "
                         + str(packet.packetCounter) + " packet before: " + str(self.lastReceivedPacket.packetList)
                         + " packet after: " + str(packet.packetList))

        self.lastReceivedPacket = packet
        if packet.id in [EVENT_PACKET_DATA_PDU, EVENT_PACKET_ADV_PDU]:
            self.lastReceivedTimestampPacket = packet

    def getPacketTime(self, packet):
        ble_payload_length = self.lastReceivedPacket.payloadLength - BLE_HEADER_LENGTH

        if packet.phy == PHY_1M:
            return 8 * (1 + ble_payload_length)
        elif packet.phy == PHY_2M:
            return 4 * (2 + ble_payload_length)
        elif packet.phy == PHY_CODED:
            # blePacket is not assigned if not packet is "OK" (CRC error)
            ci = packet.packetList[BLEPACKET_POS + 4]
            fec2_block_len = ble_payload_length - 4 - 1
            fec1_block_us = 80 + 256 + 16 + 24
            if ci == PHY_CODED_CI_S8:
                return fec1_block_us + 64 * fec2_block_len + 24
            elif ci == PHY_CODED_CI_S2:
                return fec1_block_us + 16 * fec2_block_len + 6
        # Unknown PHY or Coding Indicator
        return 0

    def convertPacketListProtoVer2(self, packet):
        # Convert to version 2
        packet.packetList[PROTOVER_POS] = 2

        # Convert to common packet ID
        if packet.packetList[ID_POS] == EVENT_PACKET_ADV_PDU:
            packet.packetList[ID_POS] = EVENT_PACKET_DATA_PDU

        if packet.packetList[ID_POS] != EVENT_PACKET_DATA_PDU:
            # These types do not have a timestamp
            return

        # Convert time-stamp to End to Start delta
        time_delta = 0
        if self.lastReceivedTimestampPacket is not None and self.lastReceivedTimestampPacket.valid:
            time_delta = (packet.timestamp -
                          (self.lastReceivedTimestampPacket.timestamp +
                           self.getPacketTime(self.lastReceivedTimestampPacket)))

        time_delta = toLittleEndian(time_delta, 4)
        packet.packetList[TIMESTAMP_POS  ] = time_delta[0]
        packet.packetList[TIMESTAMP_POS+1] = time_delta[1]
        packet.packetList[TIMESTAMP_POS+2] = time_delta[2]
        packet.packetList[TIMESTAMP_POS+3] = time_delta[3]


    def handlePacketCompatibility(self, packet):
        if self.supportedProtocolVersion == PROTOVER_V2 and packet.packetList[PROTOVER_POS] > PROTOVER_V2:
            self.convertPacketListProtoVer2(packet)

    def setSupportedProtocolVersion(self, supportedProtocolVersion):
        if (supportedProtocolVersion != PROTOVER_V3):
            logging.info("Using packet compatibility, converting packets to protocol version %d", supportedProtocolVersion)
        self.supportedProtocolVersion = supportedProtocolVersion

    def getPacket(self, timeout=None):
        packetList = []
        try:
            packetList = self.decodeFromSLIP(timeout)
        except Exceptions.UARTPacketError:  # FIXME: This is never thrown...
            logging.exception("")
            return None
        else:
            packet = Packet(packetList)
            if packet.valid:
                self.handlePacketCompatibility(packet)
                self.handlePacketHistory(packet)
            return packet

    def sendPacket(self, id, payload):
        packetList = [HEADER_LENGTH] + [len(payload)] + [PROTOVER_V1] + toLittleEndian(self.packetCounter, 2) + [id] + payload
        packetList = self.encodeToSLIP(packetList)
        self.packetCounter += 1
        self.uart.writeList(packetList)

    def sendScan(self, findScanRsp = False, findAux = False, scanCoded = False):
        flags0 = findScanRsp | (findAux << 1) | (scanCoded << 2)
        self.sendPacket(REQ_SCAN_CONT, [flags0])
        logging.info("Scan flags: %s" % bin(flags0))

    def sendFollow(self, addr, followOnlyAdvertisements = False, followOnlyLegacy = False, followCoded = False):
        flags0 = followOnlyAdvertisements | (followOnlyLegacy << 1) | (followCoded << 2)
        logging.info("Follow flags: %s" % bin(flags0))
        self.sendPacket(REQ_FOLLOW, addr + [flags0])

    def sendPingReq(self):
        self.sendPacket(PING_REQ, [])

    def getBytes(self, value, size):
        if (len(value) < size):
            value = [0] * (size - len(value)) + value
        else:
            value = value[:size]

        return value

    def sendTK(self, TK):
        TK = self.getBytes(TK, 16)
        self.sendPacket(SET_TEMPORARY_KEY, TK)
        logging.info("Sent TK to sniffer: " + str(TK))

    def sendPrivateKey(self, pk):
        pk = self.getBytes(pk, 32)
        self.sendPacket(SET_PRIVATE_KEY, pk)
        logging.info("Sent private key to sniffer: " + str(pk))

    def sendLegacyLTK(self, ltk):
        ltk = self.getBytes(ltk, 16)
        self.sendPacket(SET_LEGACY_LONG_TERM_KEY, ltk)
        logging.info("Sent Legacy LTK to sniffer: " + str(ltk))

    def sendSCLTK(self, ltk):
        ltk = self.getBytes(ltk, 16)
        self.sendPacket(SET_SC_LONG_TERM_KEY, ltk)
        logging.info("Sent SC LTK to sniffer: " + str(ltk))

    def sendIRK(self, irk):
        irk = self.getBytes(irk, 16)
        self.sendPacket(SET_IDENTITY_RESOLVING_KEY, irk)
        logging.info("Sent IRK to sniffer: " + str(irk))

    def sendSwitchBaudRate(self, newBaudRate):
        self.sendPacket(SWITCH_BAUD_RATE_REQ, toLittleEndian(newBaudRate, 4))

    def switchBaudRate(self, newBaudRate):
        self.uart.switchBaudRate(newBaudRate)

    def sendHopSequence(self, hopSequence):
        for chan in hopSequence:
            if chan not in VALID_ADV_CHANS:
                raise Exceptions.InvalidAdvChannel("%s is not an adv channel" % str(chan))
        payload = [len(hopSequence)] + hopSequence + [37]*(3-len(hopSequence))
        self.sendPacket(SET_ADV_CHANNEL_HOP_SEQ, payload)
        self.notify("NEW_ADV_HOP_SEQ", {"hopSequence":hopSequence})

    def sendVersionReq(self):
        self.sendPacket(REQ_VERSION, [])

    def sendTimestampReq(self):
        self.sendPacket(REQ_TIMESTAMP, [])

    def sendGoIdle(self):
        self.sendPacket(GO_IDLE, [])


class Packet:
    def __init__(self, packetList):
        try:
            if not packetList:
                raise Exceptions.InvalidPacketException("packet list not valid: %s" % str(packetList))

            self.protover = packetList[PROTOVER_POS]

            if self.protover > PROTOVER_V3:
                logging.exception("Unsupported protocol version %s" % str(self.protover))
                raise RuntimeError("Unsupported protocol version %s" % str(self.protover))

            self.packetCounter = parseLittleEndian(packetList[PACKETCOUNTER_POS:PACKETCOUNTER_POS + 2])
            self.id = packetList[ID_POS]

            if int(self.protover) == PROTOVER_V1:
                self.payloadLength = packetList[PAYLOAD_LEN_POS_V1]
            else:
                self.payloadLength = parseLittleEndian(packetList[PAYLOAD_LEN_POS:PAYLOAD_LEN_POS + 2])

            self.packetList = packetList
            self.readPayload(packetList)

        except Exceptions.InvalidPacketException as e:
            logging.error("Invalid packet: %s" % str(e))
            self.OK = False
            self.valid = False
        except Exception as e:
            logging.exception("packet creation error %s" %str(e))
            logging.info("packetList: " + str(packetList))
            self.OK = False
            self.valid = False

    def __repr__(self):
        return "UART packet, type: "+str(self.id)+", PC: "+str(self.packetCounter)

    def readPayload(self, packetList):
        self.blePacket = None
        self.OK = False

        if not self.validatePacketList(packetList):
            raise Exceptions.InvalidPacketException("packet list not valid: %s" % str(packetList))
        else:
            self.valid = True

        self.payload = packetList[PAYLOAD_POS:PAYLOAD_POS+self.payloadLength]

        if self.id == EVENT_PACKET_ADV_PDU or self.id == EVENT_PACKET_DATA_PDU:
            try:
                self.bleHeaderLength = packetList[BLE_HEADER_LEN_POS]
                if self.bleHeaderLength == BLE_HEADER_LENGTH:
                    self.flags = packetList[FLAGS_POS]
                    self.readFlags()
                    self.channel = packetList[CHANNEL_POS]
                    self.rawRSSI = packetList[RSSI_POS]
                    self.RSSI = -self.rawRSSI
                    self.eventCounter = parseLittleEndian(packetList[EVENTCOUNTER_POS:EVENTCOUNTER_POS+2])

                    self.timestamp = parseLittleEndian(packetList[TIMESTAMP_POS:TIMESTAMP_POS+4])

                    # The hardware adds a padding byte which isn't sent on air.
                    # We remove it, and update the payload length in the packet list.
                    if self.phy == PHY_CODED:
                        self.packetList.pop(BLEPACKET_POS+6+1)
                    else:
                        self.packetList.pop(BLEPACKET_POS+6)
                    self.payloadLength -= 1
                    if self.protover >= PROTOVER_V2:
                        # Write updated payload length back to the packet list.
                        payloadLength = toLittleEndian(self.payloadLength, 2)
                        packetList[PAYLOAD_LEN_POS  ] = payloadLength[0]
                        packetList[PAYLOAD_LEN_POS+1] = payloadLength[1]
                    else: # PROTOVER_V1
                        packetList[PAYLOAD_LEN_POS_V1] = self.payloadLength
                else:
                    logging.info("Invalid BLE Header Length " + str(packetList))
                    self.valid = False

                if self.OK:
                    try:
                        if self.protover >= PROTOVER_V3:
                            packet_type = (PACKET_TYPE_ADVERTISING
                                           if self.id == EVENT_PACKET_ADV_PDU else
                                           PACKET_TYPE_DATA)
                        else:
                            packet_type = (PACKET_TYPE_ADVERTISING
                                           if packetList[BLEPACKET_POS : BLEPACKET_POS + 4] == ADV_ACCESS_ADDRESS else
                                           PACKET_TYPE_DATA)

                        self.blePacket = BlePacket(packet_type, packetList[BLEPACKET_POS:], self.phy)
                    except Exception as e:
                        logging.exception("blePacket error %s" % str(e))
            except Exception as e:
                # malformed packet
                logging.exception("packet error %s" % str(e))
                self.OK = False
        elif self.id == PING_RESP:
            if self.protover < PROTOVER_V3:
                self.version = parseLittleEndian(packetList[PAYLOAD_POS:PAYLOAD_POS+2])
        elif self.id == RESP_VERSION:
            self.version = ''.join([chr(i) for i in packetList[PAYLOAD_POS:]])
        elif self.id == RESP_TIMESTAMP:
            self.timestamp = parseLittleEndian(packetList[PAYLOAD_POS:PAYLOAD_POS+4])
        elif self.id == SWITCH_BAUD_RATE_RESP or self.id == SWITCH_BAUD_RATE_REQ:
            self.baudRate = parseLittleEndian(packetList[PAYLOAD_POS:PAYLOAD_POS+4])
        else:
            logging.info("Unknown packet ID")

    def readFlags(self):
        self.crcOK = not not (self.flags & 1)
        self.direction = not not (self.flags & 2)
        self.encrypted = not not (self.flags & 4)
        self.micOK = not not (self.flags & 8)
        self.phy = (self.flags >> 4) & 7
        self.OK = self.crcOK and (self.micOK or not self.encrypted)

    def getList(self):
        return self.packetList

    def validatePacketList(self, packetList):
        try:
            if (self.payloadLength + HEADER_LENGTH) == len(packetList):
                return True
            else:
                return False
        except:
            logging.exception("Invalid packet: %s" % str(packetList))
            return False

class BlePacket():
    def __init__(self, type, packetList, phy):
        self.type = type

        offset = 0
        offset = self.extractAccessAddress(packetList, offset)
        offset = self.extractFormat(packetList, phy, offset)

        if self.type == PACKET_TYPE_ADVERTISING:
            offset = self.extractAdvHeader(packetList, offset)
        else:
            offset = self.extractConnHeader(packetList, offset)

        offset = self.extractLength(packetList, offset)
        self.payload = packetList[offset:]

        if self.type == PACKET_TYPE_ADVERTISING:
            offset = self.extractAddresses(packetList, offset)
            self.extractName(packetList, offset)


    def __repr__(self):
        return "BLE packet, AAddr: "+str(self.accessAddress)

    def extractAccessAddress(self, packetList, offset):
        self.accessAddress = packetList[offset:offset+4]
        return offset + 4

    def extractFormat(self, packetList, phy, offset):
        self.coded = phy == PHY_CODED
        if self.coded:
            self.codingIndicator = packetList[offset] & 3
            return offset + 1

        return offset

    def extractAdvHeader(self, packetList, offset):
        self.advType = packetList[offset] & 15
        self.txAddrType = (packetList[offset] >> 6) & 1
        if self.advType in [1, 3, 5]:
            self.rxAddrType = (packetList[offset] << 7) & 1
        elif self.advType == 7:
            flags = packetList[offset + 2]
            if flags & 0x02:
                self.rxAddrType = (packetList[offset] << 7) & 1
        return offset + 1

    def extractConnHeader(self, packetList, offset):
        self.llid = packetList[offset] & 3
        self.sn = (packetList[offset] >> 2) & 1
        self.nesn = (packetList[offset] >> 3) & 1
        self.md = (packetList[offset] >> 4) & 1
        return offset + 1

    def extractAddresses(self, packetList, offset):
        addr = None
        scanAddr = None

        if self.advType in [0, 1, 2, 4, 6]:
            addr = packetList[offset:offset+6]
            addr.reverse()
            addr += [self.txAddrType]
            offset += 6

        if self.advType in [3, 5]:
            scanAddr = packetList[offset:offset+6]
            scanAddr.reverse()
            scanAddr += [self.txAddrType]
            offset += 6
            addr = packetList[offset:offset+6]
            addr.reverse()
            addr += [self.rxAddrType]
            offset += 6

        if self.advType == 1:
            scanAddr = packetList[offset:offset+6]
            scanAddr.reverse()
            scanAddr += [self.rxAddrType]
            offset += 6

        if self.advType == 7:
            ext_header_len = packetList[offset] & 0x3f
            offset += 1

            ext_header_offset = offset
            flags = packetList[offset]
            ext_header_offset += 1

            if flags & 0x01:
                addr = packetList[ext_header_offset:ext_header_offset+6]
                addr.reverse()
                addr += [self.txAddrType]
                ext_header_offset += 6

            if flags & 0x02:
                scanAddr = packetList[ext_header_offset:ext_header_offset+6]
                scanAddr.reverse()
                scanAddr += [self.rxAddrType]
                ext_header_offset += 6

            offset += ext_header_len

        self.advAddress = addr
        self.scanAddress = scanAddr
        return offset

    def extractName(self, packetList, offset):
        name = ""
        if self.advType in [0, 2, 4, 6, 7]:
            i = offset
            while i < len(packetList):
                length = packetList[i]
                if (i+length+1) > len(packetList) or length == 0:
                    break
                type = packetList[i+1]
                if type == 8 or type == 9:
                    nameList = packetList[i+2:i+length+1]
                    name = ""
                    for j in nameList:
                        name += chr(j)
                i += (length+1)
            name = '"'+name+'"'
        elif (self.advType == 1):
            name = "[ADV_DIRECT_IND]"

        self.name = name

    def extractLength(self, packetList, offset):
        self.length = packetList[offset]
        return offset + 1

def parseLittleEndian(list):
    total = 0
    for i in range(len(list)):
        total+=(list[i] << (8*i))
    return total

def toLittleEndian(value, size):
    list = [0]*size
    for i in range(size):
        list[i] = (value >> (i*8)) % 256
    return list

