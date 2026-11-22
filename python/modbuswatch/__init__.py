"""modbuswatch — passive Modbus/TCP posture monitor + LoRaWAN backhaul tier
(vendored; Solarflere). Receive-only.

Package layout: parser (MBAP+PDU decode, MBW-030 framing check), state (flow
keys, learn-then-arm Modbus baseline, sweep/enum/UMAS trackers, plus the LoRa
gateway census / server / DevNonce / FCnt trackers), findings (registry +
detector engine — `feed` for Modbus, `feed_lora` for the backhaul tier),
sensor (scapy pcap/live driver, dual-stack TCP and UDP), lora (hand-rolled
Semtech GWMP + LoRaWAN PHYPayload decoder), fingerprint (LoRaWAN device/gateway
fingerprinting over the bundled IEEE OUI snapshot oui_snapshot.dat — DevEUI /
gateway vendor, JoinEUI, DevAddr→NetID→operator, regional band, per-DevAddr
behaviour), modbuswatch (standalone CLI entrypoint).

Ragnar's in-app adapters in network_diagnostics.py are do_modbus_watch (the
learn-then-arm Modbus scan) and do_lorawan_watch (the LoRaWAN backhaul scan,
no learning window) — two separate buttons on the Modbus & LoRaWAN Watch card.
"""
