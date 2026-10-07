"""modbuswatch — passive Modbus/TCP posture monitor (vendored; Solarflere).

Receive-only. Package layout: parser (MBAP+PDU decode, MBW-030 framing check),
state (flow keys, learn-then-arm baseline, sweep/enum/UMAS trackers), findings
(registry + detector engine), sensor (scapy pcap/live driver, dual-stack),
modbuswatch (standalone CLI entrypoint). Ragnar's in-app adapter is
do_modbus_watch in network_diagnostics.py.
"""
