#!/bin/sh
# Copyright (C) 2024  ANSSI
# SPDX-License-Identifier: CC0-1.0

set -euo pipefail

SURICATA_CMD="suricata"
if [ -n "$PCAP_OVER_IP" ]; then
    PCAP_OVER_IP=$(echo "$PCAP_OVER_IP" | tr ":" " ")
    SURICATA_CMD="nc -d $PCAP_OVER_IP | $SURICATA_CMD"
fi

# Arguments override default Suricata configuration,
# see https://github.com/OISF/suricata/blob/suricata-7.0.5/suricata.yaml.in
eval "$SURICATA_CMD" \
    --runmode=single --no-random -k none \
    -S suricata/rules/suricata.rules \
    -l suricata/output \
    --set plugins.0=suricata/libeve_sqlite_output.so \
    --set outputs.0.fast.enabled=no \
    --set outputs.1.eve-log.filetype=sqlite \
    --set outputs.1.eve-log.pcap-file=${PCAP_FILE:=true} \
    --set outputs.1.eve-log.types.3.http.dump-all-headers=both \
    --set outputs.1.eve-log.types.6.files.force-hash.0=sha256 \
    --set outputs.1.eve-log.types.21.dhcp.extended=yes \
    --set outputs.1.eve-log.types.23.mqtt.passwords=yes \
    --set outputs.1.eve-log.types.25.pgsql.enabled=yes \
    --set outputs.1.eve-log.types.25.pgsql.passwords=yes \
    --set outputs.7.stats.enabled=no \
    --set outputs.9.file-store.enabled=yes \
    --set outputs.9.file-store.force-filestore=yes \
    --set outputs.9.file-store.stream-depth=0 \
    --set outputs.12.lua.enabled=yes \
    --set outputs.12.lua.scripts.0=suricata/suricata-tcp-payload-sqlite-output.lua \
    --set outputs.12.lua.scripts.1=suricata/suricata-udp-payload-sqlite-output.lua \
    --set app-layer.protocols.pgsql.enabled=yes \
    --set app-layer.protocols.modbus.enabled=yes \
    --set app-layer.protocols.dnp3.enabled=yes \
    --set app-layer.protocols.enip.enabled=yes \
    --set app-layer.protocols.sip.enabled=yes \
    --set app-layer.protocols.http.libhtp.default-config.request-body-limit=50mb \
    --set app-layer.protocols.http.libhtp.default-config.response-body-limit=0 \
    --set stream.reassembly.depth=50mb \
    --set flow-timeouts.tcp.established=60 \
    --set flow-timeouts.tcp.emergency-established=60 \
    --set flow-timeouts.tcp.closed=5 \
    --set flow-timeouts.tcp.emergency-closed=5 \
    "$@"
