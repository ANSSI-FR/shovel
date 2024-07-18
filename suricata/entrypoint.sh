#!/bin/sh
# Copyright (C) 2024  ANSSI
# SPDX-License-Identifier: CC0-1.0

set -x

# Arguments override default Suricata configuration,
# see https://github.com/OISF/suricata/blob/suricata-7.0.5/suricata.yaml.in

SURICATA_PARAM="--runmode=single --no-random"
if [ "${PCAP_FILE_CONTINUOUS:=true}" = true ]; then
    SURICATA_PARAM="${SURICATA_PARAM} --pcap-file-continuous"
fi

SURICATA_PARAM="-S suricata/rules/suricata.rules \
    -l suricata/output \
    --set plugins.0=suricata/libeve_sqlite_output.so \
    --set outputs.0.fast.enabled=no \
    --set outputs.1.eve-log.filetype=sqlite \
    --set outputs.1.eve-log.filename=suricata/output/eve.db \
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
    --set outputs.12.lua.enabled=yes \
    --set outputs.12.lua.scripts.0=suricata/suricata-tcp-payload-sqlite-output.lua \
    --set outputs.12.lua.scripts.1=suricata/suricata-udp-payload-sqlite-output.lua \
    --set pcap-file.checksum-checks=no \
    --set app-layer.protocols.pgsql.enabled=yes \
    --set app-layer.protocols.modbus.enabled=yes \
    --set app-layer.protocols.dnp3.enabled=yes \
    --set app-layer.protocols.enip.enabled=yes \
    --set app-layer.protocols.sip.enabled=yes \
    --set stream.reassembly.depth=50mb"


echo "Starting Suricata with PCAP_FILE=${PCAP_FILE:=true} PCAP_FILE_CONTINUOUS=${PCAP_FILE_CONTINUOUS:=true}"

if [ ! -z "${PCAP_OVER_IP}" ]; then
    socat TCP:${PCAP_OVER_IP} STDOUT | suricata -r /dev/stdin ${SURICATA_PARAM}
else
    suricata -r input_pcaps ${SURICATA_PARAM}
fi


