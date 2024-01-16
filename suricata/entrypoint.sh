#!/bin/sh
# Copyright (C) 2023  ANSSI
# SPDX-License-Identifier: GPL-3.0-only

echo "Cleaning previous Suricata output"
rm -f suricata/output/eve.json suricata/output/tcpstore.log suricata/output/udpstore.log

SURICATA_PARAM="--runmode=single --no-random"
if [ "${PCAP_FILE_CONTINUOUS:=true}" = true ]; then
    SURICATA_PARAM="${SURICATA_PARAM} --pcap-file-continuous"
fi
echo "Starting Suricata with HOME_NET=$CTF_HOME_NET PCAP_FILE=$PCAP_FILE PCAP_FILE_CONTINUOUS=$PCAP_FILE_CONTINUOUS"
suricata -c suricata/suricata.yaml -r input_pcaps -l suricata/output \
    --set vars.address-groups.HOME_NET="${CTF_HOME_NET}" \
    --set outputs.1.eve-log.pcap-file=${PCAP_FILE:=true} \
    ${SURICATA_PARAM}
