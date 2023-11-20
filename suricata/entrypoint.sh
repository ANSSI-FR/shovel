#!/bin/sh
# Copyright (C) 2023  ANSSI
# SPDX-License-Identifier: GPL-3.0-only

echo "Cleaning previous Suricata output"
rm -f suricata/output/eve.json suricata/output/tcpstore.log suricata/output/udpstore.log

echo "Starting Suricata with HOME_NET=$CTF_HOME_NET"
suricata -c suricata/suricata.yaml -r input_pcaps -l suricata/output --set vars.address-groups.HOME_NET="$CTF_HOME_NET" --runmode=single --no-random --pcap-file-continuous
