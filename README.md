# Shovel

<!--
Copyright (C) 2023-2024  ANSSI
SPDX-License-Identifier: CC0-1.0
-->

Shovel is a web application that offers a graphical user interface to explore
[Suricata EVE outputs](https://docs.suricata.io/en/suricata-7.0.1/output/eve/eve-json-output.html).
Its primary focus is to help [Capture-the-Flag players](https://en.wikipedia.org/wiki/Capture_the_flag_(cybersecurity))
analyse network traffic dumps during stressful and time-limited attack-defense games such as
[FAUSTCTF](https://faustctf.net/) or [ECSC](https://ecsc.eu/).
Shovel is developed in the context of
[ECSC Team France](https://ctftime.org/team/159269/) training.

![Shovel during ENOWARS7](./.github/demo.webp)

You might also want to have a look at these other awesome traffic analyser tools:

  - https://github.com/secgroup/flower (first commit in 2018)
  - https://github.com/eciavatta/caronte (first commit in 2020)
  - https://github.com/OpenAttackDefenseTools/tulip (fork from flower in May 2022)

Compared to these traffic analyser tools, Shovel relies on Suricata while making
some opinionated choices for the frontend. This has a few nice implications:

  - dissection of all application protocols already supported by Suricata (TCP and UDP),
  - flows payloads and dissections are stored inside SQLite databases for fast queries,
  - filters based on libmagic, e.g. quickly filter flows containing PDF documents or PNG images,
  - no heavy build tools needed, Shovel is easy to tweak.

Moreover, Shovel is batteries-included with some Suricata alert rules.

```
      ┌────────────────────────┐
      │ Suricata with:         │   eve.db    ┌───────────────┐
pcap  │  - Eve SQLite plugin   ├────────────►│               │
─────►│  - TCP payloads plugin │ payload.db  │ Python webapp │
      │  - UDP payloads plugin ├────────────►│               │
      └────────────────────────┘             └────▲──────────┘
                                            .env  │
                                            ──────┘
```

## Setup

### 0. Before the Capture-the-Flag event begins

Copy `example.env` to `.env` and update the configuration parameters.
Also add the flag format in `suricata/rules/suricata.rules` if needed.

If you are playing a CTF using an IPv6 network, you might want to [enable IPv6 support in Docker deamon](https://docs.docker.com/config/daemon/ipv6/) before the CTF starts.

### 1. Network capture setup

You should place network captures in `input_pcaps/` folder.
Capture files should be splitted into chunks to be progressively imported.
If the CTF event does not already provide PCAP files, then you may adapt the
following command for a GNU/Linux system (22 is SSH):
```bash
ssh root@10.20.9.6 tcpdump -i game -n -w - 'tcp port not 22' | tcpdump -n -r - -G 30 -w input_pcaps/trace-%Y-%m-%d_%H-%M-%S.pcap
```
For a Microsoft Windows system, you may adapt the following command (3389 is RDP):
```powershell
.\tshark.exe -b duration:60 -w \\share\captures\trace -f "tcp port not 3389"
```

### 2. Launch Suricata and webapp via Docker (option A)

Start Suricata and the web application using `docker compose up -d --build`.

By default, all services are only accessible from `localhost`.
You should edit `docker-compose.yml` if you want to expose some services to your local network.

Please note that restarting Suricata will cause all network capture files to be loaded again.
This is fine, but it might add some delay before observing new flows.

### 2. Launch Suricata and webapp traditionally (option B)

You may launch Suricata then the web application using the following:
```bash
# Start Suricata
./suricata/entrypoint.sh -r input_pcaps --pcap-file-continuous
```

```bash
# Start web app
export $(grep -vE "^(#.*|\s*)$" .env)
(cd webapp && uvicorn --host 127.0.0.1 main:app)
```

Please note that restarting Suricata will cause all network capture files to be loaded again.
This is fine, but it might add some delay before observing new flows.

## Frequently Asked Questions

### Is Suricata `flow_id` really unique?

`flow_id` is derived from timestamp (ms scale) and current flow parameters (such
as source and destination ports and addresses). See source code:
<https://github.com/OISF/suricata/blob/suricata-6.0.13/src/flow.h#L680>.

### How do I reload rules without restarting Suricata?

You can edit suricata rules in `suricata/rules/suricata.rules`, then reload the rules
using:
```bash
kill -USR2 $(pidof suricata)
```
