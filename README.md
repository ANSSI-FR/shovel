# Shovel

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
  - use a single SQLite database,
  - on disk TCP/UDP/HTTP payload deduplication,
  - filters based on libmagic, e.g. quickly filter flows containing PDF documents or PNG images,
  - no heavy build tools needed, Shovel is easy to tweak.

Moreover, Shovel is batteries-included with Grafana visualizations and some Suricata alert rules.

## Setup

### 0. Before the Capture-the-Flag event begins

Copy `example.env` to `.env` and tweak the configuration parameters.
Also add the flag format in `suricata/custom.rules` if needed.

If you are playing a CTF using an IPv6 network, you might want to [enable IPv6 support in Docker deamon](https://docs.docker.com/config/daemon/ipv6/) before the CTF starts.

### 1. Network capture setup

You should place network captures in `input_pcaps/` folder.
Capture files should be splitted into chunks to be progressively imported.
If the CTF event does not already provide PCAP files, then you can adapt one
of the following commands for a GNU/Linux system:
```bash
ssh root@10.20.9.6 tcpdump -i wg-faustctf -n -w - 'tcp port not 22' | tcpdump -n -r - -G 30 -w input_pcaps/trace-%Y-%m-%d_%H-%M-%S.pcap
```
For a Microsoft Windows system, you may adapt the following command (3389 is RDP):
```powershell
.\tshark.exe -b duration:60 -w \\share\captures\trace -f "tcp port not 3389"
```

### 2. Launch Suricata and webapp via Docker (option A)

Start Suricata, the web application and Grafana using `docker compose up -d --build`.

Please note that restarting Suricata will cause all network capture files to be loaded again from zero.

### 2. Launch Suricata and webapp traditionally (option B)

You may launch Suricata then the web application using the following:
```bash
# Start Suricata
export $(grep -vE "^(#.*|\s*)$" .env)
./suricata/entrypoint.sh
```

```bash
# Start web app
export $(grep -vE "^(#.*|\s*)$" .env)
(cd webapp && uvicorn --host 0.0.0.0 main:app)
```

Please note that restarting Suricata will cause all network capture files to be loaded again from zero.

## Frequently Asked Questions

### Is Suricata `flow_id` really unique?

`flow_id` is derived from timestamp (ms scale) and current flow parameters (such
as source and destination ports and addresses). See source code:
<https://github.com/OISF/suricata/blob/suricata-6.0.13/src/flow.h#L680>.

### How do I reload rules without rebuilding the database?

You can edit suricata rules in `suricata/custom.rules`, then reload the rules
using:
```bash
kill -USR2 $(pidof suricata)
```

## Licensing

Copyright (C) 2023  ANSSI

Shovel is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3.

Shovel is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Shovel. If not, see <https://www.gnu.org/licenses/>.
