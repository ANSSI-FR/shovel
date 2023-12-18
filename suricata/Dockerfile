# Copyright (C) 2023  ANSSI
# SPDX-License-Identifier: GPL-3.0-only

FROM alpine:3.19
RUN apk add --no-cache suricata
COPY . /suricata
CMD ["/suricata/entrypoint.sh"]
