# Copyright (C) 2023  ANSSI
# SPDX-License-Identifier: CC0-1.0

FROM alpine:3.19
RUN apk add --no-cache suricata lua5.1-sqlite
COPY . /suricata
CMD ["/suricata/entrypoint.sh"]
