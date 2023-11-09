# SPDX-License-Identifier: GPL-3.0-only

FROM alpine:20230901
RUN apk add --no-cache suricata
COPY . /suricata
CMD ["/suricata/entrypoint.sh"]
