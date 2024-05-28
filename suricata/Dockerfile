# Copyright (C) 2023-2024  ANSSI
# SPDX-License-Identifier: CC0-1.0
FROM alpine:3.20 AS builder
WORKDIR /src/
RUN apk add --no-cache cargo musl-dev
COPY ./suricata-eve-sqlite-output/ /src/
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release

FROM alpine:3.20
RUN apk add --no-cache suricata lua5.1-sqlite
COPY . /suricata
COPY --from=builder /src/target/release/libeve_sqlite_output.so /suricata/
CMD ["/suricata/entrypoint.sh"]
