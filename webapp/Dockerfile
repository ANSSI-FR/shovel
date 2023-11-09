# Copyright (C) 2023  ANSSI
# SPDX-License-Identifier: GPL-3.0-only

FROM alpine:20230329
RUN apk add --no-cache py3-jinja2 py3-uvloop && \
    apk add --no-cache -X http://dl-cdn.alpinelinux.org/alpine/edge/testing py3-aiosqlite py3-starlette uvicorn
COPY . /webapp
WORKDIR /webapp
CMD ["uvicorn", "--host", "0.0.0.0", "main:app"]
