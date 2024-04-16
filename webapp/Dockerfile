# Copyright (C) 2023  ANSSI
# SPDX-License-Identifier: GPL-3.0-only

FROM alpine:3.19
# TODO: remove py3-click, py3-asgiref, py3-h11 and custom pip command when alpine 3.20 will be released
RUN apk add --no-cache py3-aiosqlite py3-jinja2 py3-starlette py3-uvloop py3-click py3-asgiref py3-h11 py3-pip && \
  pip install --no-cache-dir --break-system-packages uvicorn~=0.29.0
COPY . /webapp
WORKDIR /webapp
CMD ["uvicorn", "--host", "0.0.0.0", "main:app"]
