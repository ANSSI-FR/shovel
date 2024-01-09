# Copyright (C) 2023  ANSSI
# SPDX-License-Identifier: GPL-3.0-only

FROM alpine:20231219
RUN apk add --no-cache py3-aiosqlite py3-jinja2 py3-starlette py3-uvloop uvicorn
COPY . /webapp
WORKDIR /webapp
CMD ["uvicorn", "--host", "0.0.0.0", "main:app"]
