# Copyright (C) 2023-2024  ANSSI
# SPDX-License-Identifier: CC0-1.0
FROM alpine:3.20
RUN apk add --no-cache py3-aiosqlite py3-jinja2 py3-starlette py3-uvloop uvicorn
COPY . /webapp
WORKDIR /webapp
CMD ["uvicorn", "--host", "0.0.0.0", "main:app"]
