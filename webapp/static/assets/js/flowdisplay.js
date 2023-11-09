'use strict'

/*
 * Copyright (C) 2023  ANSSI
 * SPDX-License-Identifier: GPL-3.0-only
 */

import Api from './api.js'

const MAGIC_EXT = {
  'ASCII text': 'txt',
  'GIF image': 'gif',
  'HTML document': 'html',
  'JPEG image': 'jpg',
  'JSON text data': 'json',
  'PDF document': 'pdf',
  'PNG image': 'png',
  'SVG Scalable Vector Graphics image': 'svg'
}

/**
 * Flow display
 */
class FlowDisplay {
  constructor () {
    this.apiClient = new Api()

    // On new flow selected, update display
    window.addEventListener('locationchange', () => this.update())

    // Load config
    const appData = document.getElementById('app').dataset
    this.startTs = Math.floor(Date.parse(appData.startDate) / 1000)
    this.tickLength = Number(appData.tickLength)

    // On V key, switch view
    document.addEventListener('keydown', e => {
      if (e.target.tagName !== 'INPUT' && !e.ctrlKey && !e.altKey && e.code === 'KeyV') {
        if (document.getElementById('display-raw-hex-tab').classList.contains('active')) {
          document.getElementById('display-raw-utf8-tab').click()
        } else {
          document.getElementById('display-raw-hex-tab').click()
        }
        e.preventDefault()
      }
    })
  }

  /**
   * Get extension from libmagic output
   * @param {String} magic
   * @returns Extension corresponding to this magic
   */
  getExtFromMagic (magic) {
    for (const [magicPrefix, ext] of Object.entries(MAGIC_EXT)) {
      if (magic.startsWith(magicPrefix)) {
        return ext
      }
    }
    return 'bin'
  }

  /**
   * Render a `hexdump -C` like output
   * @param {Uint8Array} byteArray
   * @returns String representation
   */
  renderHexDump (byteArray) {
    let hexdump = ''

    const asciiRepr = slice => {
      let ascii = ''
      slice.forEach((b) => {
        if (b >= 0x20 && b < 0x7F) {
          ascii += String.fromCharCode(b)
        } else {
          ascii += '.'
        }
      })
      return ascii
    }

    byteArray.forEach((b, i) => {
      if (i % 16 === 0) {
        hexdump += i.toString(16).padStart(8, '0') + '  '
      }

      hexdump += b.toString(16).padStart(2, '0') + ' '

      if (i % 16 === 15 || i === byteArray.length - 1) {
        if (i % 16 !== 15) {
          hexdump += ' '.repeat((15 - (i % 16)) * 3)
          if (i % 16 < 8) {
            hexdump += ' '
          }
        }
        const sliceStart = Math.floor(i / 16) * 16
        const slice = byteArray.slice(sliceStart, sliceStart + 16)
        hexdump += ` |${asciiRepr(slice)}|\n`
      } else if (i % 8 === 7) {
        hexdump += ' '
      }
    })

    hexdump += `${byteArray.length.toString(16).padStart(8, '0')}\n`
    return hexdump
  }

  async update () {
    // Show welcome page when no flows are selected
    const url = new URL(document.location)
    const flowId = url.searchParams.get('flow')
    document.getElementById('display-welcome').classList.toggle('d-none', flowId !== null)
    document.getElementById('display-flow').classList.add('d-none')
    document.getElementById('display-alerts').classList.add('d-none')
    document.getElementById('display-app').classList.add('d-none')
    document.getElementById('display-raw').classList.add('d-none')
    if (flowId === null) {
      document.title = 'Shovel'
      return
    }
    const flow = await this.apiClient.getFlow(flowId)

    // Format flow data
    const tick = Math.floor((flow.flow.ts_start / 1000 - this.startTs) / this.tickLength)
    const dateParams = {
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
      fractionalSecondDigits: 3
    }
    const dateStart = new Date(flow.flow.ts_start)
    const formatedDateStart = new Intl.DateTimeFormat('en-US', dateParams).format(dateStart)
    const dateEnd = new Date(flow.flow.ts_end)
    const formatedDateEnd = new Intl.DateTimeFormat('en-US', dateParams).format(dateEnd)

    // Change document title
    document.title = `Tick ${tick} - ${flow.flow.dest_ipport} - Shovel`

    // Flow card
    document.getElementById('display-flow').classList.remove('d-none')
    document.querySelector('#display-flow > header > span').textContent = `${flow.flow.proto} flow, ${flow.flow.src_ipport} ➔ ${flow.flow.dest_ipport}`
    document.querySelector('#display-flow > header > a').href = `static/${flow.flow.pcap_filename}`
    const flowBody = document.querySelector('#display-flow > pre')
    flowBody.title = `${flow.flow.ts_start} - ${flow.flow.ts_end}`
    flowBody.textContent = `Tick ${tick}, from ${formatedDateStart} to ${formatedDateEnd}`
    flowBody.textContent += `\nClient sent ${flow.flow.pkts_toserver} packets (${flow.flow.bytes_toserver} bytes), server replied with ${flow.flow.pkts_toclient} packets (${flow.flow.bytes_toclient} bytes).`

    // Alert and anomaly cards
    const alertsDiv = document.getElementById('display-alerts')
    while (alertsDiv.lastChild) {
      alertsDiv.removeChild(alertsDiv.lastChild)
    }
    alertsDiv.classList.remove('d-none')
    flow.alert?.forEach(data => {
      if (data.signature !== 'tag') {
        const cardEl = document.createElement('div')
        cardEl.classList.add('card', 'm-3', 'bg-secondary-subtle', 'font-monospace', `border-${data.color}`)
        const cardHeader = document.createElement('div')
        cardHeader.classList.add('card-header')
        cardHeader.textContent = data.signature
        cardEl.appendChild(cardHeader)
        alertsDiv.appendChild(cardEl)
      }
    })
    flow.anomaly?.forEach(data => {
      const cardEl = document.createElement('div')
      cardEl.classList.add('card', 'm-3', 'bg-secondary-subtle', 'font-monospace', 'border-warning')
      const cardHeader = document.createElement('div')
      cardHeader.classList.add('card-header')
      cardHeader.textContent = `Anomaly! ${JSON.stringify(data)}`
      cardEl.appendChild(cardHeader)
      alertsDiv.appendChild(cardEl)
    })

    // Application protocol card
    const appProto = flow.flow.app_proto
    if (appProto && appProto !== 'failed' && flow[appProto] !== undefined) {
      document.getElementById('display-app').classList.remove('d-none')
      document.querySelector('#display-app > header > a').classList.toggle('d-none', appProto !== 'http')
      const body = document.querySelector('#display-app > div > pre')
      body.textContent = ''
      if (appProto === 'http' || appProto === 'http2') {
        document.querySelector('#display-app > header > span > span').textContent = 'HTTP'
        document.querySelector('#display-app > header > a').href = `api/replay-http/${flowId}`
        let txCount = 0
        flow[appProto].forEach(data => {
          const linkEl = document.createElement('a')
          linkEl.classList.add('text-decoration-none')
          linkEl.href = `#fileinfo-${txCount}`
          linkEl.textContent = `${data.http_method ?? '?'} http://${data.hostname}:${data.http_port ?? flow.flow.dest_port}${data.url ?? ''}, protocol: ${data.protocol ?? '?'}, response code: ${data.status ?? '?'}\n`
          body.appendChild(linkEl)
          txCount += 1
        })
      } else if (appProto === 'ssh') {
        document.querySelector('#display-app > header > span > span').textContent = 'SSH'
        flow.ssh?.forEach(data => {
          body.textContent += `${data.client.software_version} (SSH ${data.client.proto_version}) ➔ ${data.server.software_version} (SSH ${data.server.proto_version})\n`
        })
      } else if (appProto === 'tls') {
        document.querySelector('#display-app > header > span > span').textContent = 'TLS'
        flow.tls?.forEach(data => {
          body.textContent = `SNI:         ${data.sni}`
          body.textContent += data.session_resumed ? '\nSession resumed' : ''
          body.textContent += data.subject ? `\nSubject:     ${data.subject}` : ''
          body.textContent += data.issuerdn ? `\nIssuerDn:    ${data.issuerdn}` : ''
          body.textContent += data.fingerprint ? `\nFingerprint: ${data.fingerprint}` : ''
          body.textContent += data.serial ? `\nSerial:      ${data.serial}` : ''
          body.textContent += data.notbefore ? `\nValidity from ${data.notbefore} to ${data.notafter}` : ''
        })
      } else {
        document.querySelector('#display-app > header > span > span').textContent = appProto.toUpperCase()
        flow[appProto].forEach(data => {
          body.textContent += `${JSON.stringify(data)}\n`
        })
      }
    }

    // Fileinfo cards
    const fileinfoDiv = document.getElementById('display-fileinfos')
    while (fileinfoDiv.lastChild) {
      fileinfoDiv.removeChild(fileinfoDiv.lastChild)
    }
    flow.fileinfo?.forEach(data => {
      let mainEl
      const fileHref = `static/filestore/${data.sha256.slice(0, 2)}/${data.sha256}`
      const ext = this.getExtFromMagic(data.magic)
      const cardBtns = document.createElement('span')
      if (['gif', 'jpg', 'png', 'svg'].includes(ext)) {
        mainEl = document.createElement('img')
        mainEl.classList.add('img-payload')
        mainEl.src = fileHref
      } else if (ext === 'pdf') {
        mainEl = document.createElement('iframe')
        mainEl.width = 500
        mainEl.height = 700
        fetch(fileHref, {}).then((d) => d.blob()).then((blob) => {
          blob = blob.slice(0, blob.size, 'application/pdf')
          const objectURL = URL.createObjectURL(blob)
          mainEl.src = objectURL
        })
      } else if (['html', 'json', 'txt'].includes(ext)) {
        mainEl = document.createElement('code')
        fetch(fileHref, {}).then((d) => d.text()).then((d) => {
          mainEl.textContent = d
        })
      } else {
        // Unknown format, also prepare hexdump view
        mainEl = document.createElement('div')
        const utf8View = document.createElement('code')
        const hexView = document.createElement('code')
        fetch(fileHref, {}).then((d) => d.arrayBuffer()).then((d) => {
          const byteArray = new Uint8Array(d)
          const utf8Decoder = new TextDecoder()
          utf8View.textContent = utf8Decoder.decode(byteArray)
          hexView.textContent = this.renderHexDump(byteArray)
          hexView.classList.add('d-none')
          mainEl.appendChild(utf8View)
          mainEl.appendChild(hexView)
        })

        // Add utf-8/hex switch button
        const switchViewBtn = document.createElement('a')
        switchViewBtn.classList.add('text-nowrap')
        switchViewBtn.classList.add('pe-2')
        switchViewBtn.href = '#'
        switchViewBtn.textContent = 'Hex'
        switchViewBtn.addEventListener('click', e => {
          const wasHex = utf8View.classList.contains('d-none')
          hexView.classList.toggle('d-none', wasHex)
          utf8View.classList.toggle('d-none', !wasHex)
          e.target.textContent = wasHex ? 'Hex' : 'UTF-8'
          e.preventDefault()
        })
        cardBtns.appendChild(switchViewBtn)
      }

      const downloadBtn = document.createElement('a')
      downloadBtn.classList.add('text-nowrap')
      downloadBtn.href = fileHref
      downloadBtn.download = `${data.filename?.replace(/[^A-Za-z0-9]/g, '_')}.${ext}`
      downloadBtn.textContent = 'Download file'
      cardBtns.appendChild(downloadBtn)

      const cardHeader = document.createElement('header')
      cardHeader.classList.add('card-header', 'd-flex', 'justify-content-between')
      cardHeader.textContent = `File ${data.filename}, ${data.magic}`
      cardHeader.appendChild(cardBtns)
      const cardBody = document.createElement('pre')
      cardBody.classList.add('card-body', 'mb-0')
      cardBody.appendChild(mainEl)
      const cardEl = document.createElement('div')
      cardEl.classList.add('card', 'm-3', 'bg-secondary-subtle', 'font-monospace', 'border-warning')
      cardEl.id = `fileinfo-${data.tx_id}`
      cardEl.appendChild(cardHeader)
      cardEl.appendChild(cardBody)
      fileinfoDiv.appendChild(cardEl)
    })

    // Raw data card
    const proto = flow.flow.proto.toLowerCase()
    if (proto === 'tcp' || proto === 'udp') {
      const promises = flow.raw.map(async (data) => {
        // TODO: automatically switch to hex view when the UTF-8 is invalid
        let d = await fetch(`static/${proto}store/${data.sha256.slice(0, 2)}/${data.sha256}`, {})
        d = await d.arrayBuffer()
        const byteArray = new Uint8Array(d)
        const utf8Decoder = new TextDecoder()
        return {
          data: {
            utf8: utf8Decoder.decode(byteArray),
            hex: this.renderHexDump(byteArray)
          },
          direction: data.server_to_client
        }
      })
      if (promises.length) {
        document.getElementById('display-raw').classList.remove('d-none')
        document.getElementById('display-raw-replay').href = `api/replay-${proto}/${flowId}`

        const utf8View = document.getElementById('display-raw-utf8')
        const hexView = document.getElementById('display-raw-hex')
        utf8View.textContent = 'Loading...'
        hexView.textContent = 'Loading...'
        Promise.all(promises).then(results => {
          utf8View.textContent = ''
          hexView.textContent = ''
          results.forEach(e => {
            const codeElUtf8 = document.createElement('code')
            codeElUtf8.classList.add('text-white')
            codeElUtf8.classList.toggle('bg-danger', e.direction === 0)
            codeElUtf8.classList.toggle('bg-success', e.direction === 1)
            codeElUtf8.textContent = e.data.utf8
            utf8View.appendChild(codeElUtf8)

            const codeElHex = document.createElement('code')
            codeElHex.classList.add('text-white')
            codeElHex.classList.toggle('bg-danger', e.direction === 0)
            codeElHex.classList.toggle('bg-success', e.direction === 1)
            codeElHex.textContent = e.data.hex
            hexView.appendChild(codeElHex)
          })
        })
      }
    }
  }
}

const flowDisplay = new FlowDisplay()
flowDisplay.update()
