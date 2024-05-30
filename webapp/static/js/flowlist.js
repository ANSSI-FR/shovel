'use strict'

/*
 * Copyright (C) 2023  ANSSI
 * SPDX-License-Identifier: GPL-3.0-only
 */

import Api from './api.js'

/**
 * Flow list sidebar
 *
 * Triggers 'locationchange' event on the window to update flow display.
 */
class FlowList {
  constructor () {
    this.apiClient = new Api()
    const url = new URL(document.location)
    this.selectedFlowId = url.searchParams.get('flow')
  }

  async init () {
    // On left/right arrow keys, go to previous/next flow
    document.addEventListener('keydown', e => {
      if (e.target.tagName !== 'INPUT' && !e.ctrlKey && !e.altKey) {
        switch (e.code) {
          case 'ArrowLeft':
            if (this.selectedFlowId) {
              let prevElem = document.querySelector('#flow-list a.active')?.previousElementSibling
              if (prevElem && prevElem.tagName.toLowerCase() === 'span') {
                prevElem = prevElem.previousElementSibling
              }
              prevElem?.click()
            } else {
              document.querySelector('#flow-list a')?.click()
            }
            e.preventDefault()
            break
          case 'ArrowRight':
            if (this.selectedFlowId) {
              let nextElem = document.querySelector('#flow-list a.active')?.nextElementSibling
              if (nextElem && nextElem.tagName.toLowerCase() === 'span') {
                nextElem = nextElem.nextElementSibling
              }
              nextElem?.click()
            } else {
              document.querySelector('#flow-list a')?.click()
            }
            e.preventDefault()
            break
        }
      }
    })

    // On flow click, update URL and dispatch 'locationchange' event
    document.getElementById('flow-list').addEventListener('click', e => {
      if (!e.ctrlKey) {
        const newFlowId = e.target.closest('a')?.dataset?.flow
        if (newFlowId && this.selectedFlowId !== newFlowId) {
          this.selectedFlowId = newFlowId
          window.history.pushState(null, '', e.target.closest('a').href)
          window.dispatchEvent(new Event('locationchange'))
        }
        e.preventDefault()
      }
    })

    // On load more button click, update URL then update flows list
    document.getElementById('flow-list-show-older').addEventListener('click', async e => {
      const lastFlowTs = document.getElementById('flow-list').lastElementChild?.dataset.ts_start
      const url = new URL(document.location)
      url.searchParams.set('to', Math.floor(lastFlowTs))
      window.history.pushState(null, '', url.href)
      await this.update()
      document.getElementById('flow-list').firstElementChild?.scrollIntoView()
      e.preventDefault()
    })

    // On browser history pop, dispatch 'locationchange' event, then update flows list
    window.addEventListener('popstate', e => {
      const url = new URL(document.location)
      const newFlowId = url.searchParams.get('flow')
      if (this.selectedFlowId !== newFlowId) {
        this.selectedFlowId = newFlowId
        window.dispatchEvent(new Event('locationchange'))
      }
      this.update()
    })

    // On 'locationchange' event, update active flow
    window.addEventListener('locationchange', _ => {
      this.updateActiveFlow()
    })

    // On services filter change, update URL then update flows list
    document.getElementById('services-select').addEventListener('change', e => {
      const url = new URL(document.location)
      url.searchParams.delete('service')
      e.target.value.split(',').forEach(s => {
        if (s) {
          url.searchParams.append('service', s)
        }
      })
      window.history.pushState(null, '', url.href)
      this.update()
    })

    // Don't close filter dropdown on click inside
    document.getElementById('dropdown-filter').addEventListener('click', e => {
      e.stopPropagation()
    })

    // On time filter change, update URL then update flows list
    document.getElementById('filter-time-until').addEventListener('change', e => {
      const untilTick = Number(e.target.value)
      const url = new URL(document.location)
      if (untilTick) {
        url.searchParams.set('to', Math.floor((untilTick + 1) * this.tickLength + this.startTs))
      } else {
        url.searchParams.delete('to')
        e.target.value = null
      }
      window.history.pushState(null, '', url.href)
      this.update()
    })

    // On protocol filter change, update URL then update flows list
    document.getElementById('filter-protocol').addEventListener('change', e => {
      const appProto = e.target.value
      const url = new URL(document.location)
      if (appProto) {
        url.searchParams.set('app_proto', appProto)
      } else {
        url.searchParams.delete('app_proto')
      }
      window.history.pushState(null, '', url.href)
      this.update()
    })

    // On glob search filter submit, update URL then update flows list
    document.getElementById('filter-search').addEventListener('keyup', e => {
      if (e.key !== 'Enter') {
        return
      }
      const search = e.target.value
      const url = new URL(document.location)
      if (search) {
        url.searchParams.set('search', search)
      } else {
        url.searchParams.delete('search')
      }
      window.history.pushState(null, '', url.href)
      this.update()
    })

    // On tags filter change, update URL then update flows list
    document.getElementById('filter-tag').addEventListener('click', e => {
      const tag = e.target.closest('a')?.dataset.tag
      if (tag) {
        const url = new URL(document.location)
        const activeTags = url.searchParams.getAll('tag')
        if (activeTags.includes(tag)) {
          // Remove tag
          url.searchParams.delete('tag')
          activeTags.forEach(t => {
            if (t !== tag) {
              url.searchParams.append('tag', t)
            }
          })
        } else {
          // Add tag
          url.searchParams.append('tag', tag)
        }
        window.history.pushState(null, '', url.href)
        this.update()
        e.preventDefault()
      }
    })

    // Trigger initial flows list update
    const appData = document.getElementById('app').dataset
    this.startTs = Math.floor(Date.parse(appData.startDate) / 1000)
    this.tickLength = Number(appData.tickLength)
    this.update()
  }

  /**
   * Pretty print delay
   * @param {Number} delay Delay in milliseconds
   * @returns Pretty string representation
   */
  pprintDelay (delay) {
    if (delay > 1000) {
      delay = delay / 1000
      return `${delay.toPrecision(3)} s`
    } else {
      return `${delay.toPrecision(3)} ms`
    }
  }

  /**
   * Pretty print service IP address and port
   * @param {String} ipport
   * @returns Pretty string representation
   */
  pprintService (ipport) {
    // Find name using service filter dataset
    const name = document.querySelector(`select#services-select optgroup[data-ipports~='${ipport}']`)?.label
    const port = ipport.split(':').slice(-1)
    if (name) {
      return `${name} (:${port})`
    } else {
      return ipport
    }
  }

  /**
   * Build tag element
   * @param {String} text Tag name
   * @param {String} color Tag color
   * @returns HTML element representing the tag
   */
  tagBadge (text, color) {
    const badge = document.createElement('span')
    badge.classList.add('badge', `text-bg-${color ?? 'none'}`, 'mb-1', 'me-1', 'p-1')
    badge.textContent = text
    return badge
  }

  /**
   * Update protocols in filters dropdown
   */
  async updateProtocolFilter (appProto) {
    const protocolSelect = document.getElementById('filter-protocol')

    // Empty select options
    while (protocolSelect.lastChild) {
      protocolSelect.removeChild(protocolSelect.lastChild)
    }

    // Add protocols
    const option = document.createElement('option')
    option.value = ''
    option.textContent = 'All'
    protocolSelect.appendChild(option)
    appProto.forEach((proto) => {
      const option = document.createElement('option')
      option.value = proto
      option.textContent = proto.toUpperCase()
      protocolSelect.appendChild(option)
    })

    // Update protocol filter select state
    const url = new URL(document.location)
    const current = url.searchParams.get('app_proto')
    protocolSelect.value = current ?? ''
    protocolSelect.classList.toggle('is-active', current !== null)
  }

  /**
   * Update tags in filters dropdown
   */
  updateTagFilter (tags) {
    // Empty dropdown content
    const tagFilterDropdown = document.getElementById('filter-tag')
    while (tagFilterDropdown.lastChild) {
      tagFilterDropdown.removeChild(tagFilterDropdown.lastChild)
    }

    tags.forEach(t => {
      // Create tag and append to dropdown
      const { tag, color } = t
      const url = new URL(document.location)
      const activeTags = url.searchParams.getAll('tag')
      const badge = this.tagBadge(tag, color)
      badge.classList.add('border', 'border-2')
      badge.classList.toggle('border-purple', activeTags.includes(tag))
      badge.classList.toggle('text-bg-purple', activeTags.includes(tag))
      const link = document.createElement('a')
      link.href = '#'
      link.dataset.tag = tag
      link.appendChild(badge)
      tagFilterDropdown.appendChild(link)
    })
  }

  /**
   * Empty and refill flows list
   */
  async updateFlowsList (flows, tags) {
    // Empty list
    const flowList = document.getElementById('flow-list')
    while (flowList.lastChild) {
      flowList.removeChild(flowList.lastChild)
    }

    // Fill list
    document.getElementById('flow-list').classList.remove('d-none')
    document.getElementById('flow-list-loading-indicator').classList.add('d-none')
    let lastTick = -1
    flows.forEach((flow) => {
      const date = new Date(flow.ts_start)
      const startDate = new Intl.DateTimeFormat(
        'en-US',
        { hour: 'numeric', minute: 'numeric', second: 'numeric', fractionalSecondDigits: 1 }
      ).format(date)
      const tick = Math.floor((flow.ts_start / 1000 - this.startTs) / this.tickLength)

      // Create tick element on new tick
      if (tick !== lastTick) {
        const tickEl = document.createElement('span')
        tickEl.classList.add('list-group-item', 'sticky-top', 'pt-3', 'pb-1', 'px-2', 'border-0', 'border-bottom', 'bg-light-subtle', 'text-center', 'fw-semibold')
        tickEl.textContent = `Tick ${tick}`
        flowList.appendChild(tickEl)
        lastTick = tick
      }

      // Build URL
      const url = new URL(document.location)
      url.searchParams.set('flow', flow.id)

      // Build DOM elements
      const flowEl = document.createElement('a')
      flowEl.classList.add('list-group-item', 'list-group-item-action', 'py-1', 'px-2', 'lh-sm', 'border-0', 'border-bottom')
      flowEl.href = url.href
      flowEl.dataset.flow = flow.id
      flowEl.dataset.ts_start = flow.ts_start / 1000

      const flowInfoDiv = document.createElement('div')
      flowInfoDiv.classList.add('d-flex', 'justify-content-between', 'mb-1')
      const flowInfoDiv1 = document.createElement('small')
      flowInfoDiv1.textContent = this.pprintService(flow.dest_ipport)
      const flowInfoDiv2 = document.createElement('small')
      flowInfoDiv2.textContent = `${this.pprintDelay(flow.ts_end - flow.ts_start)}, ${startDate}`
      flowInfoDiv.appendChild(flowInfoDiv1)
      flowInfoDiv.appendChild(flowInfoDiv2)
      flowEl.appendChild(flowInfoDiv)

      // Use application protocol (or 'raw') as first badge
      const appProto = flow.app_proto !== 'failed' ? flow.app_proto : null
      const badge = this.tagBadge((appProto ?? 'raw').toUpperCase())
      flowEl.appendChild(badge)

      const flowTags = flow.tags?.split(',')
      tags.forEach(t => {
        const { tag, color } = t
        if (flowTags?.includes(tag)) {
          const badge = this.tagBadge(tag, color)
          flowEl.appendChild(badge)
        }
      })

      flowList.appendChild(flowEl)
    })

    // Display a button if we are only displaying 100 flows
    document.getElementById('flow-list-show-older').classList.toggle('d-none', flows.length !== 100)
  }

  /**
   * Update highlighted flow in flows list
   */
  updateActiveFlow () {
    document.querySelector('#flow-list a.active')?.classList.remove('active')
    const linkElement = document.querySelector(`#flow-list a[data-flow="${this.selectedFlowId}"]`)
    linkElement?.classList.add('active')
    linkElement?.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' })
  }

  async update () {
    // Show loading indicator while waiting for API
    document.getElementById('flow-list-loading-indicator').classList.remove('d-none')
    document.getElementById('flow-list').classList.add('d-none')
    document.getElementById('flow-list-show-older').classList.add('d-none')

    const url = new URL(document.location)
    const fromTs = url.searchParams.get('from')
    const toTs = url.searchParams.get('to')
    const services = url.searchParams.getAll('service')
    const filterAppProto = url.searchParams.get('app_proto')
    const filterSearch = url.searchParams.get('search')
    const filterTags = url.searchParams.getAll('tag')
    const { flows, appProto, tags } = await this.apiClient.listFlows(
      fromTs ? Number(fromTs) : null,
      toTs ? Number(toTs) : null,
      services,
      filterAppProto,
      filterSearch,
      filterTags
    )

    // Update search input
    const searchInput = document.getElementById('filter-search')
    searchInput.value = filterSearch ?? ''
    searchInput.classList.toggle('is-active', filterSearch !== null)

    await this.updateProtocolFilter(appProto)
    this.updateTagFilter(tags)
    await this.updateFlowsList(flows, tags)
    this.updateActiveFlow()

    // Update filter dropdown visual indicator
    document.querySelector('#dropdown-filter > button').classList.toggle('text-bg-purple', toTs || filterTags.length || filterAppProto || filterSearch)

    // Update service filter select state
    document.getElementById('services-select').value = services.join(',')

    // Update time filter state
    if (toTs) {
      const toTick = (Number(toTs) - this.startTs) / this.tickLength - 1
      document.getElementById('filter-time-until').value = toTick
    }
    document.getElementById('filter-time-until').classList.toggle('is-active', toTs)
  }
}

const flowList = new FlowList()
flowList.init()
