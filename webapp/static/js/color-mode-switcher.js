'use strict'
/* eslint-env browser */

/*
 * Copyright (C) 2024  ANSSI
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * Get user preferred theme from their past choice or browser
 * @returns {String} User preferred theme
 */
function getPreferredTheme () {
  const storedTheme = localStorage.getItem('theme')
  if (storedTheme) {
    return storedTheme
  }
  // Privacy-hardened browsers always return light
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

// Change body theme early to prevent flash
let currentTheme = getPreferredTheme()
document.documentElement.setAttribute('data-bs-theme', currentTheme)

// On browser color-scheme change, update
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  currentTheme = getPreferredTheme()
  document.documentElement.setAttribute('data-bs-theme', currentTheme)
})

window.addEventListener('load', () => {
  // Toggle on T key, ignore input fields or key repeat
  document.addEventListener('keydown', e => {
    if (e.target.tagName !== 'INPUT' && !e.repeat && !e.ctrlKey && e.key === 't') {
      currentTheme = currentTheme === 'light' ? 'dark' : 'light'
      document.documentElement.setAttribute('data-bs-theme', currentTheme)
      localStorage.setItem('theme', currentTheme)
      e.preventDefault()
    }
  })
})
