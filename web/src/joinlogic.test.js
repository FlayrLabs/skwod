import test from 'node:test'
import assert from 'node:assert/strict'
import { shouldAutoOpen, firstDownload } from './joinlogic.js'

const safariMac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15'
const chromeMac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
const firefoxMac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0'

test('the app is tried on load everywhere except Safari', () => {
  assert.equal(shouldAutoOpen('ios', 'anything'), false)
  assert.equal(shouldAutoOpen('mac', safariMac), false)
  assert.equal(shouldAutoOpen('mac', chromeMac), true)
  assert.equal(shouldAutoOpen('mac', firefoxMac), true)
  assert.equal(shouldAutoOpen('android', 'Mozilla/5.0 (Linux; Android 15; Pixel 9) Chrome/131.0.0.0 Mobile Safari/537.36'), true)
  assert.equal(shouldAutoOpen('other', undefined), true)
})

test("this device's download goes first", () => {
  assert.equal(firstDownload('ios'), 'ios')
  assert.equal(firstDownload('android'), 'android')
  assert.equal(firstDownload('mac'), 'mac')
  assert.equal(firstDownload('other'), null)
})
