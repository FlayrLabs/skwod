// The two decisions the join page makes about the device it is on. Pure, so they are tested.

/**
 * Whether to try `skwod://…` once on load, without waiting for a tap. Only where a miss is
 * silent: Safari (iPhone, iPad and Mac) answers an unknown scheme with an error dialog, so there
 * the person presses "Open in Skwod" themselves.
 */
export function shouldAutoOpen(platform, userAgent) {
  const safari = platform === 'ios' ||
    (platform === 'mac' && /^((?!Chrome|Chromium|Edg|Firefox|OPR).)*Safari/.test(userAgent || ''))
  return !safari
}

/** Which download button goes first: this device's, or the usual order on anything else. */
export function firstDownload(platform) {
  return ['mac', 'android', 'ios'].includes(platform) ? platform : null
}
