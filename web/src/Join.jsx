import { useState, useEffect } from 'react'
import Downloads from './Downloads.jsx'
import { parseFragment, detectPlatform } from './invite.js'
import { shouldAutoOpen, firstDownload } from './joinlogic.js'

/* The join page: https://skwod.io/join#<node id>[.<join code>][&u=…][&l=…]

   It reads the invite from the URL fragment, which the browser keeps to itself, and hands it to
   the Skwod app as skwod://join/… (src/invite.js has the grammar). It makes no network request
   and stores nothing. The card is the one the site's old invite gate used (glass panel on the
   mesh background), so it reads as the same site. */

const platform = detectPlatform(typeof navigator === 'undefined' ? undefined : navigator)
let autoOpened = null // the app link already tried on load, so a re-render never tries it twice

const Shell = ({ wide = false, children }) => (
  <div className="relative min-h-screen font-body flex items-center justify-center px-6 py-10">
    <div className="mesh" /><div className="grain" />
    <div className="pointer-events-none absolute inset-0">
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 h-96 w-96 rounded-full bg-squid-indigo/20 blur-[130px]" />
    </div>
    <div className={`rise relative w-full ${wide ? 'max-w-[440px]' : 'max-w-[400px]'}`}>
      <div className="glass-strong rounded-[28px] px-8 py-10 text-center shadow-[0_40px_120px_-30px_rgba(58,107,255,0.5)]">
        <img src="/skwod-icon.png" alt="Skwod" width={64} height={64} className="rounded-2xl mx-auto mb-6" />
        {children}
        <p className="text-[12px] text-white/30 mt-6 font-mono">end-to-end encrypted · self-hosted</p>
      </div>
    </div>
  </div>
)

const HomeLink = () => (
  <a href="/" className="w-full rounded-full bg-white text-black font-semibold text-[15px] py-3 flex items-center justify-center gap-2 hover:bg-white/90 active:scale-[0.99] transition">
    See what Skwod is
  </a>
)

export default function Join() {
  const [hash, setHash] = useState(() => location.hash)
  const [copied, setCopied] = useState('')
  const invite = parseFragment(hash)
  const appLink = invite.ok ? invite.appLink : null

  useEffect(() => {
    const onHash = () => { setHash(location.hash); setCopied('') }
    addEventListener('hashchange', onHash)
    return () => removeEventListener('hashchange', onHash)
  }, [])

  // Try the app once without waiting for a tap, where a miss is silent.
  useEffect(() => {
    if (!appLink || autoOpened === appLink || !shouldAutoOpen(platform, navigator.userAgent)) return
    autoOpened = appLink
    location.href = appLink // always skwod://join/…, built from validated parts only
  }, [appLink])

  if (!invite.ok && invite.reason === 'demo') {
    return (
      <Shell wide>
        <h1 className="font-display font-extrabold text-[26px] tracking-tight text-white mb-2">
          This is a <span className="text-squid">demo</span> invite
        </h1>
        <p className="text-[14px] text-white/55 leading-snug mb-7">
          It came from the preview on our homepage, so there's no Skwod behind it. Download
          Skwod for Mac and click Start server to host your own, or ask a friend who hosts
          one for their invite.
        </p>
        <Downloads quiet first={firstDownload(platform)} />
        <div className="mt-6"><HomeLink /></div>
      </Shell>
    )
  }

  if (!invite.ok) {
    const missing = invite.reason === 'missing'
    return (
      <Shell>
        <h1 className="font-display font-extrabold text-[26px] tracking-tight text-white mb-2">
          {missing ? <>This link has <span className="text-squid">no invite</span> in it</> : <>This invite link is <span className="text-squid">damaged</span></>}
        </h1>
        <p className="text-[14px] text-white/55 leading-snug mb-7">
          {missing
            ? 'An invite link ends with a # followed by a long code. That part is missing here, most likely because the link was cut off when it was copied. Ask whoever invited you to send it again.'
            : 'The part after the # is not a valid Skwod invite, so nothing was opened. Part of the link was probably lost or changed on the way. Ask whoever invited you to send it again.'}
        </p>
        <HomeLink />
      </Shell>
    )
  }

  const copy = async () => {
    // The skwod:// form is copied because every build of the app accepts it when pasted.
    try {
      await navigator.clipboard.writeText(invite.appLink)
      setCopied('Copied. Paste it into Skwod.')
    } catch {
      setCopied('Copying is blocked here. Copy the address of this page instead.')
    }
  }

  return (
    <Shell wide>
      <h1 className="font-display font-extrabold text-[26px] tracking-tight text-white mb-2">
        You're invited to a <span className="text-squid">Skwod</span>
      </h1>
      <p className="text-[14px] text-white/55 leading-snug mb-7">
        Open this invite in the Skwod app to ask to join. It leads to the server with the
        key <span className="font-mono text-white/85">{invite.shortKey}</span>.
      </p>

      <div className="flex flex-col gap-3">
        <a href={invite.appLink}
          className="w-full rounded-full bg-white text-black font-semibold text-[15px] py-3 flex items-center justify-center gap-2 hover:bg-white/90 active:scale-[0.99] transition">
          Open in Skwod
        </a>
        <button type="button" onClick={copy}
          className="w-full rounded-full glass text-white/80 font-semibold text-[15px] py-3 flex items-center justify-center gap-2 hover:bg-white/[0.08] active:scale-[0.99] transition">
          Copy invite
        </button>
        <p role="status" className="text-[13px] text-white/55 min-h-[18px]">{copied}</p>
      </div>

      <p className="text-[13px] text-white/45 mt-3 mb-4">Don't have Skwod yet? Install it, then come back and press Open in Skwod.</p>
      <Downloads quiet first={firstDownload(platform)} />

      <p className="text-[12px] text-white/40 leading-snug mt-7">
        If the button does nothing, copy the invite, open Skwod and paste it where the app asks
        for an invite link. This page did not send your invite anywhere: the part of the address
        after the # stays in your browser.
      </p>
    </Shell>
  )
}
