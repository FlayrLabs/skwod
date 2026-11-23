import { useState, useEffect, useRef } from 'react'
import Showcase from './Showcase.jsx'
import Downloads from './Downloads.jsx'
import { MAC_URL, RELEASES_URL, SOURCE_URL } from './release.js'

/* ---------- inline icons (stroke = currentColor, so they inherit text color) ---------- */
const Icon = ({ d, size = 20, fill = 'none', stroke = 2 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={fill} stroke="currentColor"
    strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round">{d}</svg>
)
const ServerRack = ({ size = 46 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
    <rect x="3" y="4" width="18" height="7" rx="1.6" /><rect x="3" y="13" width="18" height="7" rx="1.6" />
    <line x1="7" y1="7.5" x2="7" y2="7.5" /><line x1="7" y1="16.5" x2="7" y2="16.5" />
  </svg>
)
const Play = () => <Icon size={16} d={<><polygon points="6 4 20 12 6 20 6 4" fill="currentColor" stroke="none" /></>} />
const Stop = () => <Icon size={14} d={<rect x="6" y="6" width="12" height="12" rx="2" fill="currentColor" stroke="none" />} />
const Copy = ({ size = 16 }) => <Icon size={size} d={<><rect x="9" y="9" width="12" height="12" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></>} />
const Check = ({ size = 16 }) => <Icon size={size} d={<polyline points="20 6 9 17 4 12" />} />
const Lock = ({ size = 20 }) => <Icon size={size} d={<><rect x="4.5" y="10" width="15" height="11" rx="2.4" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></>} />
const Globe = ({ size = 20 }) => <Icon size={size} d={<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.6 2.5 15.4 0 18M12 3c-2.5 2.6-2.5 15.4 0 18" /></>} />
const Bolt = ({ size = 20 }) => <Icon size={size} d={<polygon points="13 2 4 14 11 14 10 22 20 9 13 9 13 2" />} />
const Video = ({ size = 20 }) => <Icon size={size} d={<><rect x="2.5" y="6" width="13" height="12" rx="2.2" /><path d="M15.5 10.5l6-3.5v10l-6-3.5" /></>} />
const Devices = ({ size = 20 }) => <Icon size={size} d={<><rect x="2.5" y="4.5" width="14" height="10" rx="1.6" /><rect x="16.5" y="8.5" width="5" height="11" rx="1.2" /><path d="M6 18.5h6" /></>} />
/* The invite the demo mints on "Start server". It is visibly a demo (#demo-…), and the join
   page answers it with "this is a demo" instead of trying to open a server that doesn't exist. */
function randomInvite() {
  const code = () => Math.random().toString(36).slice(2, 6).toUpperCase().padEnd(4, '7')
  return `https://skwod.io/join#demo-SKWD-${code()}-${code()}`
}

/* ---------------------- The faithful, interactive Host wizard ---------------------- */
function HostWizard() {
  const [phase, setPhase] = useState('idle') // idle | starting | running
  const [invite, setInvite] = useState(null)
  const [copied, setCopied] = useState(false)
  const timer = useRef(null)

  const start = () => {
    setPhase('starting')
    timer.current = setTimeout(() => {
      setInvite(randomInvite())
      setPhase('running')
    }, 2100)
  }
  const stop = () => {
    clearTimeout(timer.current)
    setPhase('idle'); setInvite(null); setCopied(false)
  }
  useEffect(() => () => clearTimeout(timer.current), [])

  const link = invite || '…'

  return (
    <div className="w-full max-w-[440px] mx-auto">
      {/* macOS-style window chrome, so it reads as the real app window */}
      <div className="glass-strong rounded-2xl overflow-hidden shadow-[0_40px_120px_-30px_rgba(58,107,255,0.5)]">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.06]">
          <span className="w-3 h-3 rounded-full bg-[#ff5f57]" />
          <span className="w-3 h-3 rounded-full bg-[#febc2e]" />
          <span className="w-3 h-3 rounded-full bg-[#28c840]" />
          <span className="ml-2 text-[13px] text-white/40 font-mono">skwod · host</span>
          <span className="ml-auto text-[10.5px] uppercase tracking-wider text-white/45 border border-white/15 rounded-full px-2 py-0.5">Preview of the Mac app</span>
        </div>

        <div className="px-7 pt-8 pb-7">
          {/* header, matches HostWizardView.header */}
          <div className="flex flex-col items-center text-center gap-2.5 mb-6">
            <div className="text-squid"><ServerRack /></div>
            <h3 className="font-display text-[26px] font-extrabold tracking-tight">Host a Skwod</h3>
            <p className="text-[13.5px] text-white/55 leading-snug max-w-[340px]">
              Run your own Skwod on this Mac so your friends can join. Your messages stay
              end-to-end encrypted, so this machine only ever sees ciphertext.
            </p>
          </div>

          {phase === 'idle' && (
            <div className="glass rounded-[20px] p-5 flex flex-col gap-4">
              {/* storage folder row */}
              <div className="flex items-center gap-3">
                <div className="min-w-0">
                  <div className="text-[11px] text-white/45">Storage folder</div>
                  <div className="text-[12px] font-mono text-white/85 truncate">~/Library/Application Support/skwod-host-data</div>
                </div>
                <a href={MAC_URL} className="ml-auto shrink-0 glass rounded-lg px-3 py-1.5 text-[12px] text-white/80 hover:bg-white/[0.08] transition">Choose…</a>
              </div>
              <button onClick={start}
                className="w-full rounded-full bg-white text-black font-semibold text-[15px] py-3 flex items-center justify-center gap-2 hover:bg-white/90 active:scale-[0.99] transition">
                <Play /> Start server
              </button>
              <p className="text-[12px] text-white/45 text-center leading-snug">
                Free. No account, no domain. Your server's key is its address, made automatically.
              </p>
              <div className="flex items-center gap-2 text-[12px] text-white/40 justify-center pt-1">
                <Globe size={14} /> <span>Want it always on? Run it with <span className="font-mono text-white/60">docker</span> on a NAS like Unraid or Synology.</span>
              </div>
            </div>
          )}

          {phase === 'starting' && (
            <div className="glass rounded-[20px] p-8 flex flex-col items-center gap-4">
              <span className="spin w-8 h-8 rounded-full border-2 border-white/15 border-t-squid" />
              <p className="text-[14px] text-white/70">Starting your Skwod and connecting its address…</p>
            </div>
          )}

          {phase === 'running' && (
            <div className="glass rounded-[20px] p-5 flex flex-col gap-4">
              <div className="flex items-center gap-2.5">
                <span className="live-dot w-2.5 h-2.5 rounded-full bg-[#28c840] shadow-[0_0_12px_#28c840]" />
                <span className="font-semibold">Your Skwod is live</span>
                <button onClick={stop} className="ml-auto glass rounded-lg px-3 py-1.5 text-[12px] text-[#ff6b6b] hover:bg-white/[0.06] transition flex items-center gap-1.5">
                  <Stop /> Stop
                </button>
              </div>
              <p className="text-[13px] text-white/55 leading-snug">
                Invite your friends: send them this link. They open it, pick a name and ask to join.
              </p>
              <div className="glass rounded-xl p-3 flex items-center gap-3">
                <div className="min-w-0">
                  <div className="text-[10.5px] text-white/45">Invite link for your friends</div>
                  <div className="text-[12.5px] font-mono text-white truncate">{link}</div>
                </div>
                <button
                  onClick={() => { navigator.clipboard?.writeText(link); setCopied(true); setTimeout(() => setCopied(false), 1600) }}
                  className="ml-auto shrink-0 text-white/60 hover:text-white transition">
                  {copied ? <Check /> : <Copy />}
                </button>
              </div>
              <a href={MAC_URL} className="w-full rounded-full bg-white text-black font-semibold text-[14px] py-2.5 flex items-center justify-center gap-2 hover:bg-white/90 transition">
                Share the invite with friends
              </a>
              <div className="flex items-start gap-2 text-[11.5px] text-white/40 leading-snug pt-1 border-t border-white/[0.06] mt-1 pt-3">
                <Lock size={14} />
                <span>When a friend asks to join, they show up under Waiting to join. Click Let in. Only the people you let in can read along.</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* the step the demo is on, spelled out below the window */}
      <div className="flex items-center justify-center gap-2 mt-5 text-[12px] text-white/40 font-mono">
        {['click Start', 'address goes live', 'share to join'].map((s, i) => {
          const active = (phase === 'idle' && i === 0) || (phase === 'starting' && i === 1) || (phase === 'running' && i === 2)
          return (
            <span key={s} className="flex items-center gap-2">
              <span className={active ? 'text-squid' : ''}>{s}</span>
              {i < 2 && <span className="text-white/20">→</span>}
            </span>
          )
        })}
      </div>
    </div>
  )
}

/* ---------------------- squid wordmark ---------------------- */
const Wordmark = ({ size = 28 }) => (
  <span className="flex items-center gap-2.5 select-none">
    <img src="/skwod-icon.png" alt="Skwod" width={size} height={size} className="rounded-[7px]" />
    <span className="font-display font-extrabold tracking-tight" style={{ fontSize: size * 0.82 }}>Skwod</span>
  </span>
)

/* ---------------------- features: the bento grid ---------------------- */

/* A card shell with a gradient icon tile, hover lift, glow, and animated top hairline. */
function FeatureCard({ icon, title, children, className = '' }) {
  return (
    <div
      className={`group relative overflow-hidden rounded-[20px] glass p-6 md:p-7 transition duration-500
        hover:-translate-y-1 hover:bg-white/[0.06] hover:ring-1 hover:ring-squid/30
        hover:shadow-[0_24px_70px_-20px_rgba(58,215,255,0.35)] ${className}`}
    >
      <div className="pointer-events-none absolute -top-20 -right-20 h-48 w-48 rounded-full bg-squid/15 blur-3xl opacity-0 transition duration-500 group-hover:opacity-100" />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-squid/60 to-transparent opacity-0 transition duration-500 group-hover:opacity-100" />
      <div className="relative flex h-full flex-col">
        <div className="mb-5 inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-white/[0.14] to-white/[0.02] ring-1 ring-white/10 text-squid transition duration-500 group-hover:scale-105 group-hover:text-white group-hover:ring-squid/40">
          {icon}
        </div>
        <h3 className="font-display font-bold text-[19px] mb-2 tracking-tight">{title}</h3>
        <div className="text-[14px] text-white/55 leading-relaxed">{children}</div>
      </div>
    </div>
  )
}

/* Live "the host only sees ciphertext" visual: a readable message on top, and below it the base64
   the host machine actually stores, continuously churning a few characters so it reads as a live
   encrypted stream. */
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const randB64 = (n) => Array.from({ length: n }, () => B64[Math.floor(Math.random() * B64.length)]).join('')

function CipherDemo() {
  const [ct, setCt] = useState(() => randB64(96))
  useEffect(() => {
    const id = setInterval(() => {
      setCt((prev) => {
        const arr = prev.split('')
        for (let k = 0; k < 6; k++) arr[Math.floor(Math.random() * arr.length)] = B64[Math.floor(Math.random() * B64.length)]
        return arr.join('')
      })
    }, 90)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="glass rounded-2xl p-4 flex flex-col gap-3">
      {/* what you read */}
      <div>
        <div className="text-[10px] uppercase tracking-wider text-white/35 mb-1.5">On your devices</div>
        <div className="flex items-start gap-2.5">
          <img src="/skwod-icon.png" width={26} height={26} className="rounded-[7px] mt-0.5" alt="" />
          <div>
            <div className="text-[12px] font-semibold text-white leading-none mb-1">maya</div>
            <div className="text-[13px] text-white/85">game night friday 🎲</div>
          </div>
        </div>
      </div>
      {/* the lock divider */}
      <div className="flex items-center gap-2 text-[10px] text-squid/70">
        <span className="h-px flex-1 bg-gradient-to-r from-transparent to-squid/30" />
        <Lock size={12} /> <span className="font-mono">encrypted on-device</span>
        <span className="h-px flex-1 bg-gradient-to-l from-transparent to-squid/30" />
      </div>
      {/* what the host stores */}
      <div>
        <div className="text-[10px] uppercase tracking-wider text-white/35 mb-1.5">On the host machine</div>
        <div className="rounded-lg bg-black/40 ring-1 ring-white/10 px-3 py-2 font-mono text-[11.5px] leading-relaxed text-squid/80 break-all select-none">
          {ct}
        </div>
      </div>
    </div>
  )
}

const EXPECT_CHIPS = ['Voice calls', 'Video calls', 'Servers', 'Channels', 'DMs', 'Replies', 'Reactions', 'Photos', 'File drops', 'Voice notes', 'Apple Music', 'Chess', 'Stories', 'Message sounds', 'Mute']

export default function App() {
  return (
    // overflow-x-clip: the decorative glows are wider than a phone screen; clip them at the page
    // edge so they cannot widen the page (they are blurred light, nothing visible is lost).
    <div className="relative min-h-screen font-body overflow-x-clip">
      <div className="mesh" /><div className="grain" />

      {/* nav */}
      <header className="fixed top-0 inset-x-0 z-40">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <Wordmark size={30} />
          <nav className="hidden sm:flex items-center gap-7 text-[14px] text-white/60">
            <a href="#host" className="hover:text-white transition">Hosting</a>
            <a href="#features" className="hover:text-white transition">Features</a>
            <a href={MAC_URL} className="text-white font-medium hover:text-squid transition">Download</a>
          </nav>
        </div>
      </header>

      {/* hero, two-column: the "Your squad. Your server." copy + the live host wizard */}
      <section id="host" className="relative overflow-hidden pt-32 pb-16 md:pt-40 md:pb-24">
        {/* background glow */}
        <div className="pointer-events-none absolute inset-0">
          <div className="absolute top-1/4 left-1/4 h-96 w-96 rounded-full bg-squid-indigo/20 blur-[128px]" />
          <div className="absolute top-1/3 right-1/4 h-80 w-80 rounded-full bg-squid-deep/15 blur-[128px]" />
        </div>

        <div className="relative mx-auto grid max-w-6xl gap-12 px-6 lg:grid-cols-2 lg:items-center lg:gap-16">
          {/* left, copy */}
          <div className="flex flex-col gap-6">
            <div className="rise inline-flex w-fit items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-1.5 text-[13px] text-white/50" style={{ animationDelay: '0.05s' }}>
              <span className="live-dot h-2 w-2 rounded-full bg-green-400" /> Self-hosted &middot; End-to-end encrypted
            </div>
            <h1 className="rise font-heading text-4xl leading-[1.05] font-extrabold tracking-tight text-white md:text-5xl lg:text-6xl" style={{ animationDelay: '0.12s' }}>
              Your squad.<br />
              <span className="bg-gradient-to-r from-squid-indigo via-squid-deep to-squid bg-clip-text text-transparent">Your server.</span>
            </h1>
            <p className="rise text-xl leading-snug font-medium text-white/75 md:text-2xl" style={{ animationDelay: '0.2s' }}>
              Self-hostable, encrypted group chats. Not even{' '}
              <span className="font-semibold text-white underline decoration-squid/50 decoration-2 underline-offset-4">you</span>{' '}
              can read your own database.
            </p>
            <p className="rise max-w-md text-[17px] leading-relaxed text-white/55" style={{ animationDelay: '0.28s' }}>
              Group chat meets stories, for your closest friends. Every message, call, and file is
              encrypted on-device before it ever hits your machine. Host it from your Mac in one click.
            </p>
            <p className="rise text-[13px] text-white/35" style={{ animationDelay: '0.34s' }}>
              Fun fact: a group of squid is called a squad. That's us.
            </p>
            <div className="rise" style={{ animationDelay: '0.4s' }}><Downloads compact /></div>
            <p className="rise text-[12px] text-white/30 font-mono" style={{ animationDelay: '0.46s' }}>
              post-quantum encrypted · self-hosted · zero ads, zero tracking
            </p>
          </div>

          {/* right, the live host wizard */}
          {/* min-w-0: without it the one-line storage path sets this column's minimum width and
              the whole hero is pushed past the edge of a phone screen */}
          <div className="rise w-full min-w-0" style={{ animationDelay: '0.32s' }}>
            <HostWizard />
          </div>
        </div>
      </section>

      {/* device showcase, real app screens rebuilt in HTML */}
      <Showcase />

      {/* features, bento grid */}
      <section id="features" className="relative max-w-6xl mx-auto px-6 py-20 md:py-24">
        <div className="pointer-events-none absolute inset-x-0 top-1/4 mx-auto h-72 max-w-3xl rounded-full bg-squid-deep/10 blur-[130px]" />
        <div className="relative">
          <h2 className="font-display font-extrabold text-[34px] md:text-[44px] tracking-tight mb-3 text-center">
            A real messenger. <span className="text-squid">Without the middleman.</span>
          </h2>
          <p className="text-center text-white/50 max-w-lg mx-auto mb-14 text-[16px]">
            Everything you'd expect from a group chat, engineered so no company, including us, can see inside it.
          </p>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {/* Featured: end-to-end encrypted, with the live ciphertext demo */}
            <FeatureCard
              icon={<Lock />}
              title="End-to-end encrypted"
              className="sm:col-span-2"
            >
              <div className="grid gap-5 md:grid-cols-2 md:items-center">
                <p>
                  PQXDH + Double Ratchet, the same modern protocol class as Signal. Your host machine
                  only ever stores ciphertext, public keys, and routing metadata.
                  <span className="text-white/80"> Never your messages.</span>
                </p>
                <CipherDemo />
              </div>
            </FeatureCard>

            <FeatureCard icon={<ServerRack size={20} />} title="You host it, not us">
              Skwod runs nothing centrally. Every server is a friend’s own machine. One click on a Mac
              spins up a server and its own address. No account, no rented cloud, nothing to shut down.
            </FeatureCard>

            <FeatureCard icon={<Globe />} title="Your own address">
              Your server's address is its key: no domain, no port forwarding and no accounts. Share one{' '}
              <span className="font-mono text-white/75">skwod.io/join</span> link and friends find it automatically.
            </FeatureCard>

            <FeatureCard icon={<Devices />} title="Mac, iPhone &amp; Android">
              Native apps on every device, all linked to the same account with their own keys. Send from
              your phone, pick up on your Mac.
            </FeatureCard>

            <FeatureCard icon={<Check />} title="Free on Mac">
              The desktop app is free, forever. Mobile is a few dollars a month to keep the lights on.
              No ads, no data harvesting. There’s nothing to harvest.
            </FeatureCard>

            <FeatureCard icon={<Video />} title="Voice &amp; video calls">
              Hop on a call with the whole group, camera on or off. Every call gets its own keys, so
              only the people on it can hear or see it. Hit Ring everyone and their phones ring.
            </FeatureCard>

            {/* Wide closer: everything you expect, as chips */}
            <FeatureCard icon={<Bolt />} title="Everything you expect" className="lg:col-span-2">
              <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <p className="md:max-w-xs">
                  All the group-chat features you already know, even shared Apple Music and a game of
                  chess. Familiar, just yours.
                </p>
                <div className="flex flex-wrap gap-2 md:justify-end md:max-w-md">
                  {EXPECT_CHIPS.map((c) => (
                    <span
                      key={c}
                      className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-[12.5px] text-white/65 transition hover:border-squid/40 hover:text-white hover:bg-squid/10"
                    >
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            </FeatureCard>
          </div>
        </div>
      </section>

      {/* closing CTA */}
      <section className="relative max-w-6xl mx-auto px-6 py-24 text-center">
        <div className="glass-strong rounded-[32px] px-8 py-16 md:py-20 relative overflow-hidden">
          <div className="absolute -top-24 left-1/2 -translate-x-1/2 w-[420px] h-[420px] rounded-full bg-squid/10 blur-[90px]" />
          <div className="relative">
            <img src="/skwod-icon.png" alt="" width={64} height={64} className="rounded-2xl mx-auto mb-7" />
            <h2 className="font-display font-extrabold text-[38px] md:text-[52px] tracking-tight leading-[1.02] mb-5">
              Start a Skwod tonight.
            </h2>
            <p className="text-white/55 max-w-md mx-auto mb-9 text-[16.5px]">
              Download it, click Start server, send your friends a link. That's the whole setup.
            </p>
            <div className="flex justify-center"><Downloads /></div>
          </div>
        </div>
      </section>

      <footer className="relative max-w-6xl mx-auto px-6 py-12 border-t border-white/[0.06] flex flex-col sm:flex-row items-center justify-between gap-4 text-[13px] text-white/40">
        <Wordmark size={22} />
        <p className="font-mono">end-to-end encrypted · self-hosted · © {new Date().getFullYear()} Flayr Labs LLC</p>
      </footer>

      {/* open-source and trademark note, in the footer's own type */}
      <p className="relative max-w-6xl mx-auto px-6 pb-12 -mt-4 text-center sm:text-left text-[12px] leading-relaxed text-white/30 font-mono">
        Free software under the AGPL-3.0 ·{' '}
        <a href={SOURCE_URL} rel="noopener" className="hover:text-white transition">source code</a> ·{' '}
        <a href={RELEASES_URL} rel="noopener" className="hover:text-white transition">all releases</a>.
        The Skwod name and logo are trademarks of Flayr Labs LLC. Not affiliated with Signal Messenger, LLC.
      </p>
    </div>
  )
}
