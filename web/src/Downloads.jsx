import { MAC_URL, APK_URL, TESTFLIGHT_URL, CONTACT_EMAIL } from './release.js'

const Apple = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor"><path d="M17.05 12.9c-.03-2.6 2.12-3.85 2.22-3.91-1.21-1.77-3.1-2.01-3.77-2.04-1.6-.16-3.13.94-3.94.94-.81 0-2.07-.92-3.4-.9-1.75.03-3.36 1.02-4.26 2.58-1.82 3.16-.47 7.83 1.3 10.39.86 1.25 1.89 2.66 3.24 2.61 1.3-.05 1.79-.84 3.36-.84 1.57 0 2.01.84 3.39.81 1.4-.02 2.29-1.28 3.15-2.54.99-1.46 1.4-2.87 1.42-2.94-.03-.01-2.72-1.05-2.75-4.15zM14.6 5.3c.72-.87 1.2-2.08 1.07-3.3-1.03.04-2.28.69-3.02 1.56-.66.77-1.24 2-1.08 3.18 1.15.09 2.32-.58 3.03-1.44z" /></svg>
)
const Android = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor"><path d="M6 9v7a1 1 0 0 0 1 1h1v3a1 1 0 0 0 2 0v-3h4v3a1 1 0 0 0 2 0v-3h1a1 1 0 0 0 1-1V9H6zM4 9a1 1 0 0 0-1 1v5a1 1 0 0 0 2 0v-5a1 1 0 0 0-1-1zM20 9a1 1 0 0 0-1 1v5a1 1 0 0 0 2 0v-5a1 1 0 0 0-1-1zM16.5 3.5l1-1.7a.35.35 0 0 0-.6-.35l-1.05 1.8A6.9 6.9 0 0 0 12 2.6c-1.36 0-2.63.33-3.75.9L7.2 1.7a.35.35 0 0 0-.6.35l1 1.7A5.9 5.9 0 0 0 5 8.3h14a5.9 5.9 0 0 0-2.5-4.8zM9.5 6.3a.8.8 0 1 1 0-1.6.8.8 0 0 1 0 1.6zm5 0a.8.8 0 1 1 0-1.6.8.8 0 0 1 0 1.6z" /></svg>
)

const IPHONE_INVITE_NOTE = `iPhone beta: invite only. Ask the person who invited you, or email ${CONTACT_EMAIL}`
const IPHONE_INVITE_MAILTO = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent('Skwod iPhone beta invite')}`

const GLASS = 'group flex items-center gap-3 rounded-2xl glass-strong text-white pl-4 pr-5 py-3 font-semibold'
const LIVE = ' hover:bg-white/[0.08] active:scale-[0.98] transition'

/* ---------------------- download buttons ----------------------
   `first` puts one platform's button first ('mac' | 'android' | 'ios'); `quiet` drops the white
   primary treatment, for pages where something else is the main action (the join page). */
export default function Downloads({ compact = false, first = null, quiet = false }) {
  const buttons = {
    mac: (
      <a key="mac" href={MAC_URL} rel="noopener"
        className={quiet ? GLASS + LIVE : 'group flex items-center gap-3 rounded-2xl bg-white text-black pl-4 pr-5 py-3 font-semibold hover:bg-white/90 active:scale-[0.98] transition shadow-[0_10px_40px_-10px_rgba(255,255,255,0.35)]'}>
        <Apple />
        <span className="flex flex-col leading-none text-left">
          <span className={`text-[10px] font-normal mb-0.5 ${quiet ? 'opacity-50' : 'opacity-60'}`}>Download for</span>
          <span className="text-[15px]">macOS · free</span>
        </span>
      </a>
    ),
    android: (
      <a key="android" href={APK_URL} rel="noopener" className={GLASS + LIVE}>
        <Android />
        <span className="flex flex-col leading-none text-left">
          <span className="text-[10px] font-normal opacity-50 mb-0.5">Download the</span>
          <span className="text-[15px]">Android APK</span>
        </span>
      </a>
    ),
    // The iPhone beta is invite-only: friends are added to TestFlight by the person who invited
    // them, so there is no public link. While TESTFLIGHT_URL is empty (site.config.js) the card
    // says so and opens an e-mail to ask; if a public link is ever set, it becomes that link.
    ios: TESTFLIGHT_URL ? (
      <a key="ios" href={TESTFLIGHT_URL} rel="noopener" className={GLASS + LIVE}>
        <Apple />
        <span className="flex flex-col leading-none text-left">
          <span className="text-[10px] font-normal opacity-50 mb-0.5">iPhone beta on</span>
          <span className="text-[15px]">TestFlight</span>
        </span>
      </a>
    ) : (
      <a key="ios" href={IPHONE_INVITE_MAILTO} title={IPHONE_INVITE_NOTE} aria-label={IPHONE_INVITE_NOTE}
        className={GLASS + LIVE}>
        <Apple />
        <span className="flex flex-col leading-none text-left">
          <span className="text-[10px] font-normal opacity-50 mb-0.5">iPhone beta · invite only · {CONTACT_EMAIL}</span>
          <span className="text-[15px]">Ask who invited you</span>
        </span>
      </a>
    ),
  }
  const order = ['mac', 'android', 'ios']
  if (order.includes(first)) order.unshift(...order.splice(order.indexOf(first), 1))
  return (
    <div className={`flex flex-wrap gap-3 ${compact ? '' : 'justify-center'}`}>
      {order.map((k) => buttons[k])}
    </div>
  )
}
