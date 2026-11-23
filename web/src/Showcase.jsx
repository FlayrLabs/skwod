/* Real product screenshots of the native skwod apps, the macOS #general chat and the iPhone
   chat, side by side, captured from a live, end-to-end encrypted "gamenight" server.
   No mockups: this is the actual app. */

const SHOT = {
  macChat: '/shots/mac-chat.webp',
  iosChat: '/shots/ios-chat.webp',
}

export default function Showcase() {
  return (
    <section className="relative max-w-6xl mx-auto px-6 py-24 md:py-28">
      <h2 className="font-display font-extrabold text-[34px] md:text-[46px] tracking-tight mb-3 text-center">
        The same Skwod, <span className="text-squid">everywhere.</span>
      </h2>
      <p className="text-center text-white/50 max-w-lg mx-auto mb-16 text-[16px]">
        Native on your Mac and your iPhone. Servers, channels, DMs, and stories, all end-to-end
        encrypted. These are real screenshots, not mockups.
      </p>

      {/* macOS chat + iPhone chat, side by side */}
      <div className="relative max-w-5xl mx-auto">
        <div className="pointer-events-none absolute -inset-x-10 -top-10 bottom-0 bg-squid-indigo/10 blur-[120px] rounded-full" />
        <div className="relative flex flex-col md:flex-row items-center md:items-end justify-center gap-10 md:gap-6">
          {/* Mac window (already carries its own chrome + shadow) */}
          <img
            src={SHOT.macChat}
            alt="Skwod on macOS, the #general channel of a gamenight server, end-to-end encrypted"
            className="w-full md:w-[68%] h-auto drop-shadow-[0_50px_120px_rgba(58,107,255,0.35)]"
          />
          {/* iPhone (corners already rounded) in a thin titanium bezel */}
          <div className="w-[220px] md:w-[26%] md:max-w-[240px] shrink-0">
            <div
              className="rounded-[46px] p-[9px] shadow-[0_40px_100px_-25px_rgba(58,107,255,0.55)]"
              style={{ background: 'linear-gradient(155deg,#2b2b33,#0c0c11)' }}
            >
              <div className="rounded-[38px] overflow-hidden bg-black">
                <img
                  src={SHOT.iosChat}
                  alt="Skwod on iPhone, an encrypted group chat"
                  className="w-full h-auto block"
                />
              </div>
            </div>
          </div>
        </div>
      </div>
      <p className="text-center text-[13px] text-white/40 font-mono mt-12">
        macOS &amp; iPhone · #general · end-to-end encrypted
      </p>
    </section>
  )
}
