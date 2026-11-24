import Foundation

/// Build 49: the emoji the app's own picker offers (reactions on iPhone and Mac, the Mac
/// composer), grouped like the system keyboard, searchable by Unicode name, with recents.
/// Foundation only: the logic tests compile it.
enum EmojiCatalog {
    struct Category: Identifiable, Equatable {
        let id: String
        let symbol: String   // SF Symbol for the category strip
        let title: String
        let emoji: [String]
    }

    static let categories: [Category] = [
        Category(id: "smileys", symbol: "face.smiling", title: "Smileys", emoji: split("""
        😀 😃 😄 😁 😆 😅 😂 🤣 🥲 ☺️ 😊 😇 🙂 🙃 😉 😌 😍 🥰 😘 😗 😙 😚 😋 😛 😝 😜 🤪 🤨 🧐 🤓 😎 🥸 🤩 🥳 😏 😒 😞 😔 😟 😕 🙁 ☹️ 😣 😖 😫 😩 🥺 😢 😭 😤 😠 😡 🤬 🤯 😳 🥵 🥶 😱 😨 😰 😥 😓 🤗 🤔 🫣 🤭 🫢 🤫 🤥 😶 😐 😑 😬 🙄 😯 😦 😧 😮 😲 🥱 😴 🤤 😪 😵 🤐 🥴 🤢 🤮 🤧 😷 🤒 🤕 🤑 🤠 😈 👿 👹 👺 🤡 💩 👻 💀 👽 🤖 🎃 😺 😸 😹 😻 😼 😽 🙀 😿 😾
        """)),
        Category(id: "people", symbol: "hand.wave", title: "People", emoji: split("""
        👋 🤚 🖐️ ✋ 🖖 👌 🤌 🤏 ✌️ 🤞 🫰 🤟 🤘 🤙 👈 👉 👆 🖕 👇 ☝️ 👍 👎 ✊ 👊 🤛 🤜 👏 🙌 🫶 👐 🤲 🤝 🙏 ✍️ 💅 🤳 💪 🦾 👀 👁️ 👅 👄 🫦 👶 🧒 👦 👧 🧑 👱 👨 🧔 👩 🧓 👴 👵 🙍 🙎 🙅 🙆 💁 🙋 🧏 🙇 🤦 🤷 👮 🕵️ 💂 👷 🤴 👸 🦸 🦹 🧙 🧚 🧛 🧜 🧝 🧞 🧟 💃 🕺 👯 🧘 🏃 🚶
        """)),
        Category(id: "animals", symbol: "pawprint", title: "Animals & Nature", emoji: split("""
        🐶 🐱 🐭 🐹 🐰 🦊 🐻 🐼 🐨 🐯 🦁 🐮 🐷 🐸 🐵 🙈 🙉 🙊 🐔 🐧 🐦 🐤 🦆 🦅 🦉 🦇 🐺 🐗 🐴 🦄 🐝 🐛 🦋 🐌 🐞 🐜 🕷️ 🐢 🐍 🦎 🐙 🦑 🦐 🦀 🐡 🐠 🐟 🐬 🐳 🐋 🦈 🐊 🐅 🐆 🦓 🦍 🐘 🦒 🐪 🦘 🐄 🐎 🐖 🐑 🐐 🦌 🐕 🐈 🐓 🦃 🦚 🦜 🦢 🌵 🎄 🌲 🌳 🌴 🌱 🌿 ☘️ 🍀 🍁 🍂 🍃 🍄 🌷 🌹 🥀 🌺 🌸 🌼 🌻 🌞 🌝 🌚 🌙 ⭐️ 🌟 ✨ ⚡️ 🔥 🌈 ☀️ ⛅️ ☁️ 🌧️ ⛈️ ❄️ ☃️ 💧 🌊
        """)),
        Category(id: "food", symbol: "fork.knife", title: "Food & Drink", emoji: split("""
        🍏 🍎 🍐 🍊 🍋 🍌 🍉 🍇 🍓 🫐 🍈 🍒 🍑 🥭 🍍 🥥 🥝 🍅 🍆 🥑 🥦 🥬 🥒 🌶️ 🌽 🥕 🧄 🧅 🥔 🍠 🥐 🥯 🍞 🥖 🧀 🥚 🍳 🥞 🧇 🥓 🍗 🍖 🌭 🍔 🍟 🍕 🥪 🌮 🌯 🥗 🍝 🍜 🍲 🍛 🍣 🍱 🥟 🍤 🍙 🍚 🍘 🍥 🍢 🍡 🍧 🍨 🍦 🥧 🧁 🍰 🎂 🍮 🍭 🍬 🍫 🍿 🍩 🍪 🥜 🍯 🥛 ☕️ 🍵 🧃 🥤 🧋 🍶 🍺 🍻 🥂 🍷 🥃 🍸 🍹 🍾 🧊
        """)),
        Category(id: "activity", symbol: "soccerball", title: "Activity", emoji: split("""
        ⚽️ 🏀 🏈 ⚾️ 🥎 🎾 🏐 🏉 🥏 🎱 🏓 🏸 🏒 🏑 🥍 🏏 ⛳️ 🏹 🎣 🥊 🥋 🛹 🛼 ⛸️ 🥌 🎿 🏂 🏋️ 🤸 ⛹️ 🤺 🏌️ 🏇 🧗 🚴 🏆 🥇 🥈 🥉 🏅 🎖️ 🎫 🎟️ 🎪 🎭 🎨 🎬 🎤 🎧 🎼 🎹 🥁 🎷 🎺 🎸 🪕 🎻 🎲 ♟️ 🎯 🎳 🎮 🕹️ 🧩
        """)),
        Category(id: "travel", symbol: "car", title: "Travel & Places", emoji: split("""
        🚗 🚕 🚙 🚌 🏎️ 🚓 🚑 🚒 🚚 🚜 🛵 🏍️ 🚲 🛴 🚨 🚔 🚍 🚘 🚖 ✈️ 🛫 🛬 🚀 🛸 🚁 ⛵️ 🚤 🛳️ 🚢 ⚓️ 🚧 ⛽️ 🚏 🗺️ 🗿 🗽 🗼 🏰 🏯 🏟️ 🎡 🎢 🎠 ⛲️ 🏖️ 🏝️ 🏜️ 🌋 ⛰️ 🏔️ 🗻 🏕️ 🏠 🏡 🏢 🏬 🏥 🏦 🏨 🏪 🏫 ⛪️ 🕌 🕍 🌆 🌇 🌃 🌉 🌌 🎆 🎇
        """)),
        Category(id: "objects", symbol: "lightbulb", title: "Objects", emoji: split("""
        ⌚️ 📱 💻 ⌨️ 🖥️ 🖨️ 🖱️ 💾 💿 📷 📸 📹 🎥 📞 ☎️ 📺 📻 🎙️ ⏰ ⏳ 🔋 🔌 💡 🔦 🕯️ 💸 💵 💰 💳 💎 ⚖️ 🧰 🔧 🔨 🛠️ ⚙️ 🔫 💣 🔪 🛡️ 🔮 💊 💉 🧬 🧪 🌡️ 🧹 🧺 🧻 🚽 🛁 🔑 🗝️ 🚪 🛋️ 🛏️ 🧸 🎁 🎈 🎏 🎀 🎊 🎉 ✉️ 📦 📝 📁 📅 📌 📎 ✂️ 🔒 🔓 🔍
        """)),
        Category(id: "symbols", symbol: "heart", title: "Symbols", emoji: split("""
        ❤️ 🧡 💛 💚 💙 💜 🖤 🤍 🤎 💔 ❤️‍🔥 ❣️ 💕 💞 💓 💗 💖 💘 💝 💟 ☮️ ✝️ ☪️ 🕉️ ☯️ ♈️ ♉️ ♊️ ♋️ ♌️ ♍️ ♎️ ♏️ ♐️ ♑️ ♒️ ♓️ 🆔 ⚛️ ✴️ 🆚 💯 💢 ♨️ 🚫 ⛔️ ❌ ⭕️ 🛑 ❗️ ❕ ❓ ❔ ‼️ ⁉️ ⚠️ 🔱 ⚜️ 🔰 ♻️ ✅ ✔️ ☑️ ➕ ➖ ➗ ✖️ 💲 ➰ ➿ 〽️ ✳️ ❇️ 🔝 🔜 🔙 🔛 🔚 💤 🎵 🎶 🔔 🔕 💬 💭 🗯️ ♠️ ♣️ ♥️ ♦️ 🃏 🀄️ 🏁 🚩 🏳️ 🏴 🏳️‍🌈
        """)),
    ]

    static var all: [String] { categories.flatMap(\.emoji) }

    private static func split(_ s: String) -> [String] {
        s.split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init).filter { !$0.isEmpty }
    }

    /// The emoji's Unicode name(s) in lowercase, e.g. "thumbs up sign" (what search matches).
    static func name(_ emoji: String) -> String {
        let m = NSMutableString(string: emoji)
        CFStringTransform(m, nil, kCFStringTransformToUnicodeName, false)
        return (m as String).replacingOccurrences(of: "\\N{", with: " ").replacingOccurrences(of: "}", with: " ")
            .replacingOccurrences(of: "VARIATION SELECTOR-16", with: "").lowercased()
            .trimmingCharacters(in: .whitespaces)
    }

    /// Emoji whose name contains every word of `query` (empty query: nothing).
    static func search(_ query: String, in pool: [String] = all) -> [String] {
        let words = query.lowercased().split(separator: " ").map(String.init).filter { !$0.isEmpty }
        guard !words.isEmpty else { return [] }
        return pool.filter { e in
            let n = name(e)
            return words.allSatisfy { n.contains($0) }
        }
    }

    // MARK: recents

    static let recentsKey = "skwod.emoji.recents"
    static let maxRecents = 24

    /// `recents` after using `emoji`: it moves to the front, the list stays bounded.
    static func used(_ emoji: String, recents: [String]) -> [String] {
        Array(([emoji] + recents.filter { $0 != emoji }).prefix(maxRecents))
    }

    static func recents(_ defaults: UserDefaults = .standard) -> [String] {
        (defaults.stringArray(forKey: recentsKey) ?? []).filter { !$0.isEmpty && $0.count <= 4 }.prefix(maxRecents).map { $0 }
    }

    static func noteUsed(_ emoji: String, _ defaults: UserDefaults = .standard) {
        defaults.set(used(emoji, recents: recents(defaults)), forKey: recentsKey)
    }
}
