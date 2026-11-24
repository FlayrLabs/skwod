package io.skwod.app

import android.content.Context

/**
 * Build 49: the emoji the app's own picker offers (the Apple app's `EmojiCatalog`): categories,
 * search by Unicode name, recents. Pure apart from [recents]/[noteUsed] (unit-tested).
 */
object EmojiCatalog {
    data class Category(val title: String, private val raw: String) {
        val emoji: List<String> get() = raw.split(' ', '\n').filter { it.isNotBlank() }
    }

    val categories = listOf(
        Category("Smileys", "😀 😃 😄 😁 😆 😅 😂 🤣 🥲 ☺️ 😊 😇 🙂 🙃 😉 😌 😍 🥰 😘 😗 😙 😚 😋 😛 😝 😜 🤪 🤨 🧐 🤓 😎 🥸 🤩 🥳 😏 😒 😞 😔 😟 😕 🙁 ☹️ 😣 😖 😫 😩 🥺 😢 😭 😤 😠 😡 🤬 🤯 😳 🥵 🥶 😱 😨 😰 😥 😓 🤗 🤔 🫣 🤭 🫢 🤫 🤥 😶 😐 😑 😬 🙄 😯 😦 😧 😮 😲 🥱 😴 🤤 😪 😵 🤐 🥴 🤢 🤮 🤧 😷 🤒 🤕 🤑 🤠 😈 👿 👹 👺 🤡 💩 👻 💀 👽 🤖 🎃 😺 😸 😹 😻 😼 😽 🙀 😿 😾"),
        Category("People", "👋 🤚 🖐️ ✋ 🖖 👌 🤌 🤏 ✌️ 🤞 🫰 🤟 🤘 🤙 👈 👉 👆 🖕 👇 ☝️ 👍 👎 ✊ 👊 🤛 🤜 👏 🙌 🫶 👐 🤲 🤝 🙏 ✍️ 💅 🤳 💪 🦾 👀 👁️ 👅 👄 🫦 👶 🧒 👦 👧 🧑 👱 👨 🧔 👩 🧓 👴 👵 🙍 🙎 🙅 🙆 💁 🙋 🧏 🙇 🤦 🤷 👮 🕵️ 💂 👷 🤴 👸 🦸 🦹 🧙 🧚 🧛 🧜 🧝 🧞 🧟 💃 🕺 👯 🧘 🏃 🚶"),
        Category("Animals & Nature", "🐶 🐱 🐭 🐹 🐰 🦊 🐻 🐼 🐨 🐯 🦁 🐮 🐷 🐸 🐵 🙈 🙉 🙊 🐔 🐧 🐦 🐤 🦆 🦅 🦉 🦇 🐺 🐗 🐴 🦄 🐝 🐛 🦋 🐌 🐞 🐜 🕷️ 🐢 🐍 🦎 🐙 🦑 🦐 🦀 🐡 🐠 🐟 🐬 🐳 🐋 🦈 🐊 🐅 🐆 🦓 🦍 🐘 🦒 🐪 🦘 🐄 🐎 🐖 🐑 🐐 🦌 🐕 🐈 🐓 🦃 🦚 🦜 🦢 🌵 🎄 🌲 🌳 🌴 🌱 🌿 ☘️ 🍀 🍁 🍂 🍃 🍄 🌷 🌹 🥀 🌺 🌸 🌼 🌻 🌞 🌝 🌚 🌙 ⭐️ 🌟 ✨ ⚡️ 🔥 🌈 ☀️ ⛅️ ☁️ 🌧️ ⛈️ ❄️ ☃️ 💧 🌊"),
        Category("Food & Drink", "🍏 🍎 🍐 🍊 🍋 🍌 🍉 🍇 🍓 🫐 🍈 🍒 🍑 🥭 🍍 🥥 🥝 🍅 🍆 🥑 🥦 🥬 🥒 🌶️ 🌽 🥕 🧄 🧅 🥔 🍠 🥐 🥯 🍞 🥖 🧀 🥚 🍳 🥞 🧇 🥓 🍗 🍖 🌭 🍔 🍟 🍕 🥪 🌮 🌯 🥗 🍝 🍜 🍲 🍛 🍣 🍱 🥟 🍤 🍙 🍚 🍘 🍥 🍢 🍡 🍧 🍨 🍦 🥧 🧁 🍰 🎂 🍮 🍭 🍬 🍫 🍿 🍩 🍪 🥜 🍯 🥛 ☕️ 🍵 🧃 🥤 🧋 🍶 🍺 🍻 🥂 🍷 🥃 🍸 🍹 🍾 🧊"),
        Category("Activity", "⚽️ 🏀 🏈 ⚾️ 🥎 🎾 🏐 🏉 🥏 🎱 🏓 🏸 🏒 🏑 🥍 🏏 ⛳️ 🏹 🎣 🥊 🥋 🛹 🛼 ⛸️ 🥌 🎿 🏂 🏋️ 🤸 ⛹️ 🤺 🏌️ 🏇 🧗 🚴 🏆 🥇 🥈 🥉 🏅 🎖️ 🎫 🎟️ 🎪 🎭 🎨 🎬 🎤 🎧 🎼 🎹 🥁 🎷 🎺 🎸 🪕 🎻 🎲 ♟️ 🎯 🎳 🎮 🕹️ 🧩"),
        Category("Travel & Places", "🚗 🚕 🚙 🚌 🏎️ 🚓 🚑 🚒 🚚 🚜 🛵 🏍️ 🚲 🛴 🚨 🚔 🚍 🚘 🚖 ✈️ 🛫 🛬 🚀 🛸 🚁 ⛵️ 🚤 🛳️ 🚢 ⚓️ 🚧 ⛽️ 🚏 🗺️ 🗿 🗽 🗼 🏰 🏯 🏟️ 🎡 🎢 🎠 ⛲️ 🏖️ 🏝️ 🏜️ 🌋 ⛰️ 🏔️ 🗻 🏕️ 🏠 🏡 🏢 🏬 🏥 🏦 🏨 🏪 🏫 ⛪️ 🕌 🕍 🌆 🌇 🌃 🌉 🌌 🎆 🎇"),
        Category("Objects", "⌚️ 📱 💻 ⌨️ 🖥️ 🖨️ 🖱️ 💾 💿 📷 📸 📹 🎥 📞 ☎️ 📺 📻 🎙️ ⏰ ⏳ 🔋 🔌 💡 🔦 🕯️ 💸 💵 💰 💳 💎 ⚖️ 🧰 🔧 🔨 🛠️ ⚙️ 🔫 💣 🔪 🛡️ 🔮 💊 💉 🧬 🧪 🌡️ 🧹 🧺 🧻 🚽 🛁 🔑 🗝️ 🚪 🛋️ 🛏️ 🧸 🎁 🎈 🎏 🎀 🎊 🎉 ✉️ 📦 📝 📁 📅 📌 📎 ✂️ 🔒 🔓 🔍"),
        Category("Symbols", "❤️ 🧡 💛 💚 💙 💜 🖤 🤍 🤎 💔 ❤️‍🔥 ❣️ 💕 💞 💓 💗 💖 💘 💝 💟 ☮️ ✝️ ☪️ 🕉️ ☯️ ♈️ ♉️ ♊️ ♋️ ♌️ ♍️ ♎️ ♏️ ♐️ ♑️ ♒️ ♓️ 🆔 ⚛️ ✴️ 🆚 💯 💢 ♨️ 🚫 ⛔️ ❌ ⭕️ 🛑 ❗️ ❕ ❓ ❔ ‼️ ⁉️ ⚠️ 🔱 ⚜️ 🔰 ♻️ ✅ ✔️ ☑️ ➕ ➖ ➗ ✖️ 💲 ➰ ➿ 〽️ ✳️ ❇️ 🔝 🔜 🔙 🔛 🔚 💤 🎵 🎶 🔔 🔕 💬 💭 🗯️ ♠️ ♣️ ♥️ ♦️ 🃏 🀄️ 🏁 🚩 🏳️ 🏴 🏳️‍🌈"),
    )

    val all: List<String> get() = categories.flatMap { it.emoji }

    /** The emoji's Unicode name(s), lowercase ("thumbs up sign"). */
    fun name(emoji: String): String = emoji.codePoints().toArray()
        .filter { it != 0xFE0F && it != 0x200D }
        .joinToString(" ") { (Character.getName(it) ?: "").lowercase() }

    /** Emoji whose name contains every word of [query] (empty query: nothing). */
    fun search(query: String, pool: List<String> = all): List<String> {
        val words = query.lowercase().split(' ').filter { it.isNotBlank() }
        if (words.isEmpty()) return emptyList()
        return pool.filter { e -> val n = name(e); words.all { n.contains(it) } }
    }

    const val MAX_RECENTS = 24
    fun used(emoji: String, recents: List<String>): List<String> = (listOf(emoji) + recents.filter { it != emoji }).take(MAX_RECENTS)

    fun recents(ctx: Context): List<String> =
        ctx.getSharedPreferences("skwod-emoji", Context.MODE_PRIVATE).getString("recents", "")!!.split(' ').filter { it.isNotBlank() }.take(MAX_RECENTS)

    fun noteUsed(ctx: Context, emoji: String) {
        ctx.getSharedPreferences("skwod-emoji", Context.MODE_PRIVATE).edit().putString("recents", used(emoji, recents(ctx)).joinToString(" ")).apply()
    }
}
