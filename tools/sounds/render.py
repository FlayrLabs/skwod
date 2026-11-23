#!/usr/bin/env python3
"""Render Skwod's interface sounds.

Every sound is synthesised here from sine partials and envelopes — nothing is sampled,
recorded or derived from any other product's sounds. Standard library only.

    python3 tools/sounds/render.py

writes 16-bit mono 44.1 kHz WAV files (a format AudioToolbox on iOS/macOS and SoundPool on
Android both play as they are) to
    apps/apple/Resources/Sounds/skwod_<name>.wav
    apps/android/app/src/main/res/raw/skwod_<name>.wav
Re-run after changing a recipe and commit the outputs with the script.
"""
import math
import os
import struct
import wave

RATE = 44100
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
OUT = [
    os.path.join(ROOT, "apps", "apple", "Resources", "Sounds"),
    os.path.join(ROOT, "apps", "android", "app", "src", "main", "res", "raw"),
]


def note(freq, start, length, gain=1.0, attack=0.006, decay=6.0, glide=0.0, partials=((1, 1.0), (2, 0.22), (3, 0.06))):
    """One soft bell-like note: a few sine partials, a quick attack, an exponential tail.
    `glide`: semitones the pitch moves over the note (positive = up)."""
    return dict(freq=freq, start=start, length=length, gain=gain, attack=attack, decay=decay, glide=glide, partials=partials)


def render(notes, total, peak=0.55):
    n = int(total * RATE)
    buf = [0.0] * n
    for v in notes:
        first = int(v["start"] * RATE)
        count = min(int(v["length"] * RATE), n - first)
        phase = [0.0] * len(v["partials"])
        for i in range(count):
            t = i / RATE
            f = v["freq"] * 2 ** (v["glide"] * (t / v["length"]) / 12)
            env = min(1.0, t / v["attack"]) * math.exp(-v["decay"] * t / v["length"])
            # A short fade at the very end so nothing clicks.
            env *= min(1.0, (count - i) / (0.004 * RATE))
            s = 0.0
            for k, (mult, amp) in enumerate(v["partials"]):
                phase[k] += 2 * math.pi * f * mult / RATE
                s += amp * math.sin(phase[k])
            buf[first + i] += v["gain"] * env * s
    top = max(abs(x) for x in buf) or 1.0
    return [x / top * peak for x in buf]


SOUNDS = {
    # Sent: one soft, short upward blip — quiet, so a fast typist is not rattled by it.
    "sent": (render([note(659.25, 0.0, 0.11, glide=5, decay=5.0)], 0.13, peak=0.30)),
    # Received: two notes, a fourth apart, rising.
    "received": (render([note(587.33, 0.0, 0.16, decay=5.0), note(783.99, 0.085, 0.24, decay=5.5)], 0.34, peak=0.50)),
    # Someone joined the call: two quick rising notes (a fifth).
    "call_join": (render([note(440.0, 0.0, 0.14, decay=4.5), note(659.25, 0.10, 0.22, decay=5.0)], 0.34, peak=0.45)),
    # Someone left: the same two, falling.
    "call_leave": (render([note(659.25, 0.0, 0.14, decay=4.5), note(440.0, 0.10, 0.24, decay=5.0)], 0.36, peak=0.45)),
    # Incoming call (desktop): a three-note figure twice, then a rest; played in a loop.
    "ring": (render(
        [note(f, s, 0.30, decay=3.5, partials=((1, 1.0), (2, 0.35), (4, 0.08)))
         for rep in (0.0, 0.62) for f, s in ((523.25, rep), (659.25, rep + 0.14), (783.99, rep + 0.28))],
        2.2, peak=0.55)),
}


def main():
    for folder in OUT:
        os.makedirs(folder, exist_ok=True)
        for name, samples in SOUNDS.items():
            # Android rings with the system ringtone; the ring is for the desktop app.
            if name == "ring" and "android" in folder:
                continue
            path = os.path.join(folder, f"skwod_{name}.wav")
            with wave.open(path, "wb") as w:
                w.setnchannels(1)
                w.setsampwidth(2)
                w.setframerate(RATE)
                w.writeframes(b"".join(struct.pack("<h", int(max(-1.0, min(1.0, s)) * 32767)) for s in samples))
            print(f"{os.path.relpath(path, ROOT)}  {os.path.getsize(path)} bytes")


if __name__ == "__main__":
    main()
