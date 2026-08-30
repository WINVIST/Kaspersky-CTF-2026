#!/usr/bin/env python3
import sys
import wave

import numpy as np


FREQUENCIES = (997, 2203, 4211)
MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9", "..--.-": "_",
}


def read_wav(path):
    with wave.open(path, "rb") as wav:
        if wav.getnchannels() != 1 or wav.getsampwidth() != 2:
            raise ValueError("expected mono PCM16 WAV")
        sample_rate = wav.getframerate()
        samples = np.frombuffer(wav.readframes(wav.getnframes()), dtype="<i2")
    return sample_rate, samples.astype(np.float64) / 32768.0


def demodulate(samples, sample_rate):
    block_size = sample_rate // 40  # 25 ms
    envelopes = []

    for start in range(0, len(samples), block_size):
        chunk = samples[start:start + block_size]
        absolute_t = (start + np.arange(len(chunk))) / sample_rate
        columns = []

        for frequency in FREQUENCIES:
            columns.append(np.cos(2 * np.pi * frequency * absolute_t))
            columns.append(np.sin(2 * np.pi * frequency * absolute_t))

        coefficients = np.linalg.lstsq(np.column_stack(columns), chunk, rcond=None)[0]
        envelopes.append([
            np.hypot(coefficients[i], coefficients[i + 1])
            for i in range(0, len(coefficients), 2)
        ])

    return np.asarray(envelopes)


def runs(states):
    starts = np.r_[0, 1 + np.flatnonzero(states[1:] != states[:-1])]
    ends = np.r_[starts[1:], len(states)]
    return [(start, end, bool(states[start])) for start, end in zip(starts, ends)]


def remove_short_motion(states, minimum=3):
    """Drop one-frame threshold spikes without touching the Morse pauses."""
    cleaned = states.copy()
    for start, end, is_moving in runs(cleaned):
        if is_moving and end - start < minimum:
            cleaned[start:end] = False
    return cleaned


def decode(envelopes):
    xyz = (envelopes - envelopes.min(axis=0)) / np.ptp(envelopes, axis=0)
    speed = np.linalg.norm(np.diff(xyz, axis=0), axis=1)
    moving = remove_short_motion(speed > 0.01)
    motion_runs = [run for run in runs(moving) if run[0] >= 60]

    decoded = []
    morse_text = []
    current = ""

    for start, end, is_moving in motion_runs:
        frames = end - start

        if is_moving:
            mark = "." if frames <= 6 else "-"
            current += mark
            morse_text.append(mark)
        elif frames >= 6 and current:
            decoded.append(MORSE.get(current, f"[{current}]"))
            morse_text.append(" ")
            current = ""

    if current:
        decoded.append(MORSE.get(current, f"[{current}]"))

    return "".join(morse_text).strip(), "".join(decoded)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "challenge.wav"
    sample_rate, samples = read_wav(path)
    morse, text = decode(demodulate(samples, sample_rate))
    print(morse)
    print(text)
    print(f"kaspersky{{{text}}}")


if __name__ == "__main__":
    main()

