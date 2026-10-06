window.GameAudio = (function () {
    "use strict";

    let ctx = null;
    let muted = localStorage.getItem("gamesAudioMuted") === "true";

    function getCtx() {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return null;
        if (!ctx) ctx = new AudioContext();
        if (ctx.state === "suspended") ctx.resume();
        return ctx;
    }

    function tone(freq, duration, type, delay, gainPeak) {
        if (muted) return;
        const c = getCtx();
        if (!c) return;
        const osc = c.createOscillator();
        const gain = c.createGain();
        osc.type = type || "sine";
        osc.frequency.value = freq;
        const startAt = c.currentTime + (delay || 0);
        gain.gain.setValueAtTime(0, startAt);
        gain.gain.linearRampToValueAtTime(gainPeak || 0.15, startAt + 0.01);
        gain.gain.exponentialRampToValueAtTime(0.0001, startAt + duration);
        osc.connect(gain);
        gain.connect(c.destination);
        osc.start(startAt);
        osc.stop(startAt + duration + 0.02);
    }

    function setMuted(value) {
        muted = value;
        localStorage.setItem("gamesAudioMuted", value ? "true" : "false");
    }

    return {
        isMuted: () => muted,
        setMuted,
        toggleMuted: () => { setMuted(!muted); return muted; },
        click:   () => tone(320, 0.06, "square", 0, 0.08),
        pop:     () => tone(260, 0.08, "sine", 0, 0.12),
        success: () => { tone(523, 0.10, "sine", 0, 0.14); tone(784, 0.14, "sine", 0.08, 0.14); },
        fail:    () => tone(140, 0.20, "sawtooth", 0, 0.10),
        win:     () => { tone(523, 0.12, "sine", 0, 0.16); tone(659, 0.12, "sine", 0.10, 0.16); tone(784, 0.20, "sine", 0.20, 0.16); },
        merge:   (tier) => { const b = 300 + tier * 60; tone(b, 0.12, "sine", 0, 0.14); tone(b * 1.5, 0.12, "sine", 0.05, 0.10); },
    };
})();