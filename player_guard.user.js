// ==UserScript==
// @name         Player Guard — user-only pause + client-side ad neutralizer
// @namespace    local.adfilter
// @version      1.0
// @description  Only the user can pause the video. Ad-triggered pauses, ad breaks, and cue markers are nullified before the player ever acts on them.
// @match        *://*/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

/*
 * WHAT THIS DOES THAT THE NETWORK LAYER CANNOT
 * ────────────────────────────────────────────
 * DNS blocking and manifest rewriting both operate on bytes in flight. Neither
 * can touch the decision a player makes in JavaScript to call video.pause() and
 * hand the screen to an ad module. That decision happens entirely inside the
 * page, after the network is done. So the "only the user may pause" rule has to
 * be enforced here, in the DOM.
 *
 * Two distinct ad mechanisms, handled differently:
 *
 *   SSAI (server-side)  — ads are stitched into the same stream. The player
 *                         never pauses; it just plays ad segments. Nothing to
 *                         do here — manifest_filter.py handles it upstream.
 *
 *   CSAI (client-side)  — the player pauses content, swaps in an ad player
 *                         (usually Google IMA), plays the ad, then resumes.
 *                         This is the pause you want abolished. Handled below.
 *
 * Install: Violentmonkey or Tampermonkey. Narrow the @match line to the sites
 * you actually use — the default match-all runs this on every page you visit.
 */

(function () {
    'use strict';

    const CONFIG = {
        // How long after a real user input a pause() call is still considered
        // user-initiated. Covers the player's own click handler dispatching
        // asynchronously. Too long and a site can piggyback on your click.
        gestureWindowMs: 1200,

        // Watchdog: if the video ends up paused with no user gesture behind it,
        // resume it. Backoff below prevents a fight with the page.
        autoResume: true,
        maxForcedResumes: 6,      // per cooldown window
        cooldownMs: 10000,

        // Replace the Google IMA SDK with a stub that reports "no ad" instantly.
        // This is the single highest-value item here: without it, a player whose
        // ad request was blocked sits in its own ad timeout — often 5-8 seconds
        // of black screen — before falling back to content. The stub collapses
        // that to one tick.
        stubIMA: true,

        // Filter HLS/DASH manifests fetched by the page. Redundant if you are
        // running manifest_filter.py in the path; useful when you are not.
        filterManifestsInPage: true,

        // Hide ad-break markers drawn on the scrub bar.
        hideCueMarkers: true,

        log: true,
    };

    const log = (...a) => CONFIG.log && console.debug('[player-guard]', ...a);

    // ═══════════════════════════════════════════════════════════════════
    // 1. USER GESTURE TRACKING
    // ═══════════════════════════════════════════════════════════════════
    // isTrusted is the browser's own guarantee that an event came from real
    // hardware input. A page cannot forge it — dispatchEvent() always produces
    // isTrusted === false. That property is the entire basis of this script.

    let lastGestureAt = 0;

    const GESTURES = ['pointerdown', 'mousedown', 'keydown', 'touchstart', 'click'];
    for (const type of GESTURES) {
        window.addEventListener(type, (e) => {
            if (e.isTrusted) lastGestureAt = Date.now();
        }, { capture: true, passive: true });
    }

    const userIsDriving = () => (Date.now() - lastGestureAt) < CONFIG.gestureWindowMs;

    // ═══════════════════════════════════════════════════════════════════
    // 2. PAUSE GATE
    // ═══════════════════════════════════════════════════════════════════

    const nativePause = HTMLMediaElement.prototype.pause;
    const nativePlay = HTMLMediaElement.prototype.play;

    // Escape hatch: our own watchdog and any deliberate override set this so it
    // does not gate itself.
    let bypassGate = false;

    HTMLMediaElement.prototype.pause = function () {
        if (bypassGate || userIsDriving()) {
            return nativePause.apply(this, arguments);
        }

        // Genuine non-ad reasons a page pauses that we should not fight:
        //  - the element is not actually playing
        //  - the tab is hidden (background throttling, PiP handoff)
        //  - playback already ended
        if (this.paused || this.ended || document.visibilityState === 'hidden') {
            return nativePause.apply(this, arguments);
        }

        log('blocked programmatic pause on', this.currentSrc?.slice(0, 80) || this);
        return undefined;   // real pause() returns undefined, so this is honest
    };

    // ═══════════════════════════════════════════════════════════════════
    // 3. AUTO-RESUME WATCHDOG
    // ═══════════════════════════════════════════════════════════════════
    // A player can pause without calling pause() — by tearing down the source,
    // or by pausing from inside a context we did not intercept. The watchdog
    // catches the outcome rather than the call.

    const resumeState = new WeakMap();

    function watch(el) {
        if (resumeState.has(el)) return;
        resumeState.set(el, { count: 0, windowStart: Date.now() });

        el.addEventListener('pause', () => {
            if (!CONFIG.autoResume) return;
            if (userIsDriving() || el.ended || el.seeking) return;
            if (document.visibilityState === 'hidden') return;

            const st = resumeState.get(el);
            const now = Date.now();
            if (now - st.windowStart > CONFIG.cooldownMs) {
                st.count = 0;
                st.windowStart = now;
            }
            if (st.count >= CONFIG.maxForcedResumes) {
                // Back off. If we are still fighting the page after this many
                // tries, something legitimate wants it paused and looping would
                // just burn CPU and lock the tab.
                log('resume backoff — yielding to the page');
                return;
            }
            st.count++;

            bypassGate = true;
            const p = nativePlay.call(el);
            if (p && p.catch) p.catch(() => {});
            bypassGate = false;
            log('auto-resumed unrequested pause');
        }, true);
    }

    // Catch elements that exist now and any added later.
    const scanMedia = (root) => {
        try {
            root.querySelectorAll?.('video, audio').forEach(watch);
        } catch (_) {}
    };

    new MutationObserver((muts) => {
        for (const m of muts) {
            for (const n of m.addedNodes) {
                if (n.nodeType !== 1) continue;
                if (n.tagName === 'VIDEO' || n.tagName === 'AUDIO') watch(n);
                else scanMedia(n);
            }
        }
    }).observe(document.documentElement, { childList: true, subtree: true });

    scanMedia(document);
    document.addEventListener('DOMContentLoaded', () => scanMedia(document));

    // ═══════════════════════════════════════════════════════════════════
    // 4. AD EVENT LISTENERS
    // ═══════════════════════════════════════════════════════════════════
    // Players register handlers for ad lifecycle events on the media element.
    // Refusing to register them means the handler that would have paused the
    // video never exists in the first place.

    const AD_EVENT_RE = /^(ad|ima|vast|vpaid|vmap|cue|break)[-_.]?(start|begin|break|pod|request|load|impress|progress|complete|end|error|skip|marker)/i;

    const nativeAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, fn, opts) {
        if (typeof type === 'string'
            && AD_EVENT_RE.test(type)
            && (this instanceof HTMLMediaElement)) {
            log('refused ad listener:', type);
            return;
        }
        return nativeAddEventListener.call(this, type, fn, opts);
    };

    // ═══════════════════════════════════════════════════════════════════
    // 5. GOOGLE IMA STUB
    // ═══════════════════════════════════════════════════════════════════
    // IMA is what most web players use for pre/mid-roll. The contract the player
    // expects is: request ads → get AD_ERROR or ALL_ADS_COMPLETED → resume
    // content. We provide that answer immediately. No ad is fetched, no
    // impression is recorded, and the player's own ad timeout never starts.

    if (CONFIG.stubIMA) {
        const makeIMA = () => {
            const listeners = new Map();
            function EventBus() {}
            EventBus.prototype.addEventListener = function (t, f) {
                if (!listeners.has(t)) listeners.set(t, []);
                listeners.get(t).push(f);
            };
            EventBus.prototype.removeEventListener = function (t, f) {
                const arr = listeners.get(t) || [];
                const i = arr.indexOf(f);
                if (i >= 0) arr.splice(i, 1);
            };
            const fire = (t, payload) =>
                (listeners.get(t) || []).forEach((f) => {
                    try { f(payload); } catch (_) {}
                });

            const AdErrorEvent = { Type: { AD_ERROR: 'adError' } };
            const AdEvent = {
                Type: {
                    ALL_ADS_COMPLETED: 'allAdsCompleted',
                    CONTENT_RESUME_REQUESTED: 'contentResumeRequested',
                    CONTENT_PAUSE_REQUESTED: 'contentPauseRequested',
                    COMPLETE: 'complete', LOADED: 'loaded', STARTED: 'start',
                },
            };

            function AdsLoader() {}
            AdsLoader.prototype = Object.create(EventBus.prototype);
            AdsLoader.prototype.requestAds = function () {
                // Answer on the next tick, the way a real network call would,
                // so players that assume asynchrony do not break.
                setTimeout(() => {
                    fire(AdErrorEvent.Type.AD_ERROR, {
                        getError: () => ({
                            getErrorCode: () => 1009,   // VAST_EMPTY_RESPONSE
                            getMessage: () => 'No ads available',
                            toString: () => 'AdError 1009: No ads available',
                        }),
                        type: 'adError',
                    });
                    fire(AdEvent.Type.CONTENT_RESUME_REQUESTED, { type: 'contentResumeRequested' });
                    fire(AdEvent.Type.ALL_ADS_COMPLETED, { type: 'allAdsCompleted' });
                }, 0);
            };
            AdsLoader.prototype.contentComplete = function () {};
            AdsLoader.prototype.destroy = function () { listeners.clear(); };
            AdsLoader.prototype.getSettings = () => ({
                setPlayerType() {}, setPlayerVersion() {}, setLocale() {},
                setAutoPlayAdBreaks() {}, setNumRedirects() {},
                setVpaidMode() {}, setDisableCustomPlaybackForIOS10Plus() {},
            });

            const noop = () => {};
            return {
                AdsLoader,
                AdsManagerLoadedEvent: { Type: { ADS_MANAGER_LOADED: 'adsManagerLoaded' } },
                AdErrorEvent, AdEvent,
                AdDisplayContainer: function () {
                    return { initialize: noop, destroy: noop };
                },
                AdsRequest: function () { return {}; },
                AdsRenderingSettings: function () { return {}; },
                ImaSdkSettings: { VpaidMode: { DISABLED: 0, ENABLED: 1, INSECURE: 2 } },
                settings: {
                    setPlayerType: noop, setPlayerVersion: noop, setLocale: noop,
                    setVpaidMode: noop, setDisableCustomPlaybackForIOS10Plus: noop,
                    setAutoPlayAdBreaks: noop, setNumRedirects: noop,
                },
                ViewMode: { NORMAL: 'normal', FULLSCREEN: 'fullscreen' },
                UiElements: { AD_ATTRIBUTION: 'adAttribution', COUNTDOWN: 'countdown' },
                VERSION: '3.0.0',
            };
        };

        window.google = window.google || {};
        try {
            Object.defineProperty(window.google, 'ima', {
                value: makeIMA(),
                writable: false,
                configurable: false,
            });
            log('IMA stubbed');
        } catch (e) {
            window.google.ima = makeIMA();
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // 6. IN-PAGE MANIFEST FILTERING
    // ═══════════════════════════════════════════════════════════════════
    // Mirrors the HLS rules in manifest_filter.py for the case where you are
    // not running the proxy. The proxy version is more thorough — it repairs
    // MEDIA-SEQUENCE and key continuity, and handles DASH.

    const AD_URI_RE = /\/(adbreak|ad-break|adsegment|creative|creatives|preroll|midroll|postroll|adpod|ad-pod|ads|ad|dai|ssai|vast|vmap)\//i;

    function filterHLS(text) {
        if (!text.includes('#EXTM3U')) return text;
        const out = [];
        let inBreak = false, pending = [], dropped = false;

        for (const raw of text.split('\n')) {
            const line = raw.trim();
            if (!line) continue;

            if (line[0] === '#') {
                const up = line.toUpperCase();
                if (up.startsWith('#EXT-X-CUE-OUT') || up.startsWith('#EXT-OATCLS-SCTE35')
                    || up.startsWith('#EXT-X-SCTE35')) { inBreak = true; continue; }
                if (up.startsWith('#EXT-X-CUE-IN')) { inBreak = false; continue; }
                if (up.includes('EXT-X-DATERANGE')
                    && (up.includes('SCTE35') || up.includes('X-ASSET')
                        || up.includes('INTERSTITIAL'))) { continue; }
                if (up.startsWith('#EXT-X-ASSET')) continue;
                if (up.startsWith('#EXT-X-DISCONTINUITY')
                    && !up.startsWith('#EXT-X-DISCONTINUITY-SEQUENCE')) {
                    if (dropped) { dropped = false; continue; }
                    out.push(line); continue;
                }
                if (up.startsWith('#EXTINF') || up.startsWith('#EXT-X-BYTERANGE')) {
                    pending.push(line); continue;
                }
                out.push(line);
                continue;
            }

            if (inBreak || AD_URI_RE.test(line)) {
                pending = []; dropped = true; continue;
            }
            out.push(...pending, line);
            pending = [];
        }
        return out.join('\n') + '\n';
    }

    const looksLikeManifest = (url) =>
        /\.m3u8?(\?|$)/i.test(url) || /\.mpd(\?|$)/i.test(url);

    if (CONFIG.filterManifestsInPage && window.fetch) {
        const nativeFetch = window.fetch;
        window.fetch = async function (input, init) {
            const url = typeof input === 'string' ? input : (input?.url || '');
            const resp = await nativeFetch.apply(this, arguments);
            if (!looksLikeManifest(url)) return resp;
            try {
                const body = await resp.clone().text();
                const filtered = filterHLS(body);
                if (filtered === body) return resp;
                log('filtered manifest', url.slice(0, 80));
                return new Response(filtered, {
                    status: resp.status,
                    statusText: resp.statusText,
                    headers: resp.headers,
                });
            } catch (_) {
                return resp;
            }
        };
    }

    if (CONFIG.filterManifestsInPage) {
        const XHR = XMLHttpRequest.prototype;
        const nativeOpen = XHR.open;
        XHR.open = function (method, url) {
            this.__pgURL = url;
            return nativeOpen.apply(this, arguments);
        };
        // responseText is a getter on the prototype; shadow it per-instance.
        const desc = Object.getOwnPropertyDescriptor(XHR, 'responseText');
        if (desc && desc.get) {
            Object.defineProperty(XHR, 'responseText', {
                configurable: true,
                get: function () {
                    const raw = desc.get.call(this);
                    if (typeof raw === 'string' && looksLikeManifest(this.__pgURL || '')) {
                        try { return filterHLS(raw); } catch (_) { return raw; }
                    }
                    return raw;
                },
            });
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // 7. SCRUB-BAR CUE MARKERS
    // ═══════════════════════════════════════════════════════════════════

    if (CONFIG.hideCueMarkers) {
        const css = document.createElement('style');
        css.textContent = `
            .ytp-ad-progress, .ytp-ad-progress-list,
            [class*="ad-marker" i], [class*="admarker" i],
            [class*="cue-point" i], [class*="cuepoint" i],
            [class*="ad-break-marker" i], [class*="ad-cue" i],
            [data-testid*="ad-marker" i] {
                display: none !important;
            }
        `;
        (document.head || document.documentElement).appendChild(css);
    }

    log('active');
})();
