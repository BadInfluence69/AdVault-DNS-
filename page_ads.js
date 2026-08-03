// ==========================================================================
// page_ads.js — removes YouTube's static page ads (homepage, search, sidebar)
// --------------------------------------------------------------------------
// Runs in the ISOLATED world, so it cannot collide with the MAIN-world hooks
// in player_guard, content.js, or cleaner.js. Those three own the video path:
// pause gating, IMA stubbing, manifest filtering, and JSON ad-slot purging.
// This file never touches <video>, never patches a prototype, and never
// intercepts a network call. It only deletes DOM nodes that are ads.
//
// Division of labour with page_ads.css:
//   CSS  — hides ad elements the instant they paint (no flash of ad content)
//   JS   — removes the ad node AND the empty grid cell / section it sat in,
//          so the feed reflows instead of leaving a gap
// ==========================================================================

(function () {
    'use strict';

    const CONFIG = {
        // Remove nodes outright rather than leaving them hidden. Removal is
        // what closes the gap in the rich-grid; hiding alone often does not.
        removeNodes: true,

        // Also strip the "Sponsored"/"Promoted" badged results that YouTube
        // renders as an ordinary ytd-video-renderer. Off by default because
        // it relies on a text/badge check that can, in principle, catch a
        // legitimate result. Flip to true if promoted results still appear.
        badgeHeuristic: false,

        log: false,
    };

    const log = (...a) => CONFIG.log && console.debug('[page-ads]', ...a);

    // ----------------------------------------------------------------------
    // 1. WHAT COUNTS AS AN AD
    // ----------------------------------------------------------------------
    // Keep this list in sync with page_ads.css. The CSS hides, this removes.

    const AD_SELECTOR = [
        // feed / homepage
        'ytd-ad-slot-renderer',
        'ytd-in-feed-ad-layout-renderer',
        'ytd-banner-promo-renderer',
        'ytd-banner-promo-renderer-background',
        'ytd-statement-banner-renderer',
        'ytd-primetime-promo-renderer',
        'ytd-brand-video-shelf-renderer',
        'ytd-brand-video-singleton-renderer',
        'ytd-inline-survey-renderer',
        '#masthead-ad',
        // search
        'ytd-promoted-sparkles-web-renderer',
        'ytd-promoted-sparkles-text-search-renderer',
        'ytd-promoted-video-renderer',
        'ytd-search-pyv-renderer',
        'ytd-carousel-ad-renderer',
        // watch page
        'ytd-display-ad-renderer',
        'ytd-compact-promoted-video-renderer',
        'ytd-compact-promoted-item-renderer',
        'ytd-action-companion-ad-renderer',
        'ytd-companion-slot-renderer',
        'ytd-player-legacy-desktop-watch-ads-renderer',
        '#player-ads',
        '#offer-module',
        // mobile
        'ytm-promoted-video-renderer',
        'ytm-promoted-sparkles-web-renderer',
        'ytm-companion-slot',
        'ytm-carousel-ad-renderer',
    ].join(',');

    // Layout wrappers that exist only to position one item. If an ad was the
    // wrapper's only real content, the wrapper goes too — that is what stops
    // the blank tile from appearing in the homepage grid.
    const WRAPPER_TAGS = new Set([
        'YTD-RICH-ITEM-RENDERER',
        'YTD-RICH-SECTION-RENDERER',
        'YTD-ITEM-SECTION-RENDERER',
        'YTD-SHELF-RENDERER',
        'YTD-COMPACT-VIDEO-RENDERER',
        'YTM-ITEM-SECTION-RENDERER',
    ]);

    // If a wrapper still holds one of these after the ad is gone, it is
    // carrying real content and must be left alone.
    const REAL_CONTENT_SELECTOR = [
        'ytd-video-renderer',
        'ytd-grid-video-renderer',
        'ytd-rich-item-renderer',
        'ytd-compact-video-renderer',
        'ytd-playlist-renderer',
        'ytd-radio-renderer',
        'ytd-channel-renderer',
        'ytd-reel-shelf-renderer',
        'ytd-reel-item-renderer',
        'ytd-movie-renderer',
        'ytd-post-renderer',
        'ytm-video-with-context-renderer',
        'ytm-compact-video-renderer',
    ].join(',');

    // ----------------------------------------------------------------------
    // 2. REMOVAL
    // ----------------------------------------------------------------------

    function drop(el) {
        if (!el || !el.isConnected) return;
        if (CONFIG.removeNodes) {
            el.remove();
        } else {
            el.style.setProperty('display', 'none', 'important');
        }
    }

    // Walk up from an ad node, removing wrappers that have nothing left in
    // them. Stops at the first wrapper that still contains real content, and
    // never climbs past a container that holds siblings (a grid row, the feed
    // itself), so a single ad can never take the page down with it.
    function pruneUpward(adNode) {
        let target = adNode;
        let parent = target.parentElement;
        let hops = 0;

        while (parent && hops < 4) {
            if (!WRAPPER_TAGS.has(parent.tagName)) break;

            // Does anything other than this ad live inside the wrapper?
            const survivors = Array.from(
                parent.querySelectorAll(REAL_CONTENT_SELECTOR)
            ).filter((n) => !target.contains(n) && n !== target);

            if (survivors.length > 0) break;

            target = parent;
            parent = target.parentElement;
            hops++;
        }

        log('removing', target.tagName, target.id || '');
        drop(target);
    }

    function sweep(root) {
        let found;
        try {
            found = root.querySelectorAll ? root.querySelectorAll(AD_SELECTOR) : [];
        } catch (_) {
            return;
        }
        for (const node of found) pruneUpward(node);

        if (CONFIG.badgeHeuristic) sweepBadged(root);
    }

    // Optional: catch promoted results rendered as a normal video card with a
    // "Sponsored" / "Promoted" badge instead of a dedicated ad element.
    function sweepBadged(root) {
        let cards;
        try {
            cards = root.querySelectorAll(
                'ytd-video-renderer, ytd-rich-item-renderer, ytd-compact-video-renderer'
            );
        } catch (_) {
            return;
        }
        for (const card of cards) {
            const badge = card.querySelector(
                'ytd-badge-supported-renderer, .badge-style-type-ad, [aria-label="Sponsored"]'
            );
            if (!badge) continue;
            const text = (badge.textContent || '').trim().toLowerCase();
            if (text === 'sponsored' || text === 'promoted' || text === 'ad') {
                log('badge match', text);
                pruneUpward(card);
            }
        }
    }

    // ----------------------------------------------------------------------
    // 3. KEEPING UP WITH THE PAGE
    // ----------------------------------------------------------------------
    // YouTube is a single-page app: it swaps the whole feed without a reload,
    // and it injects feed ads lazily as you scroll. A one-shot pass at load
    // would catch almost nothing, so watch for additions instead.

    let queued = false;
    const pending = new Set();

    function schedule() {
        if (queued) return;
        queued = true;
        requestAnimationFrame(() => {
            queued = false;
            const batch = Array.from(pending);
            pending.clear();
            for (const node of batch) {
                if (node.isConnected) sweep(node);
            }
        });
    }

    const observer = new MutationObserver((mutations) => {
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (node.nodeType !== 1) continue;

                // Fast path: the added node is itself an ad.
                let isAd = false;
                try {
                    isAd = node.matches(AD_SELECTOR);
                } catch (_) {}

                if (isAd) {
                    pruneUpward(node);
                } else {
                    pending.add(node);
                }
            }
        }
        if (pending.size) schedule();
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
    });

    // Full passes at the points where YouTube has just rebuilt the page.
    const fullSweep = () => sweep(document);

    fullSweep();
    document.addEventListener('DOMContentLoaded', fullSweep);
    window.addEventListener('load', fullSweep);

    // Polymer's own navigation events — these fire on document, so an
    // isolated-world listener still sees them.
    document.addEventListener('yt-navigate-finish', fullSweep);
    document.addEventListener('yt-page-data-updated', fullSweep);
    document.addEventListener('yt-service-request-completed', fullSweep);

    log('active');
})();
