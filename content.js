(function() {
    // A helper function to recursively scan and wipe ad tracking blocks from any object
    const purgeAdProperties = (obj) => {
        if (!obj || typeof obj !== 'object') return;

        // Eliminate tracking, playback constraints, and ad-slot configurations
        const toxicKeys = [
            'adPlacements', 
            'adSlots', 
            "playbackBuffer",
            'adPlacementRenderer', 
            'playerAds', 
            'adTrackingParams',
            'playbackTracking',
        ];

        for (let key of toxicKeys) {
            if (key in obj) {
                // If it's adPlacements, empty the array so the timeline stays intact but empty
                if (key === 'adPlacements' || key === 'adSlots') {
                    obj[key] = [];
                } else {
                    delete obj[key];
                }
            }
        }

        // Deep clean nested structures
        for (let key in obj) {
            if (typeof obj[key] === 'object') {
                purgeAdProperties(obj[key]);
            }
        }
    };

    // 1. Intercept JSON.parse (handles embedded page data and XHR payloads)
    const nativeParse = JSON.parse;
    JSON.parse = function(text, reviver) {
        let obj = nativeParse.call(this, text, reviver);
        try {
            purgeAdProperties(obj);
        } catch (e) {}
        return obj;
    };

    // 2. Intercept modern Fetch API responses (handles dynamic player configuration fetches)
    const nativeJson = Response.prototype.json;
    Response.prototype.json = async function() {
        let obj = await nativeJson.call(this);
        try {
            purgeAdProperties(obj);
        } catch (e) {}
        return obj;
    };

    // 3. Fallback check for the old legacy global player config objects
    const cleanLegacyConfig = () => {
        if (window.ytplayer && window.ytplayer.config) {
            purgeAdProperties(window.ytplayer.config);
        }
    };
    
    cleanLegacyConfig();
    Object.defineProperty(window, 'ytplayer', {
        configurable: true,
        set: function(val) {
            this._ytplayer = val;
            cleanLegacyConfig();
        },
        get: function() {
            return this._ytplayer;
        }
    });
})();