(function() {
    // Target the initial configuration object where ad slots are defined
    const cleanYoutubeConfig = () => {
        if (window.ytplayer && window.ytplayer.config) {
            let cfg = window.ytplayer.config;
            
            // Remove ad spec arrays that force the player to buffer an ad chunk
            if (cfg.args) {
                delete cfg.args.ad_device;
                delete cfg.args.ad_flags;
                delete cfg.args.ad_logging_flag;
                delete cfg.args.adsense_video_doc_id;
                cfg.args.ad3_module = "0"; 
            }
            
            // Neutralize the player response object structure where mid-rolls are defined
            if (cfg.player_response) {
                try {
                    let response = JSON.parse(cfg.player_response);
                    if (response.adPlacements) {
                        // Empty out the ad placements in timeline progressbar entirely
                        response.adPlacements = [];
                    }
                    cfg.player_response = JSON.stringify(response);
                } catch (e) {}
            }
        }
    };

    // Run immediately, and also intercept the object assignment
    cleanYoutubeConfig();
    
    Object.defineProperty(window, 'ytplayer', {
        configurable: true,
        set: function(val) {
            this._ytplayer = val;
            cleanYoutubeConfig();
        },
        get: function() {
            return this._ytplayer;
        }
    });
})();