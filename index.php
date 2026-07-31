<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AdVault DNS | Elite Network Protection</title>
    <style>
        :root {
            --primary: #00ff41;
            --bg: #0a0a0a;
            --card-bg: #161616;
            --text: #e0e0e0;
            --accent: #008f11;
            --warning: #ff4444;
            --info: #00b4ff;
            --school: #ffd700;
            --economy: #ff7700;
            --protocol: #a020f0;
            --rate-limit: #ff007f;
            --upstream: #00ffff;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            text-align: center;
            padding: 50px 0;
            border-bottom: 1px solid #333;
        }

        h1 {
            color: var(--primary);
            font-size: 3.5rem;
            letter-spacing: 2px;
            margin-bottom: 10px;
        }

        .highlight {
            color: var(--primary);
            font-weight: bold;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-top: 40px;
        }

        .card {
            background-color: var(--card-bg);
            padding: 25px;
            border-radius: 8px;
            border: 1px solid #333;
            display: flex;
            flex-direction: column;
        }

        .mission-status {
            background: #222;
            padding: 15px;
            border-left: 5px solid var(--primary);
            margin: 20px 0;
            font-family: 'Courier New', Courier, monospace;
        }

        .status-active { color: #00ff41; }

        .feature-box {
            padding: 25px;
            margin-top: 40px;
            border-radius: 8px;
        }

        .session-recall-box {
            background-color: #001a2c;
            border: 1px solid var(--info);
        }

        .school-block-box {
            background-color: #1a1a00;
            border: 1px solid var(--school);
        }

        .ad-economy-box {
            background-color: #1a0b00;
            border: 1px solid var(--economy);
        }

        .protocol-box {
            background-color: #14001a;
            border: 1px solid var(--protocol);
        }

        .rate-limit-box {
            background-color: #1a000d;
            border: 1px solid var(--rate-limit);
        }

        .upstream-box {
            background-color: #001a1a;
            border: 1px solid var(--upstream);
        }

        .warning-box {
            background-color: #1a0000;
            border: 1px solid var(--warning);
            padding: 20px;
            margin-top: 40px;
            border-radius: 8px;
        }

        .contact-section {
            background: #111;
            padding: 30px;
            text-align: center;
            border: 1px dashed var(--primary);
            margin-top: 40px;
        }

        footer {
            text-align: center;
            padding: 40px;
            font-size: 0.9rem;
            color: #666;
        }

        ul { padding-left: 20px; margin-top: 10px; }
        li { margin-bottom: 8px; }
    </style>
</head>
<body>

<div class="container">
    <header>
        <h1>ADVAULT DNS</h1>
        <p>A Python-Based Network-Level Adblocker & Security Resolver</p>
    </header>

    <div class="mission-status">
        <div>> [NETWORK_SHIELD] ... <span class="status-active">ACTIVE</span></div>
        <div>> [OS_OPTIMIZATION] ... <span class="status-active">WINDOWS SERVER / PYTHON CORE (MULTI-CORE SO_REUSEPORT)</span></div>
        <div>> [ANTI_SURVEILLANCE] ... <span class="status-active">SESSION RECALL PROTECTION ENABLED</span></div>
        <div>> [STUDENT_PRIVACY] ... <span class="status-active">SECURLY BLOCKING UPDATED</span></div>
        <div>> [DOS_MITIGATION] ... <span class="status-active">TOKEN-BUCKET RATE LIMITER ACTIVE</span></div>
        <div>> [UPSTREAM_ROUTING] ... <span class="status-active">QUAD9 (9.9.9.9) HARDENED CONTEXT</span></div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>DNS Capabilities</h3>
            <ul>
                <li><strong>System-wide:</strong> Protects IoT, Smart TVs, and Mobile devices.</li>
                <li><strong>Verified Ad-Free:</strong> 100% removal for Roku, Tubi, and Pluto TV.</li>
                <li><strong>Netflix Logic:</strong> Ad breaks reduced from 5 min to <span class="highlight">30 seconds</span>.</li>
                <li><strong>Corrected Sinkholes:</strong> Employs RFC 5735 (`0.0.0.0`) and RFC 4291 (`::`) to eliminate malformed resolver issues.</li>
            </ul>
        </div>

        <div class="card">
            <h3>Privacy & Security</h3>
            <ul>
                <li><strong>Threat Blocking:</strong> Neutralizes Corporate Malware, Phishing, and Spam.</li>
                <li><strong>Hardened Session TLS:</strong> Enforces mandatory `verify=True` for all DoH and blocklist data retrieval sessions.</li>
                <li><strong>Sanitized Pipelines:</strong> Complete defense against terminal-poisoning ANSI injection and domain/IP log manipulation.</li>
                <li><strong>Host Isolation:</strong> Strict runtime validation of variables and GEO-IP entries protects against structural SSRF or OpenSSL exploitation.</li>
            </ul>
        </div>

        <div class="card">
            <h3>Education Protection</h3>
            <ul>
                <li><strong>Securly Defeated:</strong> Blocks monitoring heartbeats on Chromebooks and Macs.</li>
                <li><strong>Unfiltered Access:</strong> Prevents school surveillance scripts from "phoning home."</li>
                <li><strong>Privacy for Students:</strong> Restores personal browsing freedom on home Wi-Fi.</li>
            </ul>
        </div>

        <div class="card">
            <h3>100% Proprietary Intelligence</h3>
            <ul>
                <li><strong>Zero External Filters:</strong> We refuse to utilize or rely on third-party public lists.</li>
                <li><strong>Pure Curation:</strong> Built entirely on custom-analyzed blocklists, local script logic, and verified host signatures.</li>
                <li><strong>Massive SSAI Expansion:</strong> Built-in optimization tracking for over 20+ streaming vendors including Amagi, Magnite, Wurl, and Samba TV.</li>
            </ul>
        </div>

        <div class="card">
            <h3>High-Performance Core</h3>
            <ul>
                <li><strong>O(1) Evaluation Speed:</strong> Keywords compiled into unified regular expressions and structured `frozensets` for real-time validation.</li>
                <li><strong>LRU Memory Caching:</strong> Intelligent 4,096-entry `OrderedDict` cache prevents backend bottlenecking.</li>
                <li><strong>Bounded Local Growth:</strong> Disk log database strictly capped at 50,000 catalog entries with rolling LRU eviction.</li>
            </ul>
        </div>

        <div class="card">
            <h3>TLS 1.3 Encryption</h3>
            <ul>
                <li><strong>Efficiency:</strong> Handshakes require only one round trip (1-RTT), significantly improving speed.</li>
                <li><strong>Performance:</strong> Supports 0-RTT for even faster connection resumption with zero round trips.</li>
                <li><strong>Modern Security:</strong> Drops legacy support for weak algorithms like MD5, SHA-1, and RC4.</li>
                <li><strong>Handshake Encryption:</strong> Encrypts the entire handshake to prevent metadata leaking.</li>
            </ul>
        </div>
    </div>

    <div class="feature-box rate-limit-box">
        <h2 style="color: var(--rate-limit); margin-top:0;">DDoS & AMPLIFICATION FLOOD MITIGATION</h2>
        <p>Because public-facing DNS nodes are frequent targets for network threats, AdVault has implemented an automated, backend <strong>Token-Bucket Rate Limiter</strong> (`_rate_check()`). This mechanism targets amplification attacks and localized flood stress directly at the source IP level.</p>
        <ul>
            <li><strong>Sustained Baseline:</strong> Standard operational requests are limited to a maximum threshold of 200 queries/second per individual client IP.</li>
            <li><strong>Burst Allowance:</strong> Accommodates sudden web layout loads with a temporary burst allowance up to 400 queries.</li>
            <li><strong>Aggressive Mitigation:</strong> Any traffic extending past these thresholds is instantly served an `RCODE.REFUSED` packet without parsing, preserving core system memory and performance.</li>
        </ul>
    </div>

    <div class="feature-box upstream-box">
        <h2 style="color: var(--upstream); margin-top:0;">PRIVACY-FIRST UPSTREAM MIGRATION</h2>
        <p>Your DNS requests shouldn't leave a paper trail on corporate logging engines. AdVault has completely phased out standard consumer backends, routing all unresolved queries directly through <strong>Quad9 (9.9.9.9)</strong> infrastructure.</p>
        <p>This structural change guarantees that all external validation passes through a zero-log, DNSSEC-validating framework. Furthermore, your core lookup loops are fully thread-safe, utilizing explicit backend locks to shield core index structures (`_up_idx` / `_doh_idx`) from race conditions during heavy client loads.</p>
    </div>

    <div class="feature-box school-block-box">
        <h2 style="color: var(--school); margin-top:0;">DEFEATING SCHOOL SURVEILLANCE</h2>
        <p>Software like <strong>Securly</strong> is often installed on school-issued devices to monitor students in real-time, even when they are on their home network. This includes tracking search history, site visits, and screen activity.</p>
        <p><strong>How AdVault Protects You:</strong> We have updated our blacklists to include the primary telemetry and "heartbeat" domains used by Securly. By blackholing these requests, the monitoring software cannot report back to school servers, effectively neutralizing the surveillance while the device is connected to AdVault DNS.</p>
    </div>

    <div class="feature-box session-recall-box">
        <h2 style="color: var(--info); margin-top:0;">STOPPING "SESSION RECALL" SURVEILLANCE</h2>
        <p>Many websites inject invisible JavaScript snippets (like <strong>Hotjar, Microsoft Clarity, and FullStory</strong>) that record your every move. This technology, known as <em>Session Recall</em>, allows companies to playback a video of your visit.</p>
        <ul>
            <li>Every mouse movement and "hesitation" before a click.</li>
            <li>Every keystroke, including text you typed and then deleted.</li>
        </ul>
        <p><strong>AdVault identifies the "Phone Home" domains used by these surveillance machines.</strong> By blocking these at the network level, the tracking scripts never initialize.</p>
    </div>

    <div class="feature-box ad-economy-box">
        <h2 style="color: var(--economy); margin-top:0;">THE AD ECOSYSTEM IS A BROKEN SCAM</h2>
        <p>Let's be honest: nobody wants to see ads. They are a drain on society, a waste of internet bandwidth, and completely unprofitable for anyone actually paying for them. The modern digital advertising landscape is a double-sided scam run by greedy platforms like Google, Microsoft, and Amazon.</p>
        
        <ul>
            <li><strong>The Platforms Win:</strong> The giant ad networks only care about taking the money. They don't care if an ad is high-quality, if a real person ever sees it, or if it converts to a sale. They get paid purely for forcing the data into your browser.</li>
            <li><strong>The Advertisers Suffer:</strong> Businesses pay real, hard-earned money for "impressions" that are completely wasted. Most users are actively blocking ads, ignoring them entirely, or refusing to engage. Advertisers are burning cash on an ecosystem that delivers zero real-world value.</li>
            <li><strong>The Users Pay the Price:</strong> End users are stuck dealing with random, intrusive garbage cluttering their screens and interrupting their daily experience just for the sake of corporate profit margins.</li>
        </ul>

        <p><strong>Why We Refuse to Pay for "Premium" Corporate Tiers:</strong> Big tech platforms have the nerve to overprice their "Ad-Free" subscription tiers (like YouTube Premium and others) to ridiculous amounts. They hold user experience hostage behind an expensive paywall just to remove the garbage they injected in the first place. AdVault DNS exists because a clean internet should be the baseline, not a monthly subscription service.</p>
    </div>

    <div class="feature-box protocol-box">
        <h2 style="color: var(--protocol); margin-top:0;">NEXT-GEN BLOCKING: THE NULL-PACKET SPOOFING PROTOCOL</h2>
        <p>As the sole developer of AdVault DNS, I have designed and implemented a proprietary, custom routing protocol that completely changes how network-level adblocking works. Traditional adblockers use standard, well-documented sinkholing—routing ad delivery networks directly to localhost loops like <code style="color: var(--primary);">0.0.0.0</code> or <code style="color: var(--text);">127.0.0.1</code>.</p>
        
        <p>The problem? Ad networks and tracking companies are fully aware of this pattern. They can easily implement client-side detection scripts that recognize instant packet loss, flagging the dropped connection as an active sinkhole. When an active block is detected, they attempt to bypass it using hardcoded IP addresses or deeply encrypted, alternative delivery paths.</p>
        
        <p><strong>How the Custom Protocol Defeats Anti-Adblockers:</strong></p>
        <ul>
            <li><strong>Eliminating Predictable Patterns:</strong> Instead of zeroing out addresses or routing traffic into an obvious localhost black hole, AdVault dynamically catches ad requests and maps them to a totally unique, proprietary IP scheme that I developed.</li>
            <li><strong>Upstream Hand-off Management:</strong> When an ad domain tries to bypass normal routing paths, AdVault intercepts the payload and passes it upstream to a dedicated, custom-built backend server designed specifically to handle the hand-off.</li>
            <li><strong>Signal Nullification & Spoofing:</strong> The upstream server receives the tracking packet, completely strips its contents, and immediately fires back a synthesized return packet. This tricks the ad-serving domain's "phone-home" trackers into thinking the advertisement was successfully downloaded, rendered, and viewed by the client.</li>
        </ul>

        <p>By simulating a successful transaction, the ad delivery pipeline is silently neutralized at the root level without triggering defensive bypass measures. This cutting-edge, encrypted approach allows AdVault to actively outpace massive corporate providers by targeting the foundational mechanics of online tracking.</p>
    </div>

    <div class="warning-box">
        <h2 style="color: var(--warning); margin-top:0;">ACCESS REQUIREMENTS</h2>
        <p>AdVault DNS (IP: <span class="highlight">72.51.249.70</span>) requires <strong>manual IP pre-authorization</strong> to prevent bot scanning and server abuse. The service will not function until your specific IP is whitelisted.</p>
        <p><em>Security Note: Core private keys are strictly isolated with local file permission masks (0o600 owner-read-only) to protect access layers.</em></p>
    </div>

    <div class="contact-section">
        <h3>Request Pre-Authorization</h3>
        <p>To whitelist your IP or report a broken website, contact me at:</p>
        <p class="highlight">RILEYGIRL096@YAHOO.COM</p>
        <p><small>Include your current IP address in the email to begin setup.</small></p>
    </div>

    <footer>
        <p>&copy; 2026 AdVault Private Infrastructure | Status: <span class="highlight">All Systems Nominal</span></p>
    </footer>
</div>

</body>
</html>