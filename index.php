<?php
// Define file paths for blocklists and allowlist
$blocklist_file = 'dynamic_blocklist.txt'; // Path to your primary blocklist file
$allowlist_file = 'allowlist.txt';        // Path to your allowlist file

// Initialize stats counters
$total_blocked_domains = 0;
$total_allowed_domains = 0;

// Define keywords for categorization (case-insensitive search)
// Prioritize categories in the order they are checked below (e.g., malware first)
$malware_keywords = [
    'malware', 'virus', 'trojan', 'ransom', 'exploit', 'botnet', 'ddos', 'c2', 'commandandcontrol',
    'worm', 'spyware', 'adware', 'keygen', 'crack', 'pharma', 'pirate', 'badware', 'infected',
    'securityalert', 'vulnerable', 'cryptomining', 'xmr', 'monero', 'miner', 'coin-hive',
    'coinhive', 'fakewebsite', 'hacktool', 'pwned', 'exploits'
];

$scam_keywords = [
    'scam', 'phishing', 'fraud', 'fake', 'hoax', 'phish', 'spoof', 'bogus',
    'bitcoin-scam', 'crypto-scam', 'giveaway', 'prize', 'win-money', 'free-money',
    'login-verify', 'account-alert', 'security-update', 'urgent-action', 'verify-account',
    'paypal-fraud', 'bank-security', 'refund-scam', 'tax-scam', 'lottery-scam', 'techsupport', "bitcoin" // Added common scam vectors
];

$ad_keywords = [
    'ad', 'ads', 'adserver', 'adnetwork', 'googlesyndication', 'doubleclick', 'doubleverify',
    'amazon-adsystem', 'pubmatic', 'criteo', 'adnxs', 'adservice', 'adtech',
    'bidder', 'yieldmo', 'applovin', 'unityads', 'chartboost', 'adcolony',
    'advertising', ' programmatic', 'media.net', 'openx', 'rubiconproject', 'smaato',
    'indexexchange', 'magnite', 'spotx', 'yieldbot', 'rtb', 'dsp', 'ssp', 'demandbase', 'vungle',
    'ironsource', 'fyber', 'mopub', 'admob', 'inmobi', 'conversant', 'taboola', 'outbrain',
    'nativead', 'popcash', 'propellerads', 'adcash', 'revenuehits', 'revcontent', 'exoclick' // Extensive ad-related keywords
];

$tracking_keywords = [
    'tracker', 'analytics', 'smetrics', 'pixel', 'beacon', 'segment', 'mixpanel',
    'amplitude', 'matomo', 'gtm', 'tagmanager', 'connect.facebook.net',
    'google-analytics.com', 'tracking', 'telemetry', 'log', 'stats', 'data',
    'events.data.microsoft.com', 'telemetry.microsoft.com', 'client.telemetry.microsoft.com',
    'app-measurement.com', 'crashlytics.com', 'firebaseinstallations.googleapis.com',
    'datadog', 'newrelic', 'sentry.io', 'fullstory.com', 'hotjar.com',
    'mixpanel.com', 'pendo.io', 'optimizely.com', 'rudderlabs.com', 'segment.io',
    'api.segment.io', 'events.amplitude.com', 'log.mixpanel.com', 'ingest.sentry.io',
    'rum.browser-intake-datadoghq.com', 'collector.newrelic.com',
    'diag', 'diagnostics', 'monitor', 'profiling', 'user-data', 'usage', 'collect',
    'cookie', 'fingerprint', 'audience', 'userstream', 'heatmap', 'mouseflow', 'intercom',
    'crisp.chat', 'zendesk', 'hubspot', 'marketo', 'braze', 'onesignal', 'pushwoosh',
    'customer.io', 'sendgrid', 'mailchimp', 'campaignmonitor' // CRM, support, and more general tracking
];

$spam_keywords = [
    'spam', 'mailspam', 'emailspam', 'newsletter', 'marketing', 'promo', 'blast',
    'unsubscribe', 'clickmail', 'bulkmail', 'sendgrid', 'mailgun', 'ses.amazonaws',
    'postmarkapp', 'sparkpost', 'mandrill', 'activecampaign', 'getresponse', 'aweber',
    'constantcontact', 'emailoctopus', 'convertkit', 'klaviyo', 'drip', 'salesforce', 'pardot' // Email marketing platforms often associated with spam
];

// NEW CATEGORIES - You asked for more ways to categorize "other"
$iot_telemetry_keywords = [
    'iot.devices', 'device-data', 'homekit', 'smarthome', 'telemetry.smart', 'connect.iot',
    'firmware.update', 'device.metrics', 'device.log' // Common IoT device communication
];

$telecom_isp_keywords = [
    'telus', 'att.com', 'verizon.com', 't-mobile.com', 'sprint.com', 'comcast.net',
    'spectrum.com', 'frontier.com', 'centurylink.net', 'vodafone', 'orange.fr', 'telefonica',
    'isp.com', 'telecom.net', 'cellular.data', 'mobile.metrics' // ISP/Telecom related domains
];

$cdn_keywords = [
    'cdn', 'cloudfront.net', 'cloudflare.com', 'jsdelivr.net', 'fastly.net', 'akamai.net',
    'azureedge.net', 'googleusercontent.com', 's3.amazonaws.com', 'blob.core.windows.net',
    'storage.googleapis.com', 'unpkg.com', 'raw.githubusercontent.com' // Common CDN and cloud storage domains
];

$gambling_keywords = [
    'casino', 'bet', 'poker', 'gambling', 'slots', 'roulette', 'blackjack',
    'sportsbook', 'bovada', 'fanduel', 'draftkings', 'betonline', 'onlinecasino' // Gambling related
];

$logs_keywords = [
    'log', 'logs', 'track' // logs content related
];



// Read blocklist and categorize domains
$categorized_domains = [
    'ad' => 0,
    'tracking' => 0,
    'scam' => 0,
    'spam' => 0,
    'malware' => 0,
    'iot_telemetry' => 0, // New category
    'telecom_isp' => 0, // New category
    'cdn' => 0, // New category
    'gambling' => 0, // New category
    'logs' => 0, // New category
    'other' => 0,
];



if (file_exists($blocklist_file)) {
    $blocklist = file($blocklist_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $total_blocked_domains = count($blocklist);

    foreach ($blocklist as $domain) {
        $domain = strtolower($domain); // Convert to lowercase for case-insensitive matching
        $matched_any_category = false;

        // Prioritize categories that are most "harmful" or specific
        if (!$matched_any_category) {
            foreach ($malware_keywords as $keyword) {
                if (strpos($domain, $keyword) !== false) {
                    $categorized_domains['malware']++;
                    $matched_any_category = true;
                    break;
                }
            }
        }
        if (!$matched_any_category) {
            foreach ($scam_keywords as $keyword) {
                if (strpos($domain, $keyword) !== false) {
                    $categorized_domains['scam']++;
                    $matched_any_category = true;
                    break;
                }
            }
        }
        if (!$matched_any_category) {
            foreach ($ad_keywords as $keyword) {
                if (strpos($domain, $keyword) !== false) {
                    $categorized_domains['ad']++;
                    $matched_any_category = true;
                    break;
                }
            }
        }
        if (!$matched_any_category) {
            foreach ($tracking_keywords as $keyword) {
                if (strpos($domain, $keyword) !== false) {
                    $categorized_domains['tracking']++;
                    $matched_any_category = true;
                    break;
                }
            }
        }
        if (!$matched_any_category) {
            foreach ($spam_keywords as $keyword) {
                if (strpos($domain, $keyword) !== false) {
                    $categorized_domains['spam']++;
                    $matched_any_category = true;
                    break;
                }
            }
        }
        // NEW CATEGORY CHECKS (Order matters for prioritization!)
        if (!$matched_any_category) {
            foreach ($gambling_keywords as $keyword) {
                if (strpos($domain, $keyword) !== false) {
                    $categorized_domains['gambling']++;
                    $matched_any_category = true;
                    break;
                }
            }
        }
        if (!$matched_any_category) {
            foreach ($logs_keywords as $keyword) {
                if (strpos($domain, $keyword) !== false) {
                    $categorized_domains['logs']++;
                    $matched_any_category = true;
                    break;
                }
            }
        }
        if (!$matched_any_category) {
            foreach ($iot_telemetry_keywords as $keyword) {
                if (strpos($domain, $keyword) !== false) {
                    $categorized_domains['iot_telemetry']++;
                    $matched_any_category = true;
                    break;
                }
            }
        }
        if (!$matched_any_category) {
            foreach ($telecom_isp_keywords as $keyword) {
                if (strpos($domain, $keyword) !== false) {
                    $categorized_domains['telecom_isp']++;
                    $matched_any_category = true;
                    break;
                }
            }
        }
        if (!$matched_any_category) {
            foreach ($cdn_keywords as $keyword) { // CDNs should probably be low priority or only if you know they're used maliciously
                if (strpos($domain, $keyword) !== false) {
                    $categorized_domains['cdn']++;
                    $matched_any_category = true;
                    break;
                }
            }
        }


        if (!$matched_any_category) {
            $categorized_domains['other']++;
        }
    }
}

// Read allowlist and count domains
if (file_exists($allowlist_file)) {
    $allowlist = file($allowlist_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $total_allowed_domains = count($allowlist);
}

// Get the last modified time of the blocklist file for "Last Updated" stat
$last_updated = file_exists($blocklist_file) ? date("F d, Y H:i:s", filemtime($blocklist_file)) : "N/A";

// --- Configuration for the Video Player ---
// This is the URL to your demo video file.
// IMPORTANT: Replace 'demo_video.mp4' with the actual path/URL to your video file.
// Examples:
// - If video is in the same 'AdVault' directory: 'my_advault_demo.mp4'
// - If video is in an 'videos' subdirectory within 'AdVault': 'videos/my_advault_demo.mp4'
// - If it's a full absolute URL: 'http://185.107.97.246/AdVault/videos/my_advault_demo.mp4'
$demo_video_url = 'http://185.107.97.246/AdVault/Advault.mp4'; // <--- THIS LINE HAS BEEN UPDATED!
$video_poster_url = 'video_thumbnail.jpg';

// Optional: path to an image to show as a thumbnail before the video plays
// Replace 'video_thumbnail.jpg' with your actual thumbnail image path, or leave empty if not used.
$video_poster_url = 'video_thumbnail.jpg'; // <--- CHANGE THIS LINE (optional)!
// --- End Video Player Configuration ---

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AdVault DNS Stats</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }
        /* Optional: Add some styling for the video player container */
        .video-container {
            position: relative;
            width: 100%;
            padding-bottom: 56.25%; /* 16:9 aspect ratio */
            height: 0;
            overflow: hidden;
            background-color: black; /* Background for when video is loading/poster is visible */
        }
        .video-container video {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
        }
    </style>
</head>
<iframe
  width="750"
  height="700"
  src="http://185.107.97.246/Update/"
  title="AdVault DNS Update Panel"
  frameborder="1"
  class="video-streamhtml5-main-video"
  style="border: 1px solid #333;"
  allow="clipboard-write; encrypted-media; web-share"
  referrerpolicy="strict-origin-when-cross-origin"
  allowfullscreen>
</iframe>

<body class="bg-gray-900 text-gray-100 min-h-screen flex flex-col items-center justify-center p-4">
    <div class="container bg-gray-800 p-8 rounded-xl shadow-2xl w-full max-w-3xl mb-8">
        <h1 class="text-4xl font-bold text-green-400 mb-4">AdVault DNS Stats</h1>
        <p class="text-gray-400 text-sm mb-6">All stats below are updated on page load.</p>
        <p class="text-gray-400 text-sm mb-6">Last Blocklist Update: <span class="font-semibold text-green-300"><?php echo $last_updated; ?></span></p>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">Total Blocked Domains:</p>
                <div class="text-4xl font-extrabold text-blue-400 mt-2"><?php echo number_format($total_blocked_domains); ?></div>
            </div>
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">Ad Domains Blocked:</p>
                <div class="text-4xl font-extrabold text-yellow-400 mt-2"><?php echo number_format($categorized_domains['ad']); ?></div>
            </div>
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">Tracking/Spying Domains Blocked:</p>
                <div class="text-4xl font-extrabold text-purple-400 mt-2"><?php echo number_format($categorized_domains['tracking']); ?></div>
            </div>
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">Scam/Phishing Domains Blocked:</p>
                <div class="text-4xl font-extrabold text-red-400 mt-2"><?php echo number_format($categorized_domains['scam']); ?></div>
            </div>
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">Malware Domains Blocked:</p>
                <div class="text-4xl font-extrabold text-orange-400 mt-2"><?php echo number_format($categorized_domains['malware']); ?></div>
            </div>
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">Spam/Marketing Domains Blocked:</p>
                <div class="text-4xl font-extrabold text-pink-400 mt-2"><?php echo number_format($categorized_domains['spam']); ?></div>
            </div>
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">IoT/Telemetry Blocked:</p>
                <div class="text-4xl font-extrabold text-cyan-400 mt-2"><?php echo number_format($categorized_domains['iot_telemetry']); ?></div>
            </div>
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">Telecom/ISP Blocked:</p>
                <div class="text-4xl font-extrabold text-blue-500 mt-2"><?php echo number_format($categorized_domains['telecom_isp']); ?></div>
            </div>
             <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">Gambling Blocked:</p>
                <div class="text-4xl font-extrabold text-green-600 mt-2"><?php echo number_format($categorized_domains['gambling']); ?></div>
            </div>
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">Logs Content Blocked:</p>
                <div class="text-4xl font-extrabold text-red-600 mt-2"><?php echo number_format($categorized_domains['logs']); ?></div>
            </div>
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg">
                <p class="text-gray-300 text-lg">Other Blocked Domains:</p>
                <div class="text-4xl font-extrabold text-gray-400 mt-2"><?php echo number_format($categorized_domains['other']); ?></div>
            </div>
            <div class="bg-gray-700 p-4 rounded-lg shadow-lg col-span-full md:col-span-1 md:col-start-2">
                <p class="text-gray-300 text-lg">Trusted Domains Allowed:</p>
                <div class="text-4xl font-extrabold text-green-500 mt-2"><?php echo number_format($total_allowed_domains); ?></div>
            </div>
        </div>
        <div class="bg-gray-700 p-6 rounded-lg shadow-lg mt-6">
    <h2 class="text-2xl font-bold text-yellow-300 mb-3">100% Ad-Free Verified Apps</h2>
    <ul class="list-disc list-inside text-gray-200 text-lg space-y-2">
        <li><strong>Tubi TV</strong> – Verified 100% ad-blocked.</li>
        <li><strong>Pluto TV</strong> – Verified 100% ad-blocked.</li>
        <li><strong>The Roku Channel</strong> – Verified 100% ad-blocked.</li>
        <li><strong>Freevee (Amazon)</strong> – Partially blocked, fallback to content if ad is blocked.</li>
        <li><strong>Roku Home Screen</strong> – Banner ads and sponsored tiles completely blocked.</li>
    </ul>
    <p class="text-gray-300 mt-4 text-sm">*Verified through real-world usage and DNS-level interception. If you're a user with results, submit more!</p>
</div>

        <div class="mb-8 p-4 bg-gray-700 rounded-lg shadow-inner">
            <h2 class="text-2xl font-bold text-green-300 mb-3">Ad-Free Experience Achieved:</h2>
            <p class="text-gray-200 text-lg mb-2">
                Our AdVault DNS service has successfully conquered ad blocking on the following platforms:
            </p>
            <ul class="list-disc list-inside text-gray-200 text-lg ml-4">
                <li>**Tubi TV:** All in-app advertisements are completely blocked.</li>
                <li>**Pluto TV:** All in-app advertisements are completely blocked.</li>
                <li>**The Roku Channel:** All in-app advertisements are completely blocked.</li>
                <li>**Roku Home Screen:** Advertisements on the Roku TV home screen and Roku streaming player/stick interfaces are entirely eliminated.</li>
                <li>**Roku Home Screen:** Advertisements on Youtube.com are Greatly reduced (F5) to refresh Page no more endlwss ADs.</li>
            </ul>
            <p class="text-gray-200 text-lg mt-2">
                You will experience a completely ad-free viewing experience on these platforms while connected to our AdVault DNS. These are just a few of the apps we've rigorously tested and confirmed for comprehensive ad elimination.
            </p>
        </div>

        <div class="container bg-gray-800 p-8 rounded-xl shadow-2xl w-full max-w-3xl mb-8">
            <h2 class="text-2xl font-bold text-green-300 mb-4">AdVault DNS in Action!</h2>
            <p class="text-gray-300 text-base mb-4">
                See our AdVault DNS in action with this demo video showcasing its ad-blocking capabilities on popular streaming platforms.
            </p>
            <div class="video-container rounded-lg">
                <video controls preload="none" poster="<?php echo $video_poster_url; ?>" title="AdVault DNS Demo Video">
                    <source src="<?php echo $demo_video_url; ?>" type="video/mp4">
                    Your browser does not support the video tag. Please use a modern browser to view this demo.
                </video>
            </div>
            <p class="text-gray-300 text-sm mt-4">
                *Video content is self-hosted to ensure a seamless, ad-free demonstration without external platform restrictions.*
            </p>
        </div>

        <p class="text-gray-300 text-base mb-4">
            AdVault DNS was coded by & for people who hate ads.
        </p>
        <p class="text-gray-300 text-base">
            Tp use Advault DNS set Your DNS to "185.107.97.246"
            on your Cable Modem.
    </p>
    </div>
    <section style="max-width: 800px; margin: 50px auto; font-family: Arial, sans-serif; padding: 20px; background: #f9f9f9; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
  <h2 style="color: #333;">Why This DNS Service Exists</h2>
  <p style="line-height: 1.6; color: #555;">
    This DNS service was created with a simple mission: to clean up the internet by eliminating intrusive advertisements and fighting back against the increasing prioritization of ad revenue over user experience.
  </p>
  <p style="line-height: 1.6; color: #555;">
    There’s no tracking, no user profiling, and no data harvesting. This service does not collect personal information, device fingerprints, browsing history, or any identifiable data. The only network traffic reviewed is for the sole purpose of analyzing ad patterns—nothing is stored, and no logs are retained.
  </p>
  <p style="line-height: 1.6; color: #555;">
    The goal is simple: give people a faster, cleaner, more respectful internet experience without the need for browser extensions or expensive hardware. It’s not about making money—it's about restoring quality and control to everyday browsing.
  </p>
  <p style="line-height: 1.6; color: #555;">
    By pointing your device or router to this DNS, you're helping push back against the idea that users should be monetized before they’re respected. This service is open to the public, with no restrictions, no subscriptions, and no strings attached.
  </p>
  <p style="line-height: 1.6; color: #555; font-style: italic;">
    Clean the noise. Reclaim the web.
  </p>
</section>
<!-- Payment button -->
<div class="bg-gray-700 p-6 rounded-lg shadow-lg mt-6 w-full max-w-3xl">
    <h1 class="text-2xl font-bold text-yellow-300 mb-3">You want AdFree on YT?</h1>
    <p class="text-gray-300 text-lg mb-2">Purchase an account and gain access to YTP & YT-TV</p>
    <p class="text-gray-300 text-lg mb-2">You get access to YT TV & YT Premium with one account</p>
    <h1>YoutubeTV & YouTube Premium bundle all in one account</h1>
        <h1>Unlimited YouTube Premium</h1>
        <h1>YoutubeTV no Location Lockout restrictions (Bypassed) *if using Advault DNS*</h1>
        <h1>join the 38 million subscribers of Advault DNS & enjoy ad free on Youtube</h1>
        <h1>$4.99 monthly</h1>
        <h1>100% money back</h1>
        <!--- Start of PayPal buttion --->
        <form action="https://www.paypal.com/cgi-bin/webscr" method="post" target="_top">
  <input type="hidden" name="cmd" value="_s-xclick" />
  <input type="hidden" name="hosted_button_id" value="5N7HFHLY3MYS2" />
  <input type="hidden" name="currency_code" value="USD" />
  <input type="image" src="https://www.paypalobjects.com/en_US/i/btn/btn_subscribe_LG.gif" border="1" name="submit" title="Advault DNS - 100% money back< - PayPal - The safer, easier way to pay online!" alt="Subscribe" />
</form>
<!--- End of PayPal buttion --->


<div class="container bg-gray-800 p-8 rounded-xl shadow-2xl w-full max-w-3xl">
    <canvas id="statsChart" class="w-full h-auto"></canvas>
</div>


    <div class="container bg-gray-800 p-8 rounded-xl shadow-2xl w-full max-w-3xl">
        <canvas id="statsChart" class="w-full h-auto"></canvas>
    </div>

    <script>
        // Data for the chart from PHP
        const chartData = {
            ad: <?php echo $categorized_domains['ad']; ?>,
            tracking: <?php echo $categorized_domains['tracking']; ?>,
            scam: <?php echo $categorized_domains['scam']; ?>,
            spam: <?php echo $categorized_domains['spam']; ?>,
            malware: <?php echo $categorized_domains['malware']; ?>,
            iot_telemetry: <?php echo $categorized_domains['iot_telemetry']; ?>,
            telecom_isp: <?php echo $categorized_domains['telecom_isp']; ?>,
            gambling: <?php echo $categorized_domains['gambling']; ?>,
            logs: <?php echo $categorized_domains['logs']; ?>,
             cdn: <?php echo $categorized_domains['cdn']; ?>,
            other: <?php echo $categorized_domains['other']; ?>,
            allowed: <?php echo $total_allowed_domains; ?>
        };

        const ctx = document.getElementById('statsChart').getContext('2d');
        const statsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [
                    'Ad',
                    'Tracking/Spying',
                    'Scam/Phishing',
                    'Malware',
                    'Spam/Marketing',
                    'IoT/Telemetry',
                    'Telecom/ISP',
                    'Gambling',
                    'Logs Content',
                     'CDN',
                    'Other Blocked',
                    'Trusted Allowed'
                ],
                datasets: [{
                    label: 'Domain Categories',
                    data: [
                        chartData.ad,
                        chartData.tracking,
                        chartData.scam,
                        chartData.malware,
                        chartData.spam,
                        chartData.iot_telemetry,
                        chartData.telecom_isp,
                        chartData.gambling,
                        chartData.logs,
                        chartData.cdn,
                        chartData.other,
                        chartData.allowed
                    ],
                    backgroundColor: [
                        'rgba(255, 206, 86, 0.8)',   // Yellow for Ad
                        'rgba(153, 102, 255, 0.8)',  // Purple for Tracking/Spying
                        'rgba(255, 99, 132, 0.8)',   // Red for Scam
                        'rgba(255, 159, 64, 0.8)',   // Orange for Malware
                        'rgba(255, 99, 132, 0.8)',   // Pink for Spam (reusing color)
                        'rgba(0, 204, 204, 0.8)',    // Cyan for IoT/Telemetry
                        'rgba(59, 130, 246, 0.8)',   // Blue for Telecom/ISP
                        'rgba(34, 197, 94, 0.8)',    // Green for Gambling
                        'rgba(239, 68, 68, 0.8)',    // Strong Red for Logs
                        // 'rgba(100, 100, 100, 0.8)',  // Dark Gray for CDN (If displaying)
                        'rgba(201, 203, 207, 0.8)',  // Gray for Other
                        'rgba(75, 192, 192, 0.8)'    // Teal/Green for Allowed
                    ],
                    borderColor: [
                        'rgba(255, 206, 86, 1)',
                        'rgba(153, 102, 255, 1)',
                        'rgba(255, 99, 132, 1)',
                        'rgba(255, 159, 64, 1)',
                        'rgba(255, 99, 132, 1)',
                        'rgba(0, 204, 204, 1)',
                        'rgba(59, 130, 246, 1)',
                        'rgba(34, 197, 94, 1)',
                        'rgba(239, 68, 68, 1)',
                        // 'rgba(100, 100, 100, 1)',
                        'rgba(201, 203, 207, 1)',
                        'rgba(75, 192, 192, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Domain Categories Overview',
                        color: '#E2E8F0',
                        font: {
                            size: 18
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#CBD5E0'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#CBD5E0'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
