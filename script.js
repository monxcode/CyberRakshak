// DOM Elements
const urlInput = document.getElementById('url-input');
const textInput = document.getElementById('text-input');
const analyzeBtn = document.getElementById('analyze-btn');
const riskScoreElement = document.getElementById('risk-score');
const riskLabelElement = document.getElementById('risk-label');
const resultCard = document.getElementById('result-card');
const resultTitle = document.getElementById('result-title');
const resultDescription = document.getElementById('result-description');
const reasonsList = document.getElementById('reasons-list');
const tipsContainer = document.getElementById('tips-container');
const userScoreElement = document.getElementById('user-score');
const progressFill = document.getElementById('progress-fill');
const threatChart = document.getElementById('threat-chart');

// Tab functionality
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        const tabId = btn.getAttribute('data-tab');
        
        // Update active tab button
        tabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Show active tab content
        tabContents.forEach(content => {
            content.classList.remove('active');
            if (content.id === `${tabId}-tab`) {
                content.classList.add('active');
            }
        });
    });
});

// Example buttons
document.querySelectorAll('.example-btn[data-url]').forEach(btn => {
    btn.addEventListener('click', () => {
        urlInput.value = btn.getAttribute('data-url');
        // Switch to URL tab
        document.querySelector('[data-tab="url"]').click();
    });
});

document.querySelectorAll('.example-btn[data-text]').forEach(btn => {
    btn.addEventListener('click', () => {
        textInput.value = btn.getAttribute('data-text');
        // Switch to text tab
        document.querySelector('[data-tab="text"]').click();
    });
});

// Configuration
const CONFIG = {
    scores: {
        httpOnly: 2,
        ipAddress: 3,
        atInUrl: 2,
        suspiciousKeywords: 1,
        blacklistedDomain: 4,
        multipleSubdomains: 1,
        unusualTld: 2,
        misspelledBrand: 3,
        shortenedUrl: 3
    },
    thresholds: {
        safe: 2,
        suspicious: 5
    },
    blacklistedDomains: [
        'bit.ly', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'shorturl.at',
        'tiny.cc', 'shorte.st', 'bc.vc', 'adf.ly', 'fakebank.com', 
        'secure-login.xyz', 'verify-account.xyz', 'free-gift.top',
        'win-prize.club', 'update-security.xyz'
    ],
    suspiciousKeywords: [
        'login', 'verify', 'secure', 'account', 'password', 'banking',
        'update', 'urgent', 'immediately', 'suspended', 'limited',
        'confirm', 'winner', 'won', 'free', 'gift', 'prize', 'reward',
        'click', 'here', 'below', 'action required', 'security alert'
    ],
    suspiciousTlds: ['.xyz', '.top', '.club', '.info', '.biz', '.online', '.site', '.space'],
    popularBrands: [
        'google', 'facebook', 'apple', 'amazon', 'microsoft', 'paypal',
        'netflix', 'instagram', 'twitter', 'whatsapp', 'bankofamerica',
        'wellsfargo', 'chase', 'citibank', 'dropbox', 'adobe'
    ]
};

// User state
let userScore = parseInt(localStorage.getItem('cyberDetectorScore')) || 0;
let scanCount = parseInt(localStorage.getItem('scanCount')) || 0;
let badges = JSON.parse(localStorage.getItem('badges')) || {
    'first-scan': false,
    'safe-10': false,
    'detective': false,
    'expert': false
};

// Initialize
updateUserScore();
updateBadges();

// Initialize chart
let chartInstance = null;
function initChart() {
    if (chartInstance) {
        chartInstance.destroy();
    }
    
    const ctx = threatChart.getContext('2d');
    chartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Safe Indicators', 'Suspicious Indicators', 'Dangerous Indicators'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(0, 255, 140, 0.8)',
                    'rgba(255, 215, 0, 0.8)',
                    'rgba(255, 76, 76, 0.8)'
                ],
                borderColor: [
                    'rgba(0, 255, 140, 1)',
                    'rgba(255, 215, 0, 1)',
                    'rgba(255, 76, 76, 1)'
                ],
                borderWidth: 2,
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: 'rgba(255, 255, 255, 0.8)',
                        font: {
                            family: "'Poppins', sans-serif",
                            size: 12
                        },
                        padding: 20
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 15, 28, 0.9)',
                    titleColor: 'rgba(255, 255, 255, 0.9)',
                    bodyColor: 'rgba(255, 255, 255, 0.8)',
                    borderColor: 'rgba(0, 255, 247, 0.5)',
                    borderWidth: 1,
                    cornerRadius: 8
                }
            }
        }
    });
}

initChart();

// Domain extraction and normalization
function extractDomain(url) {
    try {
        // Remove protocol and www
        let domain = url.replace(/^(https?:\/\/)?(www\.)?/, '');
        // Remove path and query parameters
        domain = domain.split('/')[0];
        // Remove port number if present
        domain = domain.split(':')[0];
        return domain.toLowerCase();
    } catch (error) {
        return url.toLowerCase();
    }
}

function normalizeUrl(url) {
    if (!url) return '';
    
    // Add protocol if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
    }
    
    // Remove tracking parameters
    url = url.replace(/(\?|\&)(utm_\w+|fbclid|gclid)=[^&]+/g, '$1');
    url = url.replace(/\?$/, ''); // Remove trailing ?
    
    return url.trim();
}

// Threat detection functions
function checkHttpOnly(url) {
    return url.startsWith('http://') && !url.startsWith('https://');
}

function checkIpAddress(domain) {
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    return ipPattern.test(domain);
}

function checkAtInUrl(url) {
    return url.includes('@');
}

function checkSuspiciousKeywords(text) {
    const foundKeywords = [];
    const lowerText = text.toLowerCase();
    
    CONFIG.suspiciousKeywords.forEach(keyword => {
        const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
        if (regex.test(lowerText)) {
            foundKeywords.push(keyword);
        }
    });
    
    return foundKeywords;
}

function checkBlacklistedDomain(domain) {
    return CONFIG.blacklistedDomains.some(blacklisted => 
        domain.includes(blacklisted) || blacklisted.includes(domain)
    );
}

function checkMultipleSubdomains(domain) {
    const subdomains = domain.split('.').length - 1;
    return subdomains > 3; // More than 3 subdomains is suspicious
}

function checkUnusualTld(domain) {
    return CONFIG.suspiciousTlds.some(tld => domain.endsWith(tld));
}

function checkMisspelledBrand(domain) {
    for (const brand of CONFIG.popularBrands) {
        // Check for common misspellings
        if (domain.includes(brand)) {
            // If it contains the brand but the exact brand is not the main domain
            if (!domain.startsWith(brand + '.')) {
                // Check for common typos
                const variations = [
                    brand + 'l', // googlel
                    brand.slice(0, -1), // googl
                    brand + 'e', // googlee
                    brand.replace(/o/g, '0'), // g00gle
                    brand.replace(/i/g, '1'), // faceb00k
                ];
                
                if (variations.some(v => domain.startsWith(v + '.'))) {
                    return true;
                }
                
                // Check for extra characters
                if (domain.startsWith(brand) && domain.length > brand.length + 1) {
                    const nextChar = domain[brand.length];
                    if (nextChar !== '.') {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

function checkShortenedUrl(url) {
    const shortenedPatterns = [
        /bit\.ly\/\w+/,
        /tinyurl\.com\/\w+/,
        /ow\.ly\/\w+/,
        /is\.gd\/\w+/,
        /buff\.ly\/\w+/,
        /shorturl\.at\/\w+/
    ];
    return shortenedPatterns.some(pattern => pattern.test(url));
}

// Main analysis function
function analyzeThreat() {
    const activeTab = document.querySelector('.tab-btn.active').getAttribute('data-tab');
    let input = '';
    
    if (activeTab === 'url') {
        input = urlInput.value.trim();
        if (!input) {
            showError('Please enter a URL to analyze');
            return;
        }
    } else {
        input = textInput.value.trim();
        if (!input) {
            showError('Please enter text to analyze');
            return;
        }
    }
    
    // Reset UI
    resetResults();
    
    // Extract URLs from text if needed
    let urls = [];
    if (activeTab === 'text') {
        urls = extractUrlsFromText(input);
        if (urls.length === 0) {
            // Analyze text directly
            analyzeText(input);
            return;
        }
    } else {
        urls = [input];
    }
    
    // Analyze each URL
    const allResults = urls.map(url => analyzeUrl(url));
    
    // Combine results
    const combinedResults = combineResults(allResults);
    displayResults(combinedResults);
    
    // Update user score
    updateUserScore(combinedResults.score);
    updateScanCount();
}

function extractUrlsFromText(text) {
    const urlPattern = /(https?:\/\/[^\s]+|www\.[^\s]+)/gi;
    const matches = text.match(urlPattern) || [];
    return matches;
}

function analyzeUrl(url) {
    const normalizedUrl = normalizeUrl(url);
    const domain = extractDomain(normalizedUrl);
    
    const results = {
        url: normalizedUrl,
        domain: domain,
        score: 0,
        reasons: [],
        threatCounts: {
            safe: 0,
            suspicious: 0,
            dangerous: 0
        }
    };
    
    // Check each threat type
    if (checkHttpOnly(normalizedUrl)) {
        results.score += CONFIG.scores.httpOnly;
        results.reasons.push({
            type: 'dangerous',
            title: 'HTTP Only',
            description: 'URL uses HTTP instead of HTTPS - data transmission is not encrypted',
            icon: 'fa-lock-open'
        });
        results.threatCounts.dangerous++;
    }
    
    if (checkIpAddress(domain)) {
        results.score += CONFIG.scores.ipAddress;
        results.reasons.push({
            type: 'dangerous',
            title: 'IP Address as Domain',
            description: 'Domain is an IP address instead of a human-readable name - common in phishing',
            icon: 'fa-network-wired'
        });
        results.threatCounts.dangerous++;
    }
    
    if (checkAtInUrl(normalizedUrl)) {
        results.score += CONFIG.scores.atInUrl;
        results.reasons.push({
            type: 'suspicious',
            title: '@ Symbol in URL',
            description: 'URL contains @ symbol which can be used to hide real domain',
            icon: 'fa-at'
        });
        results.threatCounts.suspicious++;
    }
    
    if (checkShortenedUrl(normalizedUrl)) {
        results.score += CONFIG.scores.shortenedUrl;
        results.reasons.push({
            type: 'dangerous',
            title: 'Shortened URL',
            description: 'URL uses a shortening service - real destination is hidden',
            icon: 'fa-compress-alt'
        });
        results.threatCounts.dangerous++;
    }
    
    if (checkBlacklistedDomain(domain)) {
        results.score += CONFIG.scores.blacklistedDomain;
        results.reasons.push({
            type: 'dangerous',
            title: 'Blacklisted Domain',
            description: 'Domain is known to be suspicious or used in phishing attacks',
            icon: 'fa-ban'
        });
        results.threatCounts.dangerous++;
    }
    
    if (checkMultipleSubdomains(domain)) {
        results.score += CONFIG.scores.multipleSubdomains;
        results.reasons.push({
            type: 'suspicious',
            title: 'Multiple Subdomains',
            description: 'URL has an unusual number of subdomains - can be used to mimic legitimate sites',
            icon: 'fa-sitemap'
        });
        results.threatCounts.suspicious++;
    }
    
    if (checkUnusualTld(domain)) {
        results.score += CONFIG.scores.unusualTld;
        results.reasons.push({
            type: 'suspicious',
            title: 'Unusual TLD',
            description: 'Domain uses an uncommon top-level domain often associated with spam',
            icon: 'fa-globe'
        });
        results.threatCounts.suspicious++;
    }
    
    if (checkMisspelledBrand(domain)) {
        results.score += CONFIG.scores.misspelledBrand;
        results.reasons.push({
            type: 'dangerous',
            title: 'Possible Brand Misspelling',
            description: 'Domain appears to mimic a popular brand with possible typos',
            icon: 'fa-trademark'
        });
        results.threatCounts.dangerous++;
    }
    
    // Check for keywords in the URL
    const urlKeywords = checkSuspiciousKeywords(normalizedUrl);
    if (urlKeywords.length > 0) {
        results.score += CONFIG.scores.suspiciousKeywords * urlKeywords.length;
        results.reasons.push({
            type: 'suspicious',
            title: `Suspicious Keywords (${urlKeywords.length})`,
            description: `URL contains suspicious keywords: ${urlKeywords.slice(0, 3).join(', ')}`,
            icon: 'fa-key'
        });
        results.threatCounts.suspicious++;
    }
    
    // If no threats found
    if (results.score === 0) {
        results.reasons.push({
            type: 'safe',
            title: 'No Threats Detected',
            description: 'The URL appears to be safe based on our analysis',
            icon: 'fa-check-circle'
        });
        results.threatCounts.safe++;
    }
    
    return results;
}

function analyzeText(text) {
    const results = {
        text: text,
        score: 0,
        reasons: [],
        threatCounts: {
            safe: 0,
            suspicious: 0,
            dangerous: 0
        }
    };
    
    // Check for suspicious keywords
    const foundKeywords = checkSuspiciousKeywords(text);
    if (foundKeywords.length > 0) {
        results.score += CONFIG.scores.suspiciousKeywords * Math.min(foundKeywords.length, 5);
        results.reasons.push({
            type: 'suspicious',
            title: `Suspicious Keywords Found (${foundKeywords.length})`,
            description: `Text contains ${foundKeywords.length} suspicious keywords including: ${foundKeywords.slice(0, 3).join(', ')}`,
            icon: 'fa-exclamation-triangle'
        });
        results.threatCounts.suspicious++;
    }
    
    // Check for urgency markers
    const urgencyPatterns = ['urgent', 'immediately', 'act now', 'time sensitive', 'limited time'];
    const urgencyFound = urgencyPatterns.filter(pattern => 
        text.toLowerCase().includes(pattern)
    ).length;
    
    if (urgencyFound > 0) {
        results.score += 2;
        results.reasons.push({
            type: 'suspicious',
            title: 'Urgency Language Detected',
            description: 'Text uses urgent language - common tactic in phishing attempts',
            icon: 'fa-clock'
        });
        results.threatCounts.suspicious++;
    }
    
    // If no threats found
    if (results.score === 0) {
        results.reasons.push({
            type: 'safe',
            title: 'No Threats Detected',
            description: 'The text appears to be safe based on our analysis',
            icon: 'fa-check-circle'
        });
        results.threatCounts.safe++;
    }
    
    displayResults(results);
    updateUserScore(results.score);
    updateScanCount();
}

function combineResults(resultsArray) {
    const combined = {
        score: 0,
        reasons: [],
        threatCounts: {
            safe: 0,
            suspicious: 0,
            dangerous: 0
        }
    };
    
    resultsArray.forEach(result => {
        combined.score += result.score;
        combined.reasons = [...combined.reasons, ...result.reasons];
        combined.threatCounts.safe += result.threatCounts.safe;
        combined.threatCounts.suspicious += result.threatCounts.suspicious;
        combined.threatCounts.dangerous += result.threatCounts.dangerous;
    });
    
    // Cap the score for display
    combined.score = Math.min(combined.score, 10);
    
    return combined;
}

function resetResults() {
    // Reset meter
    document.querySelector('.meter-progress').style.strokeDashoffset = '565.48';
    
    // Reset risk indicators
    document.querySelectorAll('.risk-indicator').forEach(indicator => {
        indicator.classList.remove('active');
    });
    document.querySelector('.risk-indicator.safe').classList.add('active');
    
    // Clear reasons list
    reasonsList.innerHTML = `
        <div class="no-reasons">
            <i class="fas fa-info-circle"></i>
            <p>Analyzing threats...</p>
        </div>
    `;
}

function displayResults(results) {
    // Update score display
    riskScoreElement.textContent = results.score;
    
    // Determine risk level
    let riskLevel, riskColor, riskIcon;
    
    if (results.score <= CONFIG.thresholds.safe) {
        riskLevel = 'Safe';
        riskColor = '#00FF8C';
        riskIcon = 'fa-check-circle';
    } else if (results.score <= CONFIG.thresholds.suspicious) {
        riskLevel = 'Suspicious';
        riskColor = '#FFD700';
        riskIcon = 'fa-exclamation-triangle';
    } else {
        riskLevel = 'Dangerous';
        riskColor = '#FF4C4C';
        riskIcon = 'fa-skull-crossbones';
    }
    
    // Update risk label and color
    riskLabelElement.textContent = riskLevel;
    riskLabelElement.style.color = riskColor;
    
    // Update result card
    resultCard.className = 'result-card ' + riskLevel.toLowerCase();
    resultTitle.textContent = `${riskLevel} Threat Level`;
    resultDescription.textContent = getResultDescription(riskLevel, results.score);
    
    const resultIcon = resultCard.querySelector('.result-icon');
    resultIcon.className = `fas ${riskIcon} result-icon`;
    resultIcon.style.color = riskColor;
    
    // Update risk indicators
    document.querySelectorAll('.risk-indicator').forEach(indicator => {
        indicator.classList.remove('active');
    });
    document.querySelector(`.risk-indicator.${riskLevel.toLowerCase()}`).classList.add('active');
    
    // Animate meter
    const maxScore = 10;
    const circumference = 565.48; // 2 * π * 90
    const offset = circumference - (results.score / maxScore) * circumference;
    
    const meterProgress = document.querySelector('.meter-progress');
    meterProgress.style.stroke = riskColor;
    
    // Animate with delay for visual effect
    setTimeout(() => {
        meterProgress.style.strokeDashoffset = offset;
    }, 300);
    
    // Display reasons
    displayReasons(results.reasons);
    
    // Update chart
    updateChart(results.threatCounts);
    
    // Show personalized tips
    showPersonalizedTips(results);
}

function getResultDescription(riskLevel, score) {
    const descriptions = {
        Safe: `Your input scored ${score}/10 and appears to be safe. No significant threats detected.`,
        Suspicious: `Your input scored ${score}/10 and shows suspicious characteristics. Exercise caution and verify the source.`,
        Dangerous: `Your input scored ${score}/10 and contains dangerous indicators. Avoid interacting with this content.`
    };
    return descriptions[riskLevel];
}

function displayReasons(reasons) {
    reasonsList.innerHTML = '';
    
    if (reasons.length === 0) {
        reasonsList.innerHTML = `
            <div class="no-reasons">
                <i class="fas fa-check-circle"></i>
                <p>No threat indicators detected. The input appears to be safe.</p>
            </div>
        `;
        return;
    }
    
    reasons.forEach((reason, index) => {
        setTimeout(() => {
            const reasonElement = document.createElement('div');
            reasonElement.className = `reason-item slide-in ${reason.type}`;
            reasonElement.style.animationDelay = `${index * 0.1}s`;
            reasonElement.innerHTML = `
                <div class="reason-icon">
                    <i class="fas ${reason.icon}"></i>
                </div>
                <div class="reason-content">
                    <h5>${reason.title}</h5>
                    <p>${reason.description}</p>
                </div>
            `;
            reasonsList.appendChild(reasonElement);
        }, index * 100);
    });
}

function updateChart(threatCounts) {
    const total = threatCounts.safe + threatCounts.suspicious + threatCounts.dangerous;
    
    // Avoid division by zero
    if (total === 0) {
        chartInstance.data.datasets[0].data = [1, 0, 0];
    } else {
        chartInstance.data.datasets[0].data = [
            threatCounts.safe,
            threatCounts.suspicious,
            threatCounts.dangerous
        ];
    }
    
    chartInstance.update();
}

function showPersonalizedTips(results) {
    tipsContainer.innerHTML = '';
    
    const tips = [];
    
    // General safety tip
    tips.push({
        icon: 'fa-shield-alt',
        title: 'Always Verify',
        content: 'Double-check URLs and sender information before clicking links or entering credentials.'
    });
    
    // Score-based tips
    if (results.score >= CONFIG.scores.httpOnly) {
        tips.push({
            icon: 'fa-lock',
            title: 'HTTPS Required',
            content: 'Always look for HTTPS in URLs. HTTP sites do not encrypt your data.'
        });
    }
    
    if (results.reasons.some(r => r.title.includes('Shortened URL'))) {
        tips.push({
            icon: 'fa-compress-alt',
            title: 'Shortened URLs',
            content: 'Avoid clicking on shortened URLs from unknown sources. Use URL expander tools.'
        });
    }
    
    if (results.reasons.some(r => r.title.includes('Suspicious Keywords'))) {
        tips.push({
            icon: 'fa-exclamation-triangle',
            title: 'Keyword Awareness',
            content: 'Be cautious of messages containing urgent requests or too-good-to-be-true offers.'
        });
    }
    
    if (results.reasons.some(r => r.title.includes('Blacklisted Domain'))) {
        tips.push({
            icon: 'fa-ban',
            title: 'Known Threats',
            content: 'Domains on blacklists have been reported for malicious activity. Avoid them completely.'
        });
    }
    
    if (results.reasons.some(r => r.title.includes('Brand Misspelling'))) {
        tips.push({
            icon: 'fa-trademark',
            title: 'Brand Impersonation',
            content: 'Check for subtle misspellings in brand names. Phishers often use look-alike domains.'
        });
    }
    
    // Always show at least 3 tips
    while (tips.length < 3) {
        tips.push({
            icon: 'fa-user-shield',
            title: 'Stay Updated',
            content: 'Keep your software updated and use multi-factor authentication for important accounts.'
        });
    }
    
    // Display tips with animation
    tips.forEach((tip, index) => {
        setTimeout(() => {
            const tipElement = document.createElement('div');
            tipElement.className = 'tip-card glassmorphism slide-in';
            tipElement.style.animationDelay = `${index * 0.2}s`;
            tipElement.innerHTML = `
                <div class="tip-icon">
                    <i class="fas ${tip.icon}"></i>
                </div>
                <div class="tip-content">
                    <h4>${tip.title}</h4>
                    <p>${tip.content}</p>
                </div>
            `;
            tipsContainer.appendChild(tipElement);
        }, index * 200);
    });
}

function updateUserScore(addedScore = 0) {
    if (addedScore > 0) {
        // Add score based on threat detection
        const scoreToAdd = Math.max(1, 5 - Math.floor(addedScore));
        userScore += scoreToAdd;
        localStorage.setItem('cyberDetectorScore', userScore.toString());
    }
    
    userScoreElement.textContent = userScore;
    
    // Update progress bar
    const nextLevel = 50;
    const progress = Math.min((userScore / nextLevel) * 100, 100);
    progressFill.style.width = `${progress}%`;
    
    // Check for badges
    checkBadges();
}

function updateScanCount() {
    scanCount++;
    localStorage.setItem('scanCount', scanCount.toString());
    
    // Check for first scan badge
    if (scanCount === 1) {
        badges['first-scan'] = true;
        localStorage.setItem('badges', JSON.stringify(badges));
        showBadgeUnlock('first-scan');
    }
    
    // Check for 10 safe scans
    if (scanCount >= 10) {
        badges['safe-10'] = true;
        localStorage.setItem('badges', JSON.stringify(badges));
        showBadgeUnlock('safe-10');
    }
}

function checkBadges() {
    // Check for threat detective badge (score over 100)
    if (userScore >= 100 && !badges['detective']) {
        badges['detective'] = true;
        localStorage.setItem('badges', JSON.stringify(badges));
        showBadgeUnlock('detective');
    }
    
    // Check for expert badge (score over 500)
    if (userScore >= 500 && !badges['expert']) {
        badges['expert'] = true;
        localStorage.setItem('badges', JSON.stringify(badges));
        showBadgeUnlock('expert');
    }
    
    updateBadges();
}

function updateBadges() {
    document.querySelectorAll('.badge').forEach(badgeElement => {
        const badgeId = badgeElement.getAttribute('data-badge');
        
        if (badges[badgeId]) {
            badgeElement.classList.add('unlocked');
            const icon = badgeElement.querySelector('.badge-icon');
            icon.classList.remove('locked');
            
            // Set appropriate icon for each badge
            const icons = {
                'first-scan': 'fa-search',
                'safe-10': 'fa-shield-alt',
                'detective': 'fa-user-secret',
                'expert': 'fa-crown'
            };
            
            if (icons[badgeId]) {
                icon.innerHTML = `<i class="fas ${icons[badgeId]}"></i>`;
            }
        }
    });
}

function showBadgeUnlock(badgeId) {
    const badgeNames = {
        'first-scan': 'First Scan',
        'safe-10': '10 Safe Scans',
        'detective': 'Threat Detective',
        'expert': 'Security Expert'
    };
    
    // Create notification
    const notification = document.createElement('div');
    notification.className = 'badge-notification glassmorphism';
    notification.innerHTML = `
        <div class="badge-notification-content">
            <i class="fas fa-trophy"></i>
            <div>
                <h4>Badge Unlocked!</h4>
                <p>You earned the "${badgeNames[badgeId]}" badge</p>
            </div>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Add styles for notification
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px;
        border-radius: 10px;
        background: rgba(0, 255, 140, 0.1);
        border: 1px solid rgba(0, 255, 140, 0.3);
        z-index: 1000;
        animation: slideIn 0.5s ease;
    `;
    
    const content = notification.querySelector('.badge-notification-content');
    content.style.cssText = `
        display: flex;
        align-items: center;
        gap: 15px;
    `;
    
    content.querySelector('i').style.cssText = `
        font-size: 2rem;
        color: var(--neon-green);
    `;
    
    // Remove notification after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.5s ease forwards';
        setTimeout(() => notification.remove(), 500);
    }, 5000);
}

function showError(message) {
    // Create error notification
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-notification glassmorphism';
    errorDiv.textContent = message;
    
    errorDiv.style.cssText = `
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        padding: 15px 30px;
        border-radius: 10px;
        background: rgba(255, 76, 76, 0.1);
        border: 1px solid rgba(255, 76, 76, 0.3);
        color: #FF4C4C;
        font-weight: 500;
        z-index: 1000;
        animation: slideIn 0.5s ease;
    `;
    
    document.body.appendChild(errorDiv);
    
    // Remove after 3 seconds
    setTimeout(() => {
        errorDiv.style.animation = 'slideOut 0.5s ease forwards';
        setTimeout(() => errorDiv.remove(), 500);
    }, 3000);
}

// Add slideOut animation to CSS
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOut {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100%);
        }
    }
    
    .error-notification {
        animation: slideIn 0.5s ease;
    }
`;
document.head.appendChild(style);

// Event Listeners
analyzeBtn.addEventListener('click', analyzeThreat);

// Allow Enter key to trigger analysis
urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') analyzeThreat();
});

textInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && e.ctrlKey) analyzeThreat();
});

// Initialize with a demo analysis
window.addEventListener('load', () => {
    // Show initial tips
    const initialTips = [
        {
            icon: 'fa-lock',
            title: 'HTTPS Always',
            content: 'Always check for HTTPS in URLs. The "S" stands for secure and means your connection is encrypted.'
        },
        {
            icon: 'fa-exclamation-triangle',
            title: 'Urgency is Suspicious',
            content: 'Legitimate organizations rarely use urgent language. Be wary of messages demanding immediate action.'
        },
        {
            icon: 'fa-link',
            title: 'Check Links Before Clicking',
            content: 'Hover over links to see the actual URL. Don\'t click shortened URLs from unknown sources.'
        }
    ];
    
    tipsContainer.innerHTML = '';
    initialTips.forEach((tip, index) => {
        const tipElement = document.createElement('div');
        tipElement.className = 'tip-card glassmorphism';
        tipElement.style.animationDelay = `${index * 0.2}s`;
        tipElement.innerHTML = `
            <div class="tip-icon">
                <i class="fas ${tip.icon}"></i>
            </div>
            <div class="tip-content">
                <h4>${tip.title}</h4>
                <p>${tip.content}</p>
            </div>
        `;
        tipsContainer.appendChild(tipElement);
    });
});