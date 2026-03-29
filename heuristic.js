// Prenavigation Heuristics
const TRUSTED_DOMAINS = ['tiktok.com', 'paypal.com', 'google.com', 'apple.com', 'microsoft.com', 'amazon.com', 'facebook.com', 'github.com', 'netflix.com'];
const SUSPICIOUS_KEYWORDS = [
  'verify', 'bank', 'login', 'update', 'secure', 'account', 'auth', 'confirm', 
  'billing', 'support', 'service', 'wallet', 'invoice', 'payment', 'credential', 
  'password', 'recovery', 'alert', 'notification', 'suspend', 'locked', 'restricted'
];

function isWhitelisted(url) {
    try {
        let hostname = new URL(url).hostname;
        // This checks if it's exactly "google.com" OR a subdomain like "support.google.com"
        return TRUSTED_DOMAINS.some(domain => 
            hostname === domain || hostname.endsWith("." + domain)
        );
    } catch (error) {
        return false;
    }
}

function calculateRisk(urlStr) {
  try {
    const url = new URL(urlStr);
    const domain = url.hostname.replace(/^www\./, '');
    
    if (isWhitelisted(urlStr)) {
  return { penalty: 0, reasons: ['Trusted domain (Heuristic)'] };
}

    let penalty = 0;
    let reasons = [];

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
      penalty += 60;
      reasons.push('IP address used instead of domain name');
    }

    if (url.username || url.password) {
      penalty += 50;
      reasons.push('Malicious domain spoofing detected (@ symbol trick)');
    }

    if (urlStr.length > 120) {
      penalty += 10;
      reasons.push('URL is unusually long (>120 chars)');
    }

    const numDots = (domain.match(/\./g) || []).length;
    if (numDots > 3) {
      penalty += 20;
      reasons.push('Too many subdomains (suspicious structure)');
    }

    const numHyphens = (domain.match(/-/g) || []).length;
    if (numHyphens > 2) {
      penalty += 10;
      reasons.push('Multiple hyphens in domain name');
    }

    let keywordMatches = 0;
    const lowerDomain = domain.toLowerCase();
    SUSPICIOUS_KEYWORDS.forEach(keyword => {
      if (lowerDomain.includes(keyword)) keywordMatches++;
    });

    if (keywordMatches > 0) {
      penalty += keywordMatches * 30;
      reasons.push(`Found ${keywordMatches} highly suspicious keyword(s) in domain`);
    }

    return { penalty, reasons };
  } catch (e) {
    return { penalty: 100, reasons: ['Invalid URL format'] };
  }
}


window.NoPhishHeuristic = {
    calculateRisk,
    isWhitelisted 
};
