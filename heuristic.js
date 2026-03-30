// Prenavigation Heuristics
const TRUSTED_DOMAINS = ['tiktok.com', 'paypal.com', 'google.com', 'apple.com', 'microsoft.com', 'amazon.com', 'facebook.com', 'github.com', 'netflix.com'];
const SUSPICIOUS_KEYWORDS = [
  'verify', 'bank', 'login', 'update', 'secure', 'account', 'auth', 'confirm', 
  'billing', 'support', 'service', 'wallet', 'invoice', 'payment', 'credential', 
  'password', 'recovery', 'alert', 'notification', 'suspend', 'locked', 'restricted', 'paypal'
];
const CLOUD_PROVIDERS = ['s3.amazonaws.com', 'firebaseapp.com', 'web.app', 'herokuapp.com', 'netlify.app', 'vercel.app'];

function isWhitelisted(url) {
    try {
        let hostname = new URL(url).hostname;
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
      reasons.push('CRITICAL: IP address used instead of domain name');
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

    let domainKeywordMatches = 0;
    let pathKeywordMatches = 0;
    const lowerDomain = domain.toLowerCase();
    const lowerPath = url.pathname.toLowerCase();
    
    SUSPICIOUS_KEYWORDS.forEach(keyword => {
      if (lowerDomain.includes(keyword)) domainKeywordMatches++;
      if (lowerPath.includes(keyword)) pathKeywordMatches++;
    });

    // Only penalize keywords in the DOMAIN normally (e.g. paypal-login.com)
    if (domainKeywordMatches > 0) {
      penalty += domainKeywordMatches * 15;
      reasons.push(`Found ${domainKeywordMatches} highly suspicious keyword(s) in domain`);
    }

    // Cloud Storage Abuse Check
    const isCloudHosted = CLOUD_PROVIDERS.some(provider => lowerDomain.includes(provider));
    
    // If it's a cloud host AND it has keywords ANYWHERE (domain or path), it's a scam.
    if (isCloudHosted && (domainKeywordMatches > 0 || pathKeywordMatches > 0)) {
      penalty += 40; // MASSIVE PENALTY for cloud storage + brand name
      reasons.push('CRITICAL: Cloud storage abuse detected (Free host + Suspicious keywords)');
    }

    return { penalty, reasons };
  } catch (e) {
    return { penalty: 100, reasons: ['Invalid URL format'] };
  }
}

window.NoPhishHeuristic = { calculateRisk, isWhitelisted };