// DOM Analysis (Module 5)
function analyzeDOM() {
  let penalty = 0;
  let reasons = [];

  const passwordInputs = document.querySelectorAll('input[type="password"]');
  if (passwordInputs.length > 0) {
    if (window.location.protocol !== 'https:') {
      penalty += 60;
      reasons.push('Password field on insecure (HTTP) page');
    } else {
      penalty += 10;
      reasons.push('Contains password field');
    }
  }

  const forms = document.querySelectorAll('form');
  let hiddenForms = 0;
  forms.forEach(form => {
    const style = window.getComputedStyle(form);
    if (style.display === 'none' || style.opacity === '0' || style.visibility === 'hidden') {
      hiddenForms++;
    }
  });

  if (hiddenForms > 0) {
    penalty += 20;
    reasons.push(`Found ${hiddenForms} hidden form(s)`);
  }

  const scripts = document.querySelectorAll('script[src]');
  let externalScripts = 0;
  scripts.forEach(script => {
    try {
      const srcUrl = new URL(script.src);
      if (srcUrl.hostname !== window.location.hostname) {
        externalScripts++;
      }
    } catch (e) {}
  });

  if (externalScripts > 15) {
    penalty += 10;
    reasons.push(`High number of external scripts (${externalScripts})`);
  }

  return { penalty, reasons };
}

window.NoPhishDOM = { analyzeDOM };
