# 🛡️ NoPhish: Real-Time Zero-Day Phishing Detection Browser Extension

[![Chrome Extension](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-blue.svg)](https://developer.chrome.com/docs/extensions/mv3/)
[![AI Model](https://img.shields.io/badge/AI%20Engine-Random%20Forest%20Classifier-green.svg)](#3-cloud-random-forest-ai-engine)
[![Cloud Backend](https://img.shields.io/badge/Cloud%20API-Render%20(Node.js)-informational.svg)](https://nophish-backend.onrender.com)


> **NoPhish** is a lightweight, client-side Chromium browser extension (Manifest V3) that protects users against zero-day phishing attacks, credential-harvesting pages, and cloud storage abuse. It combines **local lexical heuristics**, a **cloud-hosted Random Forest AI engine**, and a **live DOM analysis module** to compute an instant **0–99 Website Safety Score**, injecting visual risk badges into Google search results and intercepting high-risk pages with a fullscreen warning overlay before credentials can be stolen.

---

## 🔗 Repository Links

* **Frontend Chrome Extension:** [https://github.com/adityaml03/NoPhish-Project](https://github.com/adityaml03/NoPhish-Project)
* **Backend API & ML Repository:** <!-- ADD YOUR BACKEND GITHUB LINK HERE -->
  ```
  👉 https://github.com/adityaml03/nophish-backend
  ```
  *(Live API deployed at: `https://nophish-backend.onrender.com/analyze`)*

---

## 📌 Table of Contents
1. [How It Works (3-Tier Detection Engine)](#-how-it-works-3-tier-detection-engine)
2. [Key Capabilities](#-key-capabilities)
3. [Detection Modules & Penalty System](#-detection-modules--penalty-system)
4. [Score Fusion Algorithm & Tiers](#-score-fusion-algorithm--tiers)
5. [User Interface & Visual Feedback](#-user-interface--visual-feedback)
6. [Extension Architecture & File Structure](#-extension-architecture--file-structure)
7. [Installation & Local Setup](#-installation--local-setup)
8. [Live Testing / Demo Mode](#-live-testing--demo-mode)
---

## ⚙️ How It Works (3-Tier Detection Engine)

Traditional browser protection (like Google Safe Browsing) relies on static blacklists that suffer from a **6 to 48-hour detection gap** before new phishing domains are indexed. 

NoPhish executes a **Hybrid Multi-Engine Pipeline** on every page load and search query:

```
                          User navigates to a URL / Search Result
                                           │
                                           ▼
                   ┌──────────────────────────────────────────────┐
                   │    1. Strict Trusted Domain Whitelist?       │
                   └───────────────────────┬──────────────────────┘
                                  YES ┌────┴────┐ NO
                                      │         │
                 Short-circuits to 99 │         ▼
                 (Zero False Positive)│  ┌─────────────────────────────────┐
                                      │  │  2. Local URL Lexical Analyzer  │ (heuristic.js)
                                      │  └──────────────┬──────────────────┘
                                      │                 ▼
                                      │  ┌─────────────────────────────────┐
                                      │  │  3. Cloud Random Forest AI API  │ (random_forest.js)
                                      │  └──────────────┬──────────────────┘
                                      │                 ▼
                                      │  ┌─────────────────────────────────┐
                                      │  │  4. Post-Navigation DOM Scanner │ (dom_analyzer.js)
                                      │  └──────────────┬──────────────────┘
                                      │                 │
                                      ▼                 ▼
                          ┌──────────────────────────────────────────────┐
                          │         Score Fusion Engine (content.js)     │
                          │   Safety Score = min(99, max(0, 100 - Total))│
                          └───────────────────────┬──────────────────────┘
                                                  │
                 ┌────────────────────────────────┼────────────────────────────────┐
                 ▼                                ▼                                ▼
         Score 80 – 99                    Score 50 – 79                     Score 0 – 49
         🟢 SAFE                          🟡 WARNING                        🔴 DANGER
  (Unrestricted browsing)          (Caution badge in popup)         (Active Warning Overlay Blocks Page)
```

---

## ✨ Key Capabilities

* **Pre-Navigation Google Search Injections:** Injects color-coded visual dots (`🟢`, `🟡`, `🔴`) directly beside search results on `google.com/search` before users click, powered by an asynchronous `MutationObserver` that monitors dynamically loaded results.
* **Instant Whitelist Bypass:** Hardcoded validation for high-traffic trusted domains (`google.com`, `paypal.com`, `apple.com`, `microsoft.com`, `amazon.com`, `github.com`, etc.) to guarantee zero false positives.
* **Cloud Storage Abuse Detection:** Specifically flags free hosting and object storage providers (`s3.amazonaws.com`, `firebaseapp.com`, `web.app`, `herokuapp.com`, `vercel.app`, `netlify.app`) combined with banking/login keywords, a rampant zero-day phishing vector.
* **Client-Side DOM Inspection:** Scans rendered HTML for unencrypted password fields (`http:`), unverified domain credential requests, hidden forms, and abnormal external script counts.
* **Active Interception Warning Modal:** High-risk pages (<50 score) are blurred and blocked with an overlay modal giving users the reason breakdown and a safe escape button.
* **Developer Demo Mode:** Test the warning overlay instantly on any website by appending `?test_nophish=danger` to the URL.

---

## 🔍 Detection Modules & Penalty System

NoPhish calculates penalties deterministically across three independent modules:

### 1. Pre-Navigation Lexical Heuristics (`heuristic.js`)
Audits URL syntax and domain composition without executing malicious code:
* **IP Address Literal (`+60 penalty`):** Catches URLs using raw IPs (e.g. `http://192.168.1.1/login`) instead of registered domains.
* **Credential Spoofing `@` Trick (`+50 penalty`):** Exploits RFC authority syntax where characters before `@` are ignored by the browser.
* **Cloud Provider + Suspicious Keyword Abuse (`+40 penalty`):** Heavily penalizes pages on S3, Firebase, Vercel, or Netlify containing keywords like `paypal`, `secure`, `bank`, or `verify`.
* **Excessive Subdomain Chaining (`+20 penalty`):** Flags domains with $>3$ dots (e.g., `paypal.com.verify-billing.site`).
* **Suspicious Domain Keywords (`+15 penalty per match`):** Targets domain names containing sensitive tokens (`login`, `auth`, `billing`, `wallet`, `credential`).
* **Multiple Hyphens (`+10 penalty`):** Flags typosquatting patterns with $>2$ hyphens (e.g., `apple-id-verify-secure.com`).
* **Excessive URL Length (`+10 penalty`):** Flags URLs exceeding 120 characters used to hide destination payloads.

### 2. Cloud Random Forest AI Engine (`random_forest.js` & `background.js`)
Sends the URL to the Node.js cloud server on Render (`https://nophish-backend.onrender.com/analyze`) running a trained **Random Forest Machine Learning model**:
* **Probability > 90% (`+55 penalty`):** `CRITICAL AI: Extreme phishing probability` (Triggers immediate danger).
* **Probability > 70% (`+30 penalty`):** `AI Warning: High phishing probability`.
* **Probability > 50% (`+15 penalty`):** `AI Notice: Suspicious URL semantics`.
* **Safe (<50%):** Adds positive confidence explanation to the report.
* **Cold-Start Resilience:** Handles cloud server spin-ups gracefully without crashing client browsing.

### 3. DOM Traversal & Security Scanner (`dom_analyzer.js`)
Audits the live rendered DOM structure of the web page:
* **Password Field on Insecure HTTP (`+60 penalty`):** Instantly triggers red danger for plaintext credential transmission.
* **Password Field on Unverified Domain (`+35 penalty`):** Penalizes unwhitelisted websites requesting password credentials.
* **Hidden Forms (`+10 penalty`):** Detects forms styled with `display: none`, `opacity: 0`, or `visibility: hidden` used by invisible credential sniffers.
* **Excessive External Scripts (`+10 penalty`):** Flags pages loading $>15$ scripts from third-party hostnames.

---

## 🧮 Score Fusion Algorithm & Tiers

The final score is synthesized inside `content.js`:

$$\text{Safety Score} = \min\left(99, \max\left(0, 100 - (\text{Penalty}_{\text{Heuristic}} + \text{Penalty}_{\text{ML}} + \text{Penalty}_{\text{DOM}})\right)\right)$$

| Score Range | Risk Level | Visual Badge | System Action |
| :-: | :-: | :-: | :--- |
| **80 – 99** | **Safe** | 🟢 Green Dot | Normal browsing. Verified domain or clean heuristic/AI scan. |
| **50 – 79** | **Warning** | 🟡 Yellow Dot | Caution advised. Popup lists identified suspicious indicators. |
| **0 – 49** | **Danger** | 🔴 Red Dot | **High Risk.** Automatically intercepts navigation with fullscreen modal. |

---

## 🖥️ User Interface & Visual Feedback

### 1. Extension Popup Dashboard (`popup.html` / `popup.js`)
Clicking the NoPhish toolbar icon opens a 320px dashboard displaying:
* A dynamic circular score badge colored green, yellow, or red based on the current page.
* Risk label (`Safe to Browse`, `Suspicious`, or `Highly Malicious`).
* Granular bulleted list of reasons explaining exactly why points were deducted.

### 2. Google Search Result Badges
On `google.com/search`, NoPhish scans organic result links and injects inline badges next to every `<h3>` title:
* Hovering over any dot displays a tooltip showing the exact score and reason breakdown.
* Dynamic DOM updates (such as clicking "More results" or infinite scroll) are automatically processed via a `MutationObserver`.

### 3. Active Warning Overlay Modal
When navigating to a high-risk site (score $<50$):
* A dark backdrop (`rgba(0,0,0,0.95)`) covers the viewport.
* Displays: **"Hold on! This site might not be safe."**
* Details box shows the safety score and all flagged threat reasons.
* Provides two buttons:
  * **"Take me back to safety"** (Calls `window.history.back()` or routes to Google).
  * **"I understand the risks, continue"** (Dismisses the overlay for advanced users).

---

## 📂 Extension Architecture & File Structure

```text
NoPhish/
├── manifest.json         # Manifest V3 metadata, permissions, host rules
├── background.js         # Service Worker handling async cloud fetch calls
├── content.js            # Core orchestrator: Score Fusion, search badge injection, modal
├── heuristic.js          # Pre-navigation heuristics, regex checks & whitelist
├── random_forest.js      # Cloud AI consumer & probability tier mapper
├── dom_analyzer.js       # Live DOM parser (password inputs, hidden forms, scripts)
├── indicator.css         # Styles for search result badges and warning overlay
├── popup.html            # Extension popup markup (score circle & reason list)
├── popup.js              # Popup script fetching analysis via chrome.runtime messaging
├── logo.html             # Logo generator utility script
├── icon16.png            # 16x16 toolbar icon
├── icon48.png            # 48x48 extension management icon
└── icon128.png           # 128x128 Chrome Web Store & high-res icon
```

---

## 🚀 Installation & Local Setup

### Running the Chrome Extension:
1. Clone or download this repository:
   ```bash
   git clone https://github.com/adityaml03/NoPhish-Project.git
   ```
2. Open Google Chrome (or Brave, Edge, Opera, or Chromium).
3. Navigate to:
   ```text
   chrome://extensions/
   ```
4. Enable **Developer mode** via the toggle switch in the top-right corner.
5. Click **Load unpacked** in the top-left corner.
6. Select the project folder containing `manifest.json`.
7. The **NoPhish** shield icon will appear in your browser extension toolbar!

---

## 🧪 Live Testing / Demo Mode

You can verify and demonstrate all three risk states in real-time:

1. **Safe Domain Test (🟢 Score: 99):**
   * Visit `https://www.google.com` or `https://github.com`.
   * Open the extension popup: displays **99/100 Safe to Browse** via Whitelist short-circuit.

2. **Pre-Navigation Search Badges:**
   * Go to `https://www.google.com/search?q=paypal+login`.
   * Notice the colored dots (`🟢`, `🟡`, `🔴`) injected next to each search result title before clicking.

3. **Active Danger Warning Modal (🔴 Score: 15):**
   * Visit any standard website and append `?test_nophish=danger` to the URL:
     ```text
     https://example.com/?test_nophish=danger
     ```
   * The page will be intercepted immediately with the red warning modal overlay!

---

