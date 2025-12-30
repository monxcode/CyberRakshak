# 🛡️ Cyber Threat Detector

🔗 **Live Demo:** https://monxcode.github.io/CyberRakshak/

**Team:** Tech4Impact  
**Type:** Frontend-only Cybersecurity Tool  
**Theme:** Gen-Z • Glassmorphism • Gamified Security Awareness  

---

##  Overview

**Cyber Threat Detector (CyberRakshak)** is a browser-based, frontend-only security tool that analyzes suspicious **URLs** and **texts**.  
This tool detects common phishing, scam, and malicious **patterns using rule-based logic —** without any backend, API, or database.

This Project  main goal:
> **Cybersecurity awareness + interactive learning**, Specially for hackathons & demos.

---

##  Key Features

###  Threat Analysis
- URL analysis (phishing indicators)
- Text analysis (urgent / scammy language)
- Auto-extract URL from Text
- Same input → same output (consistent results)

###  Rule-Based Detection Engine
Detect karta hai:
- HTTP (non-secure) URLs  
- IP address as domain  
- URL shorteners (bit.ly etc.)  
- Suspicious TLDs (`.xyz`, `.top`, `.club`)  
- Blacklisted / fake domains  
- Multiple subdomains  
- `@` symbol misuse  
- Brand impersonation & typosquatting  
- Phishing keywords & urgency language  

### Visual Risk Output
- Animated **Risk Meter (0–10)**
- Threat levels:
  - `0–2 → Safe`
  - `3–5 → Suspicious`
  - `6–10 → Dangerous`
- Color-coded UI
- Chart.js based threat breakdown
- Clear reason list with icons

###  Gamification
- User security score (points)
- Progress bar system
- Badge unlocking:
  - First Scan
  - 10 Safe Scans
  - Threat Detective
  - Security Expert
- LocalStorage based (no login needed)

###  Personalized Safety Tips
- Threat ke according dynamic safety tips
- Easy-to-understand recommendations

###  UI / UX
- Glassmorphism + neon Gen-Z design
- Smooth animations
- Fully responsive (mobile + desktop)
- Hackathon-ready visual polish

---

##  Tech Stack

- **HTML5** – Structure  
- **CSS3** – Glassmorphism, animations, responsiveness  
- **JavaScript (Vanilla)** – Rule-based threat logic  
- **Chart.js** – Threat visualization  

---

##  How It Works (Simple Flow)

1. User inputs URL or text  
2. The system performs multiple checks based on the rules.  
3. Each rule adds one threat score  
4. The final score determines the risk level.
5. In the UI:
   - Risk meter update
   - Reasons show
   - Chart update
   - Safety tips generate
   - User score & badges update

---

##  Example Inputs

- `http://secure-login-bank.com/verify`
- `https://bit.ly/suspicious-offer`
- `https://192.168.1.1/login`
- `URGENT: Your account is blocked! Click here to verify`

---

##  Disclaimer

This project is a **frontend demonstration tool** using **rule-based detection**.  
It is meant for **education, awareness, and hackathon demos** only.  
For real-world security, always rely on professional security tools.

---

##  Credits

Built Perpose : **Tech Sprint 2026 GDGOC RBU (Hackethon)**  
Contributor : **Manish Suthar & Mohan Singh Parmar**

UI inspired by modern cybersecurity dashboards  
Charts powered by **Chart.js**

---
