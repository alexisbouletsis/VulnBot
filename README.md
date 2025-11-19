# 🛡️ VulnBot — Automated Security Pull Request Reviewer

**VulnBot** is an automated security review system designed to prevent vulnerable code from being merged into software repositories.  
It integrates static analysis, risk prediction metrics, and configurable decision rules to automatically **ACCEPT** or **REJECT** pull requests.

VulnBot combines:
- 🔍 **Snyk static code analysis**  
- 📊 **EPSS (Exploit Prediction Scoring System)**  
- 🛡️ **CVSS severity scores**

to provide an objective, automated security evaluation for any PR.

---

## 🔧 Installation (Fork Required)

To use VulnBot in your own project:

1. **Fork this repository** to your GitHub account  
2. Clone your fork locally  
3. Install dependencies:
```command prompt
cd code-reviewer
npm install
```

VulnBot is written in JavaScript and runs on the Node.js runtime, which powers the CLI and GitHub Actions automation.

---

## 📁 Required Repository Structure
Your fork **must include** the following:
```command prompt
.github/
  workflows/
    pr-scan.yml     ← REQUIRED
code-reviewer/
  cli.js
  scanner.js
  epss-comparison.js
  config.json

```

---

## 🔐 Snyk Account Setup (Required)
VulnBot depends on Snyk for security scanning.
To use it, you must have:
- A Snyk Account
- Your project uploaded to Snyk
- Your personal Snyk authentication token

How to get your Snyk Token: 

1️⃣ Log in to Snyk
Go to https://snyk.io/
 and sign in.

2️⃣ Click your email (bottom-left corner)

3️⃣ Open Account Settings

4️⃣ Find Auth Token and click Show

5️⃣ Copy the token

6️⃣ Add it to your GitHub repository secrets: 

Go to: 
```command prompt
GitHub Repo → Settings → Secrets and variables → Actions → New repository secret
```

Create a secret:
``` command prompt
Name: SNYK_TOKEN
Value: <your token>
```

✔️ Done — GitHub Actions can now authenticate with Snyk.


---
## 📐 Architecture Overview

VulnBot follows a clean three-module architecture implemented entirely in JavaScript:

### 1️⃣ Controller — `cli.js`
- Entry point of the CLI tool
- Loads configuration (thresholds, weights, modes)
- Coordinates scanning and analysis
- Outputs the final decision (ACCEPT / REJECT)
- Works interactively (CLI) or automatically (GitHub Actions)

### 2️⃣ Scanner — `scanner.js`
- Executes Snyk static code analysis
- Produces:
  - `snyk-report.json`
  - `snyk-code-report.txt`
- Extracts vulnerability counts by severity (high, medium, low)
- Fetches EPSS scores from FIRST.org
- Returns structured JSON data used by the Analyzer

### 3️⃣ Analyzer — `epss-comparison.js`
- Correlates:
  - Snyk results
  - EPSS risk scores
  - CVSS severity
- Computes weighted risk scores
- Applies decision rules and thresholds
- Generates:
  - `final-report.txt`
  - `epss-plain-table.txt`
- Produces the final PR evaluation decision

---

## 🚀 GitHub Actions Usage

To enable automatic PR scanning:

1. Fork this repository
2. Ensure the `code-reviewer/` directory exists in your project
3. Add your Snyk token to GitHub Secrets:
```
   SNYK_TOKEN
```

Once configured, every pull request will trigger VulnBot.

---

## 🖥️ Local CLI Usage
```command prompt
npm install -g snyk
snyk auth
snyk test --json > snyk-report.json
snyk code test > "code-reviewer/snyk-code-report.txt"
node code-reviewer/cli.js
```

---

## ⚙️ Configuration (`config.json`)

Example:
```json
{
  "weights": { "epss": 0.7, "snyk": 0.3 },
  "thresholds": {
    "avgThreshold": 0.055,
    "criticalThreshold": 0.3,
    "cvssCutoff": 7,
    "severityCounts": {
      "critical": 1,
      "high": 2,
      "medium": 5,
      "low": null
    }
  }
}
```

---

## 🤖 Example Output
```yaml
=== Digital PR Review Summary ===
Total vulnerabilities: 12
PR Decision: REJECT
Reason: Too many HIGH vulnerabilities (3 > 2)
Average Vulnerability Score: 0.084112
```

**VulnBot** — Keeping your code secure, one PR at a time. 🛡️
