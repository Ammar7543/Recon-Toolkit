<h1 align="center">RECON-TOOLKIT V3</h1>

<p align="center">
  <b>⚡ Automated Reconnaissance & Pentesting Framework</b><br>
  <i>Fast • Modular • Resumable • Parallel • Security Research Focused</i>
</p>

<p align="center">
  <img src="YOUR_COVER_IMAGE_URL_HERE" alt="Recon-Toolkit Cover"/>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v3-blue.svg">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Kali%20Linux-black.svg">
  <img alt="Language" src="https://img.shields.io/badge/Bash-Script-success.svg">
  <img alt="License" src="https://img.shields.io/badge/license-AMXPRO-yellow.svg">
  <img alt="Status" src="https://img.shields.io/badge/status-Active-brightgreen.svg">
</p>

---

# ⚡ Overview

**Recon-Toolkit V3** is an advanced **Bash-based Reconnaissance & Pentesting Framework** built for Security Researchers, Penetration Testers, Red Teamers and Bug Bounty Hunters.

It automates the entire reconnaissance process—from subdomain enumeration to vulnerability discovery—while keeping everything organized inside a single workspace.

Instead of running dozens of individual tools manually, Recon-Toolkit combines them into one intelligent workflow with resume support, modular scanning, HTML reports and customizable phases.

---

# 🚀 Features

## Core Recon

- Subdomain Enumeration
- Live Host Detection
- Admin Panel Discovery
- Massive URL Collection
- JavaScript Collection
- Secret Discovery
- Katana Deep Crawling
- Parameter Discovery
- Directory Fuzzing
- 403 Bypass Testing
- Nuclei Vulnerability Scanning
- SQLi/XSS Parameter Hunting
- GF Pattern Detection
- Header Injection Checks
- AWS/IAM Key Detection
- SSL/TLS Analysis
- HTTP Method Testing
- WebDAV Detection
- WordPress Detection
- Final Secret Sweep

---

# 🔥 Exclusive Features

### ⚡ Parallel Slotting

Uses parallel workers to dramatically speed up:

- Enumeration
- Crawling
- JavaScript Downloading
- Directory Fuzzing
- Secret Discovery

---

### 🔄 Resume Capability

If your PC or Laptop shuts down unexpectedly...

No worries.

Recon-Toolkit automatically resumes from the last completed phase without restarting the entire scan.

---

### 🎯 Custom Scan Mode

Run only the modules you need.

Example:

- Only Enumeration
- Only Nuclei
- Only Directory Fuzzing
- Only JS Secrets

No unnecessary waiting.

---

### 🌐 Out-of-Scope Filtering

Exclude:

- Domains
- Subdomains
- Wildcards

to avoid wasting time on assets that are not part of your engagement.

Example

```
*.dev.example.com
mail.example.com
test.example.com
```

---

### 🛡 Smart Firewall Handling

Designed to work efficiently against environments protected by:

- Cloudflare
- Reverse Proxies
- Common WAFs

using smart request handling and optimized workflows.

---

### 📂 Automatic Organization

Every scan generates:

- Organized folders
- Clean output files
- HTML Reports
- Logs
- Resume checkpoints

No messy terminal output.

---

### ⚡ Massive Scope Ready

Large targets can contain:

- Millions of URLs
- Thousands of JavaScript files
- Hundreds of live hosts

Recon-Toolkit is designed to handle enterprise-scale engagements.

> Big Scope? Relax & Chill ☕

---

### 💾 Recommended Hardware

For maximum performance:

- **16GB RAM Recommended**
- Multi-Core CPU
- Kali Linux (Recommended)

---

# 🛠 Included Tools

- subfinder
- assetfinder
- httpx
- waybackurls
- gau
- katana
- nuclei
- ffuf
- dirsearch
- feroxbuster
- dalfox
- sqlmap
- gf
- uro
- paramspider
- secretfinder
- gobypass403
- wpscan
- testssl.sh
- xsser
- jq
- curl
- git
- python3
- Go

and many more...

---

# 📥 Installation

## Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/Recon-Toolkit.git
```

---

## Move into Directory

```bash
cd Recon-Toolkit
```

---

## Give Execute Permission

```bash
chmod +x recon-toolkit
```

---

## Install Dependencies

Run the installer.

```bash
./recon-toolkit
```

Select

```
2) Install
```

The toolkit will automatically download and configure every required dependency.

---

# 🚀 Running the Toolkit

Start the framework

```bash
./recon-toolkit
```

You'll see

```
1) Scan

2) Install

3) Doctor

4) Custom Scan
```

---

# 📖 Usage Guide

## Step 1

Run

```
./recon-toolkit
```

---

## Step 2

Choose

```
1) Scan
```

---

## Step 3

The toolkit automatically checks whether required tools are installed.

Example

```
Doctor

27 Found

1 Missing
```

If anything is missing simply choose

```
Install
```

---

## Step 4

Enter your target

Example

```
example.com
```

---

## Step 5

Confirm that you have written authorization before scanning.

---

## Step 6

If an old scan exists, simply resume it.

No need to restart.

---

## Step 7

(Optional)

Add Out-of-Scope Domains

Example

```
*.dev.example.com

mail.example.com
```

---

## Step 8

Choose

```
Run All Modules
```

or

```
Custom Scan
```

---

## Step 9

Select the number of parallel workers.

Example

```
15
```

---

## Step 10

Sit back and let Recon-Toolkit perform:

- Enumeration
- Crawling
- URL Collection
- JS Analysis
- Secret Discovery
- Parameter Discovery
- Vulnerability Scanning
- Report Generation

---

# 📁 Output

Every scan is automatically organized.

```
recon_example.com/

├── Subdomains
├── Live Hosts
├── URLs
├── JS Files
├── Secrets
├── Parameters
├── Nuclei
├── Reports
├── Logs
└── HTML Report
```

---

# 👨‍💻 Developer

## Muhammad Ammar

Security Researcher

Bug Bounty Hunter

Red Team Enthusiast

---

# ⭐ Support

If this project helped you,

please consider giving it a ⭐ on GitHub.

It helps the project grow.

---

# ⚠ Disclaimer

This toolkit is intended **only for authorized security assessments**.

Always obtain **written permission** before testing any target.

The developer is **not responsible** for misuse or unauthorized activities.

---

# 📜 License

Copyright © 2026 Muhammad Ammar

Licensed under **AMXPRO License**
