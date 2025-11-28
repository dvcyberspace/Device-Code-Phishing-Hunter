# **Device Code Phishing Threat Hunter (DCPTH)**
---
## 🚀 **Overview**

Device Code Phishing (DCP) is an emerging attack technique where attackers exploit OAuth / device-code authentication flows to trick users into entering verification codes on fake devices or malicious portals.

This project simulates DCP attack logs and builds a **Python-based threat-hunting tool** that identifies suspicious events using log-based analytics.

---

## 🧠 **What This Project Detects**

The detection script identifies patterns such as:

* Unusual frequency of device code requests.
* Multiple failed verification attempts in a short timeframe.
* Device codes used from **different IPs/locations**.
* Suspicious user-agent strings.
* Verification attempts on unknown or malicious domains.
---

## 🛠️ **Tech Stack**

* **Python 3+**
* `json` for log parsing
* Basic Windows terminal

---

## ⏬ **Detection and Response Flowchart**

```
             ┌────────────────────────┐
             │ sample_auth_logs.txt   │
             └──────────┬─────────────┘
                        │
              Parse each log line
                        │
                        ▼
       ┌──────────────────────────────────┐
       │ Event == DeviceCodeStart?        │
       └────────────────┬─────────────────┘
                        │
               Yes ↓            No → Continue
                        │
            Check if IP is known-good?
                        │
             ┌──────────┴──────────┐
             │                     │
       Known-good IP         Unknown IP 🚨
             │                     │
     Record as safe start     Raise Immediate Alert
             │                     │
             ▼                     ▼
         Wait for next events   Track suspicious start
                        │
                        ▼
           ┌───────────────────────────┐
           │ DeviceCodeSuccess event?  │
           └───────────────┬───────────┘
                           │
                 Yes ↓      No → Continue
                           │
          Match with suspicious start?
                           │
             ┌─────────────┴─────────────┐
             │                           │
      If matched: Raise alert      If not: ignore
             │
        Generate Report
---
