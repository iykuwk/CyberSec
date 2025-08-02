Documentation of my Cybersec journey.
This is my beginning in the CyberSecurity Journey where I will deal with some malware development codes.

# 🔐 Windows Malware Development & Entropy Evasion Research

## Overview

This repository is dedicated to the **research and development of Windows-based malware techniques**, 
specifically focusing on:

- Crafting and manipulating executable (`.exe`) files
- Lowering payload **entropy** to avoid signature/heuristic detection
- Bypassing basic detection mechanisms
- Exploring Windows API and obfuscation methods
- Understanding behavioral detection evasion
- Implementing base encoding, packing, and subtle sandbox evasion

> **This repository is for educational and research purposes only.** All code and content provided are strictly for learning 
  and analysis in a controlled environment.

---

## Objectives

- 🧠 **Understanding Windows internals** and API behaviors critical to malware execution.
- 🔍 **Investigating entropy manipulation** techniques to reduce binary detectability.
- 🎭 **Experimenting with stealth techniques**, such as process hollowing, encoded shellcode loaders, API call obfuscation
  and Privilege Escalation.
- 💾 Build custom `.exe` loaders and *trying* to study their footprint on various AV/EDR systems.
- 🛡️ Analyzing how malware analysts and reverse engineers detect and counteract low-entropy payloads.

## 🔧 Tools & Technologies

- Windows API: `Kernel32.dll`, `Ntdll.dll`, `Advapi32.dll`
- Libraries: Custom encoding/decoding, PE header manipulation
- Research Tools: PE-bear, Detect-It-Easy, Procmon, API Monitor
- Optional: Virtual Machine with snapshots (e.g., VirtualBox, VMware)
