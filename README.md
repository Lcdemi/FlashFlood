# FlashFlood

## Overview
FlashFlood is a powerful piece of malware designed for competition use, automatically deploying four different system backdoors that can be triggered from the Windows login screen. Additionally, FlashFlood manipulates Image File Execution Options (IFEO) registry keys to neutralize critical security tools. By running a single command, Red Team operators can establish persistent access unless Blue Team successfully detects and mitigates it.

## Features
- Supports four different backdoor methods:
  - **sk** – Sticky Keys
  - **osk** – On-Screen Keyboard
  - **um** – Utility Manager
  - **ds** – Display Settings
- Allows deployment of multiple backdoors simultaneously.
- Designed for easy and efficient Red Team use.

## Usage
FlashFlood can be executed via the command line:
```cmd
FlashFlood.exe
```
FlashFlood loops every 5 minutes to maintain persistence and restore backups.

## Future Plans
- C2 Integration: The ability to drop FlashFlood onto a machine through an existing Command and Control (C2) server currently under development.
- Tool Disruption: Plans to disable or kill essential security tools like Windows Defender, Windows Firewall, and any firewall rules, further increasing the persistence of the backdoor.
