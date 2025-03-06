# Gatekeeper (Subject to Change)

## Overview
Gatekeeper is a powerful piece of malware designed for competition use, automatically deploying six different system backdoors that can be triggered from the Windows login screen. By running a single command, Red Team operators can establish persistent access unless Blue Team successfully detects and mitigates it.

## Features
- Supports six different backdoor methods:
  - **sk** – Sticky Keys
  - **n** – Narrator
  - **osk** – On-Screen Keyboard
  - **um** – Utility Manager
  - **ds** – Display Settings
  - **m** – Magnifier
- Allows deployment of multiple backdoors simultaneously.
- Designed for easy and efficient Red Team use.

## Usage
Gatekeeper can be executed via the command line with multiple arguments:
```cmd
Gatekeeper.exe sk um ds m

## Future Plans

- Drop Gatekeeper on a box through my Windows C2 that is currently being developed.
- Develop Image File Execution Options (IFEO) registry keys that:
  - Delete Sysinternals tools.
  - Neuter important system commands.
  - Hide Red Team users from detection.
- Kill Windows Firewall, Windows Defender, and wipe all firewall rules.

