# FlashFlood

## Overview
FlashFlood is a powerful piece of malware designed for competition use, automatically deploying six different system backdoors that can be triggered from the Windows login screen. Additionally, FlashFlood manipulates Image File Execution Options (IFEO) registry keys to neutralize critical security tools. By running a single command, Red Team operators can establish persistent access unless Blue Team successfully detects and mitigates it.

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
FlashFlood can be executed via the command line with multiple arguments:
```cmd
FlashFlood.exe sk um ds m
```
If no arguments are provided, FlashFlood will deploy all available backdoors by default.

FlashFlood also supports looping execution for any desired duration. For example, to rerun the program every 5 minutes, use:
```cmd
FlashFlood.exe loop5 [backdoor arguments]
```
The argument loop5 triggers the program to loop every 5 minutes. Here are some additional loop duration options:
- loop1 – Loop for 1 minute
- loop5 – Loop for 5 minutes
- loop10 – Loop for 10 minutes
And so on.
If no loop argument is provided, FlashFlood will execute the backdoors once without looping.

## Future Plans
- C2 Integration: The ability to drop FlashFlood onto a machine through an existing Command and Control (C2) server currently under development.
- IFEO Key Development: More Image File Execution Options (IFEO) registry keys will be designed to hide Red Team activities from detection tools, making it harder for Blue Teams to detect and disrupt the attack.
- Tool Disruption: Plans to disable or kill essential security tools like Windows Defender, Windows Firewall, and any firewall rules, further increasing the persistence of the backdoor.
