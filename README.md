#Gatekeeper
Gatekeeper (Subject to Change) is a piece of malware that automatically opens 6 different system backdoors that can be run on the homescreen.
It can be given six arguments on the command line, including sk (Sticky Keys), n (Narrator), osk (On Screen Keyboard), um (Utility Manager), ds (Display), and m (Magnifier).
  - For example: "Gatekeeper.exe sk um ds m" spawns a Sticky Keys, Utility Manager, Display, and Magnifier Backdoor.

Future Plans:
  - Drop this on a box through my Windows C2 that I am currently developing.
  - Develop Image File Execution Options regkeys that delete sysinternals, neuter important commands, hide redteam users, etc.
  - Kill Windows Firewall, Windows Defender, and wipe all firewall rules.
