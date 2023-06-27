
- Pikabot String Decryption Code
- Matthew @ Embee_Research + Huntress
- Uses Capstone to disassemble code from a Pikabot dll file and locate "encrypted" stack strings.  
- Once located, uses dumpulator to "execute" the stack string and read decoded result. 
- TODO: Remove dumpulator and replace with Unicorn

This script was very heavily inspired by Oalabs/Risepro script. 
https://research.openanalysis.net/risepro/stealer/config/triage/2023/06/15/risepro.html

