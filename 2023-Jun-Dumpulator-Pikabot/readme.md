
- Pikabot String Decryption Code
- Matthew @ Embee_Research + Huntress
- Uses Capstone to disassemble code from a Pikabot dll file and locate "encrypted" stack strings.  
- Once located, uses dumpulator to "execute" the stack string and read decoded result. 
- TODO: Remove dumpulator and replace with Unicorn

This script was very heavily inspired by Oalabs/Risepro script. 
https://research.openanalysis.net/risepro/stealer/config/triage/2023/06/15/risepro.html

**Example of Encrypted Stack String**
![image](https://github.com/embee-research/Decoders/assets/82847168/5e734847-e389-4e81-861f-9817cf79f75f)

**Example of View Within X32dbg**
![image](https://github.com/embee-research/Decoders/assets/82847168/170150cb-05ca-4e54-a5db-1dd080d9db9f)

**Example Output**

![image](https://github.com/embee-research/Decoders/assets/82847168/27942252-3a2d-4685-8d53-f6803bd36794)
