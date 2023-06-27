"""
- Pikabot String Decryption Code
- Matthew @ Embee_Research + Huntress
- Uses Capstone to disassemble code from a Pikabot dll file and locate "encrypted" stack strings.  
- Once located, use dumpulator to "execute" the stack string and read decoded result. 
- TODO: Remove dumpulator and replace with Unicorn

This script was very heavily inspired by Oalabs/Risepro script. 
https://research.openanalysis.net/risepro/stealer/config/triage/2023/06/15/risepro.html

"""

from dumpulator import Dumpulator
import pefile,re,sys
from capstone import *
from capstone.x86 import *

#Load a pikabot minidump file
dp = Dumpulator("pika.dmp", quiet=True)

def main():
    
    #Load the dll file into capstone
    #This section was VERY heavily inspired by the oalabs risepro triage script
    #https://research.openanalysis.net/risepro/stealer/config/triage/2023/06/15/risepro.html
    filename = "pika.dll.bin"
    pe = pefile.PE(filename)
    md = Cs(CS_ARCH_X86, CS_MODE_32) 
    md.detail = True
    md.skipdata = True
    addr = 0
    instructions = []
    txt = pe.sections[0]
    #Set image base to same as x64dbg that created minidump
    image_base = 0x66B20000
    section_rva = txt.VirtualAddress

    #Disassemble code section
    for inst in md.disasm(txt.get_data(), image_base + section_rva):
        instructions.append(inst)

    new = False
    start = ""
    encs = []
    dec_len = 0
    count = 0
    #Enumerate instructions for known patterns
    for i, inst in enumerate(instructions):

        """ Reset the search if end not found in 150 lines from first mov"""
        if count > 150 or inst.mnemonic in ["call","jmp"]:
            #Reset the string search if typical pattern is not matched
            #Eg if call/jmp found, have likely searched too far
            new = False
            dec_len
            count = 0
            start = 0
            offset = 0
            end = 0


        if inst.mnemonic == 'mov' and inst.operands[0].type == X86_OP_MEM and inst.operands[1].type == X86_OP_IMM and new == False:
            #EG: mov dword ptr [EBP + -0x50]=>local_54,0x42465160
            #Capture encrypted stack strings
            new = True
            start = inst


        if new == True and ("mov" == inst.mnemonic) and inst.operands[1].type == X86_OP_REG and inst.operands[0].type == X86_OP_MEM:
            #EG: MOV byte ptr [EBP + ECX*0x1 + 0xfffffccc]=>local_3
            #Capture length of decrypted string
            if "ebp" in str(inst):

                offset = str(inst).split()[-2].split("]")[0]
                offset = int(offset,16)

        if new == True and ("cmp" == inst.mnemonic) and inst.operands[0].type == X86_OP_REG and inst.operands[1].type == X86_OP_IMM:
            #EG: CMP ECX,0xc
            #Capture first CMP instruction containing ecx, this contains the length of decoded string
            dec_len = inst.operands[1].value.imm

        if new == True and inst.mnemonic == "jl" and offset != None and dec_len != 0:# and count < 150 and new == True:
            #EG: JL LAB_66b21022
            #Capture location of first jump instruction, this instruction +1 is the end of decoding loop
            end = inst
            encs.append((start.address,dec_len, offset,instructions[i+1].address))
            offset = None
            new = False
            dec_len = 0
            count = 0
            start = 0
        
        count +=1
   
    if len(encs) > 0:
        final_decrypted_strings = []
        print("Number of strings found: {}".format(len(encs)))
        for start,dec_len,offset,end in encs:  
            #Debug
            #print("{} {} {} {}".format(hex(start),hex(dec_len),hex(offset),hex(end)))
            try:
                #Dumpulator
                #Allocate mem for stack
                ebp_buffer = dp.allocate(2000)
                #Move mem pointer so stack can be referenced "backwards"
                ebp = ebp_buffer+1000
                #Overwrite ebp with new mem buffer
                dp.write_ptr(dp.regs.ebp, ebp)
                #Reset ecx, used to count len 
                dp.regs.ecx = 0
                #"execute" each stack string
                dp.start(start,end)
                #read the result
                result = dp.read(dp.regs.ebp-offset,dec_len)


                #Check for UTF-16 or UTF-8 Encoding
                if result.count(0) < 3:
                    """Print UTF-8 Values"""
                    result = dp.read(dp.regs.ebp-offset,dec_len)
                    #print("ASCII: {}".format(result.decode('utf-8')))
                    final_decrypted_strings.append(result.decode('utf-8'))
                else:
                    """Print UTF_16 Values"""
                    result = dp.read(dp.regs.ebp-offset,dec_len*2)
                    #print("UNICO: {}".format(result.decode('utf-16')))
                    final_decrypted_strings.append(result.decode('utf-16'))
            except:
                result = dp.read(dp.regs.ebp-offset,dec_len*2)
                #print(result)
                continue

        #Remove duplicated strings
        deduped = []
        for i in final_decrypted_strings:
            if i not in deduped:
                deduped.append(i)
                print(i)
            
if __name__ == "__main__":
    main()



#This is an example of what the script is looking for in code
#This setup is consistent for *most* strings within pikabot and forms the basis of this script
"""
        66b2100b c7 45 b0        MOV        dword ptr [EBP + -0x50]=>local_54,0x42465160
                 60 51 46 42
        66b21012 c7 45 b4        MOV        dword ptr [EBP + -0x4c]=>local_50,0x566e4657
                 57 46 6e 56
        66b21019 8b ca           MOV        ECX,EDX
        66b2101b c7 45 b8        MOV        dword ptr [EBP + -0x48]=>local_4c,0x745b4657
                 57 46 5b 74
        66b21022 8a 44 0d b0     MOV        AL,byte ptr [EBP + ECX*0x1 + -0x50]=>local_54+
        66b21026 34 23           XOR        AL,0x23
        66b21028 88 84 0d        MOV        byte ptr [EBP + ECX*0x1 + 0xfffffccc]=>local_3
                 cc fc ff ff
        66b2102f 41              INC        ECX
        66b21030 83 f9 0c        CMP        ECX,0xc
        66b21033 7c ed           JL         LAB_66b21022
        66b21035 53              PUSH       EBX

"""
