"""
Decode powershell cobalt strike loader

Obtains beacon binary from initial powershell script

Matthew @ embee_research @ Huntress

Sample1: c28d5f78085140c0a796ec9df7d5e69e4912b2326d4dbf7c76239dc8c357d41d
Sample2: 2dbeaf3c67d87f690842838ace165c7549dc1bbbd697ba11b997c1b1c39465a0

Output is saved as final_cobalt_beacon.bin
Output can be given to the sentinelone Cobalt strike parser script to extract config. 
https://github.com/Sentinel-One/CobaltStrikeParser

"""


import sys,re,base64,pefile

input_name = sys.argv[1]
output_name = "pe_decoded_from_script.bin"


def ror_single(value,ror):
    """ Performs a single byte ror operation"""
    right = (value >> (ror)) & 0xff
    left = (value << (8 - ror)) & 0xff
    return left | right


def decode_shellcode(shellcode,key):
    out = bytearray(shellcode)
    for i in range(len(out)):
        key = key & 3
        temp = ror_single(out[i],key)
        out[i] = temp & 0xff
        key +=1
    return out

def main():

    #Read input powershell file
    try:
        f = open(input_name, "rb")
        pwsh = f.read()
        f.close()
    except:
        print("failed to open file")
        sys.exit(1)

    #Decode utf-16
    try:
        pwsh = pwsh.decode('utf-8')
    except:
        pwsh = pwsh.decode('utf-16')

    #Search for base64 blob
    match = re.search("[a-zA-Z0-9\+\=\/]{1000,}",pwsh).group(0)
    #Decode base64 match and jump to encoded offset at 0xc0
    enc_blob = base64.b64decode(match)
    enc_blob = enc_blob[0xc0:]

    #Get Decryption key
    key = int.from_bytes(enc_blob[0:4],'little')
    #Get size of pe
    size = int.from_bytes(enc_blob[4:8],'little')
    #Get encrypted pe
    enc_pe = enc_blob[8:]

    pe = decode_shellcode(enc_pe,key)

    
    #write output file
    try:
        f = open(output_name, "wb")
        f.write(pe)
        f.close()
    except:
        print("Failed to write output file")
        sys.exit(1)

    print("Successfully created .\{}\n".format(output_name))
    #print("First Bytes: {}".format(pe[0:10]))

    #Decode stage 2 binary
    pe = pefile.PE(output_name)
    #Get stage 3 from data section
    enc_s3 = bytearray(pe.sections[1].get_data()[0x14:])
    
    out_s3 = enc_s3
    for ivar1 in range(len(enc_s3)):
        bvar2 = (ivar1 +1) & 3
        temp = (enc_s3[ivar1] >> bvar2) | (out_s3[ivar1] << 8 - bvar2)
        temp = temp & 0xff
        out_s3[ivar1] = temp

    #write output file
    try:
        f = open("final_cobalt_beacon.bin", "wb")
        f.write(out_s3)
        f.close()
    except:
        print("Failed to write output file")
        sys.exit(1)
    print("saved final beacon file {}".format("Final_cobalt_beacon.bin"))
    print("first bytes: {}".format(out_s3[0:0x10]))


if __name__ == "__main__":
    main()
        


