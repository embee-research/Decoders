"""
Decode powershell cobalt strike loaders directly from powershell script
Matthew @ Embee_research @ Huntress

"""


import sys,re,base64
input_name = "script.ps1"
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

    print("Successfully created .\{}".format(output_name))
    print("First Bytes: {}".format(pe[0:10]))


if __name__ == "__main__":
    main()
        


