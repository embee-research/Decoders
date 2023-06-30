"""
Decode powershell cobalt strike loaders - Assumes shellcode has been obtained from Powershell script
Matthew @ Embee_research @ Huntress

"""
import sys

input_name = "shellcode_stage1.bin"
output_name = "stage2_decoded.bin"

try:
    f = open(input_name, "rb")
    enc = f.read()
    f.close()
except:
    print("failed to open file")
    sys.exit(1)

enc = enc[0xc0:]

key = int.from_bytes(enc[0:4],'little')
size = int.from_bytes(enc[4:8],'little')
out = bytearray(enc[8:])


def ror_single(value,ror):
    """ Performs a single byte ror operation"""
    right = (value >> (ror)) & 0xff
    left = (value << (8 - ror)) & 0xff
    return left | right

for i in range(len(out)):
    key = key & 3
    temp = ror_single(out[i],key)
    out[i] = temp & 0xff
    key +=1

try:
    f = open(output_name, "wb")
    f.write(out)
    f.close()
except:
    print("Failed to write output file")
    sys.exit(1)

print("Successfully created .\{}".format(output_name))
print("First Bytes: {}".format(out[0:10]))
