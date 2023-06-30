"""

Cobalt Strike - API Hashing Decoding Script (CRC32/JRM)

Matthew @ Embee_research @ Huntress

usage: cs_hashing.py 0x<hash>,0x<hash>

Takes a comma separated list of hash values and prints the associated api names. 
NOTE: The dll containing relevant api must be in the same folder as this script. 
EG: You should have kernel32.dll,advapi32.dll,wininet.dll,ws2_32.dll etc in the same folder

"""

import pefile,sys,os

xor_value = 0xedb88320 


def calc_hash(name):
    i = 0
    output = 0xffffffff
    for i in name:
        #output = output ^ ord(ptr_name[i])
        output = output ^ ord(i)
        counter =8
        while counter != 0:
            temp1 = output >> 1
            temp2 = output & 1
            output = temp1
            if temp2 != 0:
                output = temp1 ^ xor_value
            counter = counter - 1
 
    return hex(output & 0xffffffff)

#Parse the export list from a dll file
def get_export_list(path_to_file):
    pe = pefile.PE(path_to_file)
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    pe.parse_data_directories(directories=d)
    exports = [(e.name) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
    return exports

def get_cwd_dll():
    dll_list = []
    cwd = os.listdir()
    for filename in cwd:
        if ".dll" in filename:
            dll_list.append(filename)
    return dll_list

def build_export_list(dll_list):
    #For each DLL, get the exports, build a master list
    export_master_list = []
    for file_name in dll_list:
        try:
            export_master_list += get_export_list(file_name)
        except:
            print("Failed to open {}".format(file_name))
            continue
    return export_master_list

def build_hash_dictionary(export_master_list):
    #resolve each export name and calculate hashes
    hash_dict = {}
    for export_name in export_master_list:
        if export_name:
            try:
                export_name = export_name.decode()
            except:
                export_name = export_name.decode('utf-16')
                continue
            h = calc_hash(export_name)
            hash_dict[export_name] = h
            hash_dict[h] = export_name
    return hash_dict

def lookup_hash(hash_dict, value):
    try:
        return hash_dict[value]
    except Exception as e:
        print(e)
        print("Unable to Find value {}".format(lookup))
        sys.exit(1)



def main():
    #Check that at least 1 argument has been provided
    try:
        lookup = sys.argv[1]
    except:
        print("failed to parse args")
        sys.exit(1)
        
    #Enumerate DLL's from current directory
    dll_list = get_cwd_dll()
    export_master_list = build_export_list(dll_list)
    hash_dict = build_hash_dictionary(export_master_list)
  
    
    #perform the lookup
    for lookup in lookup.split(","):
       try:
           print("{} : {}".format(lookup,lookup_hash(hash_dict,lookup)))
       except:
           print("Failed to Find: {}".format(lookup))
           #sys.exit(1)
       
if __name__ == "__main__":
    main()






    



