#@Embee_Research
#https://twitter.com/embee_research

import base64,gzip

#Create Dictionary obtained from previous decoding
A1 = {"SCRT":{"L":".","J":"`","R":"&","Q":";","0":"_","1":" ","l":"^","5":",","I":"(","9":"*","i":"#","C":"<","j":"%","2":")","V":"-","v":"!","Z":"$","o":">","y":"~","D":"@","Y":"|"},"PCRT":{"j":"`","R":")","I":"#","x":"_","G":"(","U":"^","T":"&","S":"~","X":"!","0":"<","=":"@","6":".","M":",","Y":"|","d":" ","9":";","p":">","b":"*","w":"$","i":"-","l":"%"}}
#Store string from from encoding                                                                                  
encoded = "H4sIAAAAAAAEAA3OuwqDMBQA0F9Rcg2JmCwtLj7QRbNYCrbolKT1WgWxFCq4SL69PV9wsix5kTJgMUsF2QkLvFWcKRfdRwGz9wa8ety1h6EpEn/ih6ZvaQQHbVd5oj18qcLZcunnxWCoepA8YG5a2Je5Y4NqXFCLmNZtWt26bVYDYH8NSyPzSwcmSlFjByRyaET9NLQ/SOhkXCo08/o/tQ2zbvwBZp3Z46QAAAA="
encoded = str(gzip.decompress(base64.b64decode(encoded)))

#Obtain the SCRT Dictionary
dictionary = A1["SCRT"]
#Use the dictionary to perform a search/replace
#Making sure to replace the Value with the Key
# and not the other way around
for i in dictionary:
    encoded = encoded.replace(dictionary[i],i)

print("First round of Decoding: \n" + encoded + "\n")

#Reverse the string
encoded = encoded[-1:0:-1]
#base64 decode again
encoded = base64.b64decode(encoded)
#print the result
print("Second round of decoding: \n" + str(encoded))
