#Powershell script for extracting config from latest round of Jupyter malware

$malwarefile = [io.file]::readallbytes("<path to dll here>")
$malwareload = [reflection.assembly]::load($malwarefile)
for ($i = 0x06000080; $i -lt 0x06000150; $i++){

    try {
        $malstring = $malwareload.modules[0].resolveMethod($i).invoke($null, $null)
        if ($malstring.length -lt 100){
            echo $malstring
        }
    } catch {
      continue
    }
}



