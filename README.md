# Sigma to SPL Converter
A tool designed to convert Sigma rules into Splunk SPL queries. This helps security professionals quickly deploy detection rules from SigmaHQ or custom rules into their Splunk environment.

## Prerequisites
* **Python 3.11+**

## Installation
The project is frequently updated. It is recommended to clone the entire repository:
``` bash 
git clone https://github.com/Vulpes356/Convert_Sigma_to_SPL.git
cd Convert_Sigma_to_SPL 
```

## Usage
### Arguments:
    * `--file`  : Path to a single Sigma file (`.yml`)
    * `--folder`: Path to the folder containing Sigma files
    * `--table` : (Optional) Table query for the final SPL query

### Command
Convert from a single sigma file.
``` python
python main_convert.py --file <file_path>
```

Convert from a folder that have all sigma files inside.
``` python
 python main_convert.py --folder <folder_path> --table <fields> 
```

### Example
Input command
```python
python .\main_convert.py --file .\SigmaRules\SigmaHQ\example.yml 
```

Output terminal
```plaintext
From .\SigmaRules\SigmaHQ\example.yml:

index="main" sourcetype="XmlWinEventLog" (EventCode=1 OR EventCode=4688)  (ParentImage="*\\GoAnywhere\\tomcat\\*") AND ((((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe")) AND ((CommandLine="*IEX*" AND CommandLine="*enc*" AND CommandLine="*Hidden*" AND CommandLine="*bypass*") OR (match(CommandLine, "net\\s+user") OR match(CommandLine, "net\\s+group") OR match(CommandLine, "query\\s+session")) OR (CommandLine="*whoami*" OR CommandLine="*systeminfo*" OR CommandLine="*dsquery*" OR CommandLine="*localgroup administrators*" OR CommandLine="*nltest*" OR CommandLine="*samaccountname=*" OR CommandLine="*adscredentials*" OR CommandLine="*o365accountconfiguration*" OR CommandLine="*.DownloadString(*" OR CommandLine="*.DownloadFile(*" OR CommandLine="*FromBase64String(*" OR CommandLine="*System.IO.Compression*" OR CommandLine="*System.IO.MemoryStream*" OR CommandLine="*curl*"))) OR ((Image="*\\cmd.exe" AND (CommandLine="*powershell*" OR CommandLine="*whoami*" OR CommandLine="*net.exe*" OR CommandLine="*net1.exe*" OR CommandLine="*rundll32*" OR CommandLine="*quser*" OR CommandLine="*nltest*" OR CommandLine="*curl*")) OR ((CommandLine="*bitsadmin*" OR CommandLine="*certutil*" OR CommandLine="*mshta*" OR CommandLine="*cscript*" OR CommandLine="*wscript*"))))
```
