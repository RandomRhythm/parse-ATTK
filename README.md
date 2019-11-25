This script will parse the Trend Micro Anti-Threat Toolkit (ATTK) XML output. You must extract the files from ATTK zip file output.

* To parse multiple zip files extract them with to sub folders with the name of the zip
 20170101-GUID_17507
* Once extraction is complete: Copy this script to the directory containing all the extracted folders
 The script will go into each sub directory and look for the irobot\log folder to parse XML output
* You can also place in the irobot\log folder and it will automatically process the XML
* If no matching directory structure or files were found within the script directory it will prompt to browse to the log folder

The script will create multiple output files:
* outreport.txt
 Provides file details and where each file came from
* out_data.txt
 Two sets of file hashes. The first set is suspicious files. The second is all other files which could still be malicious. After hashes is the browser activity. Last is the network DNS cache.
* FileOut.csv
 CSV format of files identified by ATTK
* ATTK_Debug.log
 Debug log containing all the details from each computer. This file is useful when parsing mutliple ATTK outputs at the same time to trace back to an item to a particular computer.