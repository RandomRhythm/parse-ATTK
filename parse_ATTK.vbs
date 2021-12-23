'ATTK Parser by Ryan Boyle randomrhythm@rhythmengineering.com
'v 3.0.2 - Support ATTK for Linux output parsing
'v 3.0.1 - Public version published
'v 3.0.0 - CSV output support for multi output processing (doesn't rewrite the header row). Condense the data by hash value and only provide an example of the file path. If prevalence is not provided via ATTK output then its tracked via dict.
'v 2.8.8 - CSV output.
'v 2.8.7 - Add SEP detection
'v 2.8.6 - Fix typo. Modify Flash Player detection to call out further unsupported versions.
'v 2.8.5 - Bugfix: Dict already exists - DictUnknownFiles.add strTmpCompName & "|" & "", "No unknown files|" & vbcrlf
'v 2.8.4 - Debug logging for unknown files
'v 2.8.3 - Parse browser history and DNS cache
'v 2.8.2 - Output unique hashes to separate file
'v 2.8.1 - Added DictWhiteList, DictUnknownFiles, and DictSuspiciousHashes to find unknown files that may require further verification. Outputs all hashes that weren't whitelist or suspect
'v 2.8 - IE version check for unsupported version (lower than v11)
'v 2.7 - Change wording for silverlight not patched
'v 2.6 - Add silverlight check. Bugfix: version compare code overflow with cint changed to clng
'v 2.5 - Update CCM and Microsoft antimalware detection
'v 2.4 - Update FireAMP detection to account for different versions.
'v 2.3 - Check for Palo Alto Networks GlobalProtect.
'v 2.2 - Check for FireAMP and OfficeScan.
'v 2.1 - Updated ESET detection.
'v 2.0 - Updated app detections to remove quotes and lower case compare. Fix version compare code. Update static flash version to 20.0.0.228
'v 1.9 - ESET detection
'v 1.8 - Error handling for output path
'v 1.7 - Debug log computer name and OS version
'v 1.6 - Check for Microsoft Antimalware, Chrome, and SCCM. Check MS15-065 KB3065822 and MS15-078 KB3079904 is installed. Check listening on common ports. Check telnet server and IIS running. 
'v 1.5 - Check MS08-067 vulnerability
'v 1.4 - Check if flash player is out of date. Add debug log.
'v 1.3 - Output local IP address
'v 1.2 - Parse multiple output folders
'v 1.1 - Get computer name
'v 1.0 - Parse non-whitelisted files/hashes from scanreport.xml and javascript registry autorun malware from assessreport.xml.

'Extract ATTK zip file
'Point script to .\irobot\Log
'Script creates outreport.txt of non-whitelisted files

'outreport.txt contents:
'Computer Name|File path|Hash|ATTK Scan ID|Local IP addresses



'ProductType 1 = Desktop OS
'ProductType 2 = Server OS – Domain Controller
'ProductType 3 = Server OS – Not a Domain Controller

Const forwriting = 2
Const ForAppending = 8
Const ForReading = 1
Dim strTmpKey
Dim strTmpValue
Dim strTmpValman
DIm objShellComplete
Set objShellComplete = WScript.CreateObject("WScript.Shell") 
Dim objFSO: Set objFSO = CreateObject("Scripting.FileSystemObject")
Dim objFile
Dim DictData
Dim strLogSubPath: strLogSubPath = "\irobot\Log"
Dim BoolMultiReporting: BoolMultiReporting = False
Dim DictReportOut: set  DictReportOut = CreateObject("Scripting.Dictionary")
DIm strFlashVersion
Dim BoolDebugLog
Dim intWinMajor
Dim intWinMinor
Dim intWinBuild
Dim strStaticFPversion
Dim DictInfoReportOut: set  DictInfoReportOut = CreateObject("Scripting.Dictionary")
Dim DictWhiteList: set  DictWhiteList = CreateObject("Scripting.Dictionary")
Dim DictUnknownFiles: set  DictUnknownFiles = CreateObject("Scripting.Dictionary")
Dim DictSuspiciousHashes: set  DictSuspiciousHashes = CreateObject("Scripting.Dictionary")
Dim DictDNSCache: set  DictDNSCache = CreateObject("Scripting.Dictionary")
Dim DictBrowserHistory: set  DictBrowserHistory = CreateObject("Scripting.Dictionary")
Dim DictPrevalence: set  DictPrevalence = CreateObject("Scripting.Dictionary")
Dim DictFpathExample: set  DictFpathExample = CreateObject("Scripting.Dictionary")
'---- Config Items
BoolDebugLog = True
strStaticFPversion = "32.0.0.255"
'---- End Config Items

CurrentDirectory = GetFilePath(wscript.ScriptFullName)

if objFSO.fileexists(currentdirectory & "\ATTK_Debug.log") then objFSO.deletefile currentdirectory & "\ATTK_Debug.log"

strCachePath = CurrentDirectory & "\cache"

'create sub directory
if objFSO.folderexists(strCachePath) = False then _
objFSO.createfolder(strCachePath)


if strFlashVersion = "" then strFlashVersion = strStaticFPversion
'msgbox strFlashVersion
Set f = objFSO.GetFolder(CurrentDirectory)
Set fc = f.SubFolders
For Each f1 in fc
    if objFSO.FileExists(CurrentDirectory & "\" & f1.name & strLogSubPath & "\scanreport.xml") = True or objFSO.FileExists(CurrentDirectory & "\" & f1.name & "\log" & "\scanreport.xml") = True then
      BoolMultiReporting = True
      exit for
    end if
Next

strFile = CurrentDirectory & "\scanreport.xml"
if BoolMultiReporting = false and objFSO.fileexists(strFile) = False then

  strFolderPath = fnShellBrowseForFolderVB
  strFile = strFolderPath & "\scanreport.xml"
else
  strFolderPath = CurrentDirectory
  strFile = strFolderPath & "\scanreport.xml"
end if

strOutPutFile = strFolderPath & "\outreport.txt"
strOutPuthFile = strFolderPath & "\out_data.txt"
Set DictData = CreateObject("Scripting.Dictionary")


if objFSO.fileexists(strOutPuthFile) then objFSO.deletefile(strOutPuthFile)

if BoolMultiReporting = false then
  ParseATTKReports True
else
	boolWriteHeader = True
  For Each f1 in fc
    if objFSO.FileExists(CurrentDirectory & "\" & f1.name & strLogSubPath & "\scanreport.xml") then
      strFolderPath = CurrentDirectory & "\" & f1.name & strLogSubPath & "\"
      strFile = strFolderPath & "\scanreport.xml"
      ParseATTKReports boolWriteHeader
      boolWriteHeader = False
    elseif objFSO.FileExists(CurrentDirectory & "\" & f1.name & "\log" & "\scanreport.xml") then
      strFolderPath = CurrentDirectory & "\" & f1.name & "\log\"
      strFile = strFolderPath & "\scanreport.xml"
      ParseATTKReports boolWriteHeader
      boolWriteHeader = False    
    end if
  Next

end if

'output deduplicated rows based off hash
for each rowentry in DictPrevalence

	tmphash = getdata(rowentry, chr(34), chr(34))
	tmpfPath = DictFpathExample.item(tmphash)
	tmpRowOutput = replace(rowentry, "%VariableToReplace1%", tmpfPath)
	tmpRowOutput = replace(tmpRowOutput, "%VariableToReplace2%", DictPrevalence.item(rowentry))

	LogData currentdirectory & "\FileOut.csv",tmpRowOutput, false
next


if instr(strOutPutFile, ":") then
for each item in DictReportOut '
    strOutput = strOutput & Item & "|" & DictReportOut.Item(Item) & vbcrlf
next
LogData strOutPutFile, strOutput,False

strOutput = ""
for each item in DictInfoReportOut '
    strOutput = strOutput & Item & "|" & DictInfoReportOut.Item(Item) & vbcrlf
next
LogData strOutPutFile, strOutput,False

'output hash path
strOutput = ""
if DictSuspiciousHashes.count > 0 then

  for each item in DictSuspiciousHashes 'Detections

     strOutput = strOutput & item & "|" & DictSuspiciousHashes.item(Item) & vbcrlf

  next
end if
LogData strOutPuthFile, strOutput,False

strOutput = ""
if DictUnknownFiles.count > 0 then
  for each item in DictUnknownFiles 'Detections
     strOutput = strOutput & item & "|" & DictUnknownFiles.item(Item) & vbcrlf
  next
end if
LogData strOutPuthFile, strOutput,False

strOutput = ""
if DictBrowserHistory.count > 0 then
  for each item in DictBrowserHistory 'Detections
     strOutput = strOutput & item & vbcrlf
  next
end if
LogData strOutPuthFile, strOutput,False

strOutput = ""
if DictDNSCache.count > 0 then
  for each item in DictDNSCache 'Detections
     strOutput = strOutput & item & vbcrlf
  next
end if
LogData strOutPuthFile, strOutput,False


wscript.sleep 10
objShellComplete.run "notepad.exe " & chr(34) & strOutPutFile & chr(34)
msgbox "end"  
else
  msgbox "Error with output path: " & strOutPutFile
end if

Sub ParseATTKReports(boolWriteHeaderRow)
Dim strTmpCompName: strTmpCompName = ""
dim BoolProcessIP: BoolProcessIP = False
Dim BoolProcessDNSc: BoolProcessDNSc = False
DIm BoolProcessBH: BoolProcessBH = False
dim StrTmpLIPaddress: StrTmpLIPaddress = True
Dim DictLIP: set  DictLIP = CreateObject("Scripting.Dictionary")
Dim DictVulnInfo: set DictVulnInfo =  CreateObject("Scripting.Dictionary")
Dim strProgFiles
Dim Bool64bit
Dim BoolUnknownFileFound
BoolUnknownFileFound = False
strProgFiles = ""
DictData.RemoveAll
DictLIP.RemoveAll
DictVulnInfo.RemoveAll
if objFSO.fileexists(strFile) then
  Set objFile = objFSO.OpenTextFile(strFile)
  do while not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine 

        if instr(strData, "Entry Id") then
          strTmpValue = ""
          strTmpKey = GetData(strData, chr(34), chr(34))
        elseif instr(strData, "</Entry>") then
          'msgbox instr(strTmpValue,"<FalsePositive>false</FalsePositive>")
          strTmpWhash = GetData(strTmpValue, "<", "SHA1>")
          if instr(strTmpValue,"<FalsePositive>false</FalsePositive>") then
            strTmpValman = GetData(strTmpValue, "<", "Path>")
            if DictSuspiciousHashes.exists(strTmpWhash) = False and ishash(strTmpWhash) then _
              DictSuspiciousHashes.add strTmpWhash, strTmpValman
            strTmpValman = strTmpValman & "|" & strTmpWhash
            DictData.add strTmpKey, strTmpValman
            if BoolDebugLog = True then LogData currentdirectory & "\ATTK_Debug.log",  strFile & "- " & strTmpKey & "|" & strTmpValman ,False
            strTmpValue = ""
            strTmpKey = ""
          else
            
            if DictWhiteList.exists(strTmpWhash) = False then _
              DictWhiteList.add strTmpWhash, ""
            
          end if
        else
          strTmpValue = strTmpValue &  strData
        end if
    end if
  loop
else
  msgbox "file does not exist: " & strFile
end if

strFile = strFolderPath & "\assessreport.xml"
BoolProcessAutoruns = False
BoolProcessFiles = False
'msgbox "parsing " & strFile
if objFSO.fileexists(strFile) then
  strSSrow = "SHA1|MD5|Path|Version|" & "Publisher|" & "Company|" & "Product|Logical Size|Prevalence|Maturity|Census"
  strTmpSSlout = chr(34) & replace(strSSrow, "|",chr(34) & "," & Chr(34)) & chr(34)
  if boolWriteHeaderRow = True then logdata currentdirectory & "\FileOut.csv", strTmpSSlout, False
  Set objFile = objFSO.OpenTextFile(strFile)
  do while not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine 
        on error goto 0
        if instr(strData, "<ComputerName>") then
          strTmpCompName = GetData(strData,"<", "<ComputerName>")
        elseif instr(strData, "</ComputerName>") Then 'ATTK for Linux
          strTmpCompName = rGetData(strData,">", "</ComputerName>")
        elseif instr(strData, "<Major>") then
          intWinMajor = GetData(strData,"<", "<Major>")
          if isnumeric(intWinMajor) then intWinMajor = int(intWinMajor)
        elseif instr(strData, "<Minor>") then
          intWinMinor = GetData(strData,"<", "<Minor>")
          if isnumeric(intWinMinor) then intWinMinor = int(intWinMinor)
        elseif instr(strData, "<Major>") then
          intWinBuild = GetData(strData,"<", "<Build>")
          if isnumeric(intWinBuild) then intWinBuild = int(intWinBuild)
        elseif instr(strData, "<ProgramFiles>") then
          strProgFiles = GetData(strData,"<", "<ProgramFiles>")
          if lcase(strProgFiles) = "c:\program files (x86)" then 'this is a horrible way to detect 64-bit systems
            Bool64bit = True
          else
            Bool64bit = False
          end if
          if BoolDebugLog = True then LogData currentdirectory & "\ATTK_Debug.log",  strFile & "- " & strTmpCompName & "|" & cstr(intWinMajor) & "." & cstr(intWinMinor) & "." & cstr(intWinBuild) ,False
        elseif instr(strData, "<Files>") then 
          BoolProcessFiles = True
        elseif instr(strData, "</Files>") then 
          BoolProcessFiles = False        
        elseif instr(strData, "<Autoruns>") then
          BoolProcessAutoruns = True
        elseif instr(strData, "</Autoruns>") then
          BoolProcessAutoruns = False   
        elseif instr(strData, "<Processes>") then
          BoolProcessProcs = True
        elseif instr(strData, "</Processes>") then
          BoolProcessProcs = False                  
        elseif instr(strData, "<Ports>") then
          BoolProcessIP = True
        elseif instr(strData, "</Ports>") then
          BoolProcessIP = False
        elseif instr(strData, "<DNSCache>") then
          BoolProcessDNSc = True
        elseif instr(strData, "</DNSCache>") then
          BoolProcessDNSc = False
        elseif instr(strData, "<BrowserHistory>") then
          BoolProcessBH = True
        elseif instr(strData, "</BrowserHistory>") then
          exit do
        end if
        
        if BoolProcessFiles = True then
          if instr(strData, "<File Id=") then 
            strPFileID = getdata(strData, ">", "<File Id=")
          elseif instr(strData, "Path>") then 
            strPFilePath = getdata(strData, "<", "Path>")
          elseif instr(strData, "FileVersionNumber>") then 
            strPFileVer = getdata(strData, "<", "FileVersionNumber>")
          elseif instr(strData, "SHA1>") then 
            strFileHash =  getdata(strData, "<", "SHA1>")
          elseif instr(strData, "MD5>") then 
            strMD5 =  getdata(strData, "<", "MD5>")
          elseif instr(strData, "Signer>") then 
            strSigner =  getdata(strData, "<", "Signer>")
          elseif instr(strData, "CompanyName>") then 
            strCompanyName =  getdata(strData, "<", "CompanyName>")
          elseif instr(strData, "ProductName>") then 
            strProductName =  getdata(strData, "<", "ProductName>")
          elseif instr(strData, "Size>") then 
            strSize =  getdata(strData, "<", "Size>")
         elseif instr(strData, "Prevalence>") then 
            strPrevalence =  getdata(strData, "<", "Prevalence>")         
         elseif instr(strData, "Maturity>") then 
            strMaturity =  getdata(strData, "<", "Maturity>")    
         elseif instr(strData, "CensusScore>") then 
            strCensusScore =  getdata(strData, "<", "CensusScore>")                
          end if
          if strMD5 <> "" then
            if CheckInstalledApps(strPFilePath) <> "" then
              if DictInfoReportOut.exists(strTmpCompName & "|" & strPFilePath) = false then DictInfoReportOut.add strTmpCompName & "|" & strPFilePath,  CheckInstalledApps(strPFilePath)
            end if
            if ParseVulns(strPFilePath, strPFileVer) <> "" then
              if DictData.exists("FID:" & strPFileID) = false then DictData.add "FID:" & strPFileID, strPFilePath & "|" & strFileHash
              if DictVulnInfo.exists("FID:" & strPFileID) = false then DictVulnInfo.add "FID:" & strPFileID, strPFileVer & "|" & ParseVulns(strPFilePath, strPFileVer)
            end if
            if DictWhitelist.exists(strFileHash) = false and DictSuspiciousHashes.exists(strFileHash) = false then
              if DictUnknownFiles.exists(strFileHash) = False and ishash(strFileHash) then
                BoolUnknownFileFound = True
                DictUnknownFiles.add strFileHash,  strPFilePath
                if BoolDebugLog = True then LogData currentdirectory & "\ATTK_Debug.log",  strFile & "- " & strTmpCompName & "|" & strPFilePath  & "|" & strFileHash,False
              end if
            end if
			if DictFpathExample.exists(strFileHash) = false then
				DictFpathExample. add strFileHash,strPFilePath
			end if
			if ishash(strFileHash) = True then
				prevRow = chr(34) & strFileHash & Chr(34) & "," &  Chr(34) & strMD5 & Chr(34) & "," &  chr(34) & "%VariableToReplace1%" & Chr(34) & "," &  Chr(34) & strPFileVer & Chr(34) & "," &  chr(34) & strSigner & Chr(34) & "," & chr(34) & strCompanyName & Chr(34) & "," & chr(34) & strProductName & Chr(34) & "," & chr(34) & strSize & Chr(34)& "," & chr(34) & "%VariableToReplace2%" & Chr(34)& "," & chr(34) & strMaturity & Chr(34)& "," & chr(34) & strCensusScore & Chr(34)
			else
				prevRow = chr(34) & strFileHash & Chr(34) & "," &  Chr(34) & strMD5 & Chr(34) & "," &  chr(34) & strPFilePath & Chr(34) & "," &  Chr(34) & strPFileVer & Chr(34) & "," &  chr(34) & strSigner & Chr(34) & "," & chr(34) & strCompanyName & Chr(34) & "," & chr(34) & strProductName & Chr(34) & "," & chr(34) & strSize & Chr(34)& "," & chr(34) & "%VariableToReplace2%" & Chr(34)& "," & chr(34) & strMaturity & Chr(34)& "," & chr(34) & strCensusScore & Chr(34)
			end if
			if DictPrevalence.exists(prevRow) = False then
				DictPrevalence.add prevRow, 1
			else
				DictPrevalence.item(prevRow) = DictPrevalence.item(prevRow) + 1
			end if 


              strFileHash = ""
              strPFileVer = ""
              strPFilePath = ""
              strPFileID = ""
              strFileHash = ""
              strMD5 = ""
              strSigner = ""
              strCompanyName = ""
              strProductName = ""
              strSize = ""
              strPrevalence = ""
              strMaturity = ""
              strCensusScore = ""
          end if
        elseif BoolProcessProcs = True then
          if instr(strData, "<CommandLine>") then
            if instr(lcase(strData), "c:\windows\system32\tlntsvr.exe") or instr(lcase(strData), "c:\windows\syswow64\tlntsvr.exe") then
              if DictInfoReportOut.exists(strTmpCompName & "|" & "c:\windows\system32\tlntsvr.exe") = false then DictInfoReportOut.add strTmpCompName & "|" & "c:\windows\system32\tlntsvr.exe",  "Telnet server running"
            elseif instr(lcase(strData), "c:\windows\system32\inetsrv\inetinfo.exe") or instr(lcase(strData), "c:\windows\syswow64\inetsrv\inetinfo.exe") then
              if DictInfoReportOut.exists(strTmpCompName & "|" & "c:\windows\system32\inetsrv\inetinfo.exe") = false then DictInfoReportOut.add strTmpCompName & "|" & "c:\windows\system32\inetsrv\inetinfo.exe",  "IIS server running"
            end if
          end if
        elseif BoolProcessIP = True then
          if instr(strData, "<LocalAddress>") then
            StrTmpLIPaddress = Getdata(strData, "<", "<LocalAddress>")
            if StrTmpLIPaddress <> "127.0.0.1" and StrTmpLIPaddress <> "0.0.0.0" then
              if DictLIP.exists(StrTmpLIPaddress) = false then _
              DictLIP.add StrTmpLIPaddress, ""
            end if
          elseif instr(strData, "<LocalPort>") then
            if instr(strData, ">3389<") then 'listening on 3389 RDP
              if DictInfoReportOut.exists(strTmpCompName & "|Port:3389") = false then DictInfoReportOut.add strTmpCompName & "|Port:3389",  "listening on RDP port 3389"
            elseif instr(strData, ">23<") then 'listening on telnet
              if DictInfoReportOut.exists(strTmpCompName & "|Port:23") = false then DictInfoReportOut.add strTmpCompName & "|Port:23",  "listening on Telnet port 23"
            elseif instr(strData, ">21<") then 'listening on FTP
              if DictInfoReportOut.exists(strTmpCompName & "|Port:21") = false then DictInfoReportOut.add strTmpCompName & "|Port:21",  "listening on FTP port 21"
            elseif instr(strData, ">80<") then 'listening on HTTP
              if DictInfoReportOut.exists(strTmpCompName & "|Port:80") = false then DictInfoReportOut.add strTmpCompName & "|Port:80",  "listening on HTTP port 80"
            elseif instr(strData, ">443<") then 'listening on HTTPS
              if DictInfoReportOut.exists(strTmpCompName & "|Port:443") = false then DictInfoReportOut.add strTmpCompName & "|Port:443",  "listening on HTTPS port 443"
            elseif instr(strData, ">25<") then 'listening on SMTP
              if DictInfoReportOut.exists(strTmpCompName & "|Port:25") = false then DictInfoReportOut.add strTmpCompName & "|Port:25",  "listening on SMTP port 25"
            end if
          end if
        
        elseif BoolProcessDNSc = True then
          StrTmpBURL = ""
          if instr(strData, "<DNSCacheEntry") then
            StrTmpBURL = Getdata(strData, "<", ">")
          end if
          if DictDNSCache.exists(StrTmpBURL) = false then
            DictDNSCache.add StrTmpBURL, ""
          end if
        elseif BoolProcessBH = True then
          StrTmpBURL = ""
          if instr(strData, "<URL>") then
            StrTmpBURL = Getdata(strData, "<", "<URL>")
          end if
          if DictBrowserHistory.exists(StrTmpBURL) = false then
            DictBrowserHistory.add StrTmpBURL, ""
          end if
        elseif BoolProcessAutoruns = True then
          if instr(strData, "Autorun Id") then
            strTmpValue = ""
            strTmpLoc = ""
            strTmpValman = ""
            strTmpKey = GetData(strData, chr(34), chr(34))
          end if
          if strTmpKey <> "" then
            if instr(strData, "<Location>") then
              strTmpLoc = GetData(strData, "<", "Location>")
            elseif instr(strData, "<LaunchString>") then
              'msgbox instr(strTmpValue,"<FalsePositive>false</FalsePositive>")
              if instr(strData,"<LaunchString>") then
                if instr(lcase(strData),"javascript") then 'registry malware
                  strTmpValman = GetData(strData, "<", "LaunchString>")
                  strTmpValman = strTmpLoc & "|" & strTmpValman 
                  if strTmpKey <> "" and strTmpValman <> "" then _
                   DictData.add strTmpKey, strTmpValman
                  strTmpValue = ""
                  strTmpKey = ""
                  strTmpValman = ""
                end if
              end if
            end if
          end if
        end if
    end if
  loop
else
  msgbox "file does not exist: " & strFile
end if


StrTmpLIPaddress = ""
for each strIP in DictLIP
  if StrTmpLIPaddress = "" then
    StrTmpLIPaddress = strIP
  else
    StrTmpLIPaddress = StrTmpLIPaddress & " " & strIP
  end if
next

if BoolUnknownFileFound = False then
 if DictUnknownFiles.exists(strTmpCompName & "|" & "") = false then _
  DictUnknownFiles.add strTmpCompName & "|" & "", "No unknown files|" & vbcrlf
end if

if DictData.count = 0 then
  DictReportOut.add strTmpCompName & "||" & "", "No suspicious files|" & StrTmpLIPaddress
else
  for each item in DictData 'Detections
    strVulnOut = ""
    if DictVulnInfo.exists(Item) then strVulnOut = DictVulnInfo.item(Item)
    if DictReportOut.exists(strTmpCompName & "|" & DictData.Item(Item)) = False then _
      DictReportOut.add strTmpCompName & "|" & DictData.Item(Item), Item & "|" & StrTmpLIPaddress & "|" & strVulnOut
  next
end if
End sub


Function ParseVulns(strVulnPath, StrVulnVersion)
Dim StrVersionCompare
Dim ArrayVulnVer
if instr(lcase(strVulnPath), "c:\windows\syswow64\macromed\flash\") or instr(lcase(strVulnPath), "c:\windows\system32\macromed\flash\")then
  if instr(lcase(strVulnPath), ".ocx") or instr(lcase(strVulnPath), ".dll") then
    'check version number
    if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, strFlashVersion) then
      ParseVulns = "up to date flash player detected"
    else 'out of date
      if isnumeric(left(StrVulnVersion, 2)) then
        if cint(left(StrVulnVersion, 2)) < 18 then 
          ParseVulns = "unsupported and outdated flash player version detected"
        elseif cint(left(StrVulnVersion, 2)) = 18 then 
          ParseVulns = "outdated extended release flash player version detected"
        elseif cint(left(StrVulnVersion, 2)) < 21 then 
          ParseVulns = "unsupported and outdated flash player version detected"
        else
          ParseVulns = "outdated flash player version detected"
        end if
      else
        ParseVulns = "outdated flash player version detected"
      end if
    end if
  end if
elseif instr(lcase(strVulnPath), "c:\windows\syswow64\mshtml.dll") or instr(lcase(strVulnPath), "c:\windows\system32\mshtml.dll") then
if instr(strVulnVersion, ".") then
  ArrayVulnVer = split(strVulnVersion, ".")
  if ubound(ArrayVulnVer) > 2 then
    select case ArrayVulnVer(0)
      Case "6"
      StrVersionCompare = "6.0.3790.5662"
      Case "7"
         if ArrayVulnVer(2) = "6000" then
            StrVersionCompare = "7.0.6000.21481"
        elseif instr(strVulnVersion, "7.0.6002.1") then
          StrVersionCompare = "7.0.6002.19421"
        else
          StrVersionCompare = "7.0.6002.23728"
        end if
      Case "8"
        if ArrayVulnVer(2) = "6001" then
          if instr(strVulnVersion, "8.0.6001.2") then
            StrVersionCompare = "8.0.6001.23707"
          else
            StrVersionCompare = "8.0.6001.19652"
          end if
        else
          if instr(strVulnVersion, "8.0.7601.1") then
            StrVersionCompare = "8.0.7601.18896"
          else
            StrVersionCompare = "8.0.7601.23099"
          end if
        end if
      Case "9"
        if instr(strVulnVersion, "9.0.8112.1") then
          StrVersionCompare = "9.0.8112.16669"
        else
          StrVersionCompare = "9.0.8112.20784"
        end if
      Case "10"
        if instr(strVulnVersion, "10.0.9200.1") then
          StrVersionCompare = "10.0.9200.17412"
        else
          StrVersionCompare = "10.0.9200.21523"
        end if
      Case "11"
        if Bool64bit = False then '32-bit version
          StrVersionCompare = "11.0.9600.17905" 'x86
        else
          StrVersionCompare = "11.0.9600.17915" 'x64
        end if
    end select

    if intWinMajor = 5 then
      if intWinMinor = 2 or intWinMinor = 1 then 'windows XP/2003
        ParseVulns = "Unsupported OS Windows XP/2003"
      elseif intWinMinor = 0 then
        ParseVulns = "Unsupported OS Windows 2000"
      end if
    elseif StrVersionCompare <> "" then
      if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
        ParseVulns = "MS15-065 KB3065822 applied"
      else
        ParseVulns = "MS15-065 KB3065822 not applied"
      end if
    end if
  end if
end if
elseif instr(lcase(strVulnPath), "c:\windows\syswow64\lpk.dll") or instr(lcase(strVulnPath), "c:\windows\system32\lpk.dll") then
  'atm*.dll does not show in ATTK results 
  'so suplimented with lpk.dll which isn't a good indication of being patched for MS15-078 
  'but can indicate a vulnerable system if really outdated
  if intWinMajor = 6 then 
    if intWinMinor = 0 then 
    '6.0.6002.23749 Windows Vista and Windows Server 2008
      if instr(StrVulnVersion, "6.0.6002.1") then
        if Bool64bit = False then '32-bit version
          StrVersionCompare = "6.0.6002.18051"
        else'64bit version
          StrVersionCompare = "6.0.6002.18005"
        end if
      elseif  instr(StrVulnVersion, "6.0.6001.1") then
        StrVersionCompare = "6.0.6001.18000"
      else
        StrVersionCompare = "6.0.6002.23749"
      end if
    
    elseif intWinMinor = 1 then 
      '6.1.7601.23126 Windows 7 and Windows Server 2008 R2
      if instr(StrVulnVersion, "6.1.7601.2") then
        StrVersionCompare = "6.1.7601.23126"
      else
        StrVersionCompare = "6.1.7601.18923"
      end if
    elseif intWinMinor = 2 then 
      '6.2.9200.16384 Windows 8 and Windows Server 2012
      StrVersionCompare = "6.2.9200.16384"
    elseif intWinMinor = 3 then 
      '6.3.9600.17415 Windows 8.1 and Windows Server 2012 R2
      StrVersionCompare = "6.3.9600.17415"
    end if
    
    
    if instr(strVulnVersion, "6.1.7600.") then
      ParseVulns = "Unsupported OS. Missing Windows 7 SP1"
    elseif StrVersionCompare <> "" then
      if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
            'System may still be vulnerable so don't return anything
            'ParseVulns = "MS15-078 KB3079904 applied"
      else
        ParseVulns = "MS15-078 KB3079904 not applied"
      end if
    end if
  end if
elseif instr(lcase(strVulnPath), "c:\windows\syswow64\netapi32.dll") or instr(lcase(strVulnPath), "c:\windows\system32\netapi32.dll")then

  if intWinMajor = 5 then
    if intWinMinor = 0 then 'windows 2000
      StrVersionCompare = "5.0.2195.7203"

    elseif intWinMinor = 1 Then
      if instr(StrVulnVersion, "5.1.2600.3") then
        StrVersionCompare = "5.1.2600.3462"
      else
        StrVersionCompare = "5.1.2600.5694"
      end if
    elseif intWinBuild = 2 then 'windows XP/2003
       if instr(StrVulnVersion, "5.2.3790.3") then
          StrVersionCompare = "5.2.3790.3229"
       else
          StrVersionCompare = "5.2.3790.4392"
       end if
    end if
  elseif  intWinMajor = 6 then 
    if intWinMinor = 0 then 'windows vista/2008
      if intWinBuild = 6000 then 'sp0
       if instr(StrVulnVersion, "6.0.6000.16") then
          StrVersionCompare = "6.0.6000.16764"
       else
          StrVersionCompare = "6.0.6000.20937"
       end if      
      elseif intWinBuild = 6001 then 'sp0
       if instr(StrVulnVersion, "6.0.6000.18") then
          StrVersionCompare = "6.0.6001.18157"
       else
          StrVersionCompare = "6.0.6001.18157"
       end if      
      end if
    end if
  end if
  if StrVersionCompare <> "" then
    if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      ParseVulns = "MS08-067 applied"
    else
      ParseVulns = "MS08-067 not installed"
    end if
  end if
elseif instr(lcase(strVulnPath), "c:\program files (x86)\microsoft silverlight\") and _
instr(lcase(strVulnPath), "\silverlight.configuration.exe") then
  StrVersionCompare = "5.1.41212.0"
    if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      ParseVulns = "Silverlight patched with MS16-006 critical bulletin"
    else
      ParseVulns = "Silverlight flaw, identified as CVE-2016-0034, patched under MS16-006 critical bulletin is missing"
    end if
elseif instr(lcase(strVulnPath), "c:\program files\internet explorer\iexplore.exe") then
StrVersionCompare = "11"
    if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      'ParseVulns = "IE on a supported version"
    else
      ParseVulns = "Internet Explorer (IE) is at a version that does not receive publicly released security updates. IE version 11 is the only version still recieving updates."
    end if
end if
end function

Function CheckInstalledApps(strAVFilePath)
Dim StrCIAreturn
strAVFilePath = lcase(strAVFilePath)
if instr(strAVFilePath, chr(34)) then strAVFilePath = replace(strAVFilePath, chr(34),"")
if lcase(strAVFilePath) = "c:\program files (x86)\symantec\symantec endpoint protection\12.1.6608.6300.105\Bin\ccsvchst.exe" or lcase(strAVFilePath) = "c:\program files\symantec\symantec endpoint protection\12.1.6608.6300.105\bin\ccsvchst.exe" then
  StrCIAreturn = "Symantec Antimalware"
elseif lcase(strAVFilePath) = "c:\program files\microsoft security client\msmpeng.exe" or lcase(strAVFilePath) = "c:\program files\microsoft security client\antimalware\msmpeng.exe" then
  StrCIAreturn = "Microsoft Antimalware"
elseif lcase(strAVFilePath) = "c:\program files\eset\eset file security\x86\ekrn.exe" or strAVFilePath = "c:\program files\eset\eset endpoint antivirus\x86\ekrn.exe" or _
strAVFilePath = "c:\program files\eset\eset nod32 antivirus\x86\ekrn.exe" then
  StrCIAreturn = "ESET Antimalware"    
elseif lcase(strAVFilePath) = "c:\program files (x86)\google\chrome\application\chrome.exe" then
  StrCIAreturn = "Google Chrome"
elseif lcase(strAVFilePath) = "c:\windows\ccm\ccmexec.exe" or lcase(strAVFilePath) = "c:\windows\syswow64\ccm\ccmexec.exe" then
  StrCIAreturn = "System Center Configuration Manager"
elseif lcase(strAVFilePath) = "c:\program files (x86)\trend micro\officescan client\ntrtscan.exe" then
  StrCIAreturn = "Trend Micro Anti-virus"
elseif instr(lcase(strAVFilePath), "c:\program files\sourcefire\fireamp\") <> 0 and instr(lcase(strAVFilePath), "\sfc.exe") <> 0 Then
  StrCIAreturn = "FireAMP"
elseif lcase(strAVFilePath) = "c:\program files\palo alto networks\globalprotect\pangps.exe"  then
  StrCIAreturn = "Palo Alto Networks GlobalProtect"
end if
CheckInstalledApps = StrCIAreturn

end function

Function GetData(contents, ByVal EndOfStringChar, ByVal MatchString)
MatchStringLength = Len(MatchString)
x= 0

do while x < len(contents) - (MatchStringLength +1)

  x = x + 1
  if Mid(contents, x, MatchStringLength) = MatchString then
    'Gets server name for section
    for y = 1 to len(contents) -x
      if instr(Mid(contents, x + MatchStringLength, y),EndOfStringChar) = 0 then
          TempData = Mid(contents, x + MatchStringLength, y)
        else
          exit do  
      end if
    next
  end if
loop
GetData = TempData
end Function


function LogData(TextFileName, TextToWrite,EchoOn)
Set fsoLogData = CreateObject("Scripting.FileSystemObject")
if EchoOn = True then wscript.echo TextToWrite
  If fsoLogData.fileexists(TextFileName) = False Then
      'Creates a replacement text file 
      on error resume next
      fsoLogData.CreateTextFile TextFileName, True
      if err.number <> 0 and err.number <> 53 then msgbox err.number & " " & err.description & vbcrlf & TextFileName
      on error goto 0
  End If
if TextFileName <> "" then


  Set WriteTextFile = fsoLogData.OpenTextFile(TextFileName,ForAppending, False)
  on error resume next
  WriteTextFile.WriteLine TextToWrite
  WriteTextFile.Close
  if err.number <> 0 then 
    on error goto 0
    
  Dim objStream
  Set objStream = CreateObject("ADODB.Stream")
  objStream.CharSet = "utf-16"
  objStream.Open
  objStream.WriteText TextToWrite
  on error resume next
  objStream.SaveToFile TextFileName, 2
  if err.number <> 0 then msgbox err.number & " - " & err.message & " Problem writting to " & TextFileName
  if err.number <> 0 then msgbox "problem writting text: " & TextToWrite
  on error goto 0
  Set objStream = nothing
  end if
end if
Set fsoLogData = Nothing
End Function



Function GetFilePath (ByVal FilePathName)
found = False

Z = 1

Do While found = False and Z < Len((FilePathName))

 Z = Z + 1

         If InStr(Right((FilePathName), Z), "\") <> 0 And found = False Then
          mytempdata = Left(FilePathName, Len(FilePathName) - Z)
          
             GetFilePath = mytempdata

             found = True

        End If      

Loop

end Function


function fnShellBrowseForFolderVB()
    dim objShell
    dim ssfWINDOWS
    dim objFolder
    
    ssfWINDOWS = 36
    set objShell = CreateObject("shell.application")
        set objFolder = objShell.BrowseForFolder(0, "Example", 0, ssfDRIVES)
            if (not objFolder is nothing) then
               set oFolderItem = objFolder.items.item
               fnShellBrowseForFolderVB = oFolderItem.Path 
            end if
        set objFolder = nothing
    set objShell = nothing
end function

Function FirstVersionSupOrEqualToSecondVersion(strFirstVersion, strSecondVersion)
	
	Dim arrFirstVersion,  arrSecondVersion, i, iStop, iMax
	Dim iFirstArraySize, iSecondArraySize
	Dim blnArraySameSize : blnArraySameSize = False
	
	If strFirstVersion = strSecondVersion Then
		FirstVersionSupOrEqualToSecondVersion = True
		Exit Function
	End If
	
	If strFirstVersion = "" Then
		FirstVersionSupOrEqualToSecondVersion = False
		Exit Function
	End If
	If strSecondVersion = "" Then
		FirstVersionSupOrEqualToSecondVersion = True
		Exit Function
	End If

	arrFirstVersion = Split(strFirstVersion, "." )
	arrSecondVersion = Split(strSecondVersion, "." )
	iFirstArraySize = UBound(arrFirstVersion)
	iSecondArraySize = UBound(arrSecondVersion)
	
	If iFirstArraySize = iSecondArraySize Then
		blnArraySameSize = True
		iStop = iFirstArraySize
		For i=0 To iStop
			'msgbox "arrFirstVersion=" & arrFirstVersion(i) & vbcrlf & "arrSecondVersion=" & arrSecondVersion(i)
			If clng(arrFirstVersion(i)) < clng(arrSecondVersion(i)) Then
				FirstVersionSupOrEqualToSecondVersion = False
				Exit Function
			elseif clng(arrFirstVersion(i)) > clng(arrSecondVersion(i)) then
				FirstVersionSupOrEqualToSecondVersion = True
				Exit Function			
			End If
		Next
		FirstVersionSupOrEqualToSecondVersion = True
	Else
		If iFirstArraySize > iSecondArraySize Then
			iStop = iSecondArraySize
		Else
			iStop = iFirstArraySize
		End If
		For i=0 To iStop
			If clng(arrFirstVersion(i)) < clng(arrSecondVersion(i)) Then
				FirstVersionSupOrEqualToSecondVersion = False
				Exit Function
			End If
		Next
		If iFirstArraySize > iSecondArraySize Then
			FirstVersionSupOrEqualToSecondVersion = True
			Exit Function
		Else
			For i=iStop+1 To iSecondArraySize
				If clng(arrSecondVersion(i)) > 0 Then
					FirstVersionSupOrEqualToSecondVersion = False
					Exit Function
				End If
			Next
			FirstVersionSupOrEqualToSecondVersion = True
		End If
	End If
End Function



Function IsHash(TestString)

    Dim sTemp
    Dim iLen
    Dim iCtr
    Dim sChar
    
    'returns true if all characters in a string are alphabetical
    '   or numeric
    'returns false otherwise or for empty string
    
    sTemp = TestString
    iLen = Len(sTemp)
    If iLen > 0 Then
        For iCtr = 1 To iLen
            sChar = Mid(sTemp, iCtr, 1)
            if isnumeric(sChar) or "a"= lcase(sChar) or "b"= lcase(sChar) or "c"= lcase(sChar) or "d"= lcase(sChar) or "e"= lcase(sChar) or "f"= lcase(sChar)  then
              'allowed characters for hash (hex)
            else
              IsHash = False
              exit function
            end if
        Next
    
    IsHash = True
    End If
    
End Function

Function rGetData(contents, ByVal EndOfStringChar, ByVal MatchString)
MatchStringLength = Len(MatchString)
x= instrRev(contents, MatchString) -1
  if X >0 then
    if instrRev(left(contents, x),EndOfStringChar) > 0 then
      rGetData = Mid(contents, instrRev(left(contents, x),EndOfStringChar) +len(EndOfStringChar),x - instrRev(left(contents, x),EndOfStringChar) -len(EndOfStringChar) +1)
      exit function
    else
      rGetData = left(contents,x)
      'msgbox "failed match:" & left(contents,x -1)
      exit function
    end if
    
  end if
rGetData = ""
end Function