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

