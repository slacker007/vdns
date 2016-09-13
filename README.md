# VDNS - BSIDES AUGUSTA 2016
VDNS is a python application that was written as one of the MHF Modules.  It parses Bro's dns.log file and injests the results into the neo4j database on Mercenary-Linux.  This module requires that bro is installed on the system.  

***Example:***
```
Mercenary@Mercenary-Linux$ python vdns.py --help
Usage: vdns.py [options]

Options:
  -h, --help         show this help message and exit
  --logfile=LOGFILE  Logfile to read from.  Default: none

Mercenary@Mercenary-Linux$ python vdns.py --logfile dns.log
Enter IP of neo4j DB or press [ENTER] for localhost: 192.168.237.134
Enter neo4j DB username or press [ENTER] for neo4j:
Enter neo4j password:
[+] Creating Labels...
[+] 1 DNS Log Entries Injested
[+] 2 DNS Log Entries Injested
[+] 3 DNS Log Entries Injested
[+] 4 DNS Log Entries Injested
[+] 5 DNS Log Entries Injested
[+] 6 DNS Log Entries Injested
[+] 7 DNS Log Entries Injested
[+] 8 DNS Log Entries Injested
[+] 9 DNS Log Entries Injested
[+] 10 DNS Log Entries Injested
[+] 11 DNS Log Entries Injested
[+] 12 DNS Log Entries Injested
[+] 13 DNS Log Entries Injested
[+] 14 DNS Log Entries Injested
```
![VNDS Screenshot 1](/images/Capture1.PNG)
![VNDS Screenshot 2](/images/Capture2.PNG)
![VNDS Screenshot 3](/images/Capture3.PNG)
