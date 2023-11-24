# Tools

## nmap [https://nmap.org/](https://nmap.org/)

### Port scanning [https://nmap.org/book/man-port-scanning-basics.html](https://nmap.org/book/man-port-scanning-basics.html)

`nmap -sS 172.27.0.0/20` Scan subnet for hosts

`nmap -sV 192.168.86.150` Look for open ports on host

## netstat (Windows) [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat)

`netstat -ab` Look for listening / established connections

## hping [https://www.kali.org/tools/hping3/](https://www.kali.org/tools/hping3/)

For blocked ICMP can use traceroute.

## nslookup [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup)

`nslookup www.google.com` Lookup domain information

## tcpdump [https://www.tcpdump.org/manpages/tcpdump.1.html](https://www.tcpdump.org/manpages/tcpdump.1.html)

`tcpdump -i eth0 "src host 10.1.0.100 and (dst port 53 or dst port 80)"` Sniff packets on eth0 interface with filter

## Wireshark [https://www.wireshark.org/](https://www.wireshark.org/)

Packet capture analysis

## ettercap [https://www.ettercap-project.org/](https://www.ettercap-project.org/)

Packet injection / man in the middle attacks

## tcpreplay [https://linux.die.net/man/1/tcpreplay](https://linux.die.net/man/1/tcpreplay)

Replay TCP from pcap
