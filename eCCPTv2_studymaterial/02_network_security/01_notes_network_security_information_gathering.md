# Network Security 

## Information Gathering

### Information Gathering Introduction - Study Guide

(07/15) Information about the target:
Business: networks maps, IP addresses, ports, services, DNS, systems, alive machines, OSes.
Infrastructure: domains, physical locations, employees/departments, emails, partners/third parties, job postings, financial information, documents.

(12/15) Collect and record information: use a mind mapping tool.

### Search Engines - Study Guide

(10/71) Extract information from the company name using search engines like Google (and its dorks).
(21/71) Use DUNS and CAGE/NCAGE codes to retrieve more information.
(26/71) Extract financial information/documents about a company using EDGAR search tools. 
(29/71) Information Gathering is a cyclical process.
(32/71) Extract companies info about mergers/acquisitions/partnerships/third parties (and so technology stacks) surfing the websites.
(38/71) Extract companies info about internal hierarchies/projects (and so techonology implementations).
(41/71) Use websites like LinkedIn and Indeed to find job posts/boards.
(44/71) Extract financial/investors information using CrunchBase.
(46/71) Extract other useful info using websites like Inc, Google/Yahoo finance.
(51/71) Gather companies documents into the Harvesting phase, using Google dorks or FOCA automated tool.
(56/71) Gather companies domains/hostnames/usernames/emails into the Harvesting phase, using theHarvester tool through different search engines and social networks: `theharvester -d elsfoo.com -b google -l 100`.
(62/71) Gather companies lost (but cached) information using archive.org or Google dork `cache:elsfoo.com`.

### Social Media - Study Guide

(02/32) Use social networks to get employee's personal information like addresses, phone numbers, CV.
(08/32) Use LinkedIn's advanced search.
(13/32) Use Google dork: `site:linkedin.com`.
(15/32) Start building a network of people.
(17/32) Infer level of relationship between two people through Facebook, Twitter and LinkedIn.
(19/32) Retrieve more information about individuals using pipl/spokeo/peoplefinders tools.
(27/32) Retrieve more information about individuals using Usenet discussion forums.

### Infrastructures - Study Guide

(09/80) Retrieve website information like the owner, name servers and IP addresses through WHOIS.
(19/80) Domain Name System (DNS) is a distributed database hierarchically organized, it binds an IP address to a hostname.
(20/80) DNS servers contain textual records (database entries).
(26/80) More common DNS records:
NS: Indicates the authoritative DNS servers (who provide DNS resolution) for a domain.
A: Associates a domain with an IP address.
PTR: Associates an IP address with a domain (used in reverse resolutions).
CNAME: Defines an alias for a domain.
MX: Specifies the email servers responsible for receiving emails for the domain.
(31/80) Resolve IP address to the corresponding hostname using DNS lookup: `nslookup elsfoo.com`.
(33/80) Resolve hostname to the corresponding IP address using Reverse DNS lookup: `nslookup -type=PTR 192.X.Y.Z` or `nslookup -query=PTR 192.X.Y.Z`.
(34/80) Retrieve email servers responsible for a domain using MX DNS lookup: `nslookup -type=MX elsfoo.com`.
(35/80) The AXFR queries aim to update DNS records of a specific DNS zone requested from a main DNS server to a slave DNS. This operation is called zone transfer. When not properly configured, zone transfers represent a security risk, indeed they should be enabled only for trusted IP addresses.
When enabled, AXFR queries can used to enumerate the entire DNS records for that zone.
(40/80) Issue a zone transfer request using a more powerful tool named dig: `dig AXFR elsfoo.com @dns_server_IP/dns_server_name` (`+short` is optional, returns minimal output).
(46/80) It is possible that more than one domain is configured on the same IP address.
(48/80) Retrieve all websites (subdomains) hosted on the same IP address using Bing search query: `ip:192.X.Y.Z`.
(55/80) An Autonomous System (AS) is made of one or more netblocks under the same administrative control.
(63/80) Identify alive hosts using an ICMP ping sweep through nmap: `nmap -sn 10.0.0.0/24`.
(68/80) Nowdays though, ICMP is often disabled on perimeter routers/firewalls and even on Windows client.
(73/80) Find DNS servers in place in a given netblocks using nmap: `nmap -sS -p 53 10.0.0.0/24` (TCP 53 port) or `nmap -sU -p 53 10.0.0.0/24` (UDP 53 port).

### Whois Lookup - Video

Using the whois tools we can obtain domain information about a target except the domain IP address.
Some information may not belong to the owner or target company, but to the registrar company.
We can use `-h` option to instruct the whois tool to use a different whois server: `whois -h whois.godaddy.com elsfoo.com`.

### Information Gathering DNS - Video

Dig is a generic tool to query DNS servers.
`dig elsfoo.com A`.
`dig A -nocmd -noall -answer lsfoo.com`:
`-nocmd`: cuts off the header section;
`-noall`: hides all the other sections except the interested one;
`-answer`: limits the output to just the answer section.
Zone transfer attack targets misconfigured DNS server by requested a copy of the zone records (DNS database): `dig AXFR -nocmd -noall -answer lsfoo.com @lsfoo.com`.

Fierce is a DNS subdomains enumeration tool.
`fierce -dns elsfoo.com`: requests DNS servers, then automatically attempts to obtain the zone records and if it fails it performs a brute force of subdomains, moreover it scans the found IP spaces.
`fierce -dns els-dns.site -dnsserver ns1.els-dns.site` to specify the DNS server we want to use.

DNSEnum is another tool that tries to do the same of Fierce.
`dnsenum elsfoo.com` it automatically looks for A records and mail servers.
`dnsenum elsfoo.com -dnsserver ns1.els-dns.site` to specify the DNS server we want to use.
Sometimes servers use the name DNS for their internet and for external sites. If we have luck and find one of these sites, switching to their DNS servers will allow us to scan their whole internet.

DNSMap is a tool to perform fast DNS subdomains enumeration.
`dnsmap elsfoo.com`.

DNSRecon is one of the most powerful tools for DNS subdomains enumeration. It combines most of the DNS tools (an all-in-one tool).

DNSSEC (Domain Name System Security Extensions) is a set of extensions to permit DNS to work in a more secure way.
SRV (service) records add flexibility to DNS: allows associating a service with a domain name and providing details about the configuration and location of the service within the network.
Bind is one of the most used DNS software on the Internet (look for attacks against a specific version).

`dnsrecon -d elsfoo.com` permits also to investigate if DNSSEC is used and to enumerate the SRV records.

### Host Discovery with Fping Hping Nmap - Video

The following tools are useful for host discovering.

Fping:
`fping -a 192.X.Y.Z` to discover alive hosts.
`fping -A 192.X.Y.Z` to output only alive hosts.
`fping -A 192.X.Y.Z -r 0` to specify the number of retries.
`fping -A 192.X.Y.Z -e` to show the time of a round.
`fping -a -g 192.X.Y.0/24 -e -r 0 -q`: `-q` is to be quite, so to show only alive hosts.

Hping:
`sudo hping3 -1 192.X.Y.Z`: `-1` is for ICMP ping.
`sudo hping3 -2 192.X.Y.Z`: `-2` is for UDP ping instead.
`sudo hping3 -S 192.X.Y.Z` for sending a TCP SYN ping.
`sudo hping3 -U 192.X.Y.Z` for sending a TCP URG ping.
`sudo hping3 -S 192.X.Y.Z -p 80` to specify a destination port.
`sudo hping3 -1 192.X.Y.x -rand-dest -I eth2`: the `x` will be replaced with random numbers between 0 and 255, `-I eth2` is to set the interface to be used.

Nmap:
`sudo nmap -sn 192.X.Y.Z`: no-port (ping) scan.
If the destination machine is in the same network of the source, nmap uses ARP requests because they are faster.
To avoid this behavior: `sudo nmap -sn 192.X.Y.Z --disable-arp-ping`.
`-P` indeed is used to specify the protocol to be used:
`sudo nmap -sn 192.X.Y.Z --disable-arp-ping -PS` for sending a TCP SYN ping;
`sudo nmap -sn 192.X.Y.Z --disable-arp-ping -PA` for sending a TCP ACK ping;
`sudo nmap -sn 192.X.Y.Z --disable-arp-ping -PU` specifies the UDP protocol;
`sudo nmap -sn 192.X.Y.Z --disable-arp-ping -PU53` to specify a destination port.

### Maltego - Video

Maltego is a powerful tool that uses machines and transforms to simplify the process of collecting, analyzing, and visualizing information.

Machines: visualizations that represent different views of data. Each machine focuses on a specific aspect or set of relationships among entities in the gathered information.
Transforms: functionalities that perform data queries and retrieve information from various data sources. They act as connectors between entities and are responsible for fetching additional details or relationships related to the selected entities.

### Tools - Study Guide

(04/23) DNSdumpster is a web GUI (not-intrusive) tool to discover hosts related to a specific domain gather information about DNS records.
(07/23) DNSEnum is a CLI (not-intrusive) tool to discover hosts related to a specific domain gather information about DNS records. It permits to (recursively) brute force DNS servers and subdomains names using wordlists.
`dnsenum --subfile ./output/subdomains.txt -f /usr/share/dnsenum/dns.txt -u a elsfoo.com -r -v`:
`--subfile ./output/subdomains.txt`: store subdomains in an output file;
`-f /usr/share/dnsenum/dns.txt`: brute force using a wordlist;
`-u a`: update all files that may already exist;
`-r`: perform a recursive brute force on any discoverd domain.

### Foca Shodan - Video

Foca is a very powerful Windows tool to fingerprint applications, by which we can use search engines to find interesting files on a target website, and much more.
Then we can extract and analyze the files metadata: author, creation date and software used.

Shodan is a web GUI tool by which we can gather information about internet devices such as servers, routers, printers, webcams and more.

### Information Gathering - Lab

This exercise will help you understand how to perform DNS enumeration and find misconfiguration flaws using various tools.

In this lab environment, the user will access a Kali GUI instance.

The target server, as described below, is running a DNS server. DNS zone transfer is enabled on the server. DNS Server `witrap.com`

Your Kali has an interface with IP address 192.X.Y.Z. Run "IP addr" to know the values of X and Y.

Do not attack the gateway located at IP address 192.X.Y.1

Note: Please make sure to specify the target DNS server (192.X.Y.3) while making the DNS queries/requests. This server is NOT configured in the attacker machine. Hence, we need to specify it explicitly.

Objective: Enumerate the DNS server and answer the five given questions.

Questions:
1. How many A Records are present for witrap.com and its subdomains?
2. What is the machine's IP address that supports LDAP over TCP on witrap.com?
3. Can you find the secret flag in the TXT record of a subdomain of witrap.com?
4. What is the subdomain for which only reverse DNS entry exists for witrap.com? witrap owns the IP address range: 192.168..
5. How many records are present in the reverse zone for witrap.com (excluding SOA)? witrap owns the IP address range: 192.168..

The best tools for this lab are:
- Nmap
- dig
- nslookup

---

1. How many A Records are present for witrap.com and its subdomains? {9}

`ip addr | grep "inet"`.

`sudo nmap -sSU -p 53 --open 192.27.108.0/24`:
`-sSU`: scans for both TCP/UDP;
`-p 53`: scans ports 53 only;
`--open`: only shows hosts with open specified ports.

`dig AXFR -nocmd -noall -answer witrap.com @192.27.108.3`

2. What is the machine's IP address that supports LDAP over TCP on witrap.com? {192.27.108.8}

`dig AXFR -nocmd -noall -answer witrap.com @192.27.108.3`

3. Can you find the secret flag in the TXT record of a subdomain of witrap.com? {my_s3cr3t_fl4g}

`dig AXFR -nocmd -noall -answer witrap.com @192.27.108.3`

4. What is the subdomain for which only reverse DNS entry exists for witrap.com? witrap owns the IP address range: 192.168.. {100.60.168.192.in-addr.arpa. 86400 IN   PTR     free.witrap.com.
14.60.168.192.in-addr.arpa. 86400 IN    PTR     primary.witrap.com.
5.60.168.192.in-addr.arpa. 86400 IN     PTR     witrap.com.168.192.in-addr.arpa.
35.61.168.192.in-addr.arpa. 86400 IN    PTR     th3s3cr3tflag.witrap.com.
111.62.168.192.in-addr.arpa. 86400 IN   PTR     ldap.witrap.com.
118.62.168.192.in-addr.arpa. 86400 IN   PTR     temp.witrap.com.
81.62.168.192.in-addr.arpa. 86400 IN    PTR     reserved.witrap.com.
110.65.168.192.in-addr.arpa. 86400 IN   PTR     mx.witrap.com.
150.65.168.192.in-addr.arpa. 86400 IN   PTR     mx2.witrap.com.
15.66.168.192.in-addr.arpa. 86400 IN    PTR     secondary.witrap.com.}

`dig AXFR witrap.com 168.192.in-addr.arpa @192.27.108.3`

5. How many records are present in the reverse zone for witrap.com (excluding SOA)? witrap owns the IP address range: 192.168.. {12}

`dig AXFR -x witrap.com 192.168 @192.27.108.3`

---
---
