# Network Security

## Anonymity

### Anonymity - Study Guide

(04/08) *Transparent testing*: ensure to supply your testing IPs (no need to hide) to the customer, so you do not become inadvertently blocked during testing.
(05/08) *Dark testing*: to use when the customer want also to test their security staff and security products, processes, procedures, reporting (acting as a true hacker would). So, you will provide to the customer also a security response review.

### Browsing Anonymously - Study Guide

(02/40) Keep in mind that anytime you send traffic through another company computer to hide yourself, you are exposing all data to that company as it can sniff the data. So, do not use system that you do not own.

(03/40) Using *proxies* is basically asking another system to do something on your behalf. The most common types of proxies are HTTP and SOCKS ones. 
Note that we always need to know the protocols that the proxy handles.

In some instances, proxy servers can be chained in order to provide further obfuscation of the original IP address.

(17/40) *High anonymous (elite) proxies*: the user real IP is hidden and there is no indication to the web server that the request is coming from a proxy, they do not change the request fields.
*Anonymous proxies*: the user real IP is hidden, but they do change the request fields (as result, by analyzing the web log, it is possible to detect that a proxy server is used). Note that some server administators do restrict proxy requests.
*Transparent proxies* (a.k.a. HTTP relay proxies): these proxies offer no security and should therefore never be used for security testing, since they do not even hide the user real IP address.

Many times, these proxy servers can be misconfigured web servers that enabled the proxy services.

(22/40) There are online tools to check that your anonymity is protected: www.pentest-tools.com/home, www.tools-on.net, www.all-nettools.com.

(26/40) In HTTP client server communications there are some request fields usable for correctly identifying some information about the client.
A simple pass-through or cache proxy communication/High anonymous (elite) proxy communication:
```
REMOTE_ADDR = 94.89.100.1
HTTP_ACCEPT_LANGUAGE = en
HTTP_USER_AGENT = Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)
HTTP_HOST = www.elearnsecurity.com
HTTP_VIA = 94.89.100.1 (Squid/2.4.STABLE7)/not determined
HTTP_X_FORWARDED_FOR = 98.10.50.155/not determined
```

`HTTP_VIA`: if this field contains an IP address (or many, in case of chained servers), it indicates that there is a proxy server being used.
`HTTP_X_FORWARDED_FOR`: if this field contains an address, it indicates the actual IP address of the client that the proxy is acting on behalf of.
`REMOTE_ADDR`: can be actually the address of the proxy system or not.
By analyzing either web site logs or traffic sniffing files, an administrator can easily find the proxy addresses.

(34/40) *TOR network* protects you by bouncing the communications around a distributed network of relays run by volunteers all around the world. The client requests a (randomly selected) list of TOR nodes to construct the communication path. Note that the list of nodes changes for each request and the traffic is encrypted between each relays couple.
Remember that "TOR only works fot TCP streams and can be used by any application with SOCKS support". Many tools that you may use during a penetration test, allow you to use the TOR features.

### Tunneling for Anonymity - Study Guide

(02/14) The most effective way to achieve anonymity is to protect your traffic using a proxy (tunneling) with secure protocols and encryption such as *SSH* and *IPSEC VPNs*.
(05/14) *SSH local port forwarding* (SSH tunneling): to forward a local port on your computer in order to left the traffic pass through an encrypted SSH connection between a client and a server creating a tunnel (usually when we are dealing with an untrusted network, like Internet).
`ssh -L <LocalPort>:<RemoteIP/Hostname>:<RemotePort> <Username>@<SSHServerIP/DomainName>` (e.g. `ssh -L 3000:homepc:23 root@sshserver.com`): to run the SSH tunnel.
Once the tunnel is up and running, we can establish the real connection with the remote machine (e.g. `telnet 127.0.0.1:3000`): the traffic will automatically go through the SSH tunnel.

---
