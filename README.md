# BAMF (Backdoor Access Machine Farmer)
[![license](https://img.shields.io/badge/license-GNU-brightgreen.svg)]
[![version](https://img.shields.io/badge/version-0.1.2-lightgrey.svg)]

__DISCLAIMER__: This project should be used for authorized testing and educational purposes only.

BAMF is an open-source tool designed to leverage Shodan (a search engine for the Internet of Things) 
to discover vulnerable routers, then utilize detected backdoors/vulnerabilities to remotely access 
the router administration panel and modify the DNS server settings, changing it to an attacker controlled 
server in order to hijack the domain name resolution process and target every device on the network
with drive-by downloads, malicious redirects, etc.

Currently the only vulnerability detected and exploited is [CVE-2013-6026](https://nvd.nist.gov/vuln/detail/CVE-2013-6026), commonly known as *Joel's Backdoor*,
a severe vulnerability allowing unauthenticated access to the administration panel of many routers made by D-Link,
one of the world's largest manufacturers of routers for home and business.

### To Do
- Look into using an online vulnerability database API to enable cross-referencing responses from
the Shodan IoT search engine with signatures of backdoors/vulnerabilities
- Change to modular design to make it easier for other developers to add detection & exploitation features for other vulnerabilities
- Integrate BAMF into the [BYOB](https://github.com/malwaredllc/byob) framework as a distribution mechanism to maximize spreading potential

### Contact
__Email__: security@malwared.com

__Twitter__: [![twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/malwaredllc)

