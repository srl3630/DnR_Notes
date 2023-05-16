# Security Engineering at Google: My Interview Study Notes

### Contents
- [README](README.md)
- [Networking](#networking)
- [Web Application](#web-application)
- [Infrastructure (Prod / Cloud) Virtualisation](#infrastructure-prod--cloud-virtualisation)
- [OS Implementation and Systems](#os-implementation-and-systems)
- [Mitigations](#mitigations)
- [Cryptography, Authentication, Identity](#cryptography-authentication-identity)
- [Malware & Reversing](#malware--reversing)
- [Exploits](#exploits)
- [Attack Structure](#attack-structure)
- [Threat Modeling](#threat-modeling)
- [Detection](#detection)
- [Digital Forensics](#digital-forensics)
- [Incident Management](#incident-management)
- [Coding & Algorithms](#coding--algorithms)
- [Security Themed Coding Challenges](#security-themed-coding-challenges)

# Networking 

- OSI Model
	- Application; layer 7 (and basically layers 5 & 6) (includes API, HTTP, etc).
	- Transport; layer 4 (TCP/UDP).
	- Network; layer 3 (Routing).
	- Datalink; layer 2 (Error checking and frame synchronisation).
	- Physical; layer 1 (Bits over fibre).	
- Firewalls
	- Rules to prevent incoming and outgoing connections.	
- NAT 
	- Useful to understand IPv4 vs IPv6.
- DNS
	- (53)
	- Requests to DNS are usually UDP, unless the server gives a redirect notice asking for a TCP connection. Look up in cache happens first. DNS exfiltration. Using raw IP addresses means no DNS logs, but there are HTTP logs. DNS sinkholes.
      - TCP can also be ued when a DNS zone transfer to occur, which is when a secondary DNS server requests to replicate database from another DNS server
    - PTR reverses DNS lookups, going from IP -> Domain
- DNS exfiltration 
	- Sending data as subdomains. 
      - EX:26856485f6476a567567c6576e678.badguy.com
      - Can also be used to execute commands, by storing data in a txt record
	- Doesn’t show up in http logs, as no http request is made. 
- DNS configs
	- Start of Authority (SOA).
	- IP addresses (A and AAAA).
	- SMTP mail exchangers (MX).
	- Name servers (NS).
	- Pointers for reverse DNS lookups (PTR).
	- Domain name aliases (CNAME).
- ARP
	- Pair MAC address with IP Address for IP connections. 
- DHCP
	- UDP (67 - Server, 68 - Client)
	- Dynamic address allocation (allocated by router).
	- `DHCPDISCOVER` -> `DHCPOFFER` -> `DHCPREQUEST` -> `DHCPACK`
    - Assigns internal IP addresses to hosts
- Multiplex 
	- Timeshare, statistical share, just useful to know it exists.
- Traceroute 
	- Usually uses UDP, but might also use ICMP Echo Request or TCP SYN. TTL, or hop-limit.
	- Initial hop-limit is 128 for windows and 64 for *nix. Destination returns ICMP Echo Reply. 
- Nmap 
	- Network scanning tool.
- Intercepts (PitM - Person in the middle)
	- Understand PKI (public key infrastructure in relation to this).
- VPN 
	- Hide traffic from ISP but expose traffic to VPN provider.
- Tor 
	- Traffic is obvious on a network. 
	- How do organised crime investigators find people on tor networks.
      - Often times, the government will own a number of nodes on tor, if someone owns the entry and exit nodes, they can identify traffic that flows through it
- Proxy  
	- Why 7 proxies won’t help you.
      - Proxy doesn't hide/encrypt the data/what websites you're going to, just masks the original source
- BGP
	- Border Gateway Protocol.
	- Holds the internet together.
- Network traffic tools
	- Wireshark
	- Tcpdump
	- Burp suite
- HTTP/S 
	- (80, 443)
      - 80 is http, which is unencrypted
      - 443 is https and uses SSL/TLS
- SSL/TLS
	- (443) 
	- Super important to learn this, includes learning about handshakes, encryption, signing, certificate authorities, trust systems. A good [primer](https://english.ncsc.nl/publications/publications/2021/january/19/it-security-guidelines-for-transport-layer-security-2.1) on all these concepts and algorithms is made available by the Dutch cybersecurity center.
      - encryption
        - Public private key encryption
          - usually some combination of the private key of a website with a random string which is used to encode messages
    - Signing means a CA has authenticated the identity of the person using a certificate
      - ensures AIN
        - Authenticity
        - Integrity
        - Non-repudiation
      - Source: https://support.microsoft.com/en-us/office/digital-signatures-and-certificates-8186cd15-e7ac-4a16-8597-22bd163e8e96
    - TLS handshake
      - syn, syn-ack, ack
      - client hello, server hello/certificate/serverhellodone, clientkeyexchange/changecipherspecfinished, changechipherspecfinished
    - POODLE, BEAST, CRIME, BREACH, HEARTBLEED.
- TCP/UDP
	- Web traffic, chat, voip, traceroute.
	- TCP there is a confirmation a packet was received, this does not exist with UDP
      - The only things ensured in life are Death, Taxes, and TCP 
    - layer 4
- ICMP
	- Ping and traceroute.
    - Connectionless protocol
    - layer 3
- Mail
	- SMTP (25, 587, 465)
	- IMAP (143, 993)
	- POP3 (110, 995)
- SSH 
	- (22)
	- Handshake uses asymmetric encryption to exchange symmetric key.
- Telnet
	- (23, 992)
	- Allows remote communication with hosts.
- ARP  
	- Who is 0.0.0.0? Tell 0.0.0.1.
	- Linking IP address to MAC, Looks at cache first.
- DHCP 
	- (67, 68) (546, 547)
	- Dynamic (leases IP address, not persistent).
	- Automatic (leases IP address and remembers MAC and IP pairing in a table).
	- Manual (static IP set by administrator).
- IRC 
	- Understand use by hackers (botnets).
- FTP/SFTP 
	- (21, 22)
- RPC 
	- Predefined set of tasks that remote clients can execute.
	- Used inside orgs. 
    - understand use vs APIs
      - RPCs we can call functions on other machines
- Service ports
	- 0 - 1023: Reserved for common services - sudo required. 
	- 1024 - 49151: Registered ports used for IANA-registered services. 
	- 49152 - 65535: Dynamic ports that can be used for anything. 
- HTTP Header
	- | Verb | Path | HTTP version |
	- Domain
	- Accept
	- Accept-language
	- Accept-charset
	- Accept-encoding(compression type)
	- Connection- close or keep-alive
	- Referrer
	- Return address
	- Expected Size?
- HTTP Response Header
	- HTTP version
	- Status Codes: 
		- 1xx: Informational Response
		- 2xx: Successful
		- 3xx: Redirection
		- 4xx: Client Error
		- 5xx: Server Error
	- Type of data in response 
	- Type of encoding
	- Language 
	- Charset
- UDP Header
	- Source port
	- Destination port
	- Length
	- Checksum
- Broadcast domains and collision domains. 
- Root stores
- CAM table overflow


# Web Application 

- Same origin policy
	- Only accept requests from the same origin domain.  
- CORS 
	- Cross-Origin Resource Sharing. Can specify allowed origins in HTTP headers. Sends a preflight request with options set asking if the server approves, and if the server approves, then the actual request is sent (eg. should client send auth cookies).
- HSTS 
	- Policies, eg what websites use HTTPS.
- Cert transparency 
	- Can verify certificates against public logs
- Cookies 
	- httponly - cannot be accessed by javascript.
- CSRF
	- Cross-Site Request Forgery.
      -	make user click link with potentially unwanted actions
      - Can mitigate wit CSRF tokens
        - need to include token to make valid request
      - ref based validation also works
        - verify the request originated from own domain
	- Cookies.
- XSS
	- Reflected XSS.
      - User tricked into executing specially crafted request, can be from an error or response from a form, executes as it's coming from a trusted server
      - Has access to users info in code
    - Persistent XSS.
      - When a script is stored on a server in some form, such as a forum post or comment
	- DOM based /client-side XSS.
      - can load 
	- `<img scr=””>` will often load content from other websites, making a cross-origin HTTP request. 
- SQLi 
	- Person-in-the-browser (flash / java applets) (malware).
	- Validation / sanitisation of webforms.
    - Mitigations
      - prepared statements
        - makes query only interpret as literals
      - Stored procedures
        - sql code for a stored procedure is stored on the db
- POST 
	- Form data, no arguments in url
- GET 
	- Queries. 
	- Visible from URL.
- Directory traversal 
	- Find directories on the server you’re not meant to be able to see.
	- There are tools that do this.
    - Can bypass bypreventions 
      - with absolute paths
      - by url encoding the traversal
      - use required path, and then do directory traversal
      - can use null byte to bypass file type requirements
      - Source: https://portswigger.net/web-security/file-path-traversal
    - Can completely eliminate this by avoiding allowing user supplied filesystem calls
- APIs 
	- Think about what information they return. 
	- And what can be sent.
- Beefhook
	- Means to get user to navigate to a page with an inserted script by BEEF (browser exploitation framework)
- User agents
	- Is this a legitimate browser? Or a botnet?
    - Keep in mind, user agents are totally defined by the user of the device and can be changed at will
      - A weird UA may be suspicious, but a normal user agent doesn't mean a request isn't suspicious
- Browser extension take-overs
	- Miners, cred stealers, adware.
- Local file inclusion
  - Loading a file that wasn't intended to be loaded
    - typically combined with some sort of file upload
- Remote file inclusion (not as common these days)
  - Same as above, but doesn't require upload, can load files from other places, such as a file server
- SSRF 
	- Server Side Request Forgery.
    - Attack which causes the backend of the server to make requests not intended
      - often used to obtain cloud credentials (169.254.169.254)
        - especially important in kubernetes, as often times the network is considered trusted, so unauthenticated requests can be made to microservices
- Web vuln scanners. 
  - Rapid7, Qualsys
  - Shotgun exploits against web servers
- SQLmap.
  - automatically performs SQL injection attacks
- Malicious redirects.
  - Can be code injected into a website to cause users to be redirected to another malicious site


# Infrastructure (Prod / Cloud) Virtualisation 

- Hypervisors.
  - Software/hardware on which virtual machines are run
- Hyperjacking.
  - taking over the hypervisors, a vm escape, makes it harder to detect malicious code being run
- Containers, VMs, clusters.
  - a container is a packaging of a given software and it's runtime environment
    - build on top of the hosts kernel
  - a virtual machine is a whole virtualized operating system
- Escaping techniques.
	- Network connections from VMs / containers.  
    - containers in kube are often extremely over priveleged by default
      - check if a docker socket is mounted
      - check if the container is running as root
- Lateral movement and privilege escalation techniques.
	- Cloud Service Accounts can be used for lateral movement and privilege escalation in Cloud environments.
      - most service accounts have the editor role
      - need to allow access to setmetadata
      - set new public key for ssh access
      - you can just use gcloud compute ssh [instance name]
      - look for credentials on the box
	- GCPloit tool for Google Cloud Projects.
- Site isolation.
  - Sandboxes different websites, making it more difficult for cross pollination of data
- Side-channel attacks.
	- Spectre, Meltdown.
    - 
- Beyondcorp ( ZeroTrust )
	- Trusting the host but not the network.
    - No trusted networks just trusted devices and accounts
    - ABAC based framework, which evaluates a number of factors to determine level of access
      - Account role, device status, patching status, 
- Log4j vuln. 
  - A vulnerability exploiting the JNDI (Java Naming and Directory Interface) in arbitrary fields to get a server running java to execute arbitrary code
    - The code would be run, as the server would read the log files and perform the JNDI request and execute the provided file from the URL


# OS Implementation and Systems

- Privilege escalation techniques, and prevention.
  - edit a task run by a more priveleged user
  - some files/services will be run as a different user, edit those files
  - dump lsass
  - some type of exploit
  - passwords lying around
    - web browser
    - creds for an app
    - rc files on linux
  - pass the has attack, needs NTLM to be enabled
  - plug a razer mouse into your computer (make pc install insecure services as system)
  - DLL Hijacking
  - Unquoted service paths
- Buffer Overflows.
  - When a program writes extra data to disk, and that other data gets executed by another program
- Directory traversal (prevention).
  - don't allow users to directly access files
  - filter out `../` (naive)
  - whitelist certain inputs for the user
- Remote Code Execution / getting shells.
  - a way to remotely execute code on a remote application
    - log4j vuln
    - any operation that accepts user input without cleaning and runs that code
      - ex: subprocess.run(['ls', user_input])
    - Can chain local file inclusion and upload to achieve rce
- Local databases
	- Some messaging apps use sqlite for storing messages.
	- Useful for digital forensics, especially on phones.
- Windows
	- Windows registry and group policy.
	- Active Directory (AD).
		- Bloodhound tool. 
		- Kerberos authentication with AD.
	- Windows SMB. 
	- Samba (with SMB).
	- Buffer Overflows. 
	- ROP. 
	
- *nix 
	- SELinux.
	- Kernel, userspace, permissions.
	- MAC vs DAC.
      - DAC
        - discretionary access control
          - owner decides what is done with file
      - MAC
        - mandatory access control
          - policy is centrally controlled by an administrator
          - much more strict and requires more intentionality
	- /proc
      - filesystem created on the fly to keep track of the state of the machine
	- /tmp - code can be saved here and executed.
	- /shadow 
      - stores hashed passwords
    - /passwd
      - stores user info
	- LDAP - Lightweight Directory Browsing Protocol. Lets users have one password for many services. This is similar to Active Directory in windows.
- MacOS
	- Gotofail error (SSL).
      - can trick users into visiting a fake site and it seems trusted
	- MacSweeper.
      - basically primitive PUP/PUA
	- Research Mac vulnerabilities.
      - 

## Mitigations 
- Patching 
- Data Execution Prevention
- Address space layout randomisation
	- To make it harder for buffer overruns to execute privileged instructions at known addresses in memory.
- Principle of least privilege
	- Eg running Internet Explorer with the Administrator SID disabled in the process token. Reduces the ability of buffer overrun exploits to run as elevated user.
- Code signing
	- Requiring kernel mode code to be digitally signed.
- Compiler security features
	- Use of compilers that trap buffer overruns.
- Encryption
	- Of software and/or firmware components.
- Mandatory Access Controls
	- (MACs)
	- Access Control Lists (ACLs)
	- Operating systems with Mandatory Access Controls - eg. SELinux.
- "Insecure by exception"
	- When to allow people to do certain things for their job, and how to improve everything else. Don't try to "fix" security, just improve it by 99%.
- Do not blame the user
	- Security is about protecting people, we should build technology that people can trust, not constantly blame users. 


# Cryptography, Authentication, Identity 

- Encryption vs Encoding vs Hashing vs Obfuscation vs Signing
	- Be able to explain the differences between these things. 
    - Encryption
      - When data is modified such that only someone with a given key is able to read them
    - Encoding
      - The process of converting data into a seperate format
      - can read as long as you know the format, no secret required
    - Hashing
      - the process of converting data into a (mostly) unique string for identificaiton
      - hashing is typically one way
    - Obfuscation
      - modifying data such that the original meaning is not easily recognizable
      - this can be done to evade defender tooling or make data unreadable
    - Signing
      - The process of verifying something by backing authenticity, and ensuring the code hasn't been changed by anyone other than the author
	- [Various attack models](https://en.wikipedia.org/wiki/Attack_model) (e.g. chosen-plaintext attack).

- Encryption standards + implementations
	- [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) (asymmetrical).
	- [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (symmetrical).
	- [ECC](https://en.wikipedia.org/wiki/EdDSA) (namely ed25519) (asymmetric).
	- [Chacha/Salsa](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) (symmetric).

- Asymmetric vs symmetric
	- Asymmetric is slow, but good for establishing a trusted connection.
	- Symmetric has a shared key and is faster. Protocols often use asymmetric to transfer symmetric key.
	- Perfect forward secrecy - eg Signal uses this.

- Cyphers
	- Block vs stream [ciphers](https://en.wikipedia.org/wiki/Cipher).
	- [Block cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation).
	- [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode).

- Integrity and authenticity primitives
	- [Hashing functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) e.g. MD5, Sha-1, BLAKE. Used for identifiers, very useful for fingerprinting malware samples.
	- [Message Authentication Codes (MACs)](https://en.wikipedia.org/wiki/Message_authentication_code).
	- [Keyed-hash MAC (HMAC)](https://en.wikipedia.org/wiki/HMAC).

- Entropy
	- PRNG (pseudo random number generators).
	- Entropy buffer draining.
	- Methods of filling entropy buffer.

- Authentication
	- Certificates 
		- What info do certs contain, how are they signed? 
          - Public and private key
          - contains certificate info ( info about the cert owner)
          - digital signature by CA
		- Look at DigiNotar.
	- Trusted Platform Module 
		- (TPM)
		- Trusted storage for certs and auth data locally on device/host.
        - provides FDE (Full disk encryption) for securely booting into an operating system
          - disallows tampering outside of the OS itself
	- O-auth
		- Bearer tokens, this can be stolen and used, just like cookies.
        - Used to auth to a given sergice, has certain permissions
	- Auth Cookies
		- Client side.
        - allows the user to have a token representing they have logged in without storing credentials
	- Sessions 
		- Server side.
        - way for the server to associate requests with an authenticated user without having to submit credentials every time
	- Auth systems 
		- SAMLv2o.
          - xml based auth protocol
          - Identity providers provide SAML Assertions (digital passports) to allow access to service providers (apps)
		- OpenID.
          - decentralized auth protocol
          - can choose a provider, and then authenticate to any site using openid
		- Kerberos. 
			- Gold & silver tickets.
              - Silver is local service tickets
              - Gold gives access to domain
			- Mimikatz.
              - dumps password hashes from lsass
			- Pass-the-hash.	  
              - Using NTLM (legacy protocol) we can use the hash instead of the cracked password
	- Biometrics
		- Can't rotate unlike passwords.
	- Password management
		- Rotating passwords (and why this is bad). 
		- Different password lockers. 
	- U2F / FIDO
		- Eg. Yubikeys.
		- Helps prevent successful phishing of credentials.
	- Compare and contrast multi-factor auth methods.

- Identity
	- Access Control Lists (ACLs)
		- Control which authenicated users can access which resources.
	- Service accounts vs User accounts
		- Robot accounts or Service accounts are used for automation.
		- Service accounts should have heavily restricted privileges.
		- Understanding how Service accounts are used by attackers is important for understanding Cloud security.  
	- impersonation
		- Exported account keys.
		- ActAs, JWT (JSON Web Token) in Cloud.
          - Allows user to assume a role and access resources it has access to
	- Federated identity
      - Links identity between services
        - For example, Azure AD and on prem can be synced
        - another example is sso


# Malware & Reversing

- Interesting malware
	- Conficker.
      - Worm
      - Uses a number of tactics to spread
        - Windows Exploits
        - Autorun usbs
        - Default passwords (RDP)
	- Morris worm.
      - experimental
      - one of the first worms
      - Methods of compromise
        - weak passwords
        - windows exploits
        - trusted systems with no login
	- Zeus malware.
      - trojan
      - steals cred, banking info, etc.
        - has been used to spread other payloads, such as ransomware
	- Stuxnet.
      - worm
      - starts off spread by usb, then moves over to exploits
      - Mimics sandbox detection functionality
        - typically used to search systems for common files to avoid detonating in sandboxes
          - in this case, it searched for specific software and hardware, to avoid detonating on unintended targets
	- Wannacry.
      - worm ransomware that spread via an SMB exploit
	- CookieMiner.
      - Cred stealer payload, used to steal banking and crypto creds from macs
      - stole session cookies for websites associated to crypto, hence cookie miner
	- Sunburst.
      - backdoor
      - supply chain attack
      - waits days before communicating with C2 server
      - used a DGA to determine where to beacon to
      - mimics solarwinds with urls queried and 
      - lateral moved via powershell remote task creation
      - used a mix of encoded and junk data to throw off what secrets wer being exfiltrated

- Malware features
	- Various methods of getting remote code execution.
      - injection
      - deserialization
      - out of bounds write
	- Domain-flux.
      - when attackers frequently change domains, typically based on DGA
	- Fast-Flux.
      - When IP addresses are changed by an attacker frequently to avoid blockage
	- Covert C2 channels.
      - static noise (for airgaps)
      - stegonography based C2 (downloading images and reading encoded data from them)
      - dns a/txt records
	- Evasion techniques (e.g. anti-sandbox).
      - disable security tooling
      - masquerade as legitimate software
      - check for specific aspects of machine to attempt to detect a sandbox
	- Process hollowing. 
      - suspend the process on startup and inject malicious code before resuming
      - helps avoid detection, as code is injected into reputable process
	- Mutexes.
      - typically used for multithreading to avoid multiple processes accessing a resource
      - can be used to make sure only one instance of malware is running at a given point in time
	- Multi-vector and polymorphic attacks.
      - MVA is when multiple different attack are used to gain access to an environment
        - multi vector attacks can be used to have a higher chance of gaining access to the environment
      - Polymorphic attacks
        - when the signature of the malware/tactic/technique being used constantly changes to avoid detecton
	- RAT (remote access trojan) features.
      - download files
      - upload files
      - take screenshots
      - grab creds

- Decompiling/ reversing 
	- Obfuscation of code, unique strings (you can use for identifying code).
	- IdaPro, Ghidra.

- Static / dynamic analysis
	- Describe the differences.
      - static
        - observes indicators of file itself
          - hash
          - digital signatures
          - file headers
          - file extension
          - metadata
      - dynamic
        - observing how the malware behaves when run
	- Virus total. 
	- Reverse.it. 
	- Hybrid Analysis.


# Exploits

- Three ways to attack - Social, Physical, Network 
	- **Social**
		- Ask the person for access, phishing. 
		- Cognitive biases - look at how these are exploited.
		- Spear phishing.
		- Water holing.
		- Baiting (dropping CDs or USB drivers and hoping people use them).
		- Tailgating.
	- **Physical** 
		- Get hard drive access, will it be encrypted? 
		- Boot from linux. 
		- Brute force password.
		- Keyloggers.
		- Frequency jamming (bluetooth/wifi).
		- Covert listening devices.
		- Hidden cameras.
		- Disk encryption. 
		- Trusted Platform Module.
		- Spying via unintentional radio or electrical signals, sounds, and vibrations (TEMPEST - NSA).
	- **Network** 
		- Nmap.
		- Find CVEs for any services running.
		- Interception attacks.
		- Getting unsecured info over the network.
        - Set up Rogue AP

- Exploit Kits and drive-by download attacks

- Remote Control
	- Remote code execution (RCE) and privilege.
	- Bind shell (opens port and waits for attacker).
	- Reverse shell (connects to port on attackers C2 server).

- Spoofing
	- Email spoofing.
	- IP address spoofing.
	- MAC spoofing.
	- Biometric spoofing.
	- ARP spoofing.

- Tools
	- Metasploit.
	- ExploitDB.
	- Shodan - Google but for devices/servers connected to the internet.
	- Google the version number of anything to look for exploits.
	- Hak5 tools.


# Attack Structure

Practice describing security concepts in the context of an attack. These categories are a rough guide on attack structure for a targeted attack. Non-targeted attacks tend to be a bit more "all-in-one".

RRIEPPDCDLCEC2I

- Reconnaissance
	- OSINT, Google dorking, Shodan.
- Resource development
	- Get infrastructure (via compromise or otherwise).
	- Build malware.
	- Compromise accounts.
- Initial access
	- Phishing.
	- Hardware placements.
	- Supply chain compromise.
	- Exploit public-facing apps.
- Execution
	- Shells & interpreters (powershell, python, javascript, etc.).
	- Scheduled tasks, Windows Management Instrumentation (WMI).
- Persistence
	- Additional accounts/creds.
	- Start-up/log-on/boot scripts, modify launch agents, DLL side-loading, Webshells.
	- Scheduled tasks.
- Privilege escalation
	- Sudo, token/key theft, IAM/group policy modification.
	- Many persistence exploits are PrivEsc methods too.
- Defense evasion
	- Disable detection software & logging.
	- Revert VM/Cloud instances.
	- Process hollowing/injection, bootkits.
- Credential access
	- Brute force, access password managers, keylogging.
	- etc/passwd & etc/shadow.
	- Windows DCSync, Kerberos Gold & Silver tickets.
	- Clear-text creds in files/pastebin, etc.
- Discovery
	- Network scanning.
	- Find accounts by listing policies.
	- Find remote systems, software and system info, VM/sandbox.
- Lateral movement
	- SSH/RDP/SMB.
	- Compromise shared content, internal spear phishing.
	- Pass the hash/ticket, tokens, cookies.
- Collection
	- Database dumps.
	- Audio/video/screen capture, keylogging.
	- Internal documentation, network shared drives, internal traffic interception.
- Exfiltration
	- Removable media/USB, Bluetooth exfil.
	- C2 channels, DNS exfil, web services like code repos & Cloud backup storage.
    - domain fronting
	- Scheduled transfers.
- Command and control
	- Web service (dead drop resolvers, one-way/bi-directional traffic), encrypted channels.
	- Removable media.
	- Steganography, encoded commands.
- Impact
	- Deleted accounts or data, encrypt data (like ransomware).
	- Defacement.
	- Denial of service, shutdown/reboot systems.


# Threat Modeling

- Threat Matrix
  - way of determining which types of threats to prioritize/surface
- Trust Boundries
  - Who do we trust?
    - Identity providers
    - Hosts
    - Network?
- Security Controls
- STRIDE framework
	- **S**poofing
	- **T**ampering
	- **R**epudiation
	- **I**nformation disclosure
	- **D**enial of service
	- **E**levation of privilege 
- [MITRE Att&ck](https://attack.mitre.org/) framework
- [Excellent talk](https://www.youtube.com/watch?v=vbwb6zqjZ7o) on "Defense Against the Dark Arts" by Lilly Ryan (contains *many* Harry Potter spoilers)


# Detection

- IDS
	- Intrusion Detection System (signature based (eg. snort) or behaviour based).
	- Snort/Suricata/YARA rule writing
	- Host-based Intrusion Detection System (eg. OSSEC)

- SIEM
	- Security Information and Event Management.
    - Used as both a collector of logs, and way of querying/correlating logs to generate security signal

- IOC 
	- Indicator of compromise (often shared amongst orgs/groups).
	- Specific details (e.g. IP addresses, hashes, domains)
      - Very ephemeral, all of the above attributes can be changed very easily

- Things that create signals
	- Honeypots
    - snort
    - EDR ( Crowdstrike, Carbon Black, Falco, Wazuh)
    - Cloud Monitoring services ( GCP threat detection, AWS GuardDuty )
    - Network monitors (Darktrace)
    - Firewalls ( PAN NGFW )
    - WAFs ( Signal Sciences)
    - UEBA software ( Exabeam )

- Ways to manage, track, and triage signals
	- SIEM, eg splunk.
    - Ticketing services (Jira, OPsgenie, Zendesk)
    - MDR platforms ( Expel Workbench)

- Things that will alert a human 
	- Alerts created in a ticketing system
    - Pages
	- Notifications and analyst fatigue.

- Signatures
	- Host-based signatures
		- Eg changes to the registry, files created or modified.
		- Strings in found in malware samples appearing in binaries installed on hosts (/Antivirus).
	- Network signatures
		- Eg checking DNS records for attempts to contact C2 (command and control) servers.
    - These types of detections are very ephemeral
      - most of these attributes can be changed at will by an attacker

- Anomaly / Behaviour based detection 
	- IDS learns model of “normal” behaviour, then can detect things that deviate too far from normal - eg unusual urls being accessed, user specific- login times / usual work hours, normal files accessed.  
	- Can also look for things that a hacker might specifically do (eg, HISTFILE commands, accessing /proc).
	- If someone is inside the network- If action could be suspicious, increase log verbosity for that user.
    - This type of detection ( behavaior based ) is the most resilient to change
      - EX. it's easy to change the hash of a file/C2 Domain, it's much harder to change the functionality
      - Means detections are more robust
    - Behavior typically finds evil more consistently, but anomaly is more resistant to change tactics and techniques

- Threat Hunting
  - Process proactively looking for threats in an environment undetected by rules
  - Need to be done retro-activelty by a human
  - Typically has large amounts of results which need to be hand filtered by human
    - Three methods
      - IOC based hunt
        - look for IOCs in environment
      - Anomaly based hunt
        - look for anomalous events in an environment
      - Hypothesis driven hunt
        - Start with a hypothesis (is there C2 beaconing from interpreters?) and look for evidence

- Signature vs Anomaly vs Behavior vs Threat Hunting
    - Highest fidelity ( in order top to bottom, this is a generalization )
      - signature
      - behavior
      - anomaly
      - threat hunting
    - Highest resilience to new/changing techniques/tactics ( in order top to bottom, this is a generalization )
      - anomaly
      - threat hunting
      - behavior
      - signature
    - Highest volume ( in order top to bottom, this is a generalization )
      - threat hunting
      - anomaly
      - behavior
      - signature
    - Highest time investment (development, maintenance, and triage) ( in order top to bottom, this is a generalization )
      - threat hunting
      - signature
      - anomaly
      - behavior
    - The above applies only if we're assuming the average case fior each
      - one can make a bad version of any of these, causing excess alerting
    - Behavioral is the strongest overall
      - should be supplemented with anomaly and behavior for reliability of catching new/old attacks respectively

- Firewall rules
	- Brute force (trying to log in with a lot of failures).
	- Detecting port scanning (could look for TCP SYN packets with no following SYN ACK/ half connections).
	- Antivirus software notifications.
	- Large amounts of upload traffic.

- Honey pots
	- Canary tokens.
      - tokens placed on devices to look like real files, sends notification to server when triggered
	- Dummy internal service / web server, can check traffic, see what attacker tries.

- Things to know about attackers
	- Slow attacks are harder to detect.
	- Attacker can spoof packets that look like other types of attacks, deliberately create a lot of noise.
	- Attacker can spoof IP address sending packets, but can check TTL of packets and TTL of reverse lookup to find spoofed addresses.
	- Correlating IPs with physical location (is difficult and inaccurate often).

- Logs to look at
	- DNS queries to suspicious domains.
	- HTTP headers could contain wonky information.
	- Metadata of files (eg. author of file) (more forensics?).
	- Traffic volume.
	- Traffic patterns.
	- Execution logs.

- Detection related tools
	- Splunk.
	- Arcsight.
	- Qradar.
	- Darktrace.
	- Tcpdump.
	- Wireshark.
	- Zeek.

- A curated list of [awesome threat detection](https://github.com/0x4D31/awesome-threat-detection) resources


# Digital Forensics

 - Evidence volatility (network vs memory vs disk)

 - Network forensics
	- DNS logs / passive DNS
	- Netflow
	- Sampling rate

 - Disk forensics
	- Disk imaging
	- Filesystems (NTFS / ext2/3/4 / AFPS)
	- Logs (Windows event logs, Unix system logs, application logs)
	- Data recovery (carving)
	- Tools
	- plaso / log2timeline
	- FTK imager
	- encase

 - Memory forensics
	- Memory acquisition (footprint, smear, hiberfiles)
	- Virtual vs physical memory
	- Life of an executable
	- Memory structures
	- Kernel space vs user space
	- Tools
	- Volatility
	- Google Rapid Response (GRR) / Rekall
	- WinDbg

  - Mobile forensics
	- Jailbreaking devices, implications
	- Differences between mobile and computer forensics
	- Android vs. iPhone

  - Anti forensics
	- How does malware try to hide?
	- Timestomping

  - Chain of custody
  	- Handover notes 


# Incident Management

- Privacy incidents vs information security incidents
- Know when to talk to legal, users, managers, directors.
- Run a scenario from A to Z, how would you ...

- Good practices for running incidents 
	- How to delegate.
	- Who does what role.
	- How is communication managed + methods of communication.
	- When to stop an attack.
	- Understand risk of alerting attacker.
	- Ways an attacker may clean up / hide their attack.
	- When / how to inform upper management (manage expectations).
	- Metrics to assign Priorities (e.g. what needs to happen until you increase the prio for a case)
	- Use playbooks if available

- Important things to know and understand
	- Type of alerts, how these are triggered.
	- Finding the root cause.
	- Understand stages of an attack (e.g. cyber-killchain)
	- Symptom vs Cause.
	- First principles vs in depth systems knowledge (why both are good).
	- Building timeline of events.
	- Understand why you should assume good intent, and how to work with people rather than against them.
	- Prevent future incidents with the same root cause

  - Response models
  	- SANS' PICERL (Preparation, Identification, Containement, Eradication, Recovery, Lessons learned)
   	- Google's IMAG (Incident Management At Google)


# Detection Pipeline

- Log ingestion
  - Where are logs coming from?
  - how are the logs being obtained
    - collectors?
    - what APIs do we need to hit to obtain those logs?
- Log Storage
  - Where are we putting those logs?
    - Database? SIEM? A text file on a server (not recommended)?
- Normalization
  - What is our standard formatting for pieces of data
    - IP-Address -> ip_address
  - Why is normalization important
    - helps us query data easily across technologies
    - allows our automation to run smoothly on all devices
    - provides consistency and crucial data for analysts to triage
    - allows our detection rules to run consistently across technologies
- Detection engine
  - Do we want to build our own or use a third party?
    - MDR/MSSP provider?
    - Use a SIEM -> Ticketing System?
    - Roll our own propietary pipeline?
      - Will detections be codebased? Markdown?
- Detection/Signatures
  - IDS/IPS, Have security tech make signal for us, like XDR?
  - Write our own SIEM queries or custom queries in security tech?
- Suppressions
  - Specific logic we put on top of a rule to reduce volume
    - use specific indicators, like a process on a host, or parameters for a script that's commonly run in the environment
    - If a suppresion is too broad, that means it likely should be written into detection logic
- Enrichment
  - The icing on the cake (delicious icing at that)
  - SOAR Platforms
  - Cloud functions
  - Answers questions like...
    - What does AV/Virustotal say about this host?
    - What alerts fired from other vendors for this host/ip?
    - What was the source process for this activity?
    - What are search results for the hash like? (custom search for sandboxes?)
    - How many connections were made to the IP address in the alert?
    - And many, many more!
      - The sky is the limit
    - Does the IP in the alert have a bad reputation?

# Detection/Signature/Threat Hunting Research
- Security feeds
  - Security News platforms ( Dark Reading, Krebs on security)
    - We prefer technical breakdowns, not overviews
      - overviews can be helpful to start looking into what to look into
  - Red Teaming Blogs ( SpectreOps, Rhino Security labs, etc.)
  - Blue Team Blogs (Crowdstrike, Darktrace, ..)
    - security vendors do a pretty good job at this
    - reversed malware breakdowns
  - Threat intel feeds
- Past incidents
  - Detection & Response is an iterative process
  - Review past incidents for IOCs + new behavioral rules to model into detection strategy
  - Develop hunts to find similar activity in environment
- Social Media
  - high profile security personalities
    - good way to find IOCs and reversing breakdowns
    - news is often first broke on social media
  - hacker groups
    - *There may be ethical issues with this ( should you boost the social media reach of criminals? )*
    - some hacker groups post their activities on social media