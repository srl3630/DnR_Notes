# Common Attack Methods by Mitre Tactic and how to detect/prevent

## Endpoint ATT&CK & Detection
    #Note: Recon is a poor method of detection, but can be used for hardening environment
    Reconnaissance
        - Scans exploit scans against public facing infrastructure
            - Implement signatures for high profile attacks and correlate with what machines are vulnerable to
        - Scan public repos for access tokens
            - Frequently scrub internet for tokens and public repos
        - Probing phishing attacks
            - Detect on emails with suspicious iframes or using keywords which may indicate an email is malicious
    Resource Development
        - C2 servers
            - keep up to date threat feed and use to detect on attacker infra
        - Buying accounts in environment
            - dark web scans for emails/keywords related to your org
        - Develop/Buy Commodity malware
            - keep up to date libraries or use 3rd part services to identify malware
    Initial Access
        - Compromise a web server
            - Create detection to identify a web server process running a cmd interpreter or writing files
        - Have user install RAT software (phishing)
            - User education and keeping an allowlist of remote access tool software
        - Phishing attachment (Excel w/Macros, Scr files, etc..)
            - Identify file attachments which have multiple file extensions or follow a generic naming scheme
    Execution
        - Scripting interpreter
            - Alert on obfuscation/defense evasion techniques/ making network connections + creating files
                - domain age for network connections can help refine detection
        - LOLBIN spawning command interpreter
            - LOLBINs should not be spawning command interpreters
        - Known Admin Applications
            - Detection uncommon Admin Applications which can be used maliciously ( nirsoft, psexec. etc...)
    Persistence
        - Admin accounts
            - Alert on new admin accounts being created
        - Scheduled job (cronjob, scheduled tasks)
            - Alert when new scheduled job is created by uncommon user (admin, service accounts in environment)
        - DLL Search order hijacking
            - Detect on DLLs being loaded from uncommon directories
    Credential Access
        - MacOS Browser Credential Access
            - indentify non-browser programs accessing databases where browser credentials are stored
        - Kerberoasting
            - Indentify hosts attempting to request a large number of service tickets from a Kerberos server
        - NTDS.dit access
            - identify processes or users attempting to directly access the NTDS.dit file
    Defense Evasion
        - clearing logs
            - create a baseline for users/services that are expected to clear logs
        - scripting interpreter obfuscation
            - correlate usage of obfuscating techniques and surface if X number were found being used
        - create BITSAdmin jobs
            - montor for select commands + arguments from BITSAdmin (Transfer, create, add-file, etc..)
    Discovery
        - Account discovery ( Domain accounts )
            - Identify accounts attempting to run commands indicative of a user enumerating accounts
        - System information discovery
            - Correlate successive use of system discovery commands
        - System checks ( Detect VM )
            - detect on specific reg keys being checked to see if it's a VM
    Lateral Movement
        - Internal phishing
            - Identify users who don't commonly send out mass emails to other users
            - Identify users sending out suspicious documents
        - RDP (or other legitimate remoting tool) ( use rdp to move do another machine and dump creds )
            - Identify external users attempting to RDP or use other remote tools into an environment
        - Taint shared content
            - Run AV scans on drives and storage that are not connected to a specific computer
    Collection
        - Scanning files for credentials
            - identify common words or regex used in combination with binaries used to search files
        - Search for PII
            - identify common words or regex used in combination with binaries used to search files
        - Keyloggers
            - Identify unusual/unsigned dlls being loaded into processes
    Command & Control
        - DGA
            - Detect on very new domains being reached out to in succession
        - Domain Fronting
            - identify frequent beaconing to cdns
            - If TLS intercept is available, the actual domain behind fronting can be detected on
        - Beaconing
            - use list of curated domains, and correlate continous connections to them together
    Exfiltration
        - DNS tunneling
            - Identify large number of failed DNS requests or similarly sized responses
            - Identify DNS requests to an uncommon/unnaproved server
        - Upload to legitimate file storage site
            - Surface if storage site is not on an approved list
            - Identify excessively large file transfers
        - FTP transfer
            - Alert on FTP to external server
    Impact
        - Encrypt files
            - Detect when a large number of files are being encrypted/modified in a short period of time
                - Bonus points to only alert if multiple stale files are being encrypted
        - Account removal 
            - Detect on mass deletion of users in a short time frame
        - DOS attack
            - Monitor services for uptime (also useful for software errors)

//TODO
## Cloud ATT&CK & Detection
    Reconnaissance
        - Scans exploit scans against public facing infrastructure
            - Implement signatures for high profile attacks
    Resource Development
    Initial Access
    Execution
    Persistence
    Defense Evasion
    Discovery
    Lateral Movement
    Collection
    Command & Control
    Exfiltration
    Impact

//TODO
## SaaS ATT&CK & Detection
    Reconnaissance
    Resource Development
    Initial Access
    Execution
    Persistence
    Defense Evasion
    Discovery
    Lateral Movement
    Collection
    Command & Control
    Exfiltration
    Impact