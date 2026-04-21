// 1. Define weighted rules using Regex for flexibility
// Weight: 5 = Strong match (almost certainly this category)
// Weight: 2 = Weak match (suggestive but needs context)
// 1. Define weighted rules using Regex for flexibility
// Weight: 5 = Critical Indicator (Almost certainly this category)
// Weight: 4 = High Probability (Strong evidence)
// Weight: 3 = Medium Probability (Needs context)
// Weight: 2 = Low Probability (Suggestive)
// Weight: 1 = Very Weak (Noise unless combined)

const CATEGORY_RULES = {
  phishing: [
    // =========================================================================
    // 🚨 WEIGHT 5: CRITICAL INDICATORS (Smoking Guns & Specific Attacks)
    // =========================================================================
    // Technical Jargon & Known Attack Types
    { pattern: /quishing|qr code phishing|qr code scam/i, weight: 5 },
    { pattern: /smishing|sms phishing|text message scam/i, weight: 5 },
    { pattern: /vishing|voice phishing|callback scam|tech support scam/i, weight: 5 },
    { pattern: /whaling|ceo fraud|executive impersonation/i, weight: 5 },
    { pattern: /bec|business email compromise|email compromise/i, weight: 5 },
    { pattern: /spear phishing|targeted attack|social engineering/i, weight: 5 },
    { pattern: /clone phishing|evil twin|tabnabbing/i, weight: 5 },
    { pattern: /credential harvesting|harvest credentials|fake login page/i, weight: 5 },
    { pattern: /fatigue attack|mfa bombing|mfa spam|push notification spam/i, weight: 5 },
    { pattern: /aitm|adversary in the middle|token theft|session hijacking/i, weight: 5 },

    // Evasion & Obfuscation Techniques
    { pattern: /typosquatting|lookalike domain|fake domain|cousin domain/i, weight: 5 },
    { pattern: /homograph|punycode|ascii spoofing|unicode characters/i, weight: 5 },
    { pattern: /display name spoofing|spoofed sender|header mismatch/i, weight: 5 },
    { pattern: /open redirect|url shortener|bit\.ly|tinyurl/i, weight: 5 },
    { pattern: /html smuggling|html attachment|htm attachment/i, weight: 5 },
    { pattern: /steganography|hidden text|zero font|white text/i, weight: 5 },
    { pattern: /polyglot|obfuscated script|base64 encoded/i, weight: 5 },

    // High-Risk Scams (The "I need money now" triggers)
    { pattern: /gift card|steam card|apple card|google play card|vanilla visa/i, weight: 5 },
    { pattern: /bitcoin|btc|ethereum|crypto|wallet address|usdt/i, weight: 5 },
    { pattern: /extortion|blackmail|recorded you|webcam footage|porn/i, weight: 5 },
    { pattern: /payroll diversion|direct deposit change|update bank info/i, weight: 5 },
    { pattern: /wire transfer|ach transfer|swift code|routing number/i, weight: 5 },

    // =========================================================================
    // 🔴 WEIGHT 4: HIGH PROBABILITY (Urgency & Authority)
    // =========================================================================
    // The "Do It Now" Triggers
    { pattern: /urgent|immediate action|immediately|asap|rush/i, weight: 4 },
    { pattern: /24 hours|48 hours|deadline|expiration|expire/i, weight: 4 },
    { pattern: /final notice|last warning|account suspension|termination/i, weight: 4 },
    { pattern: /legal action|lawsuit|warrant|arrest|police/i, weight: 4 },
    { pattern: /breach|compromised|hacked|unauthorized access/i, weight: 4 },
    { pattern: /lock your account|restrict access|suspend account/i, weight: 4 },

    // Financial & Administrative Triggers
    { pattern: /invoice|overdue|payment declined|payment failed|unpaid/i, weight: 4 },
    { pattern: /receipt|purchase order|order confirmation|transaction/i, weight: 4 },
    { pattern: /tax form|w2|irs|hmrc|tax refund|audit/i, weight: 4 },
    { pattern: /salary|bonus|compensation|benefits enrollment/i, weight: 4 },
    
    // Security Theater (Fake Security Alerts)
    { pattern: /verify identity|verify account|confirm profile/i, weight: 4 },
    { pattern: /unusual sign-in|new device detected|login attempt/i, weight: 4 },
    { pattern: /security alert|security notification|policy violation/i, weight: 4 },
    { pattern: /quarantined message|spam release|release email/i, weight: 4 },
    
    // =========================================================================
    // 🟠 WEIGHT 3: MEDIUM PROBABILITY (Contextual Keywords)
    // =========================================================================
    // Brand Impersonation (Common Targets)
    { pattern: /microsoft|office 365|o365|teams|sharepoint|onedrive/i, weight: 3 },
    { pattern: /docusign|adobe sign|hellosign|pandadoc|signature request/i, weight: 3 },
    { pattern: /fedex|ups|dhl|usps|delivery|shipment|tracking/i, weight: 3 },
    { pattern: /zoom|webex|meeting invite|calendar notification/i, weight: 3 },
    { pattern: /linkedin|facebook|instagram|twitter|social media/i, weight: 3 },
    { pattern: /netflix|amazon|apple|icloud|spotify|paypal/i, weight: 3 },
    { pattern: /hr department|it support|help desk|admin|administrator/i, weight: 3 },

    // Common Phishing File Extensions & Delivery
    { pattern: /\.html$|\.htm$|\.shtml$/i, weight: 3 },
    { pattern: /\.zip$|\.rar$|\.7z$|\.tar\.gz$/i, weight: 3 },
    { pattern: /\.exe$|\.scr$|\.vbs$|\.js$|\.bat$/i, weight: 3 },
    { pattern: /\.iso$|\.img$|\.vhd$/i, weight: 3 }, // Disk image smuggling
    { pattern: /\.docm$|\.xlsm$|\.pptm$/i, weight: 3 }, // Macro-enabled docs
    
    // Generic "Action" Verbs
    { pattern: /click here|follow this link|open attachment|view document/i, weight: 3 },
    { pattern: /reset password|change password|forgot password/i, weight: 3 },
    { pattern: /enable content|enable macros|enable editing/i, weight: 3 },
    { pattern: /update info|update details|validate info/i, weight: 3 },

    // =========================================================================
    // 🟡 WEIGHT 2: LOW PROBABILITY (Suggestive / Noise)
    // =========================================================================
    // General Email Terms
    { pattern: /unknown sender|external sender|outside organization/i, weight: 2 },
    { pattern: /suspicious|weird|strange|odd/i, weight: 2 },
    { pattern: /link|url|website|page/i, weight: 2 },
    { pattern: /email|message|inbox|subject/i, weight: 2 },
    { pattern: /attachment|file|document|folder/i, weight: 2 },
    { pattern: /login|logon|sign in|sign up/i, weight: 2 },
    { pattern: /spam|junk|filter|block/i, weight: 2 }
  ],
  malware: [
    // =========================================================================
    // 🚨 WEIGHT 5: CRITICAL INDICATORS (Specific Families & C2 Frameworks)
    // =========================================================================
    // Famous Ransomware Families (The "Big Game Hunters")
    { pattern: /lockbit|blackcat|alphv|royal|akira|blackbasta|play ransomware/i, weight: 5 },
    { pattern: /ryuk|conti|revil|sodinokibi|wannacry|notpetya|darkside/i, weight: 5 },
    { pattern: /clop|moveit|hive|ragnar|lapsus|babuk|avaddon|netwalker/i, weight: 5 },
    { pattern: /stop djvu|phobos|dharma|makop|snatch|zeppelin/i, weight: 5 },

    // C2 Frameworks & Red Team Tools (Often used by attackers)
    { pattern: /cobalt strike|beacon|teamserver|aggressor script/i, weight: 5 },
    { pattern: /metasploit|meterpreter|reverse_tcp|bind_tcp|shellcode/i, weight: 5 },
    { pattern: /sliver|havoc|brute ratel|mythic|covenant|empire|starkiller/i, weight: 5 },
    { pattern: /bloodhound|sharphound|azurehound|neo4j|attack path/i, weight: 5 },
    { pattern: /mimikatz|sekurlsa|logonpasswords|lsadump|dcsync/i, weight: 5 },

    // Infostealers & Trojans (The "Log Stealers")
    { pattern: /redline|racoon|vidar|lumma|stealc|aurora|ducktail/i, weight: 5 },
    { pattern: /emotet|trickbot|qakbot|qbot|icedid|bokbot|bazarloader/i, weight: 5 },
    { pattern: /dridex|zloader|ursnif|gozi|ramnit|tinba/i, weight: 5 },
    { pattern: /remcos|njrat|asyncrat|darkcomet|nanocore|agent tesla/i, weight: 5 },

    // Critical Actions (The "End Game")
    { pattern: /files encrypted|file extension changed|cannot open files/i, weight: 5 },
    { pattern: /ransom note|readme\.txt|restore_files|decrypt_instructions/i, weight: 5 },
    { pattern: /shadow copies deleted|vssadmin delete shadows|wbadmin delete/i, weight: 5 },
    { pattern: /double extortion|data leak site|pay the ransom|decryptor/i, weight: 5 },

    // =========================================================================
    // 🔴 WEIGHT 4: HIGH PROBABILITY (MITRE ATT&CK Techniques)
    // =========================================================================
    // Evasion & Obfuscation
    { pattern: /powershell -enc|encodedcommand|bypass|noprofile/i, weight: 4 },
    { pattern: /base64|xor|rot13|obfuscated|payload|shellcode runner/i, weight: 4 },
    { pattern: /amsi bypass|etw patch|disable defender|disable av/i, weight: 4 },
    { pattern: /exclusion added|whitelist path|tamper protection disabled/i, weight: 4 },

    // Persistence Mechanisms
    { pattern: /registry run key|hkcu\\software\\microsoft\\windows\\currentversion\\run/i, weight: 4 },
    { pattern: /scheduled task|schtasks|cron job|at command/i, weight: 4 },
    { pattern: /startup folder|shell:startup|boot execution/i, weight: 4 },
    { pattern: /wmi subscription|wmic|event consumer/i, weight: 4 },
    { pattern: /dll search order hijacking|phantom dll|sideloading/i, weight: 4 },

    // Process Manipulation
    { pattern: /process injection|dll injection|reflective dll/i, weight: 4 },
    { pattern: /process hollowing|doppelganging|herpaderping/i, weight: 4 },
    { pattern: /lsass dump|procdump|comsvcs\.dll|minidump/i, weight: 4 },
    { pattern: /masquerading|svchost\.exe spoof|typo process name/i, weight: 4 },

    // Network Callbacks (IOCs)
    { pattern: /c2 traffic|command and control|heartbeat|beaconing/i, weight: 4 },
    { pattern: /dga domain|domain generation algorithm|fast flux/i, weight: 4 },
    { pattern: /user-agent string|suspicious user agent|empty user agent/i, weight: 4 },
    { pattern: /tor exit node|onion address|\.onion link/i, weight: 4 },

    // =========================================================================
    // 🟠 WEIGHT 3: MEDIUM PROBABILITY (Suspicious Artifacts & Behavior)
    // =========================================================================
    // Dangerous File Extensions (In context of "I opened a...")
    { pattern: /\.exe$|\.dll$|\.scr$|\.com$|\.pif$/i, weight: 3 },
    { pattern: /\.vbs$|\.vbe$|\.js$|\.jse$|\.wsf$|\.wsh$/i, weight: 3 },
    { pattern: /\.ps1$|\.psm1$|\.bat$|\.cmd$|\.hta$/i, weight: 3 },
    { pattern: /\.iso$|\.img$|\.vhd$|\.vhdx$/i, weight: 3 }, // Container formats
    { pattern: /\.docm$|\.xlsm$|\.pptm$|\.xlam$/i, weight: 3 }, // Macros

    // LOLBins (Living Off The Land Binaries) - Valid tools used maliciously
    { pattern: /certutil|bitsadmin|curl|wget/i, weight: 3 }, // Downloaders
    { pattern: /rundll32|regsvr32|mshta|wscript|cscript/i, weight: 3 }, // Executors
    { pattern: /net user|net group|net localgroup|whoami|ipconfig/i, weight: 3 }, // Recon
    { pattern: /psexec|wmic|winrm|powershell remoting/i, weight: 3 }, // Lateral Movement

    // Cryptomining Indicators
    { pattern: /miner|cryptominer|xmrig|monero|xmr/i, weight: 3 },
    { pattern: /high cpu usage|100% cpu|fan noise|overheating/i, weight: 3 },
    { pattern: /slow performance|laggy|system freeze|unresponsive/i, weight: 3 },

    // Browser Hijacking
    { pattern: /browser extension|unwanted toolbar|search engine changed/i, weight: 3 },
    { pattern: /redirect|redirected|pop-up ads|adware/i, weight: 3 },
    { pattern: /notification spam|allow notifications|click allow/i, weight: 3 },

    // =========================================================================
    // 🟡 WEIGHT 2: LOW PROBABILITY (Generic Symptoms / Noise)
    // =========================================================================
    { pattern: /virus|malware|bug|glitch/i, weight: 2 },
    { pattern: /slow|slow computer|pc is slow/i, weight: 2 },
    { pattern: /weird message|strange error|error code/i, weight: 2 },
    { pattern: /blue screen|bsod|crash|reboot/i, weight: 2 },
    { pattern: /unknown file|suspicious file|weird icon/i, weight: 2 },
    { pattern: /hacked|compromised|infected/i, weight: 2 }, // Vague without proof
    { pattern: /antivirus alert|defender alert|scan detected/i, weight: 2 }
],

  network: [
    // =========================================================================
    // 🚨 WEIGHT 5: CRITICAL INDICATORS (Attacks & Total Outages)
    // =========================================================================
    // Denial of Service (DoS/DDoS)
    { pattern: /ddos|distributed denial of service|dos attack|volumetric attack/i, weight: 5 },
    { pattern: /syn flood|udp flood|icmp flood|ping flood|slowloris/i, weight: 5 },
    { pattern: /amplification attack|reflection attack|ntp amplification|dns amplification/i, weight: 5 },
    { pattern: /botnet traffic|mirai|loic|hoic|traffic spike/i, weight: 5 },
    { pattern: /rate limit exceeded|scrubbing center|blackhole routing|null route/i, weight: 5 },

    // Man-in-the-Middle & Spoofing
    { pattern: /mitm|man in the middle|arp poisoning|arp spoofing/i, weight: 5 },
    { pattern: /dns spoofing|dns poisoning|cache poisoning|rogue dhcp/i, weight: 5 },
    { pattern: /ssl stripping|downgrade attack|hsts missing|invalid cert/i, weight: 5 },
    { pattern: /session hijacking|cookie stealing|sidejacking|evil twin/i, weight: 5 },
    { pattern: /mac spoofing|ip spoofing|source address spoofing/i, weight: 5 },

    // Reconnaissance & Scanning
    { pattern: /port scan|nmap|masscan|zenmap|angry ip scanner/i, weight: 5 },
    { pattern: /vulnerability scan|nessus|qualys|openvas|reconnaissance/i, weight: 5 },
    { pattern: /network mapping|network discovery|ping sweep|host discovery/i, weight: 5 },
    { pattern: /wireshark|tcpdump|pcap|packet capture|sniffing/i, weight: 5 },

    // Tunneling & Exfiltration
    { pattern: /dns tunneling|iodine|dnscat|tunneling traffic/i, weight: 5 },
    { pattern: /icmp tunneling|data exfiltration via dns|covert channel/i, weight: 5 },
    { pattern: /tor traffic|onion routing|exit node|dark web connection/i, weight: 5 },
    { pattern: /proxy avoidance|vpn bypass|shadow it vpn|ultrasurf/i, weight: 5 },

    // =========================================================================
    // 🔴 WEIGHT 4: HIGH PROBABILITY (Infrastructure & Routing)
    // =========================================================================
    // Routing Protocols (BGP/OSPF/EIGRP)
    { pattern: /bgp|border gateway protocol|route leak|route hijacking/i, weight: 4 },
    { pattern: /ospf|eigrp|rip|isis|routing loop|routing table/i, weight: 4 },
    { pattern: /neighbor down|peer down|adjacency lost|route flapping/i, weight: 4 },
    { pattern: /mpls|label switching|vrf|virtual routing forwarding/i, weight: 4 },
    { pattern: /next hop|gateway unreachable|no route to host/i, weight: 4 },

    // Firewall & Security Appliances
    { pattern: /firewall|palo alto|fortinet|cisco asa|checkpoint|sonicwall/i, weight: 4 },
    { pattern: /acl|access control list|deny rule|block rule|implicit deny/i, weight: 4 },
    { pattern: /waf|web application firewall|cloudflare|akamai|imperva/i, weight: 4 },
    { pattern: /ids|ips|intrusion detection|intrusion prevention|snort|suricata/i, weight: 4 },
    { pattern: /vpn tunnel|ipsec|ikev2|phase 1|phase 2|vpn down/i, weight: 4 },
    
    // Switching & Physical Layer
    { pattern: /spanning tree|stp|bpdu|broadcast storm|switching loop/i, weight: 4 },
    { pattern: /vlan|trunk port|access port|802.1q|tagging mismatch/i, weight: 4 },
    { pattern: /mac address table|cam table|mac flapping|port security/i, weight: 4 },
    { pattern: /link flapping|interface flapping|cable fault|sfp error/i, weight: 4 },
    { pattern: /poe|power over ethernet|switchport|stack member/i, weight: 4 },

    // =========================================================================
    // 🟠 WEIGHT 3: MEDIUM PROBABILITY (Protocols & Errors)
    // =========================================================================
    // DNS & DHCP
    { pattern: /dns|domain name system|nslookup|dig|name resolution/i, weight: 3 },
    { pattern: /nxdomain|servfail|record not found|dns timeout/i, weight: 3 },
    { pattern: /dhcp|dora process|lease expired|ip conflict|static ip/i, weight: 3 },
    { pattern: /subnet mask|default gateway|cidr|ipv4|ipv6/i, weight: 3 },

    // TCP/IP & Transport
    { pattern: /tcp handshake|syn|ack|fin|rst|connection reset/i, weight: 3 },
    { pattern: /udp|datagram|connection refused|port closed/i, weight: 3 },
    { pattern: /packet loss|retransmission|window size|buffer bloat/i, weight: 3 },
    { pattern: /mtu|maximum transmission unit|fragmentation|jumbo frames/i, weight: 3 },
    { pattern: /latency|rtt|round trip time|ping|traceroute/i, weight: 3 },

    // Wireless (Wi-Fi)
    { pattern: /ssid|access point|wlc|wireless controller|beacon/i, weight: 3 },
    { pattern: /802.1x|radius|wpa2|wpa3|eap|peap|supplicant/i, weight: 3 },
    { pattern: /signal strength|rssi|snr|channel interference|roaming/i, weight: 3 },
    { pattern: /captive portal|guest network|rogue ap|adhoc network/i, weight: 3 },

    // Load Balancing & Proxy
    { pattern: /load balancer|f5|big-ip|nginx|haproxy|alb|nlb/i, weight: 3 },
    { pattern: /proxy server|forward proxy|reverse proxy|squid/i, weight: 3 },
    { pattern: /502 bad gateway|503 service unavailable|504 gateway timeout/i, weight: 3 },
    { pattern: /ssl handshake|tls version|cipher suite|certificate expired/i, weight: 3 },

    // =========================================================================
    // 🟡 WEIGHT 2: LOW PROBABILITY (User Symptoms / General Noise)
    // =========================================================================
    // "My Internet is Broken"
    { pattern: /internet is down|no internet|offline|disconnected/i, weight: 2 },
    { pattern: /slow internet|buffering|loading forever|spinning wheel/i, weight: 2 },
    { pattern: /wifi|wi-fi|wireless|connection dropped/i, weight: 2 },
    { pattern: /cant connect|cannot connect|unable to connect/i, weight: 2 },
    { pattern: /website down|page not loading|site unreachable/i, weight: 2 },
    { pattern: /vpn not working|vpn disconnect|remote access/i, weight: 2 },
    { pattern: /teams lag|zoom lag|video freezing|choppy audio/i, weight: 2 },
    
    // Hardware (Could be anything)
    { pattern: /modem|router|switch|cable|ethernet cord/i, weight: 2 },
    { pattern: /unplugged|loose cable|blinking lights|red light/i, weight: 2 },
    { pattern: /reboot|restart router|power cycle/i, weight: 2 }
],

  account: [
    // =========================================================================
    // 🚨 WEIGHT 5: CRITICAL INDICATORS (Attacks & Compromise)
    // =========================================================================
    // Advanced Identity Attacks (AD & Kerberos)
    { pattern: /golden ticket|silver ticket|kerberoasting|as-rep roasting/i, weight: 5 },
    { pattern: /pass the hash|pth attack|pass the ticket|ptt/i, weight: 5 },
    { pattern: /dcsync|mimikatz|lsadump|ntds\.dit|secretsdump/i, weight: 5 },
    { pattern: /skeleton key|sid history injection|adminsdholder/i, weight: 5 },
    { pattern: /domain admin added|enterprise admin added|schema admin/i, weight: 5 },

    // Cloud Identity Attacks (AWS/Azure/GCP)
    { pattern: /impossible travel|geo-velocity|login from distinct locations/i, weight: 5 },
    { pattern: /unusual user agent|tor exit node|anonymous proxy login/i, weight: 5 },
    { pattern: /aws sts|getcalleridentity|iam exfiltration|metadata service/i, weight: 5 },
    { pattern: /azure ad risky user|entra id risk|conditional access failure/i, weight: 5 },
    { pattern: /consent phishing|illicit consent grant|oauth abuse/i, weight: 5 },

    // Brute Force & Stuffing
    { pattern: /credential stuffing|password spray|brute force|dictionary attack/i, weight: 5 },
    { pattern: /hydra|medusa|hashcat|john the ripper|cain and abel/i, weight: 5 },
    { pattern: /multiple failed logins|mass account lockout|account enumeration/i, weight: 5 },
    { pattern: /mfa fatigue|mfa bombing|prompt spam|push harassment/i, weight: 5 },
    { pattern: /failed login attempt threshold|bad password count/i, weight: 5 },

    // Dark Web & Leaks
    { pattern: /leaked credentials|dumped database|pastebin credential/i, weight: 5 },
    { pattern: /haveibeenpwned|breached password|compromised password/i, weight: 5 },
    { pattern: /stolen session cookie|session hijacking|aitm/i, weight: 5 },

    // =========================================================================
    // 🔴 WEIGHT 4: HIGH PROBABILITY (Privilege & Admin Abuse)
    // =========================================================================
    // Privilege Escalation
    { pattern: /privilege escalation|privesc|elevated privileges/i, weight: 4 },
    { pattern: /sudo abuse|root access|uid 0|gid 0|wheel group/i, weight: 4 },
    { pattern: /uac bypass|user account control|run as administrator/i, weight: 4 },
    { pattern: /setuid|setgid|sticky bit|unquoted service path/i, weight: 4 },
    { pattern: /shadow admins|hidden account|backdoor account/i, weight: 4 },

    // PAM (Privileged Access Management)
    { pattern: /cyberark|beyondtrust|thycotic|vault access|break glass/i, weight: 4 },
    { pattern: /psm|privileged session|session recording|jump host/i, weight: 4 },
    { pattern: /rotated password|checkout password|checkin password/i, weight: 4 },
    
    // Suspicious Modifications
    { pattern: /mfa disabled|2fa disabled|security info changed/i, weight: 4 },
    { pattern: /recovery email changed|phone number changed/i, weight: 4 },
    { pattern: /api key created|access key created|secret key/i, weight: 4 },
    { pattern: /service principal added|app registration|managed identity/i, weight: 4 },
    { pattern: /group policy modification|gpo changed|account policy/i, weight: 4 },

    // =========================================================================
    // 🟠 WEIGHT 3: MEDIUM PROBABILITY (SSO & Access Errors)
    // =========================================================================
    // SSO & Federation (Okta/Ping/OneLogin)
    { pattern: /okta|auth0|onelogin|ping identity|duo security/i, weight: 3 },
    { pattern: /sso failure|saml error|oidc|oauth2|assertion failed/i, weight: 3 },
    { pattern: /mfa challenge|authenticator app|yubikey|hardware token/i, weight: 3 },
    { pattern: /redirect loop|too many redirects|session expired/i, weight: 3 },
    { pattern: /conditional access|device compliance|intune|mdm/i, weight: 3 },

    // Permissions & Roles (RBAC/ABAC)
    { pattern: /access denied|permission denied|403 forbidden|unauthorized/i, weight: 3 },
    { pattern: /folder permission|ntfs permission|share permission/i, weight: 3 },
    { pattern: /need access|request access|grant access|revoke access/i, weight: 3 },
    { pattern: /role assignment|rbac|iam role|security group/i, weight: 3 },
    { pattern: /read only|write access|full control|modify/i, weight: 3 },

    // Account Status Codes & Jargon
    { pattern: /account disabled|account expired|password expired/i, weight: 3 },
    { pattern: /useraccountcontrol|badpwdcount|lastlogon|pwdlastset/i, weight: 3 },
    { pattern: /event id 4624|event id 4625|logon failure|logon success/i, weight: 3 },
    { pattern: /account lockout|locked out|unlock account/i, weight: 3 },

    // =========================================================================
    // 🟡 WEIGHT 2: LOW PROBABILITY (User Support / Noise)
    // =========================================================================
    // "I forgot my password"
    { pattern: /forgot password|reset password|password change/i, weight: 2 },
    { pattern: /cant login|cannot login|unable to login|trouble signing in/i, weight: 2 },
    { pattern: /new user|onboarding|create account|setup account/i, weight: 2 },
    { pattern: /termination|offboarding|disable user|delete user/i, weight: 2 },
    { pattern: /username|userid|employee id|login id/i, weight: 2 },
    
    // Generic Identity Terms
    { pattern: /profile|avatar|signature|display name/i, weight: 2 },
    { pattern: /email address|distribution list|mailbox/i, weight: 2 },
    { pattern: /credentials|passphrase|secret question/i, weight: 2 },
    { pattern: /vpn account|wifi account|domain account/i, weight: 2 }
], 
  data_leak: [
    // =========================================================================
    // 🚨 WEIGHT 5: CRITICAL INDICATORS (Confirmed Leaks & Sensitive Data)
    // =========================================================================
    // Secrets & Credentials (Hardcoded)
    { pattern: /api key|apikey|access key|secret key|private key/i, weight: 5 },
    { pattern: /aws_access_key_id|aws_secret_access_key|azure_client_secret/i, weight: 5 },
    { pattern: /google_api_key|stripe_secret_key|slack_api_token/i, weight: 5 },
    { pattern: /begin rsa private key|begin openssh private key|pem file/i, weight: 5 },
    { pattern: /connection string|jdbc:|db_password|redis_password/i, weight: 5 },
    { pattern: /bearer token|authorization header|jwt token|id_token/i, weight: 5 },

    // PII (Personally Identifiable Information)
    { pattern: /ssn|social security number|tax id|tin number/i, weight: 5 },
    { pattern: /driver's license|passport number|national id|voter id/i, weight: 5 },
    { pattern: /date of birth|dob|mother's maiden name|place of birth/i, weight: 5 },
    { pattern: /fingerprint data|biometric data|facial recognition data/i, weight: 5 },

    // PCI (Payment Card Industry)
    { pattern: /credit card|debit card|pan number|card number/i, weight: 5 },
    { pattern: /cvv|cvc|security code|expiration date|magstripe/i, weight: 5 },
    { pattern: /track 1 data|track 2 data|pci dss|cardholder data/i, weight: 5 },
    { pattern: /banking info|routing number|account number|iban|swift/i, weight: 5 },

    // PHI (Protected Health Information - HIPAA)
    { pattern: /medical record|patient id|mrn|diagnosis|treatment plan/i, weight: 5 },
    { pattern: /health insurance|policy number|prescription|medication/i, weight: 5 },
    { pattern: /hipaa violation|phi breach|ephi|patient data/i, weight: 5 },

    // Public Exposure (The "Oops" Moments)
    { pattern: /public bucket|public blob|anonymous access allowed/i, weight: 5 },
    { pattern: /pastebin|gist\.github|trello public|jira public/i, weight: 5 },
    { pattern: /indexed by google|search engine exposure|cache/i, weight: 5 },
    { pattern: /dark web|dumped data|hacker forum|breach data/i, weight: 5 },

    // =========================================================================
    // 🔴 WEIGHT 4: HIGH PROBABILITY (DLP Alerts & Exfiltration)
    // =========================================================================
    // DLP (Data Loss Prevention) Tool Alerts
    { pattern: /dlp alert|policy violation|data loss prevention/i, weight: 4 },
    { pattern: /symantec dlp|forcepoint|zscaler|netskope|mcafee dlp/i, weight: 4 },
    { pattern: /blocked by dlp|quarantined file|sensitive content detected/i, weight: 4 },
    { pattern: /classification label|sensitivity label|mip label|aip label/i, weight: 4 },
    { pattern: /highly confidential|restricted|top secret|internal use only/i, weight: 4 },

    // Physical Exfiltration
    { pattern: /usb drive|flash drive|thumb drive|external hdd|removable media/i, weight: 4 },
    { pattern: /mass storage device|smartphone storage|sd card/i, weight: 4 },
    { pattern: /print job|printed sensitive|printing confidential/i, weight: 4 },
    { pattern: /screenshot|screen capture|snipping tool|camera photo/i, weight: 4 },
    
    // Cloud Exfiltration
    { pattern: /personal email|gmail|yahoo|outlook\.com|hotmail/i, weight: 4 },
    { pattern: /auto-forward|forwarding rule|redirect email|bcc external/i, weight: 4 },
    { pattern: /mega\.nz|mediafire|4shared|rapidgator|zippyshare/i, weight: 4 },
    { pattern: /upload to|uploaded files|file transfer|ftp upload/i, weight: 4 },
    { pattern: /airdrop|bluetooth transfer|nearby share/i, weight: 4 },

    // Insider Threat Indicators
    { pattern: /taking files home|copying files|downloading bulk/i, weight: 4 },
    { pattern: /disgruntled employee|leaving company|resignation|termination/i, weight: 4 },
    { pattern: /unusual volume|mass download|bulk export|database dump/i, weight: 4 },
    { pattern: /steganography|hidden file|changed extension|mimetype mismatch/i, weight: 4 },

    // =========================================================================
    // 🟠 WEIGHT 3: MEDIUM PROBABILITY (Risky Behavior & Apps)
    // =========================================================================
    // Shadow IT / File Sharing
    { pattern: /dropbox|box\.com|onedrive personal|google drive personal/i, weight: 3 },
    { pattern: /wetransfer|sendanywhere|transfernow|filebin/i, weight: 3 },
    { pattern: /slack external|discord|whatsapp|telegram|signal/i, weight: 3 },
    { pattern: /github personal|gitlab personal|bitbucket personal/i, weight: 3 },
    { pattern: /chatgpt|openai|copilot|uploading code to ai/i, weight: 3 },

    // Intellectual Property
    { pattern: /source code|proprietary algorithm|trade secret|schematic/i, weight: 3 },
    { pattern: /customer list|client list|price list|strategy doc/i, weight: 3 },
    { pattern: /merger|acquisition|financial report|quarterly results/i, weight: 3 },
    { pattern: /legal document|contract|nda|non-disclosure/i, weight: 3 },

    // Misconfiguration (Potential Leak)
    { pattern: /s3 bucket|azure blob|gcp bucket|storage account/i, weight: 3 },
    { pattern: /permission changed|made public|acl changed|policy change/i, weight: 3 },
    { pattern: /unencrypted connection|http:|clear text protocol/i, weight: 3 },
    { pattern: /default password|default credentials|admin\/admin/i, weight: 3 },

    // =========================================================================
    // 🟡 WEIGHT 2: LOW PROBABILITY (Generic Terms / Noise)
    // =========================================================================
    // Generic File Terms
    { pattern: /attachment|spreadsheet|excel|csv|pdf/i, weight: 2 },
    { pattern: /report|document|file|presentation|slide/i, weight: 2 },
    { pattern: /zip file|archive|compressed|folder/i, weight: 2 },
    { pattern: /share|shared|sharing|link/i, weight: 2 },
    { pattern: /backup|restore|snapshot|image/i, weight: 2 },

    // Compliance Jargon (Without context)
    { pattern: /gdpr|ccpa|cpra|lgpd/i, weight: 2 },
    { pattern: /compliance|audit|regulatory/i, weight: 2 },
    { pattern: /privacy|data protection|security/i, weight: 2 },
    { pattern: /risk|assessment|policy/i, weight: 2 }
  ]
};

// 2. Critical assets that automatically boost urgency
const CRITICAL_ASSETS = [
  /production|prod|live/i,
  /database|db|sql/i,
  /server|mainframe|domain controller/i,
  /admin|root|superuser/i,
  /finance|hr|executive|ceo|cfo/i
];

const URGENCY_RULES = {
  high: [
    /urgent|immediate|asap|critical|emergency/i,
    /breach|hacked|ransomware|data loss/i,
    /system down|outage|offline/i
  ],
  medium: [
    /error|fail|issue|problem|slow/i,
    /retry|warning|alert/i
  ],
  // Low is the default if no others match
};

export function autoClassify(title = "", description = "") {
  const text = `${title} ${description}`;

  // 1. --- Category Detection ---
  let categoryScores = {};
  let bestCategory = "other";
  let highestScore = 0;
  let matchesFound = [];

  for (const [cat, rules] of Object.entries(CATEGORY_RULES)) {
    categoryScores[cat] = 0;
    rules.forEach(rule => {
      if (rule.pattern.test(text)) {
        categoryScores[cat] += rule.weight;
        matchesFound.push(`${cat} (+${rule.weight})`);
      }
    });

    if (categoryScores[cat] > highestScore) {
      highestScore = categoryScores[cat];
      bestCategory = cat;
    }
  }

  if (highestScore < 2) bestCategory = "other";

  // 2. --- Urgency Detection ---
  let urgency = "low";
  let urgencyReason = "Default priority";

  // A. Check explicit keywords first (e.g. "urgent", "server down")
  if (URGENCY_RULES.high.some(r => r.test(text))) {
    urgency = "high";
    urgencyReason = "Matched high-urgency keywords";
  } else if (URGENCY_RULES.medium.some(r => r.test(text))) {
    urgency = "medium";
    urgencyReason = "Matched medium-urgency keywords";
  }

  // B. 🔥 NEW FIX: If Category Score is 5+ (Critical Indicator), FORCE High Urgency
  if (highestScore >= 5 && urgency !== "high") {
    urgency = "high";
    urgencyReason = `Critical ${bestCategory} indicator detected (Score: ${highestScore})`;
  }
  // C. If Score is 4 (High Probability), ensure at least Medium
  else if (highestScore >= 4 && urgency === "low") {
    urgency = "medium";
    urgencyReason = `High confidence ${bestCategory} indicator detected`;
  }

  // D. Context Boost: Critical Assets (e.g. "Production Server")
  if (CRITICAL_ASSETS.some(r => r.test(text))) {
    if (urgency === "low") urgency = "medium";
    else if (urgency === "medium") urgency = "high";
    urgencyReason += " + Critical Asset Detected";
  }

  return {
    category: bestCategory,
    urgency: urgency,
    score: highestScore,
    reason: urgencyReason,
    matches: matchesFound // Optional: helpful for debugging
  };
}
// ... (Your autoClassify function is here) ...

// 👇 ADD THIS MISSING EXPORT AT THE BOTTOM
export function urgencyToScore(level) {
  const map = { high: 3, medium: 2, low: 1 };
  return map[level] || 1;
}