# Pyramid Of Pain
> Learn what is the Pyramid of Pain and how to utilize this model to determine the level of difficulty it will cause for an adversary to change the indicators associated with them, and their campaign.
> 
> ![image](https://github.com/user-attachments/assets/85ed21a6-d521-4048-a7ee-a3ced92ab35f)

## Task 1
### Introduction
This well-renowned concept is being applied to cybersecurity solutions like Cisco Security, 
SentinelOne, and SOCRadar to improve the effectiveness of CTI (Cyber Threat Intelligence), threat hunting, and incident response exercises.

Understanding the Pyramid of Pain concept as a Threat Hunter, Incident Responder, or SOC Analyst is important.

![image](https://github.com/user-attachments/assets/98271453-619a-45e6-9a5f-7dd1bef059f1)

----

## Task 2
### Hash Value (Trivial)
Hash value: a numeric value of a fixed length that uniquely identifies data. A hash value is the result of a
hashing algorithm. The following are some of the most common hashing algorithms:
- **MD5**: was designed by Ron Rivest in 1992 and is a widely used cryptographic hash function with a 128-bit hash value. MD5 hashes are NOT considered cryptographically secure.
- **SHA-1**: was invented by United States National Security Agency in 1995. When data is fed to SHA-1 Hashing Algorithm, SHA-1 takes an input and produces a 160-bit hash value string as a 40 digit hexadecimal number. NIST deprecated the use of SHA-1 in 2011 and banned its use for digital signatures at the end of 2013 based on it being susceptible to brute-force attacks. Instead, NIST recommends migrating from SHA-1 to stronger hash algorithms in the SHA-2 and SHA-3 families.
- **SHA-2**: was designed by The National Institute of Standards and Technology (NIST) and the National Security Agency (NSA) in 2001 to replace SHA-1. SHA-2 has many variants, and arguably the most common is SHA-256. The SHA-256 algorithm returns a hash value of 256-bits as a 64 digit hexadecimal number.

It is really easy to spot a malicious file if we have the hash in our arsenal.  
However, as an attacker, modifying a file by even a single bit is trivial, which would produce a different hash value. 
With so many variations and instances of known malware or ransomware, threat hunting using file hashes as the IOC (Indicators of Compromise) can become difficult.

An example of how you can change the hash value of a file by simply appending a string to the end of a file using `echo`:
- File Hash (Before Modification)
  ```bash
  PS C:\Users\THM\Downloads> Get-FileHash .\OpenVPN_2.5.1_I601_amd64.msi -Algorithm MD5
  Algorithm Hash                             Path
  _________ ____                             ____
  MD5       D1A008E3A606F24590A02B853E955CF7 C:\Users\THM\Downloads\OpenVPN_2.5.1_I601_amd64.msi
  ```
- File Hash (After Modification)
  ```bash
  PS C:\Users\THM\Downloads> echo "AppendTheHash" >> .\OpenVPN_2.5.1_I601_amd64.msi
  PS C:\Users\THM\Downloads> Get-FileHash .\OpenVPN_2.5.1_I601_amd64.msi -Algorithm MD5
  Algorithm Hash                             Path
  _________ ____                             ____
  MD5       9D52B46F5DE41B73418F8E0DACEC5E9F C:\Users\THM\Downloads\OpenVPN_2.5.1_I601_amd64.msi
  ```
### Question
1. Analyse the report associated with the hash `b8ef959a9176aef07fdca8705254a163b50b49a17217a4ff0107487f59d4a35d` here. What is the filename of the sample?

   To find the filename of the sample, visit VirusTotal and paste the given hash:

   ![image](https://github.com/user-attachments/assets/9f51adb5-cb96-48a9-9d80-971b79ec8315)

   Thus, the filename of the sample is `Sales_Receipt 5606.xls`.

----

## Task 3
### IP Address (Easy)
An IP address is used to identify any device connected to a network.
These devices range from desktops, to servers and even CCTV cameras! 
We rely on IP addresses to send and receive the information over the network. 
As a part of the Pyramid of Pain, we’ll evaluate how IP addresses are used as an indicator.

From a defense standpoint, knowledge of the IP addresses an adversary uses can be valuable.
A common defense tactic is to block, drop, or deny inbound requests from IP addresses on your parameter or external firewall. 
This tactic is often not bulletproof as it’s trivial for an experienced adversary to recover simply by using a new public IP address.

One of the ways an adversary can make it challenging to successfully carry out IP blocking is by using **Fast Flux**.
Fast Flux is a DNS technique used by botnets to hide phishing, web proxying, malware delivery, and malware communication activities behind compromised hosts acting as proxies.
The purpose of using the Fast Flux network is to make the communication between malware and its command and control server (C&C) challenging to be discovered by security professionals. 

So, the primary concept of a Fast Flux network is having multiple IP addresses associated with a domain name, which is constantly changing. 
Palo Alto created a great fictional scenario to explain Fast Flux:
[Fast Flux 101: How Cybercriminals Improve the Resilience of Their Infrastructure to Evade Detection and Law Enforcement Takedowns](https://unit42.paloaltonetworks.com/fast-flux-101/)

Read the following report (generated from any.run) for this sample [here](https://assets.tryhackme.com/additional/pyramidofpain/task3-anyrun.pdf) to answer the questions below:

### Question
1. What is the first IP address the malicious process (PID 1632) attempts to communicate with?

   To identify this, open the report and review the network activity section. Look for the connections initiated by the process.
   Upon examining the report, it is clear that the first connection is made to `50.87.136.52:443`, which is associated with the domain `craftingalegacy.com`.
   
   ![image](https://github.com/user-attachments/assets/40dd3a55-67bb-4fd7-976a-2a754109505c)

   **Answer:** `50.87.136.52`

2. What is the first domain name the malicious process ((PID 1632) attempts to communicate with?

   As stated in Question 1, it is clear that the first connection is made to `50.87.136.52:443`, which is associated with the domain `craftingalegacy.com`.

   **Answer:** `craftingalegacy.com`

----

## Task 4
### Domain Names (Simple)
Domain name: mapping an IP address to a string of text. A domain name can contain a domain and a top-level domain (evilcorp.com) or a sub-domain followed by a domain and top-level domain (tryhackme.evilcorp.com). 

Domain Names can be a little more difficult for attackers to change as they would most likely need to purchase the domain, register it and modify DNS records. Unfortunately for defenders, many DNS providers have loose standards and provide APIs to make it even easier for the attacker to change the domain.

Punnycode: a way of converting words that cannot be written in ASCII, into a Unicode ASCII encoding.

Internet Explorer, Google Chrome, Microsoft Edge, and Apple Safari are now pretty good at translating the obfuscated characters into the full Punycode domain name.

To detect malicious domains, proxy logs or web server logs can be used.

Attackers usually hide the malicious domains under URL shorteners. A URL Shortener is a tool that creates a short and unique URL that will redirect to the specific website specified during the initial step of setting up the URL Shortener link. 

> [!TIP]
> Viewing Connections in Any.run
> HTTP Requests: useful to see what resources are being retrieved from a webserver, such as a dropper or a callback.
> 
> Connections: useful to see if a process communicates with another host. For example, this could be C2 traffic, uploading/downloading files over FTP, etc.
>
> DNS Requests: Malware often makes DNS requests to check for internet connectivity (I.e. if It can't reach the internet/call home, then it's probably being sandboxed or is useless).  

Go to [this report on app.any.run](https://app.any.run/tasks/a66178de-7596-4a05-945d-704dbf6b3b90) to answer the questions for this task.

### Question
1. Provide the first suspicious domain request you are seeing.

   ![image](https://github.com/user-attachments/assets/f51bfe16-d555-41b6-a42f-8e8a84795a99)

   **Answer**: `craftingalegacy.com`

2. What term refers to an address used to access websites?

   **Answer**: `Domain Name`

3. What type of attack uses Unicode characters in the domain name to imitate the a known domain?

   **Answer**: `Punnycode attack`

4. Provide the redirected website for the shortened URL using a preview: https://tinyurl.com/bw7t8p4u

   Using [CheckShortURL](https://checkshorturl.com/) allows you to preview the final destination of a shortened link without visiting it.

   ![image](https://github.com/user-attachments/assets/d34924e4-3ab4-421e-b2d8-fe7317b341a2)

   **Answer:** `https://tryhackme.com/`

## Task 5
### Host Artifacts (Annoying)
Host artifacts are the traces or observables that attackers leave on the system, such as registry values, suspicious process execution, attack patterns or IOCs (Indicators of Compromise), files dropped by malicious applications, or anything exclusive to the current threat.

Examples: 
- Suspicious process execution from Word
- Suspicious events followed by opening a malicious application
- Files modified/dropped by the malicious actor

A security vendor has analysed the malicious sample for us. Review the report [here](https://assets.tryhackme.com/additional/pyramidofpain/task5-report.pdf) to answer the following questions.

### Question
1. A process named **regidle.exe** makes a POST request to an IP address based in the United States (US) on **port 8080**. What is the IP address?

   By reviewing the network activity and filtering for POST requests to US-based IP addresses on port 8080, it was determined that the IP address is 96.126.101.6.

   ![image](https://github.com/user-attachments/assets/847a9cd1-e628-455b-9fa4-b8c5ecb06b20)

   **Answer**:`96.126.101.6`

2. The actor drops a malicious executable (EXE). What is the name of this executable?

   Reviewing page 4 of the report under behavioral activities reveals that an executable file was dropped shortly after the process started. The file is named `G_jugk.exe` (PID: 1640).
   
   ![image](https://github.com/user-attachments/assets/dab8109f-734f-44e8-9ca6-fc2ffca2d686)

   **Answer**: `G_jugk.exe`

3. Look at this [report](https://assets.tryhackme.com/additional/pyramidofpain/vtotal2.png) by Virustotal. How many vendors determine this host to be malicious?

   ![image](https://github.com/user-attachments/assets/259003b2-cc9b-4668-a258-6ce25e84f011)

   **Answer**: `9`

## Task 6
### Network Artifacts (Annoying)
A network artifact can be a user-agent string, C2 information, or URI patterns followed by the HTTP POST requests.An attacker might use a User-Agent string that hasn’t been observed in your environment before or seems out of the ordinary. The User-Agent is defined by RFC2616 as the request-header field that contains the information about the user agent originating the request.

Network artifacts can be detected in Wireshark PCAPs (file that contains the packet data of a network) by using a network protocol analyzer such as `TShark` or exploring IDS (Intrusion Detection System) logging from a source such as `Snort`.

### Question
1. What browser uses the User-Agent string shown in the screenshot above?

   To determine the browser, search for the `User-Agent string Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)` online.

   By referencing [user-agents.net](https://user-agents.net/string/mozilla-4-0-compatible-msie-7-0-windows-nt-6-1-trident-7-0-slcc2-net-clr-2-0-50727-net-clr-3-5-30729-net-clr-3-0-30729-media-center-pc-6-0-net4-0c-net4-0e-tablet-pc-2-0-mozilla-4-0-compatible-msie-7-0-windows-nt-6-1-99790119bd400a023a3a94bd86a8d6a3ba940dde), it is confirmed that the browser in question is Internet Explorer.

   ![image](https://github.com/user-attachments/assets/431525b8-b3d3-4f15-9150-494dcad20291)

   **Answer**: `Internet Explorer`

2. How many POST requests are in the screenshot from the pcap file?

   ![image](https://github.com/user-attachments/assets/9d15b311-c04d-4b14-b2f9-e8b0c440362b)

   **Answer**: `6`

## Task 7
### Tools (Challenging)
The attacker would most likely give up trying to break into your network or go back and try to create a new tool that serves the same purpose. It will be a game over for the attackers as they would need to invest some money into building a new tool (if they are capable of doing so), find the tool that has the same potential, or even gets some training to learn how to be proficient in a certain tool. 

Attackers would use the utilities to create malicious macro documents (maldocs) for spearphishing attempts, a backdoor that can be used to establish C2 (Command and Control Infrastructure), any custom .EXE, and .DLL files, payloads, or password crackers.

Antivirus signatures, detection rules, and YARA rules can be great weapons to use against attackers at this stage.

**MalwareBazaar** and **Malshare** are good resources to provide access to the samples, malicious feeds, and YARA results - these all can be very helpful when it comes to threat hunting and incident response. 

For detection rules, **SOC Prime Threat Detection Marketplace** is a great platform, where security professionals share their detection rules for different kinds of threats including the latest CVE's that are being exploited in the wild by adversaries. 

**Fuzzy hashing** is also a strong weapon against the attacker's tools. Fuzzy hashing helps you to perform similarity analysis - match two files with minor differences based on the fuzzy hash values. One of the examples of fuzzy hashing is the usage of **SSDeep**; on the **SSDeep** official website, you can also find the complete explanation for fuzzy hashing. 

### Question
1. Provide the method used to determine similarity between the files.

   **Answer**: `Fuzzy Hashing`

2. Provide the alternative name for fuzzy hashes without the abbreviation.

   **Answer**: `context triggered piecewise hashes`

## Task 8
### TTPs (Tough)
TTPs stands for Tactics, Techniques & Procedures. This includes the whole **MITRE ATT&CK Matrix**, which means all the steps taken by an adversary to achieve his goal, starting from phishing attempts to persistence and data exfiltration. 

If you can detect and respond to the TTPs quickly, you leave the adversaries almost no chance to fight back.

### Question
1. Navigate to ATT&CK Matrix webpage. How many techniques fall under the Exfiltration category?

   ![image](https://github.com/user-attachments/assets/f396ecc9-71fc-457b-884f-75f531e7d625)

   **Answer**: `9`
   
2. Chimera is a China-based hacking group that has been active since 2018. What is the name of the commercial, remote access tool they use for C2 beacons and data exfiltration?

   To find this information, navigate to the MITRE ATT&CK Framework, specifically:
   - Exfiltration > Exfiltration Over C2 Channel (T1041) > Look for details about Chimera (ID: G0114).

   ![image](https://github.com/user-attachments/assets/263ff74d-cf28-4561-b9d3-cfb32bf761b9)

   **Answer**: `Cobalt Strike`

## Task 9
### Practical: The Pyramid of Pain
Deploy the static site attached to this task and place the prompts into the correct tiers in the pyramid of pain! Complete the static site. What is the flag?
- Tools: The attacker has utilised these to accomplish their objective.
- TTP: The attackers plans and objectives.
- Hash values: These signatures can be used to attribute payloads and artefacts to an actor.
- Domain Names: An attacker has purchased this and used it in a typo-squatting campaign.
- IP addresses: These addresses can be used to identify the infrastructure an attacker is using for their campaign.
- Network: These artifacts can present themselves as C2 traffic for example.

Flag: `THM{PYRAMIDS_COMPLETE}`


