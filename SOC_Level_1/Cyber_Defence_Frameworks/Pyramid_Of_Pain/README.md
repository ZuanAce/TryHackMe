# Pyramid Of Pain
> Learn what is the Pyramid of Pain and how to utilize this model to determine the level of difficulty it will cause for an adversary to change the indicators associated with them, and their campaign.
> 
> ![image](https://github.com/user-attachments/assets/2dbebe9e-01de-42d5-b291-28b936003d3f)

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
   







   



