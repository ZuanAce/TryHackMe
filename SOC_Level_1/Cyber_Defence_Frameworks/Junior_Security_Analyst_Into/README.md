# Junior Security Analyst Intro
> Play through a day in the life of a Junior Security Analyst, their responsibilities and qualifications needed to land a role as an analyst.
> 
> ![image](https://github.com/user-attachments/assets/2dbebe9e-01de-42d5-b291-28b936003d3f)

## Task 1
### A career as a Junior (Associate Security Analyst)
In the Junior Security Analyst role, you will be a Triage Specialist. You will spend a lot of time triaging or monitoring the event logs and alerts.
> [!NOTE]  
> Junior Security Analyst or Tier 1 SOC analyst responsibilities include:
>  - Monitor and Investigate the alerts
>  - Configure and manage security tools
>  - Develope and Implement basic IDS (a device or software application that monitors a network for malicious activity or policy violations) signatures
>  - Participate in SOC working groups, meetings
>  - Create tickets and escalate secrity incidents to Tier 2 and Team Lead if necessary
### Question
What will be your role as a Junior Security Analyst?

`Triage Specialist`

----

## Task 2
### Security Operation Center (SOC)
Definition: Security operations teams are charged with monitoring and protecting many assets, such as intellectual property, personnel data, business systems, and brand integrity. 
As the implementation component of an organisation's overall cyber security framework, security operations teams act as the central point of collaboration in coordinated efforts to monitor, assess, and defend against cyberattacks

Core functions of SOC in cyber realm 24/7:
- investigate
- monitor
- prevent
- respond to threats

What is included in the responsibilities of the SOC:
- Ticketing: Ticketing in a SOC refers to the process of managing and tracking security incidents or events. When a security alert is generated, it is assigned a ticket, and its lifecycle is monitored from detection through investigation, remediation, and closure. The ticketing system ensures proper documentation and follow-up for every security incident.
- Log Collection: Log collection involves gathering logs from various sources (servers, devices, applications, etc.) to monitor, analyze, and investigate potential security threats. Logs provide vital data that help in detecting suspicious activities, identifying vulnerabilities, and ensuring compliance.
- Knowledge Base: The knowledge base is a repository of security information, incident responses, and best practices. It serves as a reference for SOC analysts to understand common attack patterns, procedures for investigating incidents, and solutions for mitigating threats. The knowledge base aids in the quick resolution of incidents and helps in the training of new personnel.
- Research and Development: R&D in a SOC focuses on continuously improving security technologies, tools, and strategies. SOC teams research emerging threats, new attack vectors, and vulnerabilities. They also develop or improve internal processes and technologies to enhance security monitoring and incident response.
- Aggregration and Correleation: Aggregation involves collecting data from multiple sources (e.g., network devices, firewalls, and endpoints) and consolidating it into a centralized location. Correlation is the process of analyzing this data to identify patterns or relationships that may indicate a security threat. 
- Threat Intelligence: Threat intelligence refers to the collection and analysis of information related to current and emerging threats. This can include data on malware, attack patterns, and the tactics, techniques, and procedures (TTPs) of threat actors. Threat intelligence helps SOC teams stay proactive and informed, improving their ability to defend against evolving cyber threats.
- SIEM: SIEM systems aggregate and analyze security data from various sources (logs, devices, etc.) in real time. It helps detect and respond to security incidents by providing insights into network activity, identifying anomalies, and triggering alerts. SIEM is crucial for identifying patterns, compliance reporting, and responding to incidents effectively.
- Reporting: Reporting is the process of documenting security events, incidents, and metrics. SOC teams generate reports for internal stakeholders, management, and compliance purposes. These reports summarize security activity, the status of ongoing incidents, and provide an analysis of the organization's overall security posture.

> [!NOTE]  
> - EDR focuses on endpoint security.
> - SIEM aggregates and analyzes security data from multiple sources.
> - XDR extends detection and response capabilities across multiple security layers for comprehensive threat monitoring.

Preparation and Prevention 
- Stayed informed with the current cyber security threats
- Understand TTPs

Monitoring and Investigation
- SIEM and EDR to monitor suspicious and malicious network activities
- Priotise alerts based in their level

Response
- Actions such as isolating hosts, terminating malicious processes, deleting files, and more
### Question
`No answer needed`

----

## Task 3
### A day In the life of a Junior (Associate) Security Analyst
Daily routine
- Monitor the network traffic, including IPS (Intrusion Prevention System) and IDS (Intrusion Detection System) alerts, suspicious emails
- Extract the forensics data to analyze and detect the potential attacks
- Use open-source intelligence to help you make the appropriate decisions on the alerts.
### Question
1. What was the malicious IP address in the alerts?

   Upon analyzing the alert log, an unauthorized connection attempt was detected originating from the IP address `221.181.185.159`. The attempt targeted port `22`, which is commonly used for Secure Shell (SSH) access.
   SSH port activity, especially unauthorized attempts, is often an indicator of brute-force attacks or other malicious activities, making this incident highly suspicious.

   ![image](https://github.com/user-attachments/assets/11615086-d377-4b15-a915-fa97f16e1bd6)

   To confirm the nature of this IP address, a reputation check was performed using the IP-Scanner.THM tool. The results classified the IP address 221.181.185.159 as malicious. 

   ![image](https://github.com/user-attachments/assets/d33236e1-6dd1-4399-9c48-f53031a3659b)

   Thus, the malicious IP address in the alerts is `221.181.185.159`

2. To whom did you escalate the event associated with the malicious IP address?

   The event was escalated to the SOC Team Lead rather than a Sales Executive, Security Consultant, or Information Security Architect because the SOC Team Lead is directly responsible for managing and responding to security incidents.
   
   ![image](https://github.com/user-attachments/assets/0167a92c-1596-43e7-a72d-e1b87c68ca38)

   Thus, `Will Griffin` is the right answer. 

3. After blocking the malicious IP address on the firewall, what message did the malicious actor leave for you?

   So, all you have to do is to input the malicious IP, then click on Block IP Address. After blocking the malicious IP address `221.181.185.159` on the firewall, a flag was revealed:  `THM{UNTIL-WE-MEET-AGAIN}`

   ![image](https://github.com/user-attachments/assets/7199dbee-807d-4cb0-b57b-c26480d0d1e8)






   



