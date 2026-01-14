# Automotive-Cybersecurity-Projects


This repository contains a collection of practical, hands-on automotive cybersecurity projects developed to demonstrate skills across vehicle networking, diagnostics, threat modelling, embedded security, and automotive communication protocols.

These projects are highly relevant to roles in:

* Automotive Cybersecurity Engineering

* Embedded Security Engineering

* AUTOSAR Security

* ECU Development

* Cyber-Physical Systems

* Automotive R&D

Each project is self-contained and includes documentation, code, and example outputs.

📁 Projects Included
-----------------------------------------------------------------
1. UDS Security Access Tool
   STATUS: Completed ✅

**Folder:** `uds-security-access-tool/`  
**Docs:** See the `README.md` inside the project folder.

A Python implementation of key UDS routines over UDP (educational transport), including:

- **0x10 Diagnostic Session Control**
- **0x27 SecurityAccess (Seed/Key)**: Level 1 + Level 2
- **Session restriction for SecurityAccess** → NRC `0x22`
- **Brute-force & lockout protections**
  - Invalid key → NRC `0x35`
  - Exceeded attempts → NRC `0x36`
  - Required time delay not expired → NRC `0x37`

Demonstrates understanding of **seed/key flows**, **ECU state machines**, and **basic protection behaviors**.

---

 2. CAN Bus Intrusion Detection System (IDS)
    STATUS: In Progress
    
A lightweight IDS that analyses CAN traffic logs and detects anomalies using statistical methods and simple ML-based techniques. Demonstrates vehicle network security fundamentals.

Folder: can-bus-ids/

 3. DoIP ECU Discovery Tool
    STATUS: Planned
    
A simple Diagnostics over IP (DoIP) scanner for discovering ECUs over automotive Ethernet and parsing diagnostic headers. Shows experience with modern automotive communication protocols.

Folder: doip-scanner/

 4. SOME/IP Fuzzing Tool
    STATUS: Planned
    
A Python-based fuzzer for SOME/IP, targeting service discovery and message structures. Useful for demonstrating automotive network security assessment techniques.

Folder: someip-fuzzer/

 5. ISO 21434 TARA Example
    STATUS: In Progress
    
A complete cybersecurity Threat Analysis & Risk Assessment (TARA) using the HEAVENS 2.0 methodology. Shows familiarity with cybersecurity processes and automotive standards.

Folder: iso21434-tara/


🔧 Tech Stack
-----------------------------------------------------------------
* Python (data parsing, automation, prototyping)

* CAN bus tooling (python-can, cantools)

* Networking (UDP/TCP, DoIP, SOME/IP)

* ISO 21434 cybersecurity processes

* Basic ML for anomaly detection
  

🎯 Goals 
-----------------------------------------------------------------
* Build a strong foundation in automotive cybersecurity

* Demonstrate hands-on capability to employers

* Create a portfolio of practical, industry-relevant work

* Prepare for advanced topics (embedded security, AV security, adversarial ML)

* Document learning in an organised, professional way

📫 Author
-----------------------------------------------------------------
Bahieradan

Automotive Cybersecurity & Embedded Systems Engineer

LinkedIn: https://www.linkedin.com/in/bahieradan/
