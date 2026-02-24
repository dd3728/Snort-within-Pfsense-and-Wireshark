# Stage 1 — Basic ICMP Reconnaissance Detection

**Technology:** Snort IDS/IPS on pfSense
<div>
    <img src="https://img.shields.io/badge/-Snort-FF0000?&style=for-the-badge&logo=Snort&logoColor=white" />
</div>

**Objective:** Demonstrate foundational detection capability and traffic visibility

---

## 1. Purpose of This Stage

The objective of this exercise was to validate that:

* Snort is correctly deployed and operational on pfSense
* Custom rules can be written and triggered successfully
* Internal host reconnaissance activity can be detected
* Alerts can be correlated with packet-level evidence

This establishes baseline IDS functionality before moving to prevention and advanced detection.

---

## 2. Custom Snort Rule Implemented

```snort
alert icmp $HOME_NET any -> any any (
    msg:"ANY ICMP Traffic From Internal Network";
    sid:1000003;
    rev:1;
)
```
**screenshot** <div>
    <img src="https://img.shields.io/badge/-Snort-FF0000?&style=for-the-badge&logo=Snort&logoColor=white" />
</div>
https://github.com/dd3728/Snort-within-Pfsense-and-Wireshark/compare/main...dd3728-snort-project-screenshots?expand=1#diff-2e3cd3c7637cfa1e96033cc1683ff0eb706b2d2b26aac25c4d23d7c8fb523358

### Rule Logic Explanation

* **alert icmp** → Monitor ICMP protocol traffic
* **$HOME_NET any → any any** → Trigger when internal hosts send ICMP traffic to any destination
* **sid:1000003** → Unique rule identifier
* **rev:1** → Rule revision tracking

This rule detects outbound ICMP traffic originating from the internal network.

---

## 3. Traffic Generation (Controlled Test)

To simulate reconnaissance activity:

| Source Host    | Action | Target        |
| -------------- | ------ | ------------- |
| 192.168.60.100 | ping   | 8.8.8.8       |
| 192.168.60.100 | ping   | 192.168.60.10 |

**screenshot** <div>
    <img src="https://img.shields.io/badge/-Linux-FCC624?&style=for-the-badge&logo=Linux&logoColor=black" />
</div>
https://github.com/dd3728/Snort-within-Pfsense-and-Wireshark/compare/main...dd3728-snort-project-screenshots?expand=1#diff-932abfbe99ee5765364829ecf51e11a669bdaaa2407d50671043133fdfed3661

### Purpose of Each Test

* **Ping to 8.8.8.8** → Simulates outbound external connectivity check
* **Ping to 192.168.60.10** → Simulates internal host discovery

From a security perspective, ICMP echo requests are commonly used in:

* Host discovery
* Network mapping
* Reconnaissance prior to scanning

---

## 4. Detection Results

### Snort Alert Output

Snort successfully generated alerts corresponding to both ping attempts.

**screenshot-snort-alert-entries** <div>
    <img src="https://img.shields.io/badge/-Snort-FF0000?&style=for-the-badge&logo=Snort&logoColor=white" />
</div>
https://github.com/dd3728/Snort-within-Pfsense-and-Wireshark/compare/main...dd3728-snort-project-screenshots?expand=1#diff-7439db117029dda6072d9a3b3a2933ab246901e05533b09bfa21a0cbb7e604ba

This confirms:

* Rule syntax correctness
* Proper Snort interface monitoring
* Accurate detection of internal ICMP activity

Screenshots were captured as evidence of successful alert triggering.

**screenshot-notepad-downloadedfile** <div>
    <img src="https://img.shields.io/badge/-Notepad-2B91AF?&style=for-the-badge&logo=Notepad&logoColor=white" />
</div>
https://github.com/dd3728/Snort-within-Pfsense-and-Wireshark/compare/main...dd3728-snort-project-screenshots?expand=1#diff-124d137757b9211654611d80442feba61967dbbe2295d7aa8861179c87ec552c

---

## 5. Packet-Level Validation (Wireshark Analysis)

Traffic was simultaneously captured using Wireshark to validate:

* ICMP Echo Request packets (Type 8)
* Source IP: 192.168.60.100
* Destination IP: 8.8.8.8 and 192.168.60.10
* Proper request/response sequence

**screenshot-wireshark-capture-traffic** <div>
    <img src="https://img.shields.io/badge/-Wireshark-1679A7?&style=for-the-badge&logo=Wireshark&logoColor=white" />
</div>
https://github.com/dd3728/Snort-within-Pfsense-and-Wireshark/compare/main...dd3728-snort-project-screenshots?expand=1#diff-84315486259ead48113034c23f07272ca2d76de640c30674a1e3cda6c0a0ae4e

This ensures the alert was triggered by legitimate ICMP packets and not false positives.

---

## 6. Timestamp Correlation

Snort alert timestamps were correlated with:

* Wireshark capture timestamps
* Command execution time

This demonstrates:

* Detection accuracy
* Event timing precision
* Analyst-level validation workflow

Correlation is a critical SOC skill used during incident triage.

---

## 7. Security Relevance

Although basic, this stage demonstrates:

* Understanding of reconnaissance techniques
* Ability to implement custom IDS rules
* Traffic analysis skills
* Validation through multi-source correlation

In real-world SOC environments, reconnaissance detection is the first step in identifying potential intrusion attempts.

---

## 8. Key Skills Demonstrated

* Snort rule creation and deployment
* IDS traffic monitoring on pfSense
* Packet analysis using Wireshark
* Event correlation methodology
* Controlled lab attack simulation
