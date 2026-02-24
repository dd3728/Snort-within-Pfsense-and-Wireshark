# Stage 1 — Basic ICMP Reconnaissance Detection

**Technology:** Snort IDS/IPS on pfSense
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

This confirms:

* Rule syntax correctness
* Proper Snort interface monitoring
* Accurate detection of internal ICMP activity

Screenshots were captured as evidence of successful alert triggering.

---

## 5. Packet-Level Validation (Wireshark Analysis)

Traffic was simultaneously captured using Wireshark to validate:

* ICMP Echo Request packets (Type 8)
* Source IP: 192.168.60.100
* Destination IP: 8.8.8.8 and 192.168.60.10
* Proper request/response sequence

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