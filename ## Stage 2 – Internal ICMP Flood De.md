## Stage 2 – Internal ICMP Flood Detection (Lateral Movement / DoS Simulation)

* I implemented rate-based IDS detection using Snort on pfSense.
* I simulated internal ICMP flood attacks using both native Linux utilities and hping3.
* I validated detection through packet-level inspection in Wireshark.
* I confirmed correlation between packet capture and IDS alert generation.
* I demonstrated layered detection: protocol-level + behavioral thresholding.
* I validated detection accuracy with zero false positives during controlled testing.

### 1. Objective

The purpose of this stage was to move beyond basic ICMP visibility (Stage 1) and demonstrate **rate-based detection of abnormal internal ICMP activity**, simulating:

* Internal reconnaissance
* Lateral movement probing
* ICMP-based denial-of-service (DoS) conditions

This was achieved using a custom Snort rule deployed on **pfSense (Snort IDS mode)** and validated using controlled attack simulations from a Kali Linux host.

---

### 2. Custom Snort Rule Implemented

```snort
# Internal ICMP Flood Detection (Lateral Movement / Abuse)

alert icmp $HOME_NET any -> any any (
    msg:"Internal ICMP Flood Detected - Possible Recon or DoS";
    itype:8;
    detection_filter:track by_src, count 50, seconds 1;
    sid:1000011;
    rev:1;
)
```

### Rule Logic Breakdown

| Component             | Purpose                                |
| --------------------- | -------------------------------------- |
| `alert icmp`          | Inspect ICMP traffic                   |
| `itype:8`             | Match ICMP Echo Request (ping)         |
| `track by_src`        | Track packet rate per source IP        |
| `count 50, seconds 1` | Trigger alert if ≥50 pings in 1 second |
| `sid:1000011`         | Unique rule identifier                 |

**Detection Strategy:**
This rule identifies **high-frequency ICMP Echo Requests** originating from a single internal source — behavior commonly associated with:

* Ping sweeps
* Host discovery bursts
* Internal DoS attempts
* Automated reconnaissance tools

---

## 3. Attack Simulation #1 – Fast Ping (Controlled Flood)

### Command Executed (Kali Linux)

```
ping -f -i 0.002 192.168.60.100
```

### Observed Statistics

* 21,552 packets transmitted
* 0% packet loss
* ~2ms interpacket gap
* Sustained high-rate ICMP transmission

### Wireshark Observations

From the capture:

* Continuous ICMP Echo Requests (Type 8)
* Rapid sequence increments
* Identical source/destination pairing:

  * Source: 192.168.60.40
  * Destination: 192.168.60.100
* TTL stable at 64 (typical Linux default)
* High packet density within sub-second timeframes

**Interpretation:**
This is a classic **high-speed ICMP flood** generated using native OS tools. Even though packet loss was 0%, the rate exceeded normal administrative ping behavior.

### Snort IDS Result

The rule triggered multiple alerts:

> **"Internal ICMP Flood Detected – Possible Recon or DoS"**

This confirms:

* Detection filter threshold (50 packets/sec) was exceeded.
* Rate-based anomaly detection worked as intended.
* Snort correctly correlated packets per source IP.

---

## 4. Attack Simulation #2 – hping3 ICMP Flood

### Command Executed

```
sudo hping3 --icmp --flood 192.168.60.100
```

### Observed Statistics

* 315,219 packets transmitted
* 100% packet loss
* Flood mode enabled (no rate limiting)

### Behavioral Difference from Standard Ping

| Standard Ping       | hping3 Flood                   |
| ------------------- | ------------------------------ |
| Controlled interval | No interval control            |
| Replies expected    | No reply tracking              |
| OS-dependent rate   | Tool-driven maximum throughput |

This is significantly more aggressive and mimics real-world attack tooling.

### Wireshark Observations

* Extremely dense ICMP packet stream
* No meaningful spacing between frames
* Same ICMP Type 8 (Echo Request)
* Sustained packet saturation behavior

This pattern resembles internal DoS conditions.

### Snort IDS Result

Snort generated:

* Multiple `sid:1000011` alerts
* High-frequency alert logging
* Clear indication of rate-based ICMP abuse

Additionally, your screenshots show:

* `ANY ICMP Traffic From Internal Network`
* `Internal ICMP Flood Detected - Possible Recon or DoS`

This confirms:

1. Baseline ICMP rule (Stage 1) still functioning.
2. Advanced flood-detection rule triggering as designed.
3. Layered detection capability is operational.

---

## 5. What the Screenshots Demonstrate

### Wireshark Screenshot

* High-volume ICMP Echo Requests
* Sequential packet numbers with microsecond deltas
* Frame sizes consistent (60 bytes)
* Clear source/destination mapping
* Confirms attack behavior at packet level

### Snort Alert Screenshot

* Repeated alerts tied to SID 1000011
* Correct source IP attribution (attacking host-Kali)
* Correct internal network visibility
* No false positives observed from normal traffic

This validates:

* Signature accuracy
* Threshold tuning effectiveness
* Internal lateral movement detection capability

---

## 6. Security Significance

This stage demonstrates:

* Ability to detect abnormal traffic rates
* Behavioral-based detection (not just protocol matching)
* Internal threat visibility (east-west traffic)
* Early warning of DoS attempts
* Detection of reconnaissance bursts

In real enterprise environments, this type of detection helps identify:

* Compromised internal hosts
* Malware beaconing or scanning
* Insider abuse
* Automated discovery activity before lateral movement escalation