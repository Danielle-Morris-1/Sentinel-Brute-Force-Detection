# Incident Response - Brute Force Attempt Detection

**Report ID:** INC-2025-189960

**Date:** October 5, 2025

**Analyst:** Danielle Morris 

**Incident ID:** `189960`

**Incident Date and Time:** 10/5/2025, 1:05:02 PM 

**Severity:** **Medium** (Unsuccessful Attack, High Volume of Attempts)

**Status:** **Closed (True Positive)**

---

## Phase 1: Preparation (NIST 800-61)

The following foundational steps were completed prior to the incident to ensure readiness and enable detection:

* **Asset Creation & Onboarding:** Multiple **Virtual Machines (VMs)** were created in Azure and onboarded to **MDE** (Microsoft Defender for Endpoint) to ensure endpoint telemetry (`DeviceLogonEvents`) was collected and forwarded to the **Log Analytics Workspace**.
* **SIEM Configuration:** The Log Analytics Workspace was integrated with **Azure Sentinel** (our **SIEM**).

### 1.1 Detection Rule Development

A **Sentinel Scheduled Query Rule** was created using **KQL** to actively monitor for the brute force attack pattern. This step (and its resulting query) is critical for demonstrating the proactive nature of the security monitoring solution.

* **Rule Logic:** The rule was designed to detect when the same remote IP address failed to log into the same VM a given number of times. The configuration specified a threshold of **10 failed logons or more per 5 hours**.
* **KQL Query Used:** 

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize EventCount = count() by RemoteIP, ActionType, DeviceName
| where EventCount >= 10
| order by EventCount desc
```

---

## Phase 2: Detection and Analysis 

### 2.1 Summary of Detection

The incident began when the Sentinel Scheduled Query Rule successfully triggered an alert, indicating a high-volume brute force attempt targeting multiple VMs via public-facing Remote Desktop Protocol (RDP) ports.

<img width="613" height="279" alt="image" src="https://github.com/user-attachments/assets/642307eb-3cbc-4de9-b1fb-feffcfabc639" />


### 2.2 Targeted Assets 

The investigation confirmed a sustained brute force attack originating from **6 unique public IP addresses**. 

| Device Name (Local Host) | Remote IP | Event Count |
| :--- | :--- | :--- |
| **windows-target-1** | 88.214.50.62 | 95 |
| **linux-target-1.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net** | 161.132.37.66 | 65 |
| **winsb.youngsb.local** | 194.165.16.161 | 37 |
| **winsb.youngsb.local** | 91.238.181.95 | 22 |
| **winsb.youngsb.local** | 194.165.16.164 | 21 |
| **winsb.youngsb.local** | 45.227.254.153 | 18 |

---

<img width="625" height="201" alt="image" src="https://github.com/user-attachments/assets/526dd5c0-1756-4c5c-878a-a9b5b5ae2fb0" />



### 2.3 Validation of Success

A validation query was performed to confirm that the threat actors were **unsuccessful** in gaining unauthorized access.

**KQL Query Used:**
The query filtered the data for successful logons (`ActionType != "LogonFailed"`) from the remote IPs.

```kql
DeviceLogonEvents
| where RemoteIP in ("88.214.50.62","161.132.37.66","194.165.16.161","194.165.16.164","45.227.254.153", "91.238.181.95")
| where ActionType != "LogonFailed"

// Finding: The result was 0, confirming no successful logons occurred.
```

## Phase 3: Containment, Eradication, and Recovery (CER)

This phase focused on immediately limiting the scope of the incident, ensuring the systems were clean, and implementing defensive measures to prevent a recurrence.

### 3.1 Containment 

To immediately halt the remote brute force attempts and prevent any subsequent successful login—should an attacker change tactics or credentials—all affected hosts were isolated from the network.

* **Isolation via MDE:** All three affected Virtual Machines (**VMs**) were placed into **Full Isolation** using **MDE** (Microsoft Defender for Endpoint) capabilities. This action immediately blocks inbound and outbound non-critical communication for the host, effectively stopping any ongoing attack attempts and preventing lateral movement.
* **Duration:** Isolation was maintained until recovery actions (NSG lockdown) were verified as complete.


### 3.2 Eradication 

Since the analysis confirmed the brute force attack was **unsuccessful** (zero successful logons), the primary focus was on ensuring no residual threats existed and removing the vulnerability of weak credentials.

* **Targeted Password Reset:** Passwords for the specific accounts targeted by the brute force attempts (identified via the logs) were immediately **reset**.
* **Strong Password Enforcement:** Strong password policies were universally **enforced** across the domain for all privileged accounts, eliminating the simple guess-work opportunity for future attacks.
* **Anti-Malware Scan:** A comprehensive, full **anti-malware scan** was initiated on all three isolated devices via **MDE**. All scans returned clean results, confirming the systems were free of malware related to this incident.

### 3.3 Recovery 

The recovery effort focused on removing the root cause vulnerability (public-facing RDP) and implementing layers of preventative defense for user accounts.

* **Network Security Group (NSG) Hardening:**
    * The **NSG** attached to the Virtual Machines was modified to **permanently block all RDP access from the public internet**.
    * The NSG was configured to only allow RDP traffic from known, trusted source IPs (e.g., corporate VPN subnet or a hardened jump box).
* **MFA Enforcement:** **Multi-Factor Authentication (MFA)** was **enabled** and enforced for all high-value and privileged accounts. This mitigates the risk of any future credential stuffing or brute force attack succeeding.
* **Geo-blocking Implemented:** Login attempts originating from identified **high-risk geolocations** were blocked at the firewall/gateway level to further reduce the external attack surface.
* **System Verification:** The VMs were successfully restored from isolation once the NSG changes and account hardening were validated, and their services were verified to be functioning normally under the new security configuration.

### 3.4 Closure

The incident was formally closed in Sentinel.

<img width="345" height="261" alt="image" src="https://github.com/user-attachments/assets/6812ea41-f9f9-4ae1-82f9-b94f8d867226" />

**Closure Rationale:**
Evidence of a high-volume brute force attempt was found, confirming a **True Positive** for suspicious activity. The attack was unsuccessful, and all necessary containment, eradication, and preventative measures (NSG lockdown, MFA, and policy proposals) have been implemented to mitigate the risk of recurrence.


## Phase 4: Post-Incident Activity 

This final phase focuses on learning from the incident, ensuring documentation is complete, and implementing long-term policy changes to prevent similar events in the future.

### 4.1 Lessons Learned and Policy Recommendations

* **Security Policy Proposed:** A formal **corporate policy** was proposed to mandate immediate changes in deployment practices to eliminate the attack vector. This policy requires that all new **VMs** must have their **NSGs** strictly configured to prevent public-facing **RDP** access by default.
* **Enforcement Mechanism:** This security control will be enforced efficiently at scale using **Azure Policy**, ensuring compliance and preventing engineers from accidentally leaving RDP ports open to the public internet during configuration.
* **Detection Improvement:** The brute-force detection rule (Sentinel Scheduled Query Rule) was reviewed and confirmed to be effective (True Positive). No immediate tuning was required for the rule itself.
* **Process Improvement:** The response confirmed the effectiveness of **MDE** isolation and **NSG** hardening as rapid containment strategies.


---

  
