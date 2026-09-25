# DE-004 — LLMNR/NBT-NS Investigation

On September 25, 2026, an authorized isolated Windows lab test produced suspicious name-resolution replies followed by SMB authentication traffic. A packet capture showed the first answer at 18:26:21.620212 and a TCP SYN from port 59400 to port 445 at 18:26:21.635028 (14.816 milliseconds later). The Windows endpoint's Splunk Sysmon Event ID 3 showed an initiated System connection to TCP 445 using the same source port, timestamped 18:26:24.818. The capture displayed an NTLMSSP exchange and an access-denied result; no successful account access was established. WIN11 Security Event 4648 was absent in the exact one-minute test window.

The initial packet capture was preserved and hashed. A separate active-capture digest was not available for verification. The original captures and account-identifying evidence are kept private. Public examples use 192.169.70.x as a documentation-only placeholder, never as an operational subnet.

## Detection status

The exact-window Splunk SMB hunt returned one matching event. A standalone network alert for suspicious name-resolution replies followed by SMB has not been implemented or validated. Ordinary SMB traffic alone does not prove poisoning.

## Limitations and recommendations

A roughly 3.183-second difference separates the displayed packet and Splunk times; clock and event-time handling have not been independently reconciled. The original screenshots also showed activity involving a VMware host adapter, so exclusive isolation to the disposable endpoint was not demonstrated. Rotate any still-active account whose authentication exchange appeared in the private capture. For production defenses, assess disabling unnecessary LLMNR/NBT-NS, enforcing SMB signing where appropriate, restricting privileged logons on workstations and monitoring unapproved name-resolution responders.

## Technical walkthrough and evidence register

1. **Passive baseline:** Kali captured UDP 5355/137 on the VMware host-only interface. WIN11 attempted access to a deliberately nonexistent UNC hostname. TShark reported repeated LLMNR A/AAAA queries; this baseline did not establish poisoning.
2. **Passive Responder analysis:** Analyze mode observed LLMNR, NBT-NS and mDNS traffic for a second test hostname and ignored those requests. The output included traffic from the VMware host adapter as well as WIN11.
3. **Controlled active test:** Responder's console reported forged responses for the third test hostname. In the saved active PCAP, packets 9–11 included three LLMNR answers, followed by packet 12, an initial TCP SYN from port 59400 to port 445.
4. **SMB and authentication:** The same PCAP showed SMB2 negotiation and an NTLMSSP negotiate/challenge/authenticate sequence, followed by STATUS_ACCESS_DENIED. Keep the original PCAP and full response material private.
5. **Splunk corroboration:** The exact-window WIN11 Sysmon Event ID 3 search returned one initiated System TCP 445 connection using source port 59400. The source port, destination service and responder details matched the PCAP, while the displayed timestamps differed by approximately 3.183 seconds.
6. **Telemetry gap:** WIN11 Security Event 4648 returned no matching events for 18:26–18:27. Do not infer that the authentication exchange was absent.

### Redacted evidence

[Visual event-sequence diagram](evidence/01-event-sequence.svg) · [PCAP / Sysmon correlation diagram](evidence/02-pcap-sysmon.svg)

These are reconstructed diagrams based on the screenshots, **not copies of the original screenshot or PCAP**. Any future public screenshots must be reviewed and redacted before committing.

### Reusable detections

- [DE-004 Sysmon SMB hunt](../../detections/spl/DE-004-sysmon-outbound-smb.spl): exact-window variant observed once; generalized version remains untested.
- [DE-004 network-correlation design](../../detections/network/DE-004-llmnr-to-smb.md): candidate packet-level answer-to-SMB correlation; automatic alert and false-positive testing pending.

### ATT&CK context

T1557.001 describes LLMNR/NBT-NS poisoning and related adversary-in-the-middle behavior. This experiment did **not** demonstrate SMB relay or recovered credentials.
