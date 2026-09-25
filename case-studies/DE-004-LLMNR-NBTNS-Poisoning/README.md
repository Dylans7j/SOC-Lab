# DE-004 — LLMNR/NBT-NS Investigation

On September 25, 2026, an authorized isolated Windows lab test produced suspicious name-resolution replies followed by SMB authentication traffic. A packet capture showed the first answer at 18:26:21.620212 and a TCP SYN from port 59400 to port 445 at 18:26:21.635028 (14.816 milliseconds later). The Windows endpoint's Splunk Sysmon Event ID 3 showed an initiated System connection to TCP 445 using the same source port, timestamped 18:26:24.818. The capture displayed an NTLMSSP exchange and an access-denied result; no successful account access was established. WIN11 Security Event 4648 was absent in the exact one-minute test window.

The initial packet capture was preserved and hashed. A separate active-capture digest was not available for verification. The original captures and account-identifying evidence are kept private. Public examples use 192.169.70.x as a documentation-only placeholder, never as an operational subnet.

## Detection status

The exact-window Splunk SMB hunt returned one matching event. A standalone network alert for suspicious name-resolution replies followed by SMB has not been implemented or validated. Ordinary SMB traffic alone does not prove poisoning.

## Limitations and recommendations

A roughly 3.183-second difference separates the displayed packet and Splunk times; clock and event-time handling have not been independently reconciled. The original screenshots also showed activity involving a VMware host adapter, so exclusive isolation to the disposable endpoint was not demonstrated. Rotate any still-active account whose authentication exchange appeared in the private capture. For production defenses, assess disabling unnecessary LLMNR/NBT-NS, enforcing SMB signing where appropriate, restricting privileged logons on workstations and monitoring unapproved name-resolution responders.
