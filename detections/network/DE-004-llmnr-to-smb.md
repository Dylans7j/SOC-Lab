# DE-004 network analytic — suspicious name-resolution response followed by SMB

**Status: detection design, not tested as an automated alert.**

The primary evidence demonstrates an unexpected LLMNR reply followed by a TCP SYN to SMB port 445 from the same test endpoint. For an automated detection, collect timestamped LLMNR/NBT-NS queries and answers and initial TCP SYN records from the same network sensor.

1. Identify an LLMNR or NBT-NS answer from a host that is not an approved resolver.
2. Link the original querying client to a new TCP SYN **to that responder** on destination port 445 within five seconds.
3. Preserve the queried name, answering host, TCP source port, timestamps and supporting packet identifiers.
4. Add confidence when network telemetry shows NTLMSSP negotiation; record whether the SMB session was accepted or denied.
5. Exclude sanctioned responders, known host adapters, retransmissions and ordinary SMB connections lacking a suspicious preceding response.

**Observed test:** LLMNR answer at 18:26:21.620212; SYN at 18:26:21.635028 (14.816 ms), TCP source port 59400. WIN11 Sysmon also recorded source port 59400 to TCP 445, but with a displayed timestamp about 3.183 seconds later.

**Limitations:** This network analytic has not been run as a saved detection. The generalized SPL companion is a Sysmon SMB hunt, not a poisoning detector. Windows Security 4648 was not observed in the exact attack minute. The primary packet capture and authentication data are retained privately.
