# Official Wireshark Notes

This file distills the official Wireshark and TShark documentation into a few high-value rules for the skill. Use it when a statistic or workflow seems ambiguous.

## Sources

- Wireshark User's Guide: Protocol Hierarchy
  - <https://www.wireshark.org/docs/wsug_html_chunked/ChStatHierarchy.html>
- Wireshark User's Guide: Endpoints
  - <https://www.wireshark.org/docs/wsug_html_chunked/ChStatEndpoints.html>
- Wireshark User's Guide: Conversations
  - <https://www.wireshark.org/docs/wsug_html_chunked/ChStatConversations.html>
- Wireshark User's Guide: Expert Information
  - <https://www.wireshark.org/docs/wsug_html_chunked/ChAdvExpert.html>
- Wireshark User's Guide: Display Filters
  - <https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html>
- TShark Manual: `follow` stream syntax
  - <https://www.wireshark.org/docs/man-pages/tshark.html>

## What to remember

### Protocol hierarchy is structural

The protocol hierarchy view is meant to explain how packets are dissected through the stack. It is great for spotting whether the capture is mostly TCP, DNS, TLS, HTTP, ARP, and so on.

Do not treat the rows as mutually exclusive buckets. A single packet can contribute to multiple rows across layers, so percentages are not a simple pie chart.

### Endpoints answer "who exists"

The endpoints view is the best fast inventory of hosts or addresses present in the capture. It also includes separate tabs by protocol family and may include broadcast or multicast addresses.

Use it early to identify:

- top talkers
- unexpected hosts
- broadcast-heavy behavior
- whether IPv4, IPv6, TCP, or UDP dominate the capture

### Conversations answer "who exchanged meaningful traffic"

The conversations view is better than endpoints when you need to prioritize investigations. Official Wireshark docs note that conversations include fields such as relative start time, duration, bits per second, and a graphable timeline.

Use it to identify:

- long-lived sessions
- asymmetric uploads or downloads
- spikes tied to a specific pair
- the best candidate streams to follow

### Expert Info is triage, not truth

Expert Information is useful because it collects warnings, chats, notes, and errors in one place. It is an accelerator for investigation, not a substitute for it.

Treat it as:

- a fast anomaly shortlist
- a hint about retransmissions, malformed packets, handshakes, or protocol issues
- something that still needs confirmation with streams, packet details, or field extraction

### Display filters are exact syntax, not vibes

The official display filter builder documentation is a reminder to stay exact. When you are unsure about operators, field names, or compound expressions, use the MCP reference resource instead of improvising.

### Stream following uses explicit stream selectors

The official `tshark` manual documents `follow` stream selection by protocol and stream index. For TCP, the stream index behavior is zero-based. When reporting or handing off work, include the stream index so another analyst can reproduce the same view quickly.
