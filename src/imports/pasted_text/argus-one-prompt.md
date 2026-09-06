# ARGUS-ONE — COMPLETE UI/UX GENERATION PROMPT

Design and generate a complete production-quality web application called:

# ARGUS-ONE

### AI-Based Passive Metadata Threat Detection

Tagline:

**SEE EVERYTHING. REACH BACK INTO NOTHING.**

ARGUS-ONE is a cybersecurity monitoring and threat-detection platform that analyzes **normalized network flow metadata only**.

It does NOT generate traffic.
It does NOT decrypt packet payloads.
It does NOT inspect packet contents.

The interface must visually communicate:

**Passive monitoring → Metadata analysis → Independent detection engines → Explainable threat alerts → Security operations dashboard**

---

# 1. CORE PRODUCT CONCEPT

ARGUS-ONE receives normalized network flow records containing:

* timestamp
* source IP
* destination IP
* source port
* destination port
* protocol
* bytes out
* bytes in
* packets out
* packets in
* TCP flags

Optional metadata:

* DNS metadata
* TLS metadata
* QUIC metadata
* destination reputation

The detection engine currently contains these independent detectors:

1. SYN Flood
2. UDP Reflection / Amplification
3. Spoofed-Source Flood
4. Botnet C2 Beaconing
5. DGA Domain
6. DNS Tunnelling
7. Encrypted-Session Malware
8. Port Scanning
9. Data Exfiltration

Treat these as the actual ARGUS-ONE detection categories.

Do not invent unrelated detection categories.

---

# 2. VISUAL DIRECTION

Create a premium enterprise cybersecurity SOC interface.

Style:

* dark professional interface
* modern
* minimal
* technical
* high information density
* clean spacing
* sophisticated rather than flashy
* suitable for a government / defense / enterprise cybersecurity product
* no gaming aesthetic
* no excessive neon
* no unnecessary gradients
* no cyberpunk cliché graphics
* no hacker imagery

Use a dark base:

Background:
#080B10

Secondary background:
#0D1117

Cards:
#11161D

Elevated cards:
#151B23

Borders:
#242B35

Primary text:
#F3F5F7

Secondary text:
#9AA4B2

Muted text:
#66707D

Primary accent:
#20D3A2

Use severity colors carefully:

LOW:
#4C9AFF

MEDIUM:
#F2C94C

HIGH:
#F2994A

CRITICAL:
#EB5757

Success:
#20D3A2

The interface should remain predominantly dark and neutral.

Severity colors should only appear on:

* badges
* alert indicators
* charts
* threat markers
* status indicators

Do not color entire cards aggressively.

---

# 3. TYPOGRAPHY

Use a modern technical sans-serif font.

Preferred:

Inter

Fallback:

Manrope / IBM Plex Sans

Typography:

Page title:
28–32px / Bold

Section heading:
18–20px / Semibold

Card title:
14–16px / Semibold

Body:
13–14px

Metadata:
11–12px

Large metrics:
28–36px

IP addresses / technical values:
use a monospace font such as JetBrains Mono.

---

# 4. APPLICATION STRUCTURE

Create a persistent left sidebar.

Sidebar:

ARGUS-ONE logo at top.

Navigation:

OVERVIEW
Dashboard

MONITOR
Live Traffic
Flow Explorer

DETECTION
Threats
Alerts
Detection Engines

ANALYSIS
Threat Analytics
Baselines
Evidence

SYSTEM
Agent Status
Configuration
Data Sources

Bottom:

System status:
● ARGUS ENGINE ONLINE

User profile.

The sidebar should collapse into icon-only mode.

---

# 5. GLOBAL TOP BAR

Top navigation bar:

Left:

Breadcrumbs

Example:

ARGUS-ONE / Overview

Center/right:

Live monitoring indicator:

● LIVE

Last update:

Updated 2s ago

Controls:

Search

Notifications

Settings

User avatar

Add a compact global search that can search:

* alert ID
* source IP
* destination IP
* threat class
* detector
* protocol

---

# 6. DASHBOARD / OVERVIEW PAGE

This is the main landing screen after login.

Header:

ARGUS-ONE

Passive Network Threat Intelligence

Subtitle:

Real-time analysis of normalized network flow metadata.

Right:

LIVE ●

Time range selector:

5m | 15m | 1h | 6h | 24h

Refresh control.

---

## KPI ROW

Create six compact metric cards.

### CARD 1

Packets / Flows Processed

Example:

1,819,201

Small text:

+12.4% vs previous period

---

### CARD 2

Threats Detected

Example:

27

Small breakdown:

3 Critical
8 High
10 Medium
6 Low

---

### CARD 3

Critical Threats

Example:

3

Indicator:

● Requires attention

---

### CARD 4

Active Alerts

Example:

12

---

### CARD 5

Detection Engine

Status:

ACTIVE

Show:

8+ detectors

---

### CARD 6

Data Sources

Example:

4

Status:

Healthy

---

# 7. THREAT ACTIVITY CHART

Large card.

Title:

Threat Activity

Subtitle:

Detected threats over time

Create a time-series chart.

X axis:

time

Y axis:

detections

Allow filters:

All
Critical
High
Medium
Low

Use subtle severity-colored lines.

Include hover tooltip:

Time
Threat class
Severity
Risk score
Source

---

# 8. THREAT DISTRIBUTION

Create a two-column section.

Left:

DONUT / RADIAL CHART

Title:

Threat Distribution

Categories:

SYN Flood
UDP Reflection
Spoofed-Source Flood
C2 Beaconing
DGA Domain
DNS Tunnelling
Encrypted Malware
Port Scanning
Data Exfiltration

Right:

Top Threats

Display ranked list.

Example:

01
Data Exfiltration
Critical
96%

02
SYN Flood
High
87%

03
DNS Tunnelling
High
82%

---

# 9. LIVE ALERT FEED

Large table/card.

Title:

Live Detection Feed

Columns:

Time
Severity
Threat
Source
Target
Risk
Detector
Status

Example:

10:32:14
CRITICAL
Data Exfiltration
10.0.0.90
9.9.9.9
96
asymmetric_volume
OPEN

10:31:42
HIGH
SYN Flood
Multiple
10.0.0.20
87
syn_flood
OPEN

10:30:51
HIGH
DNS Tunnelling
10.0.0.80
1.1.1.1
82
dns_tunnel
OPEN

Rows should be clickable.

Clicking a row opens the alert detail page.

---

# 10. LIVE TRAFFIC PAGE

Create a dedicated Live Traffic screen.

Header:

LIVE TRAFFIC

Subtitle:

Passive normalized flow telemetry

Top controls:

LIVE ●
Pause
Resume
5s / 10s / 30s refresh

Filters:

Source IP
Destination IP
Protocol
Source Port
Destination Port
Risk
Time

Main table:

Timestamp
Source IP
Source Port
Destination IP
Destination Port
Protocol
Bytes Out
Bytes In
Packets Out
Packets In
TCP Flags
Risk

Use monospace typography for IP addresses and ports.

Example:

10:32:14
10.10.1.25
51000
172.16.1.20
443
TCP
60 B
0 B
1
0
S

---

# 11. FLOW EXPLORER PAGE

Create an advanced searchable flow investigation interface.

Header:

Flow Explorer

Search:

Search IP, port, protocol, alert ID...

Filters:

Time range
Source
Destination
Protocol
Port
Detector
Threat status

Main visualization:

Flow timeline.

Below:

Detailed flow table.

Allow users to click any flow.

Opening a flow displays:

Flow ID
Timestamp
Source
Destination
Protocol
Ports
Bytes
Packets
TCP flags

Optional context:

DNS
TLS
QUIC
Destination reputation

---

# 12. THREATS PAGE

Create a threat-management page.

Header:

Threats

Subtitle:

Detected security events generated by ARGUS-ONE detection engines.

Top statistics:

Total threats
Critical
High
Medium
Low

Filters:

Severity
Threat Class
Detector
Source
Target
Time
Status

Table:

Alert ID
Timestamp
Threat Class
Severity
Risk Score
Source
Target
Detector
Window
Status

Example:

ALT-8F32A19BC123

Data Exfiltration

CRITICAL

0.96

10.0.0.90

9.9.9.9

asymmetric_volume

300s

OPEN

---

# 13. ALERT DETAIL PAGE

This is one of the most important screens.

When the user clicks an alert, create a detailed investigation view.

Header:

← Back to Threats

CRITICAL

DATA EXFILTRATION

ALT-8F32A19BC123

Risk Score:

96%

Show a large circular risk indicator.

---

## ALERT SUMMARY CARD

Timestamp:

2026-09-05 10:32:14 UTC

Source:

10.0.0.90

Target:

9.9.9.9

Detector:

asymmetric_volume

Analysis Window:

300 seconds

Status:

OPEN

---

# 14. SOURCE → TARGET VISUALIZATION

Create a clean horizontal flow diagram:

SOURCE

10.0.0.90

↓

ARGUS-ONE

Passive Metadata Analysis

↓

TARGET

9.9.9.9

Under it display:

Outbound:
14 MB

Inbound:
3 KB

Ratio:
very high

---

# 15. EVIDENCE SECTION

This must directly reflect the agent's `evidence` array.

Title:

Detection Evidence

Create evidence cards.

Example:

### Outbound Bytes

Value:

14,000,000

Threshold:

10,000,000

Detail:

Large external outbound volume

Show:

████████████████████

Threshold marker.

---

### Outbound / Inbound Ratio

Value:

4666×

Threshold:

12×

Detail:

Outbound volume strongly exceeds replies

---

### Baseline Robust Z-Score

Value:

4.7

Threshold:

3.0

Detail:

Optional benign baseline deviation

---

### Total Bytes

Value:

14,003,000

Threshold:

10,000,000

Detail:

Five-minute flow volume

---

# 16. DETECTION EXPLANATION

Create a section:

WHY ARGUS-ONE FLAGGED THIS

Show a concise natural-language explanation.

Example:

"ARGUS-ONE observed unusually large outbound traffic from an internal source to an external destination over the five-minute analysis window. Outbound volume significantly exceeded inbound responses and exceeded the configured exfiltration threshold."

Add:

Evidence confidence
Detection method
Analysis window

Do not claim that the system inspected packet payloads.

Explicitly state:

"Detection based on passive flow metadata."

---

# 17. DETECTION ENGINES PAGE

Create a page showing every independent detector.

Title:

Detection Engines

Subtitle:

Independent explainable detection modules.

Create 9 cards.

Each card:

Detector name
Status
Purpose
Thresholds
Observations
Last triggered
Alerts generated

Cards:

1. SYN Flood
   detector:
   syn_flood

2. UDP Reflection / Amplification
   detector:
   udp_reflection

3. Spoofed-Source Flood
   detector:
   spoofed_source_flood

4. Botnet C2 Beaconing
   detector:
   periodic_beacon

5. DGA Domain
   detector:
   dns_lexical

6. DNS Tunnelling
   detector:
   dns_tunnel

7. Encrypted-Session Malware
   detector:
   tls_quic_metadata

8. Port Scanning
   detector:
   fanout_scan

9. Data Exfiltration
   detector:
   asymmetric_volume

Every detector card should have:

● ACTIVE

and a "View details" action.

---

# 18. DETECTOR DETAIL

When a detector is opened, show:

Detector:

Data Exfiltration

Internal identifier:

asymmetric_volume

Status:

ACTIVE

Analysis Window:

300 seconds

Configuration:

exfil_min_bytes:
10,000,000

exfil_min_ratio:
12.0

Show detector logic visually:

Flow metadata
↓
External destination filter
↓
Outbound volume calculation
↓
Inbound/outbound ratio
↓
Optional baseline deviation
↓
Risk score
↓
Alert

Create a clean flowchart.

---

# 19. ALERT PAGE

Create a dedicated alert queue.

Tabs:

ALL
OPEN
ACKNOWLEDGED
RESOLVED

Although the current detector directly produces structured alerts, design the UI so backend workflow state can later be added.

Each alert row:

Severity
Alert ID
Threat
Source
Target
Risk
Created
Detector
Status

Actions:

View
Acknowledge
Resolve

---

# 20. ANALYTICS PAGE

Create advanced threat analytics.

Sections:

Threat volume over time

Threat severity distribution

Detector performance

Top source IPs

Top destination IPs

Most frequent threat classes

Protocol distribution

Traffic volume

Outbound / inbound ratios

Create:

* line charts
* bar charts
* donut charts
* ranked lists

Keep charts clean and professional.

---

# 21. BASELINE PAGE

ARGUS-ONE contains a `MetadataBaseline` system.

Create:

BASELINE ANALYSIS

Show:

Baseline status
Training state
Last fitted
Number of benign flows
Features

Features:

Outbound Ratio
Total Bytes
Packets

For each feature:

Median
MAD
Current value
Robust Z-score

Explain:

"Baseline is advisory. Attack detectors do not depend on baseline availability."

Create a small informational panel explaining robust baseline methodology.

---

# 22. DNS ANALYSIS PAGE

Create a specialized DNS analytics page.

Display:

DNS queries analyzed
Unique domains
DGA detections
DNS tunnel detections
TXT/NULL/CNAME activity

Charts:

Query volume
Domain entropy
Query length
Unique subdomains

Threat table:

Domain
Source
Query Type
Entropy
Length
Detection
Risk

Example:

m3k4j8n2q7v6x9z5.example.net

A

High entropy

DGA Domain

---

# 23. TLS / QUIC ANALYSIS PAGE

Create:

Encrypted Session Analysis

Metrics:

TLS sessions
QUIC sessions
Known malicious fingerprints
Rare fingerprints
Suspicious destinations

Table:

Source
Destination
Protocol
JA3
JA3S
JA4
SNI
ALPN
Reputation
Risk

Clearly label:

"Metadata only — encrypted payloads are not inspected."

---

# 24. SYSTEM / AGENT STATUS PAGE

Create:

ARGUS-ONE ENGINE STATUS

Large status:

● OPERATIONAL

Show:

Agent:
ONLINE

Flow Store:
HEALTHY

Baseline:
AVAILABLE / NOT TRAINED

Detection Engines:
9 / 9 ACTIVE

Last Flow:
2 seconds ago

Last Alert:
8 seconds ago

Memory:
Healthy

Processing:
Healthy

Create system architecture visualization:

FLOW INPUT
↓
NORMALIZATION
↓
ROLLING FLOW STORE
↓
DETECTION ENGINES
↓
ALERT GENERATION
↓
BACKEND API
↓
WEB DASHBOARD

---

# 25. DATA SOURCES PAGE

Create:

Data Sources

Cards for:

Network Collector
Flow Exporter
DNS Metadata
TLS Metadata
QUIC Metadata
Threat Reputation

Each source has:

Status
Records/sec
Last received
Health

Use:

● Connected

or

○ Offline

---

# 26. CONFIGURATION PAGE

Create a professional configuration interface.

Sections:

Detection Thresholds

SYN Flood

syn_flows_per_second:
20

UDP Reflection

udp_flows_per_second:
30

Port Scan

scan_min_ports:
20

scan_min_hosts:
12

Exfiltration

exfil_min_bytes:
10,000,000

exfil_min_ratio:
12

C2

c2_min_observations:
5

Alert Cooldown

30 seconds

Use numeric input fields with validation.

Add:

Save Configuration

Reset

Export Configuration

Import Configuration

Do not expose arbitrary Python configuration.

---

# 27. THREAT INTELLIGENCE PAGE

Create:

Threat Intelligence

Sections:

Malicious TLS fingerprints
Trusted TLS fingerprints
Destination reputation

Tables:

Fingerprint
Type
Source
Added
Status

Allow:

Add fingerprint
Remove fingerprint
Import list
Export list

---

# 28. LOGIN PAGE

Create a premium enterprise login.

Centered ARGUS-ONE logo.

Title:

Welcome back

Subtitle:

Access the ARGUS-ONE security monitoring console.

Fields:

Email
Password

Button:

Sign in

Below:

Secure enterprise access

Minimal background.

No unnecessary graphics.

---

# 29. NOTIFICATION SYSTEM

Create notification dropdown.

Examples:

CRITICAL
Data Exfiltration detected
10.0.0.90 → 9.9.9.9

HIGH
DNS Tunnelling detected
10.0.0.80 → 1.1.1.1

MEDIUM
Port Scanning detected
10.0.0.50

Each notification opens the alert.

---

# 30. GLOBAL SEARCH

Create command-style search.

Placeholder:

Search ARGUS-ONE...

Search categories:

Alert ID
IP Address
Threat Class
Detector
Protocol
Domain

Results should appear as:

Threat
ALT-8F32A19BC123

Source IP
10.0.0.90

Detector
asymmetric_volume

---

# 31. EMPTY STATES

Design proper empty states.

Examples:

"No threats detected"

"ARGUS-ONE has not identified suspicious activity in this time range."

"No flow data available"

"Waiting for normalized flow metadata."

"No baseline configured"

"Fit a benign metadata baseline to enable advisory deviation scoring."

"No DNS metadata"

"DNS enrichment is not available for the selected flow."

---

# 32. ERROR STATES

Create professional error states.

Examples:

Agent offline

Backend unavailable

Data source disconnected

WebSocket disconnected

Malformed flow record

Invalid configuration

Show:

Problem
Impact
Recommended action
Retry

---

# 33. REAL-TIME BEHAVIOR

Design the UI for real-time backend integration.

The frontend should be structured so that REST APIs provide historical information and WebSockets provide live events.

Use conceptual endpoints:

GET /api/dashboard/summary

GET /api/traffic/live

GET /api/traffic/history

GET /api/threats

GET /api/threats/{alert_id}

GET /api/alerts

GET /api/detectors

GET /api/detectors/{detector_id}

GET /api/analytics

GET /api/baseline

GET /api/agent/status

GET /api/data-sources

GET /api/configuration

WebSocket:

/ws/live

Real-time events should update:

* KPI cards
* live traffic
* alert feed
* threat counters
* charts
* notifications
* system status

---

# 34. ALERT JSON MAPPING

The UI must be compatible with this conceptual alert structure:

{
"alert_id": "ALT-XXXXXXXXXXXX",
"timestamp": "2026-09-05T10:32:14+00:00",
"threat_class": "Data Exfiltration",
"risk_score": 0.96,
"severity": "critical",
"source": {
"ip": "10.0.0.90"
},
"target": {
"ip": "9.9.9.9"
},
"detector": "asymmetric_volume",
"window_seconds": 300,
"evidence": []
}

Every UI component must be designed around these fields.

---

# 35. EVIDENCE JSON MAPPING

Evidence objects have:

feature
value
threshold
detail

For example:

{
"feature": "outbound_bytes",
"value": 14000000,
"threshold": 10000000,
"detail": "large external outbound volume"
}

Render these as visual evidence cards.

Never hide the evidence behind a generic "AI detected this" message.

The product's key differentiator is:

**EXPLAINABLE METADATA-BASED DETECTION.**

---

# 36. RESPONSIVE DESIGN

Generate:

Desktop:
1440 × 900

Laptop:
1280 × 800

Tablet:
1024 × 768

Mobile:
390 × 844

Desktop is the primary experience.

On mobile:

Sidebar becomes bottom navigation or drawer.

Large tables become horizontally scrollable.

Charts remain readable.

---

# 37. COMPONENT SYSTEM

Create reusable Figma components for:

Buttons
Cards
Metric cards
Status indicators
Severity badges
Threat badges
Tables
Table rows
Tabs
Dropdowns
Search bars
Date pickers
Charts
Evidence cards
Risk score indicators
Timeline events
Flow nodes
Modal dialogs
Notifications
Tooltips
Pagination
Empty states
Error states

Use variants for:

severity:
low / medium / high / critical

status:
online / offline / warning

theme:
dark / elevated

---

# 38. INTERACTION DESIGN

Create prototype interactions.

Dashboard:

Click threat row
→ Alert Detail

Click detector
→ Detector Detail

Click source IP
→ Flow Explorer filtered by source IP

Click destination IP
→ Flow Explorer filtered by destination IP

Click notification
→ Alert Detail

Click KPI:
Threats
→ Threats page

Click critical count
→ Threats filtered to critical

Click live traffic
→ Live Traffic

Click Detection Engines
→ Detection Engines

---

# 39. IMPORTANT SECURITY UX RULES

Do not create controls implying ARGUS-ONE can:

* block traffic
* terminate connections
* modify packets
* decrypt payloads
* execute commands on network hosts

ARGUS-ONE is a:

**PASSIVE DETECTION AND MONITORING PLATFORM**

The UI should primarily support:

Observe
Detect
Investigate
Explain
Monitor
Analyze

---

# 40. KEY DIFFERENTIATOR

Make the product identity revolve around:

## PASSIVE + EXPLAINABLE + METADATA-ONLY

Include a subtle persistent system label somewhere in the application:

PASSIVE METADATA ANALYSIS

and:

NO PAYLOAD INSPECTION

This should be visible but not distracting.

---

# 41. OVERALL INFORMATION HIERARCHY

The application should follow:

NETWORK ACTIVITY

↓

FLOW METADATA

↓

DETECTION

↓

THREAT

↓

EVIDENCE

↓

INVESTIGATION

This should be reflected throughout the UI.

---

# 42. FINAL FIGMA DELIVERABLE

Generate the complete connected application prototype.

Create all screens:

01 Login
02 Dashboard / Overview
03 Live Traffic
04 Flow Explorer
05 Threats
06 Alert Detail
07 Alerts
08 Detection Engines
09 Detector Detail
10 Threat Analytics
11 Baseline
12 DNS Analysis
13 TLS / QUIC Analysis
14 Agent Status
15 Data Sources
16 Configuration
17 Threat Intelligence
18 Notifications
19 Global Search
20 Empty / Error States

All screens must share one design system.

Use realistic ARGUS-ONE sample data derived from the detector structure.

Do not use generic cybersecurity placeholder terminology.

Use the actual detector names, alert fields, evidence fields, risk scores, windows, source/target structure, and metadata concepts described above.

The final result should look like a **real enterprise SOC product ready to be connected to a FastAPI/Node backend**, not a conceptual mockup.

Prioritize:

1. readability
2. information hierarchy
3. explainability
4. real-time monitoring
5. investigation workflow
6. consistent components
7. clean enterprise aesthetics
8. backend/API readiness

The UI must make it immediately clear:

**ARGUS-ONE observes network metadata, independently detects suspicious patterns, calculates explainable risk, and presents structured security alerts to analysts.**
