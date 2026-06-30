#include "wikiflip.h"

#include <furi.h>
#include <gui/gui.h>
#include <gui/modules/submenu.h>
#include <gui/modules/widget.h>
#include <gui/view_dispatcher.h>
#include <stdlib.h>

struct WikiFlipApp {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* categories_menu;
    Submenu* terms_menu;
    Widget* definition_widget;
    FuriString* definition_buffer;
    const WikiFlipCategory* current_category;
    uint32_t current_category_index;
    uint32_t current_term_index;
    WikiFlipView current_view;
};

static const WikiFlipTerm wikiflip_protocols_terms[] = {
    {
        .title = "TLS 1.3",
        .definition =
            "Transport Layer Security 1.3 protects TCP-based sessions with authenticated encryption, "
            "ephemeral key exchange, and modern AEAD cipher suites. It removes legacy RSA key exchange, "
            "CBC suites, and renegotiation.\n\n"
            "Audit focus: certificate validity, SNI, ALPN, minimum protocol version, HSTS, cipher suites, "
            "OCSP stapling, and downgrade resistance.",
    },
    {
        .title = "DNSSEC",
        .definition =
            "DNSSEC adds authenticity and integrity to DNS records with DNSKEY, DS, and RRSIG data. "
            "It does not encrypt DNS traffic; it prevents forged answers when resolvers validate the chain.\n\n"
            "Audit focus: parent DS records, KSK/ZSK rollover, RRSIG expiry, NSEC/NSEC3 behavior, and resolver validation failures.",
    },
    {
        .title = "SSH",
        .definition =
            "SSH provides encrypted remote administration, public-key authentication, and TCP tunneling. "
            "Its main risk areas are login policy, accepted algorithms, key handling, and port forwarding.\n\n"
            "Audit focus: root login, password authentication, authorized_keys, weak KEX algorithms, MFA, and bastion host controls.",
    },
    {
        .title = "HTTP/2",
        .definition =
            "HTTP/2 uses multiplexing, HPACK compression, and streams over a single connection. It improves latency but can introduce "
            "stream abuse, request smuggling edge cases, and resource exhaustion.\n\n"
            "Audit focus: stream limits, reverse proxies, header normalization, and HTTP/1.1 backend translation.",
    },
    {
        .title = "HTTP/3 QUIC",
        .definition =
            "HTTP/3 runs over QUIC on UDP and integrates TLS 1.3. It improves connection mobility and latency, while changing network "
            "visibility and inspection patterns.\n\n"
            "Audit focus: UDP/443 policy, fallback behavior, certificates, logging, rate limiting, CDN, and WAF visibility.",
    },
    {
        .title = "OAuth 2.0",
        .definition =
            "OAuth 2.0 delegates authorization with access tokens, scopes, and grant flows. It is not an authentication protocol by itself; "
            "identity use cases should use OpenID Connect.\n\n"
            "Audit focus: redirect_uri validation, PKCE, scopes, token audience, token lifetime, token storage, and unsafe grants.",
    },
    {
        .title = "OpenID Connect",
        .definition =
            "OpenID Connect extends OAuth 2.0 for federated authentication with signed ID tokens, claims, discovery metadata, and JWKS.\n\n"
            "Audit focus: issuer, audience, nonce, signature verification, alg none rejection, JWKS rotation, sensitive claims, and logout.",
    },
    {
        .title = "SAML 2.0",
        .definition =
            "SAML 2.0 enables enterprise federation through XML assertions exchanged between an Identity Provider and a Service Provider.\n\n"
            "Audit focus: mandatory signatures, XML canonicalization, audience, recipient, NameID, assertion lifetime, and XML signature wrapping.",
    },
    {
        .title = "Kerberos",
        .definition =
            "Kerberos authenticates principals with tickets issued by a Key Distribution Center. In Active Directory it supports SSO, SPNs, "
            "delegation, TGTs, and TGS tickets.\n\n"
            "Audit focus: Kerberoasting, AS-REP roasting, unconstrained delegation, SPN hygiene, clock skew, and password policy.",
    },
    {
        .title = "LDAP/LDAPS",
        .definition =
            "LDAP queries directory services; LDAPS adds TLS. In Active Directory it is commonly used for identity, groups, attributes, "
            "and application authentication.\n\n"
            "Audit focus: signing, channel binding, anonymous binds, LDAPS enforcement, service account privileges, and LDAP injection.",
    },
    {
        .title = "SMB",
        .definition =
            "Server Message Block provides file sharing, named pipes, and remote administration on Windows networks. SMBv1 is obsolete "
            "and high risk.\n\n"
            "Audit focus: SMBv1 removal, signing, share permissions, NTFS permissions, anonymous sessions, and TCP/445 exposure.",
    },
    {
        .title = "MQTT",
        .definition =
            "MQTT is a lightweight publish/subscribe protocol common in IoT. It uses brokers, topics, QoS levels, and client credentials "
            "or certificates.\n\n"
            "Audit focus: TLS, authentication, topic ACLs, retained messages, anonymous access, bridge configuration, and telemetry leakage.",
    },
};

static const WikiFlipTerm wikiflip_owasp_terms[] = {
    {
        .title = "A01:2025 - Broken Access Control",
        .definition =
            "Authorization is not enforced consistently. This includes IDOR, horizontal or vertical privilege escalation, endpoint bypass, "
            "metadata abuse, insecure CORS, SSRF grouped into this category, and controls enforced only in the client.\n\n"
            "Mitigation: deny by default, centralized server-side authorization, object-level checks, ownership validation, role-based tests, "
            "rate limiting, and access failure logging.",
    },
    {
        .title = "A02:2025 - Security Misconfiguration",
        .definition =
            "Unsafe configuration in apps, cloud, containers, servers, or frameworks. Examples include defaults, unneeded services, broad "
            "permissions, debug mode, missing headers, permissive CORS, verbose errors, and public storage.\n\n"
            "Mitigation: automated hardening, versioned infrastructure as code, secure baselines, minimum configuration, secret scanning, "
            "and continuous validation.",
    },
    {
        .title = "A03:2025 - Software Supply Chain Failures",
        .definition =
            "Risk introduced by dependencies, build systems, packages, pipelines, repositories, artifacts, signatures, updates, or vendors. "
            "This goes beyond known vulnerable components.\n\n"
            "Mitigation: SBOM, pinning, SCA, trusted repositories, signatures, provenance, CI/CD review, least privilege tokens, and release controls.",
    },
    {
        .title = "A04:2025 - Cryptographic Failures",
        .definition =
            "Missing or incorrect cryptography can expose data or weaken trust. Examples include obsolete algorithms, weak keys, bad TLS, "
            "cleartext storage, and poor secret handling.\n\n"
            "Mitigation: modern cryptography, key management, rotation, KMS/HSM use, strong TLS, salted password hashing, and design review.",
    },
    {
        .title = "A05:2025 - Injection",
        .definition =
            "Untrusted input changes queries, commands, interpreters, or templates. This includes SQL, NoSQL, OS command, LDAP, XPath, "
            "template injection, and XSS where context permits.\n\n"
            "Mitigation: prepared statements, positive validation, contextual escaping, safe ORM usage, sandboxing, and strict data/code separation.",
    },
    {
        .title = "A06:2025 - Insecure Design",
        .definition =
            "Architectural or business-logic flaws that cannot be fixed with a small implementation patch. Examples include abusable workflows, "
            "missing compensating controls, absent limits, and unmodeled threats.\n\n"
            "Mitigation: threat modeling, secure design reviews, abuse cases, verifiable security requirements, and defensive patterns.",
    },
    {
        .title = "A07:2025 - Authentication Failures",
        .definition =
            "Weaknesses in identity, login, sessions, MFA, and account recovery. Examples include credential stuffing, weak passwords, unsafe "
            "reset flows, predictable sessions, and incomplete token validation.\n\n"
            "Mitigation: phishing-resistant MFA, rate limits, strong hashing, secure sessions, token rotation, abuse detection, and robust recovery.",
    },
    {
        .title = "A08:2025 - Software or Data Integrity Failures",
        .definition =
            "Software, updates, data, serialization, or pipelines are trusted without integrity verification. Examples include compromised CI/CD, "
            "untrusted plugins, unsafe deserialization, and unsigned critical data.\n\n"
            "Mitigation: signatures, artifact verification, pipeline controls, allowlists, safe deserialization, and change control.",
    },
    {
        .title = "A09:2025 - Security Logging and Alerting Failures",
        .definition =
            "Logging, monitoring, or alerting is insufficient to detect, investigate, and respond. Examples include missing critical events, "
            "uncorrelatable logs, context-free alerts, and poor retention.\n\n"
            "Mitigation: defined security events, correlation IDs, SIEM coverage, severity-aware alerts, protected logs, retention, and detection tests.",
    },
    {
        .title = "A10:2025 - Mishandling of Exceptional Conditions",
        .definition =
            "Errors, exceptions, timeouts, partial states, or dependency failures are handled unsafely. Impact can include information leakage, "
            "crashes, control bypass, data inconsistency, or denial of service.\n\n"
            "Mitigation: fail securely, generic user-facing errors, safe internal logging, timeouts, bounded retries, circuit breakers, and resilience tests.",
    },
};

static const WikiFlipTerm wikiflip_nist_terms[] = {
    {
        .title = "NIST CSF 2.0",
        .definition =
            "The Cybersecurity Framework organizes capabilities into Govern, Identify, Protect, Detect, Respond, and Recover. It supports "
            "maturity planning, risk communication, and prioritization.\n\n"
            "Audit focus: current and target profiles, control mapping, risk gaps, measurable actions, and governance ownership.",
    },
    {
        .title = "NIST SP 800-53",
        .definition =
            "A broad catalog of security and privacy controls, including AC, AU, CM, IA, IR, RA, SC, SI, and other families.\n\n"
            "Audit focus: selected baseline, control evidence, implementation testing, exceptions, and risk traceability.",
    },
    {
        .title = "NIST SP 800-61",
        .definition =
            "Incident handling guidance covering preparation, detection, analysis, containment, eradication, recovery, and post-incident activity.\n\n"
            "Audit focus: playbooks, severity model, chain of custody, communication paths, response times, and lessons learned.",
    },
    {
        .title = "NIST SP 800-30",
        .definition =
            "Risk assessment guidance for threats, vulnerabilities, likelihood, impact, existing controls, and treatment recommendations.\n\n"
            "Audit focus: repeatable methodology, risk criteria, asset traceability, and risk-based prioritization.",
    },
    {
        .title = "NIST SP 800-37 RMF",
        .definition =
            "Risk Management Framework steps include categorize, select, implement, assess, authorize, and monitor controls.\n\n"
            "Audit focus: authorization, inherited controls, POA&M tracking, continuous monitoring, and significant changes.",
    },
    {
        .title = "NIST SP 800-63",
        .definition =
            "Digital identity guidance defining IAL, AAL, and FAL levels for identity proofing, authenticators, and federation.\n\n"
            "Audit focus: MFA strength, phishing resistance, credential lifecycle, recovery, and federated claims.",
    },
    {
        .title = "NIST SP 800-171",
        .definition =
            "Protection of Controlled Unclassified Information in non-federal systems, often used in government supply chains.\n\n"
            "Audit focus: control implementation, SSP, POA&M, access, configuration, incident response, and CUI handling.",
    },
    {
        .title = "NIST SP 800-207",
        .definition =
            "Zero Trust Architecture uses continuous verification, dynamic policy, and minimum access for each session.\n\n"
            "Audit focus: policy engine, identity, device posture, segmentation, telemetry, and contextual decisions.",
    },
    {
        .title = "NIST SP 800-218 SSDF",
        .definition =
            "Secure Software Development Framework practices prepare the organization, protect software, produce secure software, and respond "
            "to vulnerabilities.\n\n"
            "Audit focus: SDLC controls, code review, SCA, threat modeling, secrets, builds, and vulnerability response.",
    },
    {
        .title = "FIPS 140-3",
        .definition =
            "A standard for validating cryptographic modules. It defines requirements for algorithms, roles, authentication, physical security, "
            "and self-tests.\n\n"
            "Audit focus: validated modules, FIPS mode, current certificates, and actual runtime configuration.",
    },
};

static const WikiFlipTerm wikiflip_cve_terms[] = {
    {
        .title = "CVE-2021-44228 Log4Shell",
        .definition =
            "Critical RCE in Apache Log4j 2 through attacker-controlled JNDI lookups. Impact was broad because Log4j is commonly included "
            "as a transitive Java dependency.\n\n"
            "Validation: affected versions, indirect dependencies, log patterns, egress paths, and historical IoCs.",
    },
    {
        .title = "CVE-2017-0144 EternalBlue",
        .definition =
            "SMBv1 vulnerability in Microsoft Windows associated with MS17-010. It can enable remote code execution on unpatched systems "
            "with TCP/445 exposed.\n\n"
            "Mitigation: patch, disable SMBv1, segment networks, and restrict unnecessary SMB exposure.",
    },
    {
        .title = "CVE-2023-34362 MOVEit",
        .definition =
            "Critical MOVEit Transfer flaw exploited for unauthenticated access and data exfiltration.\n\n"
            "Validation: version, webshells, transfer logs, unusual accounts, and abnormal data movement. Mitigation: patch, isolate, and rotate credentials.",
    },
    {
        .title = "CVE-2024-3094 XZ Utils",
        .definition =
            "Backdoor introduced into specific XZ Utils versions that affected software supply chain integrity and could impact sshd in some Linux builds.\n\n"
            "Mitigation: remove affected versions, verify packages, review provenance, and strengthen supply chain controls.",
    },
    {
        .title = "CVE-2023-23397 Outlook",
        .definition =
            "Microsoft Outlook privilege escalation where crafted reminder properties can force NTLM authentication to attacker-controlled resources.\n\n"
            "Mitigation: patch, block outbound NTLM, detect abnormal MAPI properties, and monitor external authentication.",
    },
    {
        .title = "CVE-2023-46805 Ivanti",
        .definition =
            "Authentication bypass in Ivanti Connect Secure and Policy Secure, observed in exploit chains with other flaws for remote code execution.\n\n"
            "Mitigation: patch, run integrity checks, review web roots, admin sessions, and unusual VPN access.",
    },
    {
        .title = "CVE-2024-21887 Ivanti",
        .definition =
            "Command injection in Ivanti Connect Secure and Policy Secure, exploitable by authenticated users or in chains with a prior bypass.\n\n"
            "Mitigation: update, isolate management, review logs, inspect persistence artifacts, and rotate exposed credentials.",
    },
    {
        .title = "CVE-2024-6387 regreSSHion",
        .definition =
            "Race condition in OpenSSH server related to async-unsafe signal handler behavior. It may allow pre-auth RCE on some platforms and versions.\n\n"
            "Mitigation: update OpenSSH, restrict exposure, use conservative LoginGraceTime, and filter SSH access.",
    },
    {
        .title = "CVE-2023-3519 Citrix ADC",
        .definition =
            "Unauthenticated RCE in Citrix ADC and Gateway, widely exploited against exposed appliances.\n\n"
            "Validation: version, webshells, sessions, HTTP logs, and configuration changes. Mitigation: patch immediately and hunt for compromise.",
    },
    {
        .title = "CVE-2020-1472 Zerologon",
        .definition =
            "Weakness in the Netlogon Remote Protocol that can enable domain controller takeover under vulnerable conditions.\n\n"
            "Mitigation: patch, enforce secure Netlogon, monitor DC events, and rotate secrets if compromise is suspected.",
    },
    {
        .title = "CVE-2022-30190 Follina",
        .definition =
            "Abuse of Microsoft Support Diagnostic Tool through documents or links that invoke ms-msdt for command execution.\n\n"
            "Mitigation: patch, block protocol abuse, deploy EDR rules, and detect Office processes spawning diagnostic or script interpreters.",
    },
    {
        .title = "CVE-2024-1709 ScreenConnect",
        .definition =
            "Authentication bypass in ConnectWise ScreenConnect that can allow administrative access or takeover of a vulnerable instance.\n\n"
            "Mitigation: update, review users, sessions, extensions, logs, and remotely managed hosts.",
    },
};

static const WikiFlipTerm wikiflip_blue_team_terms[] = {
    {
        .title = "SIEM",
        .definition =
            "Security Information and Event Management centralizes logs, normalizes events, correlates signals, and produces alerts.\n\n"
            "Good practice: source inventory, parser quality, use-case tuning, retention, dashboards, and rules with context.",
    },
    {
        .title = "EDR",
        .definition =
            "Endpoint Detection and Response monitors processes, memory, network, persistence, and endpoint changes. It supports isolation, "
            "evidence collection, and hunting.\n\n"
            "Audit focus: coverage, exclusions, tamper protection, offline sensors, and remote response actions.",
    },
    {
        .title = "YARA",
        .definition =
            "YARA describes file or memory patterns with strings, conditions, and modules. It is useful for malware triage, hunting, and forensics.\n\n"
            "Good practice: specific rules, metadata, false-positive testing, and version control.",
    },
    {
        .title = "Sigma",
        .definition =
            "Sigma is a generic detection rule format for logs. It allows the same detection logic to be converted to multiple SIEM query languages.\n\n"
            "Good practice: map fields, define logsource, test conversions, and document expected false positives.",
    },
    {
        .title = "SOAR",
        .definition =
            "Security Orchestration, Automation and Response automates playbooks, enrichment, tickets, and containment actions.\n\n"
            "Audit focus: approvals, limits, rollback, secrets, integrations, and error handling.",
    },
    {
        .title = "UEBA",
        .definition =
            "User and Entity Behavior Analytics detects anomalies by comparing activity to baselines for users, hosts, or services.\n\n"
            "Use cases: credential abuse, abnormal hours, impossible travel, and access volume changes.",
    },
    {
        .title = "DFIR",
        .definition =
            "Digital Forensics and Incident Response combines evidence preservation, forensic analysis, and technical response.\n\n"
            "Good practice: chain of custody, triage, timeline, memory, disk, logs, and executive plus technical reporting.",
    },
    {
        .title = "Windows 4624/4625",
        .definition =
            "Windows events for successful and failed logons. They are key for password spraying, lateral movement, and abnormal access analysis.\n\n"
            "Important fields: LogonType, AccountName, WorkstationName, IpAddress, AuthenticationPackage, Status, and SubStatus.",
    },
    {
        .title = "Sysmon",
        .definition =
            "Sysmon records detailed telemetry for processes, network, DNS, drivers, files, and registry activity.\n\n"
            "Good practice: maintained configuration, noise filtering, EDR correlation, and log integrity protection.",
    },
    {
        .title = "NDR",
        .definition =
            "Network Detection and Response analyzes traffic for beaconing, C2, exfiltration, lateral movement, and unusual protocols.\n\n"
            "Audit focus: SPAN/TAP coverage, TLS metadata, DNS, NetFlow, Zeek, and alert response.",
    },
    {
        .title = "Incident Playbook",
        .definition =
            "A repeatable response procedure for scenarios such as ransomware, phishing, BEC, leaked credentials, or compromised hosts.\n\n"
            "It should define severity, roles, containment, evidence, communications, and recovery.",
    },
    {
        .title = "Threat Hunting",
        .definition =
            "Proactive searching based on hypotheses about adversary activity that may not have triggered alerts.\n\n"
            "Outputs: findings, new detections, logging gaps, and control improvements.",
    },
};

static const WikiFlipTerm wikiflip_red_team_terms[] = {
    {
        .title = "Phishing Simulation",
        .definition =
            "A controlled exercise to measure email controls, user behavior, and reporting workflow. Metrics include delivery, open, click, "
            "credential avoidance, and reporting.\n\n"
            "Controls assessed: SPF, DKIM, DMARC, sandboxing, banners, URL blocking, and SOC response.",
    },
    {
        .title = "Lateral Movement",
        .definition =
            "Movement between systems after initial access. It may abuse sessions, shares, RDP, WinRM, WMI, SSH, Kerberos, or admin tools.\n\n"
            "Controls: segmentation, local admin hygiene, detection, and credential protection.",
    },
    {
        .title = "C2",
        .definition =
            "Command and Control infrastructure lets an operator send tasks and receive results during an authorized test. It may use HTTPS, "
            "DNS, mTLS, redirectors, and traffic profiles.\n\n"
            "Controls assessed: egress filtering, TLS inspection, DNS monitoring, and beaconing detection.",
    },
    {
        .title = "Initial Access",
        .definition =
            "The entry phase into an environment through credentials, VPN, phishing, public exposure, supply chain, or vulnerable services.\n\n"
            "Audit focus: real attack surface, preventive controls, and detection traceability.",
    },
    {
        .title = "Privilege Escalation",
        .definition =
            "Obtaining higher privileges on a host, domain, cloud account, or application through misconfigurations, weak permissions, vulnerable "
            "kernels, or local secrets.\n\n"
            "Mitigation: hardening, least privilege, patching, and monitoring privileged changes.",
    },
    {
        .title = "Persistence",
        .definition =
            "Mechanisms used to maintain access, such as services, scheduled tasks, run keys, startup items, OAuth apps, webshells, or created accounts.\n\n"
            "Blue team focus: monitor creation and modification, then compare against baselines.",
    },
    {
        .title = "Credential Access",
        .definition =
            "Techniques to obtain secrets, such as LSASS access, dumps, browser stores, keychains, configs, cloud tokens, Kerberos, and password spraying.\n\n"
            "Controls: MFA, Credential Guard, secret scanning, vaulting, and detection.",
    },
    {
        .title = "Kerberoasting",
        .definition =
            "Requesting TGS tickets for SPN-backed service accounts and cracking the service hash offline. It often requires only a standard AD user.\n\n"
            "Mitigation: long passwords, gMSA, AES, anomalous TGS monitoring, and SPN cleanup.",
    },
    {
        .title = "Pass-the-Hash",
        .definition =
            "Using NTLM hashes without knowing the plaintext password to authenticate laterally. It impacts environments with NTLM enabled and reused privileges.\n\n"
            "Mitigation: limit local admins, LAPS, segmentation, NTLM restrictions, and EDR.",
    },
    {
        .title = "Living off the Land",
        .definition =
            "Using legitimate system binaries and tools for execution, download, persistence, or evasion.\n\n"
            "Examples: PowerShell, certutil, mshta, rundll32, wmic, bitsadmin, and schtasks.",
    },
    {
        .title = "OPSEC",
        .definition =
            "Operational security for reducing noise, preserving authorized traceability, and avoiding impact. It includes timing, volume, payloads, "
            "infrastructure, and artifact handling.\n\n"
            "In formal audits, critical actions and rollback are documented.",
    },
    {
        .title = "Payload Staging",
        .definition =
            "Splitting a small first-stage loader from later components. This can reduce initial size but increases network dependencies and observable signals.\n\n"
            "Controls: egress blocking, inspection, EDR, and allowlisting.",
    },
};

static const WikiFlipTerm wikiflip_threat_intelligence_terms[] = {
    {
        .title = "IOC",
        .definition =
            "Indicator of Compromise: a hash, IP, domain, path, mutex, certificate, or log pattern associated with malicious activity.\n\n"
            "Management: source, date, confidence, context, expiration, and correlation with TTPs.",
    },
    {
        .title = "TTP",
        .definition =
            "Tactics, Techniques, and Procedures describe adversary behavior. They are usually more durable than IoCs and commonly map to MITRE ATT&CK.\n\n"
            "Use: emulation, detection, gap analysis, and defensive prioritization.",
    },
    {
        .title = "STIX/TAXII",
        .definition =
            "STIX models threat intelligence; TAXII transports it. They can share indicators, malware, campaigns, relationships, and courses of action.\n\n"
            "Use: feeds, enrichment, normalization, and source traceability.",
    },
    {
        .title = "MITRE ATT&CK",
        .definition =
            "A knowledge base of adversary tactics and techniques organized by platform and operational phase.\n\n"
            "Use: coverage mapping, detection engineering, adversary emulation, and gap reporting.",
    },
    {
        .title = "Diamond Model",
        .definition =
            "An analytic model with four vertices: adversary, capability, infrastructure, and victim. It helps relate events and form hypotheses.\n\n"
            "Use: clustering, pivoting, and campaign analysis.",
    },
    {
        .title = "Cyber Kill Chain",
        .definition =
            "A phase model: reconnaissance, weaponization, delivery, exploitation, installation, C2, and actions on objectives.\n\n"
            "Use: place controls and detections across attack phases.",
    },
    {
        .title = "OSINT",
        .definition =
            "Open Source Intelligence collects information from public sources such as domains, leaks, repositories, networks, metadata, certificates, and cloud exposure.\n\n"
            "Good practice: validate source, legality, date, and reliability.",
    },
    {
        .title = "Threat Actor",
        .definition =
            "An entity or group with motivation, resources, TTPs, and objectives. It can be criminal, state-linked, hacktivist, insider, or opportunistic.\n\n"
            "Analysis: keep attribution evidence-based and state confidence clearly.",
    },
    {
        .title = "Campaign",
        .definition =
            "A set of related activities grouped by objective, infrastructure, malware, victims, or time period. It does not require firm attribution.\n\n"
            "Use: group IoCs, TTPs, timing, sectors, and responses.",
    },
    {
        .title = "Confidence Scoring",
        .definition =
            "A measure of certainty for an intelligence judgment, based on source quality, corroboration, recency, and evidence quality.\n\n"
            "Good practice: separate facts, inferences, and analytic judgments.",
    },
};

static const WikiFlipTerm wikiflip_hardware_terms[] = {
    {
        .title = "UART",
        .definition =
            "A common serial interface for debug consoles. It usually exposes TX, RX, GND, and sometimes VCC.\n\n"
            "Audit focus: voltage, baud rate, boot logs, prompts, credentials, and privileged diagnostic commands.",
    },
    {
        .title = "JTAG",
        .definition =
            "A test and debug interface that can allow CPU halt, memory access, firmware dumping, and low-level debugging.\n\n"
            "Mitigation: disable production debug, protect fuses, and enforce secure boot.",
    },
    {
        .title = "SWD",
        .definition =
            "Serial Wire Debug is a two-wire ARM debug interface using SWDIO and SWCLK. It may expose flash, registers, and execution control.\n\n"
            "Audit focus: readout protection, mass erase behavior, and physical access assumptions.",
    },
    {
        .title = "SPI Flash",
        .definition =
            "External memory used for firmware, configuration, or data. It can often be dumped with a clip or programmer if protections are absent.\n\n"
            "Audit focus: firmware dumps, strings, binwalk, secrets, partitions, and firmware signing.",
    },
    {
        .title = "I2C",
        .definition =
            "A two-wire bus for sensors, EEPROM, and peripherals. It uses SDA/SCL lines and device addresses.\n\n"
            "Audit focus: enumerate devices, observe traffic, read EEPROM, and validate controls over sensitive data.",
    },
    {
        .title = "Logic Analyzer",
        .definition =
            "A tool for capturing digital signals and decoding buses such as UART, I2C, SPI, or 1-Wire.\n\n"
            "Use: identify protocols, timing, commands, and secrets transmitted in cleartext.",
    },
    {
        .title = "RF Sniffing",
        .definition =
            "Capturing radio communications to analyze modulation, frequency, frames, and replay behavior.\n\n"
            "Audit focus: encryption, rolling codes, replay resistance, and metadata exposure.",
    },
    {
        .title = "NFC/RFID",
        .definition =
            "Radio identification technologies including LF RFID, HF NFC, MIFARE, DESFire, and tag emulation.\n\n"
            "Audit focus: tag type, keys, UID-only access, sectors, authentication, and replay.",
    },
    {
        .title = "GPIO",
        .definition =
            "General-purpose input/output pins used for control, debug, boot straps, or hidden features.\n\n"
            "Audit focus: pin mapping, logic levels, boot states, hidden functions, and electrical protection.",
    },
    {
        .title = "Bootloader",
        .definition =
            "Early code that initializes hardware and loads firmware. If exposed, it may allow dumping, flashing, or bypass.\n\n"
            "Audit focus: commands, passwords, secure boot, rollback, recovery mode, and signature enforcement.",
    },
    {
        .title = "Secure Boot",
        .definition =
            "A boot chain that verifies signatures before running firmware. It protects integrity when keys and fuses are managed correctly.\n\n"
            "Audit focus: enforcement, anti-rollback, key storage, and debug modes.",
    },
    {
        .title = "Fault Injection",
        .definition =
            "Inducing physical faults through voltage, clock, laser, or electromagnetic glitching to alter execution flow.\n\n"
            "Mitigation: redundancy, sensors, timing checks, secure elements, and robust boot design.",
    },
};

static const WikiFlipTerm wikiflip_iso_terms[] = {
    {
        .title = "ISO 27001",
        .definition =
            "Requirements for an Information Security Management System. It covers scope, risk, leadership, support, operation, evaluation, and improvement.\n\n"
            "Audit focus: Statement of Applicability, risk treatment, control evidence, internal audits, and corrective actions.",
    },
    {
        .title = "ISO 27002",
        .definition =
            "Implementation guidance for security controls. It complements ISO 27001 with practical control guidance and attributes.\n\n"
            "Audit focus: design, implementation, maturity, gaps, and risk alignment.",
    },
    {
        .title = "ISO 27005",
        .definition =
            "Guidance for information security risk management, including context, analysis, evaluation, treatment, communication, and monitoring.\n\n"
            "Use: build a repeatable and traceable risk methodology.",
    },
    {
        .title = "ISO 27017",
        .definition =
            "Security controls for cloud services, covering both cloud providers and cloud customers.\n\n"
            "Audit focus: shared responsibility, configuration, virtualization, administration, and tenant separation.",
    },
    {
        .title = "ISO 27018",
        .definition =
            "Protection of personal data in public cloud environments for processors of personally identifiable information.\n\n"
            "Audit focus: consent, limited use, disclosure, deletion, subprocessors, and transparency.",
    },
    {
        .title = "ISO 22301",
        .definition =
            "Business Continuity Management System standard covering BIA, strategies, plans, exercises, and continual improvement.\n\n"
            "Audit focus: RTO/RPO, testing, dependencies, crisis management, and recovery.",
    },
    {
        .title = "ISO 27701",
        .definition =
            "Privacy extension for ISO 27001 and ISO 27002. It defines a PIMS and controls for controllers and processors.\n\n"
            "Audit focus: PII inventory, legal basis, rights, DPIA, and third parties.",
    },
    {
        .title = "ISO 27035",
        .definition =
            "Information security incident management guidance covering planning, detection, reporting, response, and learning.\n\n"
            "Audit focus: roles, severity, channels, evidence, lessons learned, and metrics.",
    },
    {
        .title = "ISO 27032",
        .definition =
            "Cybersecurity guidance focused on collaboration, information sharing, and cyberspace risks.\n\n"
            "Use: align information security, network security, internet security, and critical protection.",
    },
    {
        .title = "ISO 42001",
        .definition =
            "Management system standard for artificial intelligence, covering governance, risks, lifecycle, transparency, oversight, and improvement.\n\n"
            "Audit focus: AI inventory, controls, data, assessments, monitoring, and responsibilities.",
    },
};

static const WikiFlipCategory wikiflip_categories[] = {
    {
        .name = "Protocols",
        .terms = wikiflip_protocols_terms,
        .term_count = WIKIFLIP_ARRAY_SIZE(wikiflip_protocols_terms),
    },
    {
        .name = "OWASP",
        .terms = wikiflip_owasp_terms,
        .term_count = WIKIFLIP_ARRAY_SIZE(wikiflip_owasp_terms),
    },
    {
        .name = "NIST",
        .terms = wikiflip_nist_terms,
        .term_count = WIKIFLIP_ARRAY_SIZE(wikiflip_nist_terms),
    },
    {
        .name = "CVE",
        .terms = wikiflip_cve_terms,
        .term_count = WIKIFLIP_ARRAY_SIZE(wikiflip_cve_terms),
    },
    {
        .name = "Blue Team",
        .terms = wikiflip_blue_team_terms,
        .term_count = WIKIFLIP_ARRAY_SIZE(wikiflip_blue_team_terms),
    },
    {
        .name = "Red Team",
        .terms = wikiflip_red_team_terms,
        .term_count = WIKIFLIP_ARRAY_SIZE(wikiflip_red_team_terms),
    },
    {
        .name = "Threat Intelligence",
        .terms = wikiflip_threat_intelligence_terms,
        .term_count = WIKIFLIP_ARRAY_SIZE(wikiflip_threat_intelligence_terms),
    },
    {
        .name = "Hardware Hacking",
        .terms = wikiflip_hardware_terms,
        .term_count = WIKIFLIP_ARRAY_SIZE(wikiflip_hardware_terms),
    },
    {
        .name = "ISO",
        .terms = wikiflip_iso_terms,
        .term_count = WIKIFLIP_ARRAY_SIZE(wikiflip_iso_terms),
    },
};

static void wikiflip_term_selected_callback(void* context, uint32_t index);

static void wikiflip_switch_to_view(WikiFlipApp* app, WikiFlipView view) {
    app->current_view = view;
    view_dispatcher_switch_to_view(app->view_dispatcher, view);
}

static void wikiflip_show_definition(WikiFlipApp* app, const WikiFlipTerm* term) {
    widget_reset(app->definition_widget);
    furi_string_printf(app->definition_buffer, "%s\n\n%s", term->title, term->definition);
    widget_add_text_scroll_element(
        app->definition_widget,
        0,
        0,
        WIKIFLIP_SCREEN_WIDTH,
        WIKIFLIP_SCREEN_HEIGHT,
        furi_string_get_cstr(app->definition_buffer));
}

static void wikiflip_terms_menu_rebuild(WikiFlipApp* app) {
    furi_assert(app->current_category);

    submenu_reset(app->terms_menu);
    submenu_set_header(app->terms_menu, app->current_category->name);

    for(size_t i = 0; i < app->current_category->term_count; i++) {
        submenu_add_item(
            app->terms_menu,
            app->current_category->terms[i].title,
            (uint32_t)i,
            wikiflip_term_selected_callback,
            app);
    }
}

static void wikiflip_term_selected_callback(void* context, uint32_t index) {
    WikiFlipApp* app = context;
    furi_assert(app);
    furi_assert(app->current_category);

    if(index >= app->current_category->term_count) {
        return;
    }

    app->current_term_index = index;
    wikiflip_show_definition(app, &app->current_category->terms[index]);
    wikiflip_switch_to_view(app, WikiFlipViewDefinition);
}

static void wikiflip_category_selected_callback(void* context, uint32_t index) {
    WikiFlipApp* app = context;
    furi_assert(app);

    if(index >= WIKIFLIP_ARRAY_SIZE(wikiflip_categories)) {
        return;
    }

    app->current_category_index = index;
    app->current_term_index = 0;
    app->current_category = &wikiflip_categories[index];

    wikiflip_terms_menu_rebuild(app);
    submenu_set_selected_item(app->terms_menu, app->current_term_index);

    wikiflip_switch_to_view(app, WikiFlipViewTerms);
}

static bool wikiflip_navigation_callback(void* context) {
    WikiFlipApp* app = context;
    furi_assert(app);

    switch(app->current_view) {
    case WikiFlipViewDefinition:
        submenu_set_selected_item(app->terms_menu, app->current_term_index);
        wikiflip_switch_to_view(app, WikiFlipViewTerms);
        return true;
    case WikiFlipViewTerms:
        submenu_set_selected_item(app->categories_menu, app->current_category_index);
        wikiflip_switch_to_view(app, WikiFlipViewCategories);
        return true;
    case WikiFlipViewCategories:
    default:
        view_dispatcher_stop(app->view_dispatcher);
        return true;
    }
}

static void wikiflip_categories_menu_build(WikiFlipApp* app) {
    submenu_reset(app->categories_menu);
    submenu_set_header(app->categories_menu, "WikiFlip");

    for(size_t i = 0; i < WIKIFLIP_ARRAY_SIZE(wikiflip_categories); i++) {
        submenu_add_item(
            app->categories_menu,
            wikiflip_categories[i].name,
            (uint32_t)i,
            wikiflip_category_selected_callback,
            app);
    }

    submenu_set_selected_item(app->categories_menu, app->current_category_index);
}

static WikiFlipApp* wikiflip_alloc(void) {
    WikiFlipApp* app = malloc(sizeof(WikiFlipApp));
    furi_assert(app);

    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    app->categories_menu = submenu_alloc();
    app->terms_menu = submenu_alloc();
    app->definition_widget = widget_alloc();
    app->definition_buffer = furi_string_alloc();
    app->current_category = &wikiflip_categories[0];
    app->current_category_index = 0;
    app->current_term_index = 0;
    app->current_view = WikiFlipViewCategories;

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, wikiflip_navigation_callback);

    view_dispatcher_add_view(
        app->view_dispatcher, WikiFlipViewCategories, submenu_get_view(app->categories_menu));
    view_dispatcher_add_view(
        app->view_dispatcher, WikiFlipViewTerms, submenu_get_view(app->terms_menu));
    view_dispatcher_add_view(
        app->view_dispatcher, WikiFlipViewDefinition, widget_get_view(app->definition_widget));

    wikiflip_categories_menu_build(app);
    wikiflip_terms_menu_rebuild(app);

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    return app;
}

static void wikiflip_free(WikiFlipApp* app) {
    furi_assert(app);

    view_dispatcher_remove_view(app->view_dispatcher, WikiFlipViewDefinition);
    view_dispatcher_remove_view(app->view_dispatcher, WikiFlipViewTerms);
    view_dispatcher_remove_view(app->view_dispatcher, WikiFlipViewCategories);

    widget_free(app->definition_widget);
    submenu_free(app->terms_menu);
    submenu_free(app->categories_menu);
    view_dispatcher_free(app->view_dispatcher);
    furi_string_free(app->definition_buffer);
    furi_record_close(RECORD_GUI);

    free(app);
}

int32_t wikiflip_app(void* p) {
    UNUSED(p);

    WikiFlipApp* app = wikiflip_alloc();
    wikiflip_switch_to_view(app, WikiFlipViewCategories);
    view_dispatcher_run(app->view_dispatcher);
    wikiflip_free(app);

    return 0;
}
