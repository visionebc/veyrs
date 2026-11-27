"""Built-in compliance catalogues.

READ THIS BEFORE ADDING A FRAMEWORK.

VEYRS ships **control identifiers and short titles**, never reproduced
normative text from a copyrighted standard, and never a requirement invented to
fill a gap. Each catalogue below declares:

  * `source_url`   - where the authoritative document lives
  * `licence_note` - the copyright/licence position of what we ship
  * `is_partial`   - TRUE unless the catalogue here is genuinely complete
  * `official_control_count` - what the published standard actually contains,
    so a partial catalogue reports "24 of 93 identifiers shipped" rather than
    silently looking finished

`veyrs_guidance` on a control is **VEYRS' own** commentary about how the control
relates to vulnerability management. It is labelled as ours everywhere it is
displayed and is never presented as the publisher's wording.

Crosswalks between frameworks are editorial judgements by VEYRS, not endorsed
mappings. They exist to help an analyst navigate, not to prove equivalence.

To load a full catalogue an organization already licenses, use
`POST /api/v1/compliance/frameworks/{id}/controls:import` with a CSV export --
that path sets `is_partial=false` once the count matches.
"""
from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# NIST Cybersecurity Framework 2.0
# ---------------------------------------------------------------------------
# NIST publications are works of the U.S. federal government and are not subject
# to copyright in the United States. The Function/Category identifiers and names
# below are reproduced from CSWP 29 (NIST CSF 2.0, February 2024). Subcategories
# are a curated subset relevant to vulnerability and risk management.
NIST_CSF_20: dict[str, Any] = {
    "slug": "nist-csf",
    "name": "NIST Cybersecurity Framework",
    "version": "2.0",
    "publisher": "NIST",
    "description": (
        "Outcome-based cybersecurity framework organised into six Functions. "
        "VEYRS ships all 22 Categories plus the Subcategories most directly "
        "served by vulnerability and risk management data."
    ),
    "source_url": "https://www.nist.gov/cyberframework",
    "licence_note": (
        "NIST CSF 2.0 (NIST CSWP 29) is a U.S. Government work, not subject to "
        "copyright in the United States. Identifiers and names reproduced as "
        "published."
    ),
    "is_partial": True,
    "official_control_count": 106,  # Subcategories in CSF 2.0
    "controls": [
        # --- GOVERN
        ("GV.OC", "Organizational Context", "GOVERN", None, None),
        ("GV.RM", "Risk Management Strategy", "GOVERN", None, None),
        ("GV.RR", "Roles, Responsibilities, and Authorities", "GOVERN", None, None),
        ("GV.PO", "Policy", "GOVERN", None, None),
        ("GV.OV", "Oversight", "GOVERN", None, None),
        ("GV.SC", "Cybersecurity Supply Chain Risk Management", "GOVERN", None, None),
        # --- IDENTIFY
        ("ID.AM", "Asset Management", "IDENTIFY", None, None),
        ("ID.AM-01", "Inventories of hardware managed by the organization are maintained",
         "IDENTIFY", "ID.AM", "asset_inventory_coverage"),
        ("ID.AM-02", "Inventories of software, services, and systems are maintained",
         "IDENTIFY", "ID.AM", "product_inventory_coverage"),
        ("ID.AM-05", "Assets are prioritized based on classification, criticality, "
                     "resources, and impact on the mission",
         "IDENTIFY", "ID.AM", "asset_criticality_assigned"),
        ("ID.RA", "Risk Assessment", "IDENTIFY", None, None),
        ("ID.RA-01", "Vulnerabilities in assets are identified, validated, and recorded",
         "IDENTIFY", "ID.RA", "vulnerabilities_recorded"),
        ("ID.RA-05", "Threats, vulnerabilities, likelihoods, and impacts are used to "
                     "understand inherent risk and inform risk response prioritization",
         "IDENTIFY", "ID.RA", "risk_scoring_active"),
        ("ID.RA-06", "Risk responses are chosen, prioritized, planned, tracked, and "
                     "communicated",
         "IDENTIFY", "ID.RA", "findings_have_owners"),
        ("ID.IM", "Improvement", "IDENTIFY", None, None),
        # --- PROTECT
        ("PR.AA", "Identity Management, Authentication, and Access Control", "PROTECT",
         None, None),
        ("PR.AT", "Awareness and Training", "PROTECT", None, None),
        ("PR.DS", "Data Security", "PROTECT", None, None),
        ("PR.PS", "Platform Security", "PROTECT", None, None),
        ("PR.PS-02", "Software is maintained, replaced, and removed commensurate with risk",
         "PROTECT", "PR.PS", "remediation_within_sla"),
        ("PR.IR", "Technology Infrastructure Resilience", "PROTECT", None, None),
        # --- DETECT
        ("DE.CM", "Continuous Monitoring", "DETECT", None, None),
        ("DE.CM-09", "Computing hardware and software, runtime environments, and their "
                     "data are monitored to find potentially adverse events",
         "DETECT", "DE.CM", "scan_recency"),
        ("DE.AE", "Adverse Event Analysis", "DETECT", None, None),
        # --- RESPOND
        ("RS.MA", "Incident Management", "RESPOND", None, None),
        ("RS.AN", "Incident Analysis", "RESPOND", None, None),
        ("RS.CO", "Incident Response Reporting and Communication", "RESPOND", None, None),
        ("RS.MI", "Incident Mitigation", "RESPOND", None, None),
        # --- RECOVER
        ("RC.RP", "Incident Recovery Plan Execution", "RECOVER", None, None),
        ("RC.CO", "Incident Recovery Communication", "RECOVER", None, None),
    ],
}

# ---------------------------------------------------------------------------
# CIS Critical Security Controls v8
# ---------------------------------------------------------------------------
# The 18 top-level Controls plus the Safeguards of Control 7 (Continuous
# Vulnerability Management), which is the one VEYRS can evidence directly.
CIS_V8: dict[str, Any] = {
    "slug": "cis-controls",
    "name": "CIS Critical Security Controls",
    "version": "8",
    "publisher": "Center for Internet Security",
    "description": (
        "Prioritised set of defensive actions. VEYRS ships all 18 Controls and "
        "the Safeguards of Control 7, which vulnerability management data "
        "evidences directly."
    ),
    "source_url": "https://www.cisecurity.org/controls",
    "licence_note": (
        "CIS Controls are published by the Center for Internet Security under "
        "CC BY-NC-SA 4.0. Identifiers and titles are shipped for mapping; the "
        "full Safeguard descriptions must be obtained from CIS."
    ),
    "is_partial": True,
    "official_control_count": 153,  # Safeguards across all 18 Controls
    "controls": [
        ("1", "Inventory and Control of Enterprise Assets", "Basic", None,
         "asset_inventory_coverage"),
        ("2", "Inventory and Control of Software Assets", "Basic", None,
         "product_inventory_coverage"),
        ("3", "Data Protection", "Basic", None, None),
        ("4", "Secure Configuration of Enterprise Assets and Software", "Basic", None, None),
        ("5", "Account Management", "Basic", None, None),
        ("6", "Access Control Management", "Basic", None, None),
        ("7", "Continuous Vulnerability Management", "Foundational", None,
         "vulnerabilities_recorded"),
        ("7.1", "Establish and Maintain a Vulnerability Management Process",
         "Foundational", "7", "vulnerabilities_recorded"),
        ("7.2", "Establish and Maintain a Remediation Process", "Foundational", "7",
         "findings_have_owners"),
        ("7.3", "Perform Automated Operating System Patch Management", "Foundational", "7",
         "remediation_within_sla"),
        ("7.4", "Perform Automated Application Patch Management", "Foundational", "7",
         "remediation_within_sla"),
        ("7.5", "Perform Automated Vulnerability Scans of Internal Enterprise Assets",
         "Foundational", "7", "scan_recency"),
        ("7.6", "Perform Automated Vulnerability Scans of Externally-Exposed "
                "Enterprise Assets", "Foundational", "7", "internet_asset_scan_recency"),
        ("7.7", "Remediate Detected Vulnerabilities", "Foundational", "7",
         "no_overdue_kev"),
        ("8", "Audit Log Management", "Foundational", None, None),
        ("9", "Email and Web Browser Protections", "Foundational", None, None),
        ("10", "Malware Defenses", "Foundational", None, None),
        ("11", "Data Recovery", "Foundational", None, None),
        ("12", "Network Infrastructure Management", "Foundational", None, None),
        ("13", "Network Monitoring and Defense", "Organizational", None, None),
        ("14", "Security Awareness and Skills Training", "Organizational", None, None),
        ("15", "Service Provider Management", "Organizational", None, None),
        ("16", "Application Software Security", "Organizational", None, None),
        ("17", "Incident Response Management", "Organizational", None, None),
        ("18", "Penetration Testing", "Organizational", None, None),
    ],
}

# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022 Annex A
# ---------------------------------------------------------------------------
# ISO/IEC standards are copyrighted. VEYRS ships the Annex A control NUMBERS and
# their short titles -- the minimum needed to map to them -- and nothing else.
# The four themes and the total of 93 controls are stated so a partial catalogue
# is visibly partial.
ISO_27001_2022: dict[str, Any] = {
    "slug": "iso-27001",
    "name": "ISO/IEC 27001 Annex A",
    "version": "2022",
    "publisher": "ISO/IEC",
    "description": (
        "Annex A control set of ISO/IEC 27001:2022, organised into four themes. "
        "VEYRS ships the subset of control identifiers that vulnerability and "
        "risk management data can evidence."
    ),
    "source_url": "https://www.iso.org/standard/27001",
    "licence_note": (
        "ISO/IEC 27001:2022 is copyright ISO/IEC. VEYRS ships control "
        "identifiers and short titles only, for mapping purposes. The normative "
        "text must be obtained from ISO or a national standards body. Import "
        "your licensed copy to populate the full catalogue."
    ),
    "is_partial": True,
    "official_control_count": 93,
    "controls": [
        ("A.5", "Organizational controls", "Organizational", None, None),
        ("A.5.7", "Threat intelligence", "Organizational", "A.5", "threat_feeds_active"),
        ("A.5.9", "Inventory of information and other associated assets",
         "Organizational", "A.5", "asset_inventory_coverage"),
        ("A.5.12", "Classification of information", "Organizational", "A.5",
         "asset_classification_assigned"),
        ("A.5.23", "Information security for use of cloud services", "Organizational",
         "A.5", None),
        ("A.5.24", "Information security incident management planning and preparation",
         "Organizational", "A.5", None),
        ("A.5.25", "Assessment and decision on information security events",
         "Organizational", "A.5", None),
        ("A.5.26", "Response to information security incidents", "Organizational", "A.5",
         None),
        ("A.5.36", "Compliance with policies, rules and standards for information "
                   "security", "Organizational", "A.5", None),
        ("A.6", "People controls", "People", None, None),
        ("A.6.3", "Information security awareness, education and training", "People",
         "A.6", None),
        ("A.7", "Physical controls", "Physical", None, None),
        ("A.8", "Technological controls", "Technological", None, None),
        ("A.8.8", "Management of technical vulnerabilities", "Technological", "A.8",
         "vulnerabilities_recorded"),
        ("A.8.9", "Configuration management", "Technological", "A.8", None),
        ("A.8.15", "Logging", "Technological", "A.8", None),
        ("A.8.16", "Monitoring activities", "Technological", "A.8", "scan_recency"),
        ("A.8.19", "Installation of software on operational systems", "Technological",
         "A.8", "product_inventory_coverage"),
        ("A.8.20", "Networks security", "Technological", "A.8", None),
        ("A.8.25", "Secure development life cycle", "Technological", "A.8", None),
        ("A.8.28", "Secure coding", "Technological", "A.8", None),
        ("A.8.29", "Security testing in development and acceptance", "Technological",
         "A.8", None),
        ("A.8.32", "Change management", "Technological", "A.8", None),
    ],
}

# ---------------------------------------------------------------------------
# ISO/IEC 27002:2022
# ---------------------------------------------------------------------------
# Same 93 controls as Annex A, without the "A." prefix, with implementation
# guidance (which VEYRS does NOT ship -- it is the bulk of the copyrighted text).
ISO_27002_2022: dict[str, Any] = {
    "slug": "iso-27002",
    "name": "ISO/IEC 27002",
    "version": "2022",
    "publisher": "ISO/IEC",
    "description": (
        "Implementation guidance for the ISO/IEC 27001:2022 Annex A controls. "
        "VEYRS ships identifiers and short titles only."
    ),
    "source_url": "https://www.iso.org/standard/75652.html",
    "licence_note": (
        "ISO/IEC 27002:2022 is copyright ISO/IEC. The implementation guidance "
        "that makes up most of this standard is NOT shipped with VEYRS."
    ),
    "is_partial": True,
    "official_control_count": 93,
    "controls": [
        ("5.7", "Threat intelligence", "Organizational", None, "threat_feeds_active"),
        ("5.9", "Inventory of information and other associated assets", "Organizational",
         None, "asset_inventory_coverage"),
        ("5.12", "Classification of information", "Organizational", None,
         "asset_classification_assigned"),
        ("8.8", "Management of technical vulnerabilities", "Technological", None,
         "vulnerabilities_recorded"),
        ("8.9", "Configuration management", "Technological", None, None),
        ("8.16", "Monitoring activities", "Technological", None, "scan_recency"),
        ("8.32", "Change management", "Technological", None, None),
    ],
}

BUILTIN_FRAMEWORKS: tuple[dict[str, Any], ...] = (
    NIST_CSF_20, CIS_V8, ISO_27001_2022, ISO_27002_2022,
)

# ---------------------------------------------------------------------------
# Crosswalks
# ---------------------------------------------------------------------------
# EDITORIAL, by VEYRS. Not endorsed by NIST, CIS or ISO. Keyed by
# "<framework slug>:<control ref>" and listing the equivalents VEYRS considers
# closest. Displayed with an explicit "VEYRS mapping" label.
CROSSWALK: dict[str, dict[str, list[str]]] = {
    "iso-27001:A.8.8": {"nist-csf": ["ID.RA-01"], "cis-controls": ["7", "7.1"],
                        "iso-27002": ["8.8"]},
    "iso-27001:A.5.7": {"nist-csf": ["ID.RA-05"], "cis-controls": ["7"],
                        "iso-27002": ["5.7"]},
    "iso-27001:A.5.9": {"nist-csf": ["ID.AM-01", "ID.AM-02"], "cis-controls": ["1", "2"],
                        "iso-27002": ["5.9"]},
    "iso-27001:A.5.12": {"nist-csf": ["ID.AM-05"], "cis-controls": ["3"],
                         "iso-27002": ["5.12"]},
    "nist-csf:ID.RA-01": {"iso-27001": ["A.8.8"], "cis-controls": ["7", "7.1"]},
    "nist-csf:PR.PS-02": {"iso-27001": ["A.8.8"], "cis-controls": ["7.3", "7.4", "7.7"]},
    "nist-csf:ID.AM-01": {"iso-27001": ["A.5.9"], "cis-controls": ["1"]},
    "nist-csf:ID.AM-02": {"iso-27001": ["A.5.9", "A.8.19"], "cis-controls": ["2"]},
    "cis-controls:7": {"iso-27001": ["A.8.8"], "nist-csf": ["ID.RA-01", "PR.PS-02"]},
    "cis-controls:7.7": {"iso-27001": ["A.8.8"], "nist-csf": ["PR.PS-02"]},
    "cis-controls:1": {"iso-27001": ["A.5.9"], "nist-csf": ["ID.AM-01"]},
    "cis-controls:2": {"iso-27001": ["A.5.9"], "nist-csf": ["ID.AM-02"]},
}

# ---------------------------------------------------------------------------
# VEYRS guidance
# ---------------------------------------------------------------------------
# Keyed the same way. This text is OURS and is displayed as such.
GUIDANCE: dict[str, str] = {
    "iso-27001:A.8.8": (
        "VEYRS evidences this control end to end: intelligence ingestion "
        "(NVD/EPSS/KEV) proves you learn about vulnerabilities, correlation "
        "proves you know where they apply, the risk engine proves you evaluate "
        "them, and SLA/ticket records prove you act within a defined timeframe."
    ),
    "nist-csf:ID.RA-01": (
        "Satisfied by the Finding lifecycle: every correlated vulnerability is "
        "recorded against a specific asset, validated through triage, and "
        "carries an auditable state history."
    ),
    "cis-controls:7.7": (
        "Evidenced by remediation-within-SLA metrics and the absence of overdue "
        "CISA KEV findings. VEYRS reports the number, not a pass/fail verdict."
    ),
    "cis-controls:7.6": (
        "Evidenced by scan recency restricted to assets with exposure=internet."
    ),
}
