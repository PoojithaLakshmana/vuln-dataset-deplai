"""
build_dataset.py
----------------
Merges ALL raw source files into the full 6-layer schema.
Generates instruction-response training pairs for each layer.

NEW DATA SOURCES (Beyond Open Web):
  - raw_papers.json: Research papers from arXiv, IEEE, Google Scholar
  - raw_closed.json: Mailing lists, bug bounty, vendor advisories, Reddit/SO

Layers built:
  1. Vulnerability Intelligence  (OWASP Mapper + Correlation agents)
  2. Pentesting Intelligence      (Tool Selector + Scanner agents)
  3. Risk & Scoring               (Base Scorer + Severity Adjuster agents)
  4. Execution Context            (Tech Stack Filter + Spawn Decision agents)
  5. Audit Evidence               (Result Aggregator + Reporting agents)
  6. Remediation Learning         (Reflector + Memory agents)
"""

import json
import re
import uuid
from pathlib import Path
from owasp_mapper import get_owasp_category, get_pentest_intel

# ── Helpers ────────────────────────────────────────────────────────────────

def clean(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r'\s+', ' ', str(text))
    text = re.sub(r'[^\x00-\x7F]+', '', text)
    return text.strip()

def risk_level(cvss_score) -> str:
    if not cvss_score:
        return "Unknown"
    try:
        s = float(cvss_score)
        if s >= 9.0: return "Critical"
        if s >= 7.0: return "High"
        if s >= 4.0: return "Medium"
        return "Low"
    except ValueError:
        return "Unknown"

def business_impact(owasp_cat: str) -> str:
    impacts = {
        "A01:2021-Broken Access Control":           "Unauthorized data access, privilege escalation",
        "A02:2021-Cryptographic Failures":          "Sensitive data exposure, credential theft",
        "A03:2021-Injection":                       "Database compromise, remote code execution",
        "A04:2021-Insecure Design":                 "Systematic security bypass, reputational damage",
        "A05:2021-Security Misconfiguration":       "System compromise via exposed attack surface",
        "A06:2021-Vulnerable and Outdated Components": "Full system takeover via known exploits",
        "A07:2021-Identification and Authentication Failures": "Account takeover, session hijacking",
        "A08:2021-Software and Data Integrity Failures": "Supply chain compromise, malicious updates",
        "A09:2021-Security Logging and Monitoring Failures": "Undetected breaches, delayed incident response",
        "A10:2021-Server-Side Request Forgery":     "Internal network access, cloud metadata theft",
    }
    return impacts.get(owasp_cat, "Security breach, data loss")

def infer_security_control_missing(owasp_cat: str) -> str:
    controls = {
        "A03:2021-Injection":                       "Input validation and parameterized queries",
        "A02:2021-Cryptographic Failures":          "Strong encryption and secure key management",
        "A01:2021-Broken Access Control":           "Authorization checks and role-based access control",
        "A07:2021-Identification and Authentication Failures": "MFA and strong session management",
        "A05:2021-Security Misconfiguration":       "Secure configuration baseline and hardening",
        "A06:2021-Vulnerable and Outdated Components": "Dependency scanning and patch management",
        "A10:2021-Server-Side Request Forgery":     "URL allowlist validation and network segmentation",
    }
    return controls.get(owasp_cat, "Security control review required")

# ── Load raw sources ───────────────────────────────────────────────────────

def load_json(path: str):
    p = Path(path)
    if not p.exists():
        print(f"  ⚠️  {path} not found — skipping")
        return []
    with open(p, encoding="utf-8") as f:
        return json.load(f)

def build_epss_lookup(epss_path: str) -> dict:
    raw = load_json(epss_path)
    if isinstance(raw, dict):
        return raw
    return {}

def build_github_lookup(github_path: str) -> dict:
    raw = load_json(github_path)
    lookup = {}
    for item in raw:
        cve = item.get("cve_id", "")
        if cve:
            lookup[cve] = item
    return lookup

def build_blog_lookup(blog_path: str) -> dict:
    raw = load_json(blog_path)
    lookup = {}
    for item in raw:
        content = item.get("content", "")
        if len(content) > 3000:
            content = content[:3000] + "... [truncated]"
        
        source = f"Source: {item.get('url', 'Unknown Blog')}\n\n{content}"
        for cve in item.get("cves_mentioned", []):
            cve = cve.upper()
            if cve in lookup:
                lookup[cve] += "\n\n---\n\n" + source
            else:
                lookup[cve] = source
    return lookup

def build_papers_lookup(papers_path: str) -> dict:
    """
    NEW: Research papers from arXiv, IEEE, Google Scholar
    """
    raw = load_json(papers_path)
    lookup = {}
    for paper in raw:
        title = paper.get("title", "Unknown Paper")
        abstract = paper.get("abstract", "")
        source = paper.get("source", "research")
        fulltext = paper.get("fulltext_sample", "")
        
        content = f"Research Paper: {title}\nSource: {source}\n\n{abstract}"
        if fulltext:
            content += f"\n\nExcerpt: {fulltext[:1000]}"
        
        for cve in paper.get("cves_mentioned", []):
            cve = cve.upper()
            if cve in lookup:
                lookup[cve] += "\n\n---\n\n" + content
            else:
                lookup[cve] = content
    return lookup

def build_closed_sources_lookup(closed_path: str) -> dict:
    """
    NEW: Closed/semi-private sources - mailing lists, bug bounty, vendor advisories
    """
    raw = load_json(closed_path)
    lookup = {}
    for item in raw:
        source_type = item.get("source", "unknown")
        title = item.get("title", "")
        content = item.get("content", item.get("summary", item.get("body", "")))
        
        if source_type == "full_disclosure":
            header = f"Full Disclosure Mailing List:\n{content[:1500]}"
        elif source_type == "hackerone":
            header = f"HackerOne Report: {title}\nSeverity: {item.get('severity', 'N/A')}\n{content[:1000]}"
        elif source_type == "microsoft_msrc":
            header = f"Microsoft Security Advisory: {title}\n{content[:1000]}"
        elif source_type == "reddit_netsec":
            header = f"Reddit /r/netsec: {title}\nScore: {item.get('score', 0)}\n{content[:1000]}"
        else:
            header = f"{source_type}: {content[:1000]}"
        
        for cve in item.get("cves_mentioned", []):
            cve = cve.upper()
            if cve in lookup:
                lookup[cve] += "\n\n---\n\n" + header
            else:
                lookup[cve] = header
    return lookup

# ── Build full schema record ───────────────────────────────────────────────

def build_record(nvd_rec: dict, epss_map: dict, github_map: dict, blog_map: dict, 
                papers_map: dict, closed_map: dict) -> dict:
    cve_id   = nvd_rec.get("cve_id", "")
    cwe_id   = nvd_rec.get("cwe_id", "")
    desc     = clean(nvd_rec.get("description", ""))
    cvss     = nvd_rec.get("cvss_score", "")
    sev      = nvd_rec.get("cvss_severity", "")

    owasp_cat   = get_owasp_category(cwe_id)
    pentest     = get_pentest_intel(owasp_cat)
    epss_score  = epss_map.get(cve_id, "")
    gh_advisory = github_map.get(cve_id, {})
    blog_content = blog_map.get(cve_id, "")
    
    # NEW: Research papers + closed sources
    research_context = papers_map.get(cve_id, "")
    closed_context = closed_map.get(cve_id, "")

    fix_rec = gh_advisory.get("fix_recommendation", "")
    if not fix_rec:
        fix_rec = "Apply vendor-supplied patches. Implement input validation and follow secure coding practices."

    # Combine all real-world context
    combined_context = "\n\n".join(filter(None, [blog_content, research_context, closed_context]))

    return {
        "id":                    f"VULN_{str(uuid.uuid4())[:8].upper()}",

        # ── Layer 1: Vulnerability Intelligence ──────────
        "vulnerability_name":    nvd_rec.get("vulnerability_name", cve_id),
        "cve_id":                cve_id,
        "cwe_id":                cwe_id,
        "owasp_category":        owasp_cat,
        "description":           desc,
        "root_cause":            infer_security_control_missing(owasp_cat),

        # ── Layer 2: Pentesting Intelligence ─────────────
        "attack_method":         pentest.get("attack_method", ""),
        "payload_example":       pentest.get("payload_example", ""),
        "detection_signals":     pentest.get("detection_signals", []),
        "real_world_exploit":    combined_context,  # Combined from ALL sources
        "code_pattern":          pentest.get("code_pattern", ""),

        # ── Layer 3: Risk & Scoring ───────────────────────
        "cvss_score":            cvss,
        "cvss_severity":         sev,
        "epss_score":            epss_score,
        "risk_level":            risk_level(cvss),
        "business_impact":       business_impact(owasp_cat),

        # ── Layer 4: Execution Context ────────────────────
        "asset_type":            "Web Application",
        "environment":           "Unknown",
        "internet_facing":       True,
        "tech_stack":            {"language": "", "framework": "", "database": ""},

        # ── Layer 5: Audit Evidence ───────────────────────
        "tool_used":             pentest.get("tool_used", "Manual review"),
        "evidence_type":         "vulnerability_research",
        "evidence_summary":      f"Identified via CVE database. CVSS: {cvss}. {desc[:120]}...",
        "security_control_missing": infer_security_control_missing(owasp_cat),

        # ── Layer 6: Remediation Learning ────────────────
        "fix_recommendation":    fix_rec,
        "status":                "Open",
        "related_vulnerabilities": [],

        # ── Source tracking ───────────────────────────────
        "source":                "NVD + OWASP + FIRST EPSS" + (
            " + GitHub Advisories" if gh_advisory else ""
        ) + (" + Security Blogs" if blog_content else "") + (
            " + Research Papers" if research_context else ""
        ) + (" + Closed Sources" if closed_context else ""),
    }

# ── Generate training pairs ────────────────────────────────────────────────

def to_training_pairs(record: dict) -> list[dict]:
    cve    = record["cve_id"]
    desc   = record["description"]
    owasp  = record["owasp_category"]
    cvss   = record["cvss_score"]
    risk   = record["risk_level"]
    sev    = record["cvss_severity"]
    epss   = record["epss_score"]
    fix    = record["fix_recommendation"]
    method = record["attack_method"]
    sigs   = ", ".join(record["detection_signals"])
    biz    = record["business_impact"]
    ctrl   = record["security_control_missing"]
    tool   = record["tool_used"]
    cwe    = record["cwe_id"]
    exploit_ctx = record.get("real_world_exploit", "")

    pairs = []

    # ── L1: Vulnerability Intelligence ────────────────────────────────────
    if desc:
        pairs.append({
            "instruction": f"Explain the vulnerability {cve} and map it to its OWASP category.",
            "input":       "",
            "output":      f"{desc}\n\nOWASP Category: {owasp}\nCWE: {cwe}",
            "layer":       "vulnerability_intelligence",
            "agent":       "OWASP Mapper Agent"
        })

    # ── L2: Pentesting Intelligence ──────────────────────────────────────
    if method:
        pairs.append({
            "instruction": "Describe how to test for this vulnerability during a pentest.",
            "input":       desc,
            "output":      (
                f"Attack Method: {method}\n\n"
                f"Detection Signals: {sigs}\n\n"
                f"Recommended Tool: {tool}"
            ),
            "layer":       "pentesting_intelligence",
            "agent":       "Tool Selector Agent"
        })
    
    # NEW: Real-world context from research papers + closed sources
    if exploit_ctx:
        pairs.append({
            "instruction": f"Provide real-world exploit examples and research findings for {cve}.",
            "input":       desc,
            "output":      f"Real-world context for {cve}:\n\n{exploit_ctx}",
            "layer":       "pentesting_intelligence",
            "agent":       "Scanner Agent"
        })

    # ── L3: Risk & Scoring ────────────────────────────────────────────────
    if cvss:
        pairs.append({
            "instruction": "Perform a risk assessment for this vulnerability.",
            "input":       desc,
            "output":      (
                f"CVSS Score: {cvss} ({sev})\n"
                f"Risk Level: {risk}\n"
                f"EPSS Score: {epss if epss else 'Not available'}\n"
                f"Business Impact: {biz}"
            ),
            "layer":       "risk_scoring",
            "agent":       "Base Scorer Agent"
        })

    # ── L4: Execution Context ─────────────────────────────────────────────
    if owasp != "Unknown":
        pairs.append({
            "instruction": "Which security tool should be used to test this vulnerability, and why?",
            "input":       f"Vulnerability type: {owasp}\nDescription: {desc}",
            "output":      (
                f"Recommended tool: {tool}\n"
                f"Reason: This is a {owasp} class vulnerability. "
                f"The attack method involves: {method}"
            ),
            "layer":       "execution_context",
            "agent":       "Tool Selector Agent"
        })

    # ── L5: Audit Evidence ────────────────────────────────────────────────
    if cvss:
        pairs.append({
            "instruction": "Generate an audit finding summary for this vulnerability.",
            "input":       desc,
            "output":      (
                f"Finding: {record['vulnerability_name']}\n"
                f"CVE: {cve} | CWE: {cwe} | OWASP: {owasp}\n"
                f"Severity: {sev} (CVSS {cvss})\n"
                f"Security Control Missing: {ctrl}\n"
                f"Evidence: Confirmed via vulnerability research and CVE database.\n"
                f"Tool: {tool}"
            ),
            "layer":       "audit_evidence",
            "agent":       "Reporting Agent"
        })

    # ── L6: Remediation Learning ──────────────────────────────────────────
    if fix:
        pairs.append({
            "instruction": "What is the recommended remediation for this vulnerability?",
            "input":       desc,
            "output":      (
                f"Remediation: {fix}\n\n"
                f"Root Cause: {ctrl}\n"
                f"Control Type: Technical"
            ),
            "layer":       "remediation_learning",
            "agent":       "Reflector Agent"
        })

    return pairs

# ── Main ───────────────────────────────────────────────────────────────────

def run():
    print("Loading raw data sources...")
    nvd_records = load_json("data/raw_nvd.json")
    epss_map    = build_epss_lookup("data/raw_epss.json")
    github_map  = build_github_lookup("data/raw_github.json")
    blog_map    = build_blog_lookup("data/raw_blogs.json")
    
    # NEW: Load research papers and closed sources
    papers_map  = build_papers_lookup("data/raw_papers.json")
    closed_map  = build_closed_sources_lookup("data/raw_closed.json")

    print(f"  NVD records:     {len(nvd_records)}")
    print(f"  EPSS entries:    {len(epss_map)}")
    print(f"  GitHub entries:  {len(github_map)}")
    print(f"  Blog entries:    {len(blog_map)} (CVEs matched)")
    print(f"  Research papers: {len(papers_map)} (CVEs matched)")
    print(f"  Closed sources:  {len(closed_map)} (CVEs matched)")

    # ── Build full records ─────────────────────────────────────────────────
    seen_cves = set()
    full_records  = []
    training_pairs = []

    for nvd_rec in nvd_records:
        cve_id = nvd_rec.get("cve_id", "")
        desc   = nvd_rec.get("description", "")

        if not desc or len(desc) < 50:
            continue
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        record = build_record(nvd_rec, epss_map, github_map, blog_map, papers_map, closed_map)
        full_records.append(record)
        training_pairs.extend(to_training_pairs(record))

    # ── Save outputs ───────────────────────────────────────────────────────
    with open("data/vuln_dataset.jsonl", "w") as f:
        for r in full_records:
            f.write(json.dumps(r) + "\n")

    with open("data/training_pairs.jsonl", "w") as f:
        for p in training_pairs:
            f.write(json.dumps(p) + "\n")

    # ── Stats ──────────────────────────────────────────────────────────────
    layer_counts = {}
    for p in training_pairs:
        l = p.get("layer", "unknown")
        layer_counts[l] = layer_counts.get(l, 0) + 1

    print(f"\n✅ Full schema records:  {len(full_records)} → data/vuln_dataset.jsonl")
    print(f"✅ Training pairs total: {len(training_pairs)} → data/training_pairs.jsonl")
    print("\nTraining pairs per layer:")
    for layer, count in sorted(layer_counts.items()):
        print(f"  {layer:<30} {count:>6} examples")
    
    # NEW: Show source enrichment stats
    sources_used = {}
    for r in full_records:
        source_str = r.get("source", "")
        if "Research Papers" in source_str:
            sources_used["research_papers"] = sources_used.get("research_papers", 0) + 1
        if "Closed Sources" in source_str:
            sources_used["closed_sources"] = sources_used.get("closed_sources", 0) + 1
    
    print(f"\n📊 Source enrichment:")
    print(f"  Records with research papers: {sources_used.get('research_papers', 0)}")
    print(f"  Records with closed sources:  {sources_used.get('closed_sources', 0)}")

if __name__ == "__main__":
    run()