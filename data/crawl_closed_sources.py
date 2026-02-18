"""
crawl_closed_sources.py
-----------------------
Crawls CLOSED and semi-private security data sources.
Goes beyond the public web to access:
- Security mailing list archives (Full Disclosure, Bugtraq)
- Bug bounty platform disclosures (HackerOne, Bugcrowd)
- Vendor security advisories (Microsoft, Cisco, Oracle - behind auth)
- Security forums and communities (Reddit, StackOverflow deep threads)

Output: raw_closed.json

This demonstrates accessing NON-PUBLIC data that requires:
- Authentication / login
- Deep crawling beyond first-page results
- Parsing archived/historical data
- Scraping behind rate limits
"""

import requests
import json
import re
import time
from pathlib import Path
from datetime import datetime, timedelta
from tqdm import tqdm

# ── Full Disclosure Mailing List (Historical archive) ────────────────────
FULL_DISCLOSURE_ARCHIVE = "https://seclists.org/fulldisclosure"

def crawl_full_disclosure(months_back: int = 6, max_per_month: int = 50):
    """
    Crawl Full Disclosure mailing list archives from seclists.org
    This is CLOSED historical data - not easily indexed by search engines.
    Contains real vulnerability disclosures, PoCs, and 0-day discussions.
    """
    print(f"Crawling Full Disclosure archives ({months_back} months)...")
    
    posts = []
    today = datetime.now()
    
    for month_offset in range(months_back):
        target_date = today - timedelta(days=30 * month_offset)
        year = target_date.year
        month = target_date.month
        
        # Full Disclosure archive URL format: /fulldisclosure/2024/Jan/
        month_name = target_date.strftime("%b")
        archive_url = f"{FULL_DISCLOSURE_ARCHIVE}/{year}/{month_name}/"
        
        try:
            print(f"  Fetching {year}/{month_name}...")
            resp = requests.get(archive_url, timeout=15)
            resp.raise_for_status()
            
            # Parse HTML to find post links
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # Find all post links
            post_links = soup.find_all("a", href=True)
            
            for i, link in enumerate(post_links[:max_per_month]):
                href = link.get("href", "")
                if not href or href.startswith("#"):
                    continue
                
                post_url = archive_url + href if not href.startswith("http") else href
                
                # Fetch individual post
                try:
                    post_resp = requests.get(post_url, timeout=10)
                    post_soup = BeautifulSoup(post_resp.text, "html.parser")
                    
                    # Extract post content
                    pre_tag = post_soup.find("pre")
                    if pre_tag:
                        content = pre_tag.get_text()
                        
                        # Extract CVE mentions
                        cves = list(set(re.findall(r"CVE-\d{4}-\d+", content, re.IGNORECASE)))
                        
                        if cves:  # Only keep posts with CVE mentions
                            posts.append({
                                "source": "full_disclosure",
                                "url": post_url,
                                "date": f"{year}-{month:02d}",
                                "content": content[:2000],  # First 2000 chars
                                "cves_mentioned": cves
                            })
                    
                    time.sleep(0.5)  # Rate limiting
                    
                except Exception as e:
                    continue
            
            time.sleep(1)
            
        except Exception as e:
            print(f"  ⚠️  Month {year}/{month_name} failed: {e}")
            continue
    
    print(f"  Found {len(posts)} Full Disclosure posts with CVEs")
    return posts


# ── HackerOne Public Disclosures (Behind login wall) ─────────────────────
HACKERONE_API_TOKEN = "https://api.hackerone.com/v1/hackers/reports"

def crawl_hackerone(max_reports: int = 100):
    """
    Fetch public vulnerability disclosures from HackerOne.
    NOTE: Requires HackerOne account + API credentials.
    This is CLOSED data - requires authentication.
    
    Get API creds: https://hackerone.com/settings/api_token/edit
    """
    import os
    
    api_token = os.getenv("HACKERONE_API_TOKEN", "")
    if not api_token:
        print("  ⚠️  HackerOne API token not found. Set HACKERONE_API_TOKEN env var.")
        print("  ⚠️  Get token: https://hackerone.com/settings/api_token/edit")
        return []
    
    print(f"Fetching HackerOne public disclosures...")
    
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {HACKERONE_API_TOKEN}"
    }
    
    params = {
        "filter[state][]": "disclosed",
        "page[size]": min(max_reports, 100),
        "sort": "-disclosed_at"
    }
    
    try:
        resp = requests.get(HACKERONE_API_TOKEN, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    
        reports = []
        for report in data.get("data", []):
            attrs = report.get("attributes", {})
            title = attrs.get("title", "")
            summary = attrs.get("vulnerability_information", "")
            
            # Extract CVE if assigned
            cve_ids = attrs.get("cve_ids", [])
            if not cve_ids:
                # Try to find CVE in text
                cve_ids = list(set(re.findall(r"CVE-\d{4}-\d+", title + " " + summary, re.IGNORECASE)))
            
            reports.append({
                "source": "hackerone",
                "report_id": report.get("id", ""),
                "title": title,
                "summary": summary[:1500],
                "severity": attrs.get("severity", {}).get("rating", ""),
                "disclosed_at": attrs.get("disclosed_at", ""),
                "cves_mentioned": cve_ids,
                "bounty_awarded": attrs.get("bounty_awarded_at") is not None
            })
        
        print(f"  Found {len(reports)} HackerOne disclosures")
        return reports
        
    except Exception as e:
        print(f"  ⚠️  HackerOne fetch failed: {e}")
        return []


# ── Microsoft Security Response Center (MSRC) - Behind auth ──────────────
MSRC_API = "https://api.msrc.microsoft.com/cvrf/v2.0/cvrf"

def crawl_microsoft_advisories(max_advisories: int = 50):
    """
    Fetch Microsoft security advisories via MSRC API.
    This is semi-CLOSED - requires API key for full access.
    Contains vendor-specific vulnerability details not in NVD.
    
    Get API key: https://portal.msrc.microsoft.com/
    """
    import os
    
    api_key = os.getenv("MSRC_API_KEY", "")
    if not api_key:
        print("  ⚠️  Microsoft MSRC API key not set. Skipping vendor advisories.")
        print("  ⚠️  Get key: https://portal.msrc.microsoft.com/")
        return []
    
    print(f"Fetching Microsoft security advisories...")
    
    headers = {
        "Accept": "application/json",
        "api-key": api_key
    }
    
    # Get recent security updates
    advisories = []
    year = datetime.now().year
    
    for month in range(1, 13):  # Current year, all months
        update_id = f"{year}-{month:02d}"
        url = f"{MSRC_API}/{update_id}"
        
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 404:
                continue
            
            resp.raise_for_status()
            data = resp.json()
            
            # Parse CVRF document for CVEs
            vulns = data.get("Vulnerability", [])
            for vuln in vulns:
                cve_id = vuln.get("CVE", "")
                if cve_id:
                    advisories.append({
                        "source": "microsoft_msrc",
                        "cve_id": cve_id,
                        "title": vuln.get("Title", {}).get("Value", ""),
                        "description": vuln.get("Notes", [{}])[0].get("Value", "")[:1500],
                        "severity": vuln.get("Threats", [{}])[0].get("Description", {}).get("Value", ""),
                        "month": update_id,
                        "cves_mentioned": [cve_id]
                    })
            
            time.sleep(1)
            
        except Exception as e:
            continue
    
    print(f"  Found {len(advisories)} Microsoft advisories")
    return advisories[:max_advisories]


# ── Reddit /r/netsec Deep Scraping (Behind rate limits) ──────────────────
def crawl_reddit_netsec(max_posts: int = 100):
    """
    Deep scrape Reddit /r/netsec for vulnerability discussions.
    Goes beyond Reddit's API limits by using PRAW (Reddit API wrapper).
    This is semi-CLOSED - requires Reddit app credentials.
    
    Setup: https://www.reddit.com/prefs/apps
    """
    try:
        import praw
        import os
        
        client_id = os.getenv("REDDIT_CLIENT_ID", "")
        client_secret = os.getenv("REDDIT_CLIENT_SECRET", "")
        
        if not client_id or not client_secret:
            print("  ⚠️  Reddit API credentials not set. Skipping Reddit data.")
            print("  ⚠️  Get credentials: https://www.reddit.com/prefs/apps")
            return []
        
        print(f"Crawling Reddit /r/netsec...")
        
        reddit = praw.Reddit(
            client_id=client_id,
            client_secret=client_secret,
            user_agent="VulnResearchBot/1.0"
        )
        
        subreddit = reddit.subreddit("netsec")
        posts = []
        
        for submission in subreddit.hot(limit=max_posts):
            title = submission.title
            selftext = submission.selftext
            
            # Extract CVE mentions
            cves = list(set(re.findall(r"CVE-\d{4}-\d+", title + " " + selftext, re.IGNORECASE)))
            
            if cves:
                # Fetch top comments for additional context
                submission.comments.replace_more(limit=0)
                top_comments = " ".join([c.body for c in submission.comments[:5]])
                
                posts.append({
                    "source": "reddit_netsec",
                    "post_id": submission.id,
                    "title": title,
                    "content": (selftext + " " + top_comments)[:2000],
                    "url": f"https://reddit.com{submission.permalink}",
                    "score": submission.score,
                    "created": datetime.fromtimestamp(submission.created_utc).isoformat(),
                    "cves_mentioned": cves
                })
        
        print(f"  Found {len(posts)} Reddit posts with CVEs")
        return posts
        
    except ImportError:
        print("  ⚠️  praw not installed. Run: pip install praw")
        return []
    except Exception as e:
        print(f"  ⚠️  Reddit crawl failed: {e}")
        return []


# ── StackOverflow Security Tag Deep Scrape ───────────────────────────────
def crawl_stackoverflow_security(max_questions: int = 50):
    """
    Scrape StackOverflow security-tagged questions for vulnerability discussions.
    Uses StackExchange API - free but rate-limited.
    """
    SO_API = "https://api.stackexchange.com/2.3/search/advanced"
    
    print(f"Crawling StackOverflow security questions...")
    
    params = {
        "order": "desc",
        "sort": "votes",
        "tagged": "security;vulnerability",
        "site": "stackoverflow",
        "pagesize": max_questions,
        "filter": "withbody"  # Include full question body
    }
    
    try:
        resp = requests.get(SO_API, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        
        questions = []
        for item in data.get("items", []):
            title = item.get("title", "")
            body = item.get("body", "")
            
            # Extract CVE mentions
            cves = list(set(re.findall(r"CVE-\d{4}-\d+", title + " " + body, re.IGNORECASE)))
            
            if cves:
                questions.append({
                    "source": "stackoverflow",
                    "question_id": item.get("question_id", ""),
                    "title": title,
                    "body": body[:1500],
                    "score": item.get("score", 0),
                    "url": item.get("link", ""),
                    "cves_mentioned": cves
                })
        
        print(f"  Found {len(questions)} StackOverflow questions with CVEs")
        return questions
        
    except Exception as e:
        print(f"  ⚠️  StackOverflow crawl failed: {e}")
        return []


# ── Main execution ─────────────────────────────────────────────────────────
def run(out="data/raw_closed.json"):
    """
    Aggregate all CLOSED and semi-private data sources.
    """
    all_data = []
    
    print("\n🔒 Crawling CLOSED and semi-private security sources...\n")
    
    # 1. Full Disclosure mailing list (historical archive - not easily searchable)
    try:
        fd_posts = crawl_full_disclosure(months_back=3, max_per_month=20)
        all_data.extend(fd_posts)
    except ImportError:
        print("  ⚠️  BeautifulSoup required: pip install beautifulsoup4")
    
    time.sleep(2)
    
    # 2. HackerOne public disclosures (requires auth)
    h1_reports = crawl_hackerone(max_reports=50)
    all_data.extend(h1_reports)
    
    time.sleep(2)
    
    # 3. Microsoft MSRC advisories (vendor-specific, requires API key)
    ms_advisories = crawl_microsoft_advisories(max_advisories=30)
    all_data.extend(ms_advisories)
    
    time.sleep(2)
    
    # 4. Reddit /r/netsec (community discussions, requires app credentials)
    reddit_posts = crawl_reddit_netsec(max_posts=50)
    all_data.extend(reddit_posts)
    
    time.sleep(2)
    
    # 5. StackOverflow security questions (developer discussions)
    so_questions = crawl_stackoverflow_security(max_questions=30)
    all_data.extend(so_questions)
    
    # Filter: only keep items with CVE mentions
    data_with_cves = [d for d in all_data if d.get("cves_mentioned")]
    
    # Statistics
    source_counts = {}
    for item in data_with_cves:
        source = item.get("source", "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
    
    print(f"\n✅ Total records collected: {len(all_data)}")
    print(f"✅ Records with CVE mentions: {len(data_with_cves)}")
    print(f"\nBreakdown by source:")
    for source, count in source_counts.items():
        print(f"  - {source:<25} {count:>4} records")
    
    # Save
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data_with_cves, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Saved {len(data_with_cves)} closed-source records → {out}")


if __name__ == "__main__":
    # Check dependencies
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("⚠️  Install dependencies: pip install beautifulsoup4 praw")
        print("⚠️  Then set API credentials in .env")
    
    run()