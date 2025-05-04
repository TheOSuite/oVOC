import aiohttp
import asyncio
from packaging.version import parse as parse_version

OSV_API_URL = "https://api.osv.dev/v1/query"

async def fetch_vulnerabilities(session, name, version):
    payload = {
        "package": {"name": name, "ecosystem": "PyPI"},
        "version": version
    }
    try:
        async with session.post(OSV_API_URL, json=payload, timeout=10) as resp:
            resp.raise_for_status()
            return await resp.json()
    except Exception as e:
        return {"error": str(e)}

def extract_latest_secure_version(vulns):
    fixed_versions = []
    for vuln in vulns:
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed_versions.append(ev["fixed"])

    # Parse and sort semantically
    parsed = []
    for v in set(fixed_versions):
        try:
            parsed.append(parse_version(v))
        except Exception:
            continue

    if not parsed:
        return []

    # highest version first
    parsed.sort(reverse=True)
    # return as strings
    return [str(v) for v in parsed]

async def check_vulnerabilities(package_list):
    if not package_list:
        return []

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_vulnerabilities(session, pkg["name"], pkg["version"])
                 for pkg in package_list]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    results = []
    for resp in responses:
        if isinstance(resp, Exception) or resp.get("error"):
            results.append({"vulns": [], "latest_secure_version": None, "error": resp.get("error", str(resp))})
            continue

        vulns = resp.get("vulns", []) or []
        latest = extract_latest_secure_version(vulns)
        results.append({
            "vulns": vulns,
            "latest_secure_version": latest[0] if latest else None
        })

    return results

def run_vulnerability_check(package_list):
    return asyncio.run(check_vulnerabilities(package_list))
