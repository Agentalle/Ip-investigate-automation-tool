import requests
import ipaddress
import csv
import os
import time

# ======================
# CONFIG
# ======================
VT_API_KEY = "88f9247c42b4f29d3997429c1ef5c7817e8068becfcb4e171855e0150da49b04"
ABUSE_API_KEY = "0270e4ecd73216ecf81f5c974b2bec2efcbf2ef83310af4309a3985b73aaf0809830b8c3ebb3a80c"

INPUT_FILE = "testing.txt"
MASTER_CSV = "all_results.csv"

RATE_LIMIT = 2

HEADERS = [
    "S.No",
    "IP Address",
    "AbuseIP %",
    "VT Malicious %",
    "VT Hashes"
]

# ======================
# HELPERS
# ======================
def is_private(ip):
    return ipaddress.ip_address(ip).is_private

def vt_lookup(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code != 200:
            print(f"   ↳ VT API error for {ip}: status {r.status_code}, response: {r.text[:200]}")
            return None, "N/A"

        response_json = r.json()

        if "data" not in response_json:
            print(f"   ↳ No 'data' in VT response for {ip}")
            return None, "N/A"

        data = response_json["data"]["attributes"]
        if "last_analysis_stats" not in data:
            print(f"   ↳ No 'last_analysis_stats' in VT data for {ip}")
            return None, "N/A"

        stats = data["last_analysis_stats"]
        total = sum(stats.values())
        malicious = stats.get("malicious", 0)
        percent = round((malicious / total) * 100, 2) if total else 0

        # Fetch hashes if available
        hashes = []
        if "last_analysis_results" in data:
            for engine, result in data["last_analysis_results"].items():
                if result.get("category") == "malicious" and "sha256" in result:
                    hashes.append(result["sha256"])
        hashes_str = "; ".join(hashes) if hashes else "N/A"

        return percent, hashes_str

    except Exception as e:
        print(f"   ↳ VT exception for {ip}: {e}")
        return None, "ERROR"

def abuse_lookup(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(url, headers=headers, params=params, timeout=10)

        if r.status_code == 200:
            return r.json()["data"]["abuseConfidenceScore"]

    except Exception:
        pass

    return None

def load_scanned_ips():
    if not os.path.exists(MASTER_CSV):
        return set()

    with open(MASTER_CSV, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)
        return {row[1] for row in reader}

def write_row(row):
    exists = os.path.exists(MASTER_CSV)
    with open(MASTER_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(HEADERS)
        w.writerow(row)

def export_category(filename, rows):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(HEADERS)
        w.writerows(rows)

def safe_int(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return None

def safe_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None

# ======================
# MAIN SCAN
# ======================
print("\n=== IP INVESTIGATION STARTED ===")

# Clear the master CSV to start fresh with new dataset
if os.path.exists(MASTER_CSV):
    os.remove(MASTER_CSV)

results = []

with open(INPUT_FILE) as f:
    ips = [line.strip() for line in f if line.strip()]

total_ips = len(ips)
serial = 1

for count, ip in enumerate(ips, start=1):
    print(f"\n[{count}/{total_ips}] Scanning {ip}")

    print("   ↳ AbuseIPDB: loading ⏳", end="\r")
    abuse_score = abuse_lookup(ip)
    print(f"   ↳ AbuseIPDB: {abuse_score if abuse_score is not None else 'N/A'}%      ")

    print("   ↳ VirusTotal: loading ⏳", end="\r")
    vt_percent, vt_hashes = vt_lookup(ip)
    print(f"   ↳ VirusTotal: {vt_percent if vt_percent is not None else 'N/A'}%      ")

    row = [
        serial,
        ip,
        abuse_score if abuse_score is not None else 'N/A',
        vt_percent if vt_percent is not None else 'N/A',
        vt_hashes
    ]

    write_row(row)
    results.append(row)

    print("   ↳ Saved to CSV ✔")

    serial += 1
    time.sleep(RATE_LIMIT)

print(f"\n=== SCAN COMPLETE === (Scanned {len(results)} IPs)")

# ======================
# DISPLAY RESULTS
# ======================
if results:
    print("\n=== SCAN RESULTS ===")
    for row in results:
        print(f"S.No: {row[0]}, IP: {row[1]}, AbuseIP: {row[2] if row[2] is not None else 'N/A'}%, VT Malicious: {row[3] if row[3] is not None else 'N/A'}%, VT Hashes: {row[4]}")

# ======================
# CATEGORIZATION
# ======================
if os.path.exists(MASTER_CSV):
    with open(MASTER_CSV, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)
        all_rows = list(reader)
else:
    all_rows = []

abuse_above_75 = [r for r in all_rows if r[2] and safe_int(r[2]) is not None and safe_int(r[2]) >= 75]
abuse_below_75 = [r for r in all_rows if r[2] and safe_int(r[2]) is not None and safe_int(r[2]) < 75]

vt_above_50 = [r for r in all_rows if r[3] and safe_float(r[3]) is not None and safe_float(r[3]) >= 50]
vt_below_50 = [r for r in all_rows if r[3] and safe_float(r[3]) is not None and safe_float(r[3]) < 50]

export_category("abuseip_above_75.csv", abuse_above_75)
export_category("abuseip_below_75.csv", abuse_below_75)
export_category("virustotal_above_50.csv", vt_above_50)
export_category("virustotal_below_50.csv", vt_below_50)

print("\n📁 CSV EXPORT COMPLETE")

# ======================
# DISPLAY ALL RESULTS
# ======================
print("\n=== ALL SCAN RESULTS ===")
for row in all_rows:
    print(f"S.No: {row[0]}, IP: {row[1]}, AbuseIP: {row[2] if row[2] else 'N/A'}%, VT Malicious: {row[3] if row[3] else 'N/A'}%, VT Hashes: {row[4]}")
