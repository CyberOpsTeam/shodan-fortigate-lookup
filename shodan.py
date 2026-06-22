import csv
import shodan

# Replace with your Shodan API key
API_KEY = "YOUR_SHODAN_API_KEY"

INPUT_FILE = "hosts.txt"
OUTPUT_FILE = "output.csv"

api = shodan.Shodan(API_KEY)

results = []

with open(INPUT_FILE, "r") as f:
    hosts = [line.strip() for line in f if line.strip()]

for host in hosts:
    print(f"Checking {host}...")

    try:
        host_info = api.host(host)

        fortigate_matches = []

        for service in host_info.get("data", []):
            ssl_info = service.get("ssl", {})
            cert = ssl_info.get("cert", {})
            issuer = cert.get("issuer", {})

            issuer_cn = issuer.get("cn", "")

            if issuer_cn and "fortigate" in issuer_cn.lower():
                fortigate_matches.append({
                    "port": service.get("port"),
                    "issuer_cn": issuer_cn
                })

        if fortigate_matches:
            for match in fortigate_matches:
                results.append({
                    "host": host,
                    "matched": True,
                    "port": match["port"],
                    "issuer_cn": match["issuer_cn"]
                })
        else:
            results.append({
                "host": host,
                "matched": False,
                "port": "",
                "issuer_cn": ""
            })

    except shodan.APIError as e:
        results.append({
            "host": host,
            "matched": "ERROR",
            "port": "",
            "issuer_cn": str(e)
        })

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.DictWriter(
        csvfile,
        fieldnames=["host", "matched", "port", "issuer_cn"]
    )

    writer.writeheader()
    writer.writerows(results)

print(f"Results written to {OUTPUT_FILE}")
