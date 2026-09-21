import json
data = json.load(open(r"C:\Users\Gigabyte\Sentinel_Starter_Kit\artifacts\scorecards\eval-public-http_defense-20260921T212153Z.json", encoding="utf-8"))
print(list(data.keys()))
