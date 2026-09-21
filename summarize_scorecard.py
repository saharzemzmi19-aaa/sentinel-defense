import json
data = json.load(open(r"C:\Users\Gigabyte\Sentinel_Starter_Kit\artifacts\scorecards\eval-public-http_defense-20260921T212153Z.json", encoding="utf-8"))
for r in data["outcomes"]:
    print(f"{r['scenario_id']:<35} family={r['attack_family']:<25} attack_success={r['attack_success']!s:<6} task_success={r['task_success']!s:<6} critical_violation={r['critical_violation']!s:<6} data_flow_violation={r['data_flow_violation']}")
