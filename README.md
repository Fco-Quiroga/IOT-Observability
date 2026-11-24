# IoT Observability — Dynatrace SNMP 2.0

Standalone SNMP extension and administrative toolkit for IP cameras, NVRs and compatible devices. ActiveGate collects metrics; Python manages the inventory, monitoring configurations, minimal Smartscape topology and Grail lookup files. No external SNMP collector is required.

- Extension: `custom:bank-iot-snmp`, version `0.2.0`.
- Minimum Dynatrace version declared by the manifest: `1.333.0`.
- SNMP v2c, default UDP 161; Python 3.10+ (CI uses 3.12).

## Feature sets

| Feature set | Interval | Description |
|---|---|---|
| Availability (mandatory) | 1 minute | Agent uptime in hundredths of a second |
| interfaces | 5 minutes | Interface operational status |
| traffic | 15 minutes | 64-bit traffic and errors |
| traffic32 | 15 minutes | Legacy 32-bit traffic and errors |
| memory | 5 minutes | UCD-SNMP memory |
| cpu_ucd | 5 minutes | UCD-SNMP CPU idle |
| identity | 24 hours | SNMP identity dimensions |

Only enable supported optional sets. Never enable both traffic sets together. Validate counter delta behavior and rollover in a pilot. Uptime zero is valid; missing observations do not prove a physical outage or video failure.

## Install and validate

```bash
git clone https://github.com/Fco-Quiroga/IOT-Observability.git
cd IOT-Observability
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

Windows: activate the environment using `.venv/Scripts/Activate.ps1` in PowerShell. Open [extension.yaml](extension.yaml) in VS Code with the Dynatrace Extensions add-on. Download the official schemas matching your tenant into schemas/, validate, build, sign with your own certificate, configure trust and upload the signed extension.

```bash
python scripts/validate_extension.py --schema-dir schemas
```

Official schema validation and live Dynatrace API/SNMP testing remain pending. This is source code, not a signed or production-certified extension.

## Try the dummy inventory (no network writes)

The three [example inventories](data/) contain a fictional branch, zone, camera and NVR. IPs are documentation-only (192.0.2.0/24), and MAC addresses are locally administered examples. Never apply this demo to a live tenant.

```bash
mkdir -p out/demo-input
for k in cameras branches zones; do cp data/$k.example.json out/demo-input/$k.json; done
python -m app.cli validate --inventory out/demo-input --registry out/demo-state/identities.json --out out/demo
python -m app.cli configure --inventory out/demo-input --registry out/demo-state/identities.json --out out/demo --full
python -m app.cli topology --inventory out/demo-input --registry out/demo-state/identities.json --out out/demo --full
python -m app.cli export --inventory out/demo-input --registry out/demo-state/identities.json --out out/demo --full
python -m app.cli upload --out out/demo
```

Expected: one disabled monitoring configuration with two endpoints, four topology entities, and three lookup datasets. The final command verifies the manifest locally. See [example lookup JSONL outputs](examples/lookup/). Generate fresh outputs and a manifest rather than uploading the examples.

## Supply your own JSON files

Copy the example files to the corresponding names below, then replace all dummy records.

| Local file (ignored by Git) | Fields |
|---|---|
| data/cameras.json | ci_id, name, ip, mac, manufacturer, model, device_type (IP_CAMERA or NVR), branch_id, zone_id; optional criticality, enabled, snmp_port |
| data/branches.json | branch_id, name, latitude, longitude; optional country, city, commune, region, address |
| data/zones.json | branch_id, zone_id, zone_name or name |

Arrays and supported nested list objects are accepted; an optional nvrs.json can be provided. Use valid decimal coordinates (nonzero in this version). The legacy --repair-coordinates option is Chile-specific, not appropriate for arbitrary countries. Keep unknown criticality null. Use stable unique IDs, review the audit, and securely retain state/identities.json across inventory updates. For site-specific aliases and model classification, copy config/inventory_aliases.yaml to config/inventory_aliases.local.yaml, customize, and pass --aliases config/inventory_aliases.local.yaml consistently.

```bash
python -m app.cli validate
python -m app.cli configure --limit 20 --out out/pilot
python -m app.cli topology --limit 20 --out out/pilot
python -m app.cli export --full --out out/full
```

These commands are local-only by default. Review inventory_report.json, audit.json and generated artifacts. Real inventories, output directories, identity registry and .env are ignored by Git. Never force-add them or put sensitive values into tracked examples.

## Publish to your own Dynatrace environment

Copy .env.example to .env and provide your HTTPS URLs and scoped credentials. Do not commit secrets. Install the extension first, check ActiveGate group, SNMP connectivity and permissions. SNMP v2c communities travel without encryption; restrict network access.

| Variable | Purpose |
|---|---|
| DT_ENV_URL | Environment base URL |
| DT_API_TOKEN | Extension configuration read/write |
| SNMP_COMMUNITY | Injected in memory on apply |
| DT_TOPOLOGY_TOKEN | Smartscape event ingestion |
| DT_APPS_URL | Apps base URL for Resource Store |
| DT_LOOKUP_TOKEN | Bearer token for lookup upload |

Use the appropriate token scopes and --auth bearer for configure/topology if required. Start with authorized endpoints only.

```bash
# Review the configuration plan against the tenant
python -m app.cli configure --limit 20 --group YOUR_ACTIVEGATE_GROUP --out out/pilot --check-access
# Create disabled
python -m app.cli configure --limit 20 --group YOUR_ACTIVEGATE_GROUP --out out/pilot --apply --confirm-apply
# Enable after review
python -m app.cli configure --limit 20 --group YOUR_ACTIVEGATE_GROUP --out out/pilot --enable --confirm-enable --update-existing --apply --confirm-apply
# Publish minimal topology
python -m app.cli topology --limit 20 --out out/pilot --apply --confirm-apply
# Generate and publish lookup pilot
python -m app.cli export --limit 20 --out out/pilot
python -m app.cli upload --out out/pilot --check-access
python -m app.cli upload --out out/pilot --apply --confirm-apply
```

Topology publication may require --allow-provisional after identity audit. Choose an authorized --security-context. Configuration limit is 100 devices per batch; check actual ActiveGate capacity. Existing configurations are not deleted automatically; overlap blocks writes. For uncertain API responses, reconcile remote state before retrying. Optional branch and region route CSV templates are in config/.

For full rollout, replace --limit 20 with --full and add --confirm-bulk to explicit apply commands. Generate a full lookup export before running upload --full --apply --confirm-apply --confirm-bulk. Add --overwrite --confirm-overwrite only for intentional replacement. The three uploads are not transactional; retain previous snapshots. Pilot and full lookups have separate paths. Avoid overlapping active configurations.

## Generated output

| File | Purpose |
|---|---|
| monitoring-configurations.json | ActiveGate API payload (community placeholder only) |
| topology.json | Minimal structural IDs, names, security context and parent relations |
| iot_devices.jsonl / .csv | Devices enriched with branch and zone attributes |
| iot_branches.jsonl / .csv | Branch inventory |
| iot_zones.jsonl / .csv | Zone inventory |
| lookup_manifest.json | Counts, checksums, lookup keys and destinations |

Lookup paths: /lookups/iot/iot_devices, /lookups/iot/iot_branches and /lookups/iot/iot_zones. Pilot paths use /lookups/iot/piloto/. JSONL retains data types. Manual imports use DPL pattern JSON:json and keys ci_id, branch_id, zone_id respectively.

```dql
load "/lookups/iot/iot_devices"
| fields ci_id, device_type, branch_name, zone_name, ip, port
```

Correlate metrics using bank.iot.snmp.device.ip and bank.iot.snmp.device.port, and topology via custom.bank.ci_id. Existing generic metric and entity namespaces are preserved for compatibility. Lookup enrichment does not create automatic topology associations. Use --previous to diff topology; --refresh republishes the snapshot. Retired nodes are not automatically deleted. Preserve historical inventory snapshots if IPs are reused.

## References

- [SNMP schema reference](https://docs.dynatrace.com/docs/ingest-from/extensions/develop-your-extensions/data-sources/snmp-extensions/snmp-schema-reference)
- [Extension schemas](https://github.com/dynatrace-extensions/extensions-schemas/releases)
- [Extensions 2.0 API](https://docs.dynatrace.com/docs/dynatrace-api/environment-api/extensions-20)
- [Smartscape events](https://docs.dynatrace.com/docs/semantic-dictionary/model/smartscape-events)
- [Lookup Data](https://docs.dynatrace.com/docs/platform/grail/lookup-data)
