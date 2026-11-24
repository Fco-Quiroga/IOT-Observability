# IoT Observability — Dynatrace SNMP 2.0

Custom Dynatrace Extensions 2.0 extension for monitoring IP cameras, NVRs and compatible SNMP devices directly from an ActiveGate.

- Extension name: `custom:bank-iot-snmp`
- Version: `0.2.0`
- Minimum Dynatrace version in the manifest: `1.333.0`
- Data source: SNMP (configure SNMP v2c and UDP port 161 on activation).

## Metrics

| Feature set | Interval | Description |
|---|---|---|
| Availability (mandatory) | 1 minute | SNMP agent uptime |
| interfaces | 5 minutes | Interface operational status |
| traffic | 15 minutes | Interface traffic (64-bit) and errors |
| traffic32 | 15 minutes | Legacy 32-bit traffic and errors |
| memory | 5 minutes | UCD-SNMP memory |
| cpu_ucd | 5 minutes | UCD-SNMP CPU idle |
| identity | 24 hours | SNMP identity dimensions |

Enable optional feature sets only when supported by the device. Do not enable both traffic and traffic32 on the same endpoint. Verify counter delta behavior and rollover handling during testing. Interface data is collected from tables; filter the desired interface downstream. Uptime is in hundredths of a second; zero is valid. Missing observations do not necessarily mean a device is powered off, and SNMP availability does not establish video or recording health. The framework may perform additional internal SNMP checks.

## Installation

1. Open this repository in VS Code with the [Dynatrace Extensions add-on](https://docs.dynatrace.com/docs/ingest-from/extensions/develop-your-extensions/addon-for-vscode).
2. Validate [extension.yaml](extension.yaml) against the schemas matching your Dynatrace version, including the chassis MAC dimension.
3. Build and sign the extension using your own signing certificates. Configure trust according to the official Dynatrace documentation.
4. Upload the signed extension to Dynatrace and create a monitoring configuration for a test device using an ActiveGate.
5. Verify uptime observations, supported OIDs, optional feature sets, and effective collection intervals before scaling.

**Validation status:** official schema validation and live Dynatrace/SNMP testing remain pending. This source release is not a signed or production-certified extension.

## References

- [SNMP schema reference](https://docs.dynatrace.com/docs/ingest-from/extensions/develop-your-extensions/data-sources/snmp-extensions/snmp-schema-reference)
- [Extension YAML](https://docs.dynatrace.com/docs/ingest-from/extensions/develop-your-extensions/extension-yaml)
- [Official extension schemas](https://github.com/dynatrace-extensions/extensions-schemas/releases)

This repository contains only the standalone extension source and documentation. Supply your own authorized test endpoints and credentials in Dynatrace.
