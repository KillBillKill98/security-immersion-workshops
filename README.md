# Security Immersion Workshops

Threat hunting walkthroughs from Microsoft Security Immersion events and similar blue-team exercises. Each workshop is a self-contained folder with the full investigation, the KQL used, machine-readable IOCs, and a MITRE ATT&CK Navigator layer.

The goal is a reusable library. Investigations follow the same structure so they are easy to read, compare, and extend.

## Workshops

| Workshop | Theme | Malware / Actor | Status |
|----------|-------|-----------------|--------|
| [Into the Breach](./into-the-breach/) | Hospital ransomware, MSSP supply chain | Sodinokibi / REvil | Complete |

## How each workshop is organized

```
<workshop-name>/
├── README.md     Full threat hunting walkthrough
├── queries/      KQL per investigation phase
├── iocs/         IOCs as CSV and JSON
└── mitre/        ATT&CK Navigator layer (import at https://mitre-attack.github.io/attack-navigator/)
```

## Adding a new workshop

Copy the scaffold and fill it in:

```bash
cp -r _template my-new-workshop
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the structure and conventions.

## Tooling referenced

Microsoft Defender XDR, Microsoft Sentinel, Advanced Hunting (KQL), Microsoft Security Copilot.

## Disclaimer

All hostnames, accounts, hashes, and indicators belong to simulated lab environments. These are educational reconstructions, not live threat intelligence.
