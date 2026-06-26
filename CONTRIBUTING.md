# Adding a Workshop

Keep every workshop consistent so the library stays easy to navigate.

## Steps

1. Copy the scaffold.
   ```bash
   cp -r _template <workshop-name>
   ```
2. Write the walkthrough in `<workshop-name>/README.md`. Follow the section order used in existing workshops: scenario, attack at a glance, IOC table, compromised assets, per-milestone investigation, MITRE mapping, detection lessons, hardening.
3. Drop each phase query into `queries/` as a numbered `.kql` file.
4. Fill `iocs/iocs.csv` and `iocs/iocs.json`.
5. Build the `mitre/navigator-layer.json` from the techniques you observed.
6. Add a row to the workshop table in the root `README.md`.

## Conventions

- One KQL file per investigation phase, numbered in attack order.
- IOCs in both CSV (human) and JSON (machine) form.
- Map every technique to a MITRE ATT&CK ID.
- Write in plain prose. Tables and code blocks over long paragraphs.
- Never publish real customer data. Lab indicators only.

## Walkthrough section checklist

- [ ] Scenario
- [ ] Attack at a glance (flow diagram)
- [ ] Key IOCs table
- [ ] Compromised assets
- [ ] Per-milestone investigation with KQL and answers
- [ ] MITRE ATT&CK mapping
- [ ] Detection and hunting lessons
- [ ] Recommended hardening
