# Wazuh detection for Aeria

Decoders and rules (ids 100700–100799) for three log sources:

| Source | Log line | Rules |
|---|---|---|
| Back-office (module 4) | `AERIA-SECURITY event=login_failure user=… ip=… reason=…` | 100701 failed login · **100702 password guessing** (5 in 2 min, same IP) · 100703 account locked · 100704 login · **100705 login right after password guessing** (level 12) · 100706 access denied · **100707 repeated privilege abuse** |
| Ingestion (module 1) | `IngestionService : Rejected reading from LH-003: […]` | 100720 rejected reading · **100721 burst from one sensor** (fault or forged messages) · 100722 malformed message · **100723 fuzzing** |
| Mosquitto | `Client … disconnected, not authorised.` / `New connection from ip:port on port 1883.` | 100741 refused client · **100742 credential guessing** · **100743 clear-text MQTT from the network** |

Each rule carries its MITRE ATT&CK technique (T1110, T1078, T1565.002, T1040…) and refers to the EBIOS RM
operational scenarios ([`../docs/ebios-rm.md`](../docs/ebios-rm.md)).

## Install

```bash
docker cp wazuh/decoders/aeria_decoders.xml <manager>:/var/ossec/etc/decoders/
docker cp wazuh/rules/aeria_rules.xml       <manager>:/var/ossec/etc/rules/
docker exec <manager> chown wazuh:wazuh /var/ossec/etc/decoders/aeria_decoders.xml /var/ossec/etc/rules/aeria_rules.xml
docker exec <manager> /var/ossec/bin/wazuh-control restart
```

Ship the logs with a Wazuh agent on the application host (`<localfile>` entries pointing at the Spring Boot
and Mosquitto log files, `log_format` `syslog`).

## Test

```bash
python scripts/test_wazuh_rules.py --container <disposable-manager>
```

15 scenarios, each in a fresh `wazuh-logtest` session (frequency counters start at zero). Result on
Wazuh 4.14.9: **15/15** ([`../docs/audit/raw/10-wazuh-logtest.txt`](../docs/audit/raw/10-wazuh-logtest.txt)).
CI replays them on every push against the official `wazuh/wazuh-manager:4.14.9` image.

Three pitfalls met while writing them (Wazuh 4.14):

- static fields (`dstport`, `srcip`) are tested with their own tags (`<dstport>`), not with `<field>`;
- negation is `negate="yes"`, the `!` prefix is not interpreted on `<srcip>`;
- `wazuh-logtest` writes its results on stderr.
