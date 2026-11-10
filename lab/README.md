# WAFFEN second-WAF validation lab (OWASP CRS / ModSecurity)

A local, industry-standard WAF to validate WAFFEN against something other than
RedEye. [OWASP Core Rule Set](https://coreruleset.org/) on ModSecurity+nginx
reverse-proxies a local [Juice Shop](https://owasp.org/www-project-juice-shop/)
backend. Same app, a stricter and completely independent WAF.

## Run

```sh
docker compose -p waffen-lab up -d
# wait for the stack (juice-shop takes ~30–60s to boot):
curl -s -o /dev/null -w '%{http_code}\n' --retry 20 --retry-delay 3 \
     --retry-all-errors http://localhost:18080/      # -> 200
```

CRS blocks with nginx's generic `403` page (no vendor header), so let WAFFEN
**calibrate** the block signature instead of assuming RedEye's:

```sh
# does WAFFEN see a WAF? (behavioral fingerprint — CRS exposes no signature)
waffen fingerprint --target http://localhost:18080 --path /rest/products/search

# coverage + false-positive rate (0% FP = benign-first ordering working)
printf 'apple\nbanana\norange\n' > /tmp/benign.txt
waffen eval --target http://localhost:18080 --path /rest/products/search \
    --all-classes --calibrate --block-signature nginx --benign /tmp/benign.txt

# verified bypass search on the real SQLi endpoint
waffen bypass --target http://localhost:18080 --path /rest/products/search \
    --class "SQL Injection" --calibrate --block-signature nginx \
    --verify --stop-on-first --rules
```

`/rest/products/search?q=` is a genuine SQLite-backed SQLi sink, so a THROUGH that
the verifier confirms via a live `SQLITE_ERROR` is a real, error-based bypass — see
`docs/VALIDATION.md` §6 for the recorded results (3 distinct verified SQLi evasions
of CRS paranoia-level-1).

## Teardown

```sh
docker compose -p waffen-lab down
```

> Local testing only. This lab is self-contained; point WAFFEN at third-party
> targets only with authorization.
