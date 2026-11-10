# 5th WAF — open-appsec (ML / contextual detection model)

A 3rd *detection model* (after CRS's regex-blacklist and NAXSI's whitelist/scoring):
[open-appsec](https://openappsec.io) is a machine-learning WAF. This standalone,
locally-managed deployment protects a bundled Juice Shop on `:18083`, enforcing in
`prevent-learn` mode at `minimum-confidence: medium`.

```sh
cp env.example .env         # standalone profile + autoPolicyLoad already set
docker compose -p waffen-lab-oas up -d
docker exec appsec-agent open-appsec-ctl --apply-policy    # first load downloads the ML model (~1-2 min)
# verify it blocks: /?x=<script>alert(1)</script> -> 403 ; benign -> 200
waffen eval --target http://localhost:18083 --path /rest/products/search \
    --all-classes --calibrate --block-signature incident --benign /tmp/benign.txt
```

Measured: ~35% (signature) / ~55% (calibrated) coverage at **0% false-positives** — a
much more permissive profile than the CRS family, i.e. the open-source ML model lets
more through. Validating against it also surfaced + fixed a WAFFEN calibration bug
(low-confidence calibration inflated FP to 100%; now gated). See `docs/VALIDATION.md` §6.12.

> Local testing only.
