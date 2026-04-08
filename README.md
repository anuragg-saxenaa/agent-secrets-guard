# agent-secrets-guard

**Lightweight CLI to scan files and stdin for leaked secrets — and optionally redact them.**

```
pip install agent-secrets-guard
asg scan ./src/
echo "token=ghp_abcdef1234567890" | asg scanstdin --redact
```

## Supported patterns

| Label | Pattern |
|---|---|
| AWS Access Key ID | `AKIA...` |
| GitHub Token | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` |
| Slack Token | `xox[baprs]-...` |
| Generic Bearer Token | `Bearer <token>` |
| Generic API Key | `api_key=` / `api-key=` |
| JWT | `eyJ...` |
| PEM Private Key | `-----BEGIN ... PRIVATE KEY-----` |
| `.env` secret | `password=` / `secret=` / `token=` / `api_key=` |
| Discord Bot Token | `M....` |
| NuGet API Key | `oye...` |

## Install

```bash
pip install agent-secrets-guard
```

Or from source:

```bash
git clone https://github.com/anuragg-saxenaa/agent-secrets-guard.git
cd agent-secrets-guard
pip install -e .
```

## Usage

**Scan files (globbing supported):**

```bash
asg scan ./src/**/*.py
asg scan --exclude '*.log' ./src/
```

**Scan stdin:**

```bash
echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" | asg scanstdin
cat creds.txt | asg scanstdin --json
```

**Redact secrets (preserve output positions):**

```bash
cat app.log | asg scanstdin --redact > app.log.redacted
```

**Exit codes:**

| Exit | Meaning |
|---|---|
| `0` | No secrets found |
| `2` | Secrets found |
| `1` | Runtime error |

## Development

```bash
pip install -e ".[dev]"
pytest tests/
```

## License

MIT
