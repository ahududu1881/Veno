# TEST — Veno V3.0

> Profil: **NORMAL** · Port: **8080** · Ortam: **production**

```bash
make run      # go run .
make build    # bin/test
```

| Dosya | Açıklama |
|---|---|
| `config/app.toml` | Sunucu, port, TLS |
| `config/security.toml` | WAF, rate limit, CORS |
| `config/routes.toml` | Upstream proxy |
| `config/env.toml` | Gizli değişkenler (git'e ekleme!) |

- `/__veno/health` — Sağlık
- `/__veno/metrics` — Metrikler
