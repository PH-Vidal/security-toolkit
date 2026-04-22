# 🔐 Security Toolkit

Repositório criado para aprendizado de conceitos de cibersegurança com Python.

## Scripts disponíveis

- `port_scanner.py` — Verifica portas abertas em um host
- `password_checker.py` — Analisa a força de uma senha
- `hash_generator.py` — Gera hashes MD5 e SHA256
- `ping_sweep.py` — Verifica hosts ativos em uma rede local

## Como usar
```bash
python nome_do_script.py
```

## 🐳 Docker

### Build da imagem
```bash
docker build -t security-toolkit .
```

### Rodar o container
```bash
docker run -d --name security-toolkit security-toolkit sleep infinity
```

### Executar um script específico
```bash
docker run --rm security-toolkit python hash_generator.py
docker run --rm security-toolkit python password_checker.py
docker run --rm security-toolkit python port_scanner.py
docker run --rm security-toolkit python ping_sweep.py
```

## Monitoramento
Alertas configurados via GitHub Actions + Discord.