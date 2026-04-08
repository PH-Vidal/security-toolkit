# Imagem oficial Python slim
FROM python:3.11-slim

# Diretório de trabalho
WORKDIR /app

# Copia todos os scripts
COPY . .

# Comando padrão: exibe os scripts disponíveis
CMD ["python", "hash_generator.py"]