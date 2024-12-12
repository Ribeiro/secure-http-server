# Usar a imagem base oficial do Rust
FROM rust:latest

# Define o diretório de trabalho
WORKDIR /app

# Copia todos os arquivos para dentro do contêiner
COPY . .

# Instala as dependências e constrói o binário
RUN cargo build --release

# Define as variáveis de ambiente
ENV CERT_PATH=/app/certs/cert.pem
ENV KEY_PATH=/app/certs/key.pem

# Expõe a porta 8443
EXPOSE 8443

# Comando para executar o servidor
CMD ["./target/release/secure-http-server"]
