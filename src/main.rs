use std::sync::Arc;
use hyper::service::{service_fn};
use hyper::{Body, Request, Response};
use rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use dotenv::dotenv;
use std::env;
use tracing::{info, error};
use tracing_subscriber;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use hyper::server::conn::Http;
use std::net::SocketAddr;
use tokio::net::TcpListener; 

async fn load_certs_and_keys(cert_path: &str, key_path: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    info!("Carregando certificados de: {} e {}", cert_path, key_path);

    let mut cert_file = File::open(cert_path).await?;
    let mut cert_data = Vec::new();
    cert_file.read_to_end(&mut cert_data).await?;
    let certs = rustls_pemfile::certs(&mut &cert_data[..])
        .map(|certs| certs.into_iter().map(Certificate).collect::<Vec<_>>())?;

    let mut key_file = File::open(key_path).await?;
    let mut key_data = Vec::new();
    key_file.read_to_end(&mut key_data).await?;
    let keys = rustls_pemfile::pkcs8_private_keys(&mut &key_data[..])
        .map(|keys| keys.into_iter().map(PrivateKey).collect::<Vec<_>>())?;

    if keys.is_empty() {
        return Err("Nenhuma chave privada encontrada.".into());
    }

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys[0].clone())
        .map_err(|e| format!("Erro ao configurar TLS: {}", e))?;

    Ok(config)
}

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    info!("Recebida requisição de: {}", req.uri());

    let response = match req.uri().path() {
        "/" => Response::new(Body::from("Bem-vindo ao Secure HTTP Server em Rust!")),
        "/saudacao" => Response::new(Body::from("Olá, Mundo! Esta é uma rota segura.")),
        _ => Response::builder()
            .status(404)
            .body(Body::from("Rota não encontrada!"))
            .unwrap(),
    };

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();
    dotenv().ok();

    let cert_path = env::var("CERT_PATH").unwrap_or("certs/cert.pem".to_string());
    let key_path = env::var("KEY_PATH").unwrap_or("certs/key.pem".to_string());

    let server_address = env::var("SERVER_ADDRESS").unwrap_or("127.0.0.1".to_string());
    let server_port: u16 = env::var("SERVER_PORT").unwrap_or("8443".to_string()).parse()?;

    let tls_config = load_certs_and_keys(&cert_path, &key_path).await?;
    let tls_config = Arc::new(tls_config);

    let addr: SocketAddr = format!("{}:{}", server_address, server_port).parse()?;
    let listener = TcpListener::bind(&addr).await?; // Mudança aqui, usando TcpListener
    let acceptor = TlsAcceptor::from(tls_config);

    info!("Servidor HTTPS rodando em https://{}", addr);

    let server = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, _)) => {
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(tcp_stream).await {
                            Ok(tls_stream) => {
                                // Criando o serviço diretamente com `service_fn`
                                let service = service_fn(handle_request);
                                if let Err(err) = Http::new().serve_connection(tls_stream, service).await {
                                    error!("Erro ao processar conexão: {}", err);
                                }
                            }
                            Err(err) => error!("Erro ao aceitar conexão TLS: {}", err),
                        }
                    });
                }
                Err(err) => {
                    error!("Erro ao aceitar conexão TCP: {}", err);
                    break; // Opcional: Pode-se encerrar o loop em caso de erro
                }
            }
        }
    });

    if let Err(e) = server.await {
        error!("Erro no servidor: {}", e);
    }

    Ok(())
}
