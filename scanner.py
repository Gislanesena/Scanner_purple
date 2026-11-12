import os
import socket      #biblioteca para manipulação de sockets TCP
import argparse    #biblioteca para manipulação de argumentos de linha de comando
import requests    #biblioteca para requisições HTTP
from urllib.parse import urlparse    #biblioteca para manipulação de URLs
from concurrent.futures import ThreadPoolExecutor   #biblioteca para execução de threads em paralelo
from dotenv import load_dotenv

load_dotenv()

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

PORTAS_ALVO = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080]   #Portas comuns para serviços críticos e administrativos

def preparar_alvo(entrada_usuario):   #preparar_alvo recebe a entrada do usuário e retorna o host e a URL completa
    """Recebe 'site.com' ou 'https://site.com' e extrai o host e a URL completa."""
    if not entrada_usuario.startswith(("http://", "https://")):
        url_completa = f"http://{entrada_usuario}"
    else:
        url_completa = entrada_usuario
        
    host = urlparse(url_completa).hostname
    return host, url_completa

def escanear_porta(alvo_host, porta):
    """Tenta abrir conexão TCP na porta e captura o banner do serviço."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            resultado = s.connect_ex((alvo_host, porta))
            if resultado == 0:
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip().split("\n")[0]
                except Exception:
                    banner = "Serviço ativo (sem banner)"
                return (porta, banner)
    except Exception:
        pass
    return None

def avaliar_postura_defensiva(url, portas_abertas):
    """Analisa as respostas do alvo e classifica pontos positivos e negativos."""
    pontos_positivos = []
    pontos_negativos = []

    # 1. Avaliação de Exposição de Rede (Portas Críticas)
    portas_criticas = {21: "FTP", 22: "SSH", 23: "Telnet", 3306: "MySQL", 3389: "RDP"}
    expostas = [f"{p} ({portas_criticas[p]})" for p, _ in portas_abertas if p in portas_criticas]

    if not expostas:
        pontos_positivos.append("Nenhuma porta administrativa ou de banco de dados exposta publicamente.")
    else:
        pontos_negativos.append(f"Portas sensíveis expostas na rede: {', '.join(expostas)} (permite enumeração e força bruta).")

    # 2. Avaliação de Defesa Web (WAF, Rate Limit e Headers)
    try:
        resposta = requests.get(url, timeout=5)
        
        # Verifica se há proteção contra bots/WAF ativa
        if resposta.status_code in [403, 406, 429]:
            pontos_positivos.append(f"WAF ou Rate Limiting ativo bloqueou o scanner (HTTP {resposta.status_code}).")
        else:
            pontos_negativos.append("Servidor aceitou requisições automatizadas sem bloqueio de WAF/Rate Limit.")

        # Verifica vazamento de informação (Information Disclosure) no Banner
        servidor = resposta.headers.get("Server")
        if servidor:
            pontos_negativos.append(f"Vazamento de versão no cabeçalho 'Server': `{servidor}` (facilita busca por CVEs).")
        else:
            pontos_positivos.append("Cabeçalho 'Server' ocultado (dificulta identificação da tecnologia).")

        # Verifica cabeçalhos de proteção OWASP
        headers_obrigatorios = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options"
        ]
        for h in headers_obrigatorios:
            if h in resposta.headers:
                pontos_positivos.append(f"Proteção ativa: cabeçalho `{h}` configurado.")
            else:
                pontos_negativos.append(f"Brecha de configuração: cabeçalho `{h}` ausente.")

    except requests.exceptions.RequestException:
        pontos_positivos.append("Conexão HTTP recusada ou filtrada por firewall de borda.")

    return pontos_positivos, pontos_negativos

def enviar_relatorio_slack(alvo_host, portas_abertas, positivos, negativos):
    """Envia o relatório consolidado de postura de segurança para o Slack."""
    texto_portas = "\n".join([f"• *Porta {p}*: `{b}`" for p, b in portas_abertas]) or "Nenhuma porta aberta detectada."
    texto_positivos = "\n".join([f"✅ {p}" for p in positivos]) or "Nenhum controle defensivo identificado."
    texto_negativos = "\n".join([f"❌ {n}" for n in negativos]) or "Nenhuma falha óbvia detectada!"

    mensagem = (
        f"🛡️ *Relatório de Auditoria & Recon: {alvo_host}*\n\n"
        f"🔓 *Superfície de Rede (Portas Abertas):*\n{texto_portas}\n\n"
        f"🟢 *Pontos Positivos (Defesas que seguraram):*\n{texto_positivos}\n\n"
        f"🔴 *Pontos Negativos (Brechas / Atenção):*\n{texto_negativos}"
    )

    payload = {"text": mensagem}   #Payload JSON para envio ao Slack via webhook

    res = requests.post(SLACK_WEBHOOK_URL, json=payload)
    if res.status_code == 200:
        print("\n✅ Relatório de Auditoria enviado com sucesso para o Slack!")
    else:
        print(f"\n❌ Falha ao enviar relatório: {res.status_code} - {res.text}")

def main():
    parser = argparse.ArgumentParser(description="Scanner de Reconhecimento e Auditoria de Postura de Segurança")
    parser.add_argument("alvo", help="Domínio ou URL do alvo (ex: scanme.nmap.org ou https://seusite.com)")
    args = parser.parse_args()

    alvo_host, alvo_url = preparar_alvo(args.alvo)

    print(f"🔎 Iniciando Auditoria de Segurança no alvo: {alvo_host} ({alvo_url})...\n")
    
    if not SLACK_WEBHOOK_URL:
        print("⚠️ ERRO: Variável SLACK_WEBHOOK_URL não encontrada no .env!")
        return

    # 1. Scan de Portas
    print("📡 Mapeando portas TCP...")
    portas_abertas = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        resultados = executor.map(lambda p: escanear_porta(alvo_host, p), PORTAS_ALVO)
        for res in resultados:
            if res:
                print(f"   [+] Porta {res[0]} ABERTA -> {res[1]}")
                portas_abertas.append(res)

    # 2. Avaliação de Postura Defensiva
    print("\n⚖️ Avaliando controles de defesa e cabeçalhos HTTP...")
    positivos, negativos = avaliar_postura_defensiva(alvo_url, portas_abertas)

    print("\n--- RESUMO NO TERMINAL ---")
    for p in positivos:
        print(f"✅ {p}")
    for n in negativos:
        print(f"❌ {n}")

    # 3. Envio para o Slack
    enviar_relatorio_slack(alvo_host, portas_abertas, positivos, negativos)

if __name__ == "__main__":
    main()