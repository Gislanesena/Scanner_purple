# Scanner Purple 

Auditoria de controles de segurança: Programa criado para testar o nível de eficácia das defesas de um sistema. 

1. Como funciona
Quando você aponta uma ferramenta de diagnóstico para uma aplicação que possui proteções, cada resposta do servidor entrega uma pista sobre o nível de maturidade da defesa:

| **Camada de Defesa** | **Comportamento Positivo** | **Comportamento Negativo** |
|------------------|------------------------|------------------------|
|**Firewall / Rate Limiting** |Retorna status 429 Too Many Requests ou 403 Forbidden após poucas requisições rápidas, cortando o scan.|Permite centenas de requisições seguidas sem bloquear o IP ou reduzir a velocidade.|
| **WAF (Web Application Firewall)** | Detecta padrões suspeitos na URL ou cabeçalhos e bloqueia a conexão antes de chegar no servidor. | Deixa passar requisições com cabeçalhos genéricos de robôs (python-requests).|
| **Gestão de Superfície (Portas)** | Apenas portas estritamente necessárias (80, 443) respondem; portas administrativas (22, 3306) estão fechadas ou filtradas. | Banco de dados (3306, 5432) ou acesso remoto (22, 3389) expostos para a internet pública. |
| **Hardening de Aplicação (Headers)** | Cabeçalhos como HSTS, CSP e X-Frame-Options estão presentes e bem configurados. | Cabeçalhos ausentes ou servidor expondo versão exata no banner (ex: Apache/2.4.1). |

**Análise de Risco (Severidade)**: Ao separar Pontos Positivos (o que segurou o avanço) de Pontos Negativos (o que permite progressão, como uma porta 3306 aberta ou falta de CSP), você traduz dados técnicos em risco real de negócio — exatamente o que relatórios profissionais de Pentest e Purple Team entregam.

**Ciclo de Correção**: Se o relatório apontar um ponto negativo (ex: vazamento de versão no header Server), o próximo passo é ajustar a configuração do servidor (Hardening) e rodar o script novamente até aquele item migrar para a lista de Pontos Positivos.
