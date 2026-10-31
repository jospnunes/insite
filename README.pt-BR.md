# insite

Raio-x de qualquer site pelo terminal: rede, TLS, DNS, e-mail, nota de segurança, stack de tecnologia, SEO e peso da página, em cerca de um segundo.

[English](https://github.com/jospnunes/insite/blob/main/README.md)

[![CI](https://github.com/jospnunes/insite/actions/workflows/ci.yml/badge.svg)](https://github.com/jospnunes/insite/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jospnunes/insite)](https://github.com/jospnunes/insite/releases/latest)
[![crates.io](https://img.shields.io/crates/v/insite)](https://crates.io/crates/insite)
[![Licença: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](https://github.com/jospnunes/insite/blob/main/LICENSE)

![Gravação do terminal com o insite analisando um site: as fases da requisição aparecem como barras, cada módulo termina com um veredito e os achados são listados](https://raw.githubusercontent.com/jospnunes/insite/main/assets/demo.gif)

## Instalação

Linux e macOS (no Linux com glibc anterior à 2.35, o instalador escolhe a versão estática com musl):

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/jospnunes/insite/releases/latest/download/insite-installer.sh | sh
```

Homebrew (macOS e Linux):

```bash
brew install jospnunes/tap/insite
```

Arch Linux (AUR):

```bash
yay -S insite-bin
```

Debian, Ubuntu, Fedora e derivados: baixe o pacote na [página de releases](https://github.com/jospnunes/insite/releases/latest), para x86_64 ou aarch64.

```bash
sudo apt install ./insite_*_amd64.deb
sudo dnf install ./insite-*.x86_64.rpm
```

Rust 1.89 ou mais recente:

```bash
cargo install --locked insite
```

Windows, com Scoop:

```powershell
scoop bucket add insite https://github.com/jospnunes/scoop-bucket
scoop install insite
```

Windows, com PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/jospnunes/insite/releases/latest/download/insite-installer.ps1 | iex"
```

Os binários rodam em Linux (x86_64 e aarch64, glibc e musl), macOS (Intel e Apple silicon) e Windows x86_64. O `--browser` precisa de um Chrome, Chromium, Edge ou Brave instalado e ainda não roda no Windows.

## Experimente

```
insite wordpress.org                                # um site, o relatório completo
insite --browser wordpress.org                      # soma LCP, CLS e TBT de um carregamento real
insite wordpress.org example.com mozilla.org        # vários sites, um relatório para cada
insite --json wordpress.org | jq -r '.modules.security.data.grade'   # só a nota de segurança
insite --save wp.json.gz wordpress.org              # guarda o instantâneo bruto
insite --from wp.json.gz                            # analisa de novo, sem rede
insite explain sec.hsts.short                       # o que um achado significa e como corrigir
```

A execução com `--browser` soma uma linha ao relatório:

```
browser   LCP 1.1 s · CLS 0.00 · TBT 18 ms · 50 requests, 1.6 MB · 70% third-party · mobile, unthrottled
```

E o `explain` imprime (o texto da ferramenta é em inglês):

```
HSTS max-age is shorter than six months  sec.hsts.short · low

The HSTS policy (<value>) lasts less than six months, so browsers that have not visited recently fall back to plain HTTP on the first request.

Fix
Raise `max-age` to at least 15552000 (180 days); a year (31536000) is common.
```

## O que ele verifica

- **network**: redirecionamentos, DNS, TCP, TLS, TTFB e download por fase, versão do HTTP, IPv6.
- **tls**: certificado, cadeia, validade, nomes, protocolo.
- **dns**: registros, DNSSEC, SPF, DMARC, DKIM, MTA-STS, CAA.
- **infra**: AS, hospedagem, CDN, desafios de bot.
- **security**: nota de A+ a F, calculada como no [MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory).
- **stack**: 7.647 tecnologias das assinaturas do [webappanalyzer](https://github.com/enthec/webappanalyzer) e bibliotecas JavaScript com versão vulnerável conhecida.
- **seo**: indexação, título, descrição, canonical, títulos de seção, Open Graph, robots.txt, sitemap.
- **weight**: tamanho do HTML, scripts, recursos que bloqueiam a renderização, imagens, terceiros.
- **browser** (`--browser`): LCP, CLS, TBT e FCP, requisições e bytes por tipo, erros do console.

<details>
<summary>Todas as verificações, módulo por módulo</summary>

| Módulo | O quê |
| --- | --- |
| network | cadeia de redirecionamentos, DNS, TCP, TLS, TTFB e download por fase, versão do HTTP, IPv6, HTTPS forçado, novas tentativas |
| tls | certificado, cadeia (cadeias incompletas diagnosticadas com o CCADB), validade, nomes, chave, SCTs, OCSP stapling, protocolo |
| dns | A/AAAA/CNAME/NS/MX/CAA, DNSSEC, SPF (`include:` seguidos, limite de 10 consultas), DMARC, seletores DKIM, MTA-STS, TLS-RPT, BIMI |
| infra | AS e dono, hospedagem, CDN, servidor, desafios de bot |
| security | nota de A+ a F com a pontuação do [MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory), mais conteúdo misto, formulários inseguros, vazamento de versão, downgrades para HTTP, security.txt |
| stack | 7.647 tecnologias das assinaturas do [webappanalyzer](https://github.com/enthec/webappanalyzer), cada uma com a evidência e onde foi vista (página, DNS ou certificado); bibliotecas com versão vulnerável conhecida são marcadas com dados do [Retire.js](https://github.com/RetireJS/retire.js) |
| seo | indexação, título, descrição, canonical, títulos de seção, idioma, Open Graph, dados estruturados, robots.txt, sitemap |
| weight | tamanho e compressão do HTML, scripts, recursos que bloqueiam a renderização, imagens, terceiros por nome |
| browser | com `--browser`: LCP, CLS, TBT e FCP com classificação, requisições e bytes por tipo, recursos mais pesados, parcela de terceiros, erros do console |

</details>

## Por que o insite

Uma execução inteira leva cerca de um segundo: a mediana é de 888 ms numa lista de referência de 100 sites, um site por vez, a partir de uma VPS em Boston, em 30/10/2026 ([método](https://github.com/jospnunes/insite/blob/main/docs/methodology.md#timing)).

Todo achado traz a evidência, e o que o insite não conseguiu medir aparece como "não medido", nunca como ausente. Em 20 sites rotulados à mão, a detecção de stack tem precisão de 0,995 (detecções incertas fora da conta) e concorda com o núcleo JavaScript do Wappalyzer com F1 de 0,997 em 90 sites. Em 26 sites, a nota e a pontuação de segurança bateram com as análises publicadas pelo Observatory sempre que os dois viram a mesma página ([comparação](https://github.com/jospnunes/insite/blob/main/docs/methodology.md#security-grade-and-the-observatory)).

Ele é passivo. Lê o que qualquer visitante veria, sem varredura de portas, sem fuzzing de caminhos e sem teste de vulnerabilidade.

> **Não aponte o insite para alvos não confiáveis a partir de uma rede sensível.** Ele segue redirecionamentos, e a URL de `Sitemap:` do `robots.txt`, para qualquer endereço que apontem, inclusive endereços privados. Um site hostil pode fazê-lo requisitar um endereço interno.

## Comparação com outras ferramentas

Cada célula vem do README ou da documentação da própria ferramenta. Um traço significa que ela não menciona o item.

| | Stack | TLS | Cabeçalhos de segurança | DNS e e-mail | SEO | Web Vitals |
| --- | --- | --- | --- | --- | --- | --- |
| insite | sim | sim | nota de A+ a F | sim | sim | com `--browser` |
| [httpx](https://github.com/projectdiscovery/httpx) | base do Wappalyzer (`-tech-detect`) | coleta de dados (`-tls-grab`) | sonda do cabeçalho CSP | CNAME e IP | - | - |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | mais de 1800 plugins | - | - | - | - | - |
| [testssl.sh](https://github.com/testssl/testssl.sh) | - | protocolos, cifras, falhas conhecidas, certificado | HSTS e outros (`--header`) | CAA; MX sobre STARTTLS (`--mx`) | - | - |
| [Lighthouse](https://github.com/GoogleChrome/lighthouse) | - | só o uso de HTTPS | HSTS, clickjacking, CSP | - | sim | LCP, CLS, TBT |

O testssl.sh testa falhas conhecidas como Heartbleed e ROBOT, que o insite não testa, e o Lighthouse também audita acessibilidade. O insite relata todas essas áreas numa passada passiva. Ele não substitui a profundidade dessas ferramentas.

## Para agentes de IA e scripts

`--json` e `--ndjson` imprimem o relatório como dados, um relatório por site (dois com `--ndjson --browser`: `fast` e depois `full`), e `--md` escreve um Markdown para colar no contexto de um modelo. Os `id` e `params` dos achados são estáveis, os títulos e textos podem mudar, e o `schema_version` segue semver. Códigos de saída: 0 completo, 1 inacessível, 2 erro de uso, 3 parcial, 130 interrompido.

```
insite --json -m security wordpress.org | jq -c '.modules.security.findings[] | {id, severity, params}'
```

```
{"id":"sec.csp.missing","severity":"medium","params":{"value":""}}
{"id":"sec.hsts.short","severity":"low","params":{"value":"max-age=3600"}}
{"id":"sec.sri.missing","severity":"low","params":{"value":"https://stats.wp.com/e-202644.js"}}
```

Mais dois achados foram cortados. Se um agente escolhe os alvos, vale o aviso acima.

## Documentação e licença

- [Uso](https://github.com/jospnunes/insite/blob/main/docs/usage.md): todas as opções, modo lote, modo navegador, saída ao vivo, assinaturas próprias, estabilidade do JSON (em inglês).
- [Metodologia](https://github.com/jospnunes/insite/blob/main/docs/methodology.md): princípios, tempo, precisão, a comparação com o Observatory (em inglês).
- [Arquitetura](https://github.com/jospnunes/insite/blob/main/docs/arquitetura.md): o documento de desenho, em português.
- [Changelog](https://github.com/jospnunes/insite/blob/main/CHANGELOG.md).

O insite é software livre sob a GPL-3.0-or-later. A consulta de AS usa o serviço DNS público de IP para ASN da Team Cymru. O insite não é afiliado a nenhum dos projetos abaixo nem endossado por eles.

<details>
<summary>Dados embutidos e suas licenças</summary>

| Dados | Fonte | Licença |
| --- | --- | --- |
| Assinaturas de tecnologia | [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) | GPL-3.0 |
| Certificados de CA divulgados aos programas de raízes (só nomes e identificadores de chave) | [Common CA Database](https://www.ccadb.org/) | CDLA-Permissive-2.0 |
| Versões vulneráveis conhecidas de bibliotecas JavaScript (faixas, severidades, identificadores) | [Retire.js](https://github.com/RetireJS/retire.js) | Apache-2.0 |
| Lista de preload do HSTS | [Chromium](https://source.chromium.org/chromium/chromium/src/+/main:net/http/transport_security_state_static.json) | BSD-3-Clause |
| Metodologia de pontuação de segurança | [MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory) | MPL-2.0 |
| Raízes de confiança | Mozilla, via [webpki-roots](https://github.com/rustls/webpki-roots) | CDLA-Permissive-2.0 |
| Lista de sufixos públicos | [publicsuffix.org](https://publicsuffix.org/), via o crate `psl` | MPL-2.0 |

Os scripts em `scripts/` regeneram os dados embutidos, e o relatório lista a versão de cada fonte que usou.

</details>
