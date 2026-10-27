# Plano de Desenvolvimento — Ecossistema AegisToken
## Integração de Bibliotecas Maduras (Python e Rust) e Evolução do Ferramental

Este documento estabelece o **Plano de Desenvolvimento** para a expansão do ecossistema **AegisToken**, consolidando a integração das **bibliotecas maduras em Python e Rust** mapeadas em [`docs/pesquisa-bibliotecas.md`](pesquisa-bibliotecas.md).

O foco deste plano é guiar a transição de um firmware validado em bancada para uma solução completa de produto:
1. **Ferramental de Host Unificado (`aegistoken-host`)** com suporte a CCID/PC-SC e FIDO2.
2. **Desktop Manager Multiplataforma** para provisionamento, gestão de passkeys, OATH/TOTP e PIV.
3. **Saneamento de Licenças** nos validadores de teste (eliminação do copyleft LGPL do `pyscard`).
4. **Governança de Dependências** estritamente sob **`MIT OR Apache-2.0`**.

---

## 1. Princípios Arquiteturais e Regras de Licenciamento

- **Licença Estrita:** Toda nova biblioteca incorporada ao repositório ou distribuída junto aos binários deve possuir licenciamento duplo `MIT OR Apache-2.0` ou equivalente permissivo (`BSD-2-Clause`, `BSD-3-Clause`). Nenhuma dependência `GPL` ou `LGPL` é permitida.
- **Isolamento de Domínio:** O firmware (`aegis-core` e `aegis-applets`) permanece estritamente `no_std`/`no_alloc` e independente de bibliotecas de host ou drivers de sistema operacional.
- **Autoridade do Firmware:** O firmware é a autoridade absoluta de capacidades (`GET_CAPABILITIES`) e segurança; o Desktop Manager e o CLI apenas propõem operações e exibem o estado real do hardware.

---

## 2. Eixos de Desenvolvimento (Workstreams)

### Eixo 1: Saneamento e Permissividade dos Validadores (Python & Rust)
**Objetivo:** Eliminar a dependência de `pyscard` (LGPL-2.1+) nos scripts de validação de hardware (AC-016..AC-021) e padronizar o ferramental sob licenças permissivas.

- **Etapa 1.1: Módulo PC/SC Permissivo em Python (`scripts/pcsc_transport.py`) — [CONCLUÍDA]**
  - Implementado driver de transporte PC/SC em Python puro via `ctypes` (`winscard.dll` no Windows e `libpcsclite.so.1` no Linux) sob licença **MIT OR Apache-2.0**.
  - Scripts `validate_ccid.py`, `validate_piv.py`, `validate_oath.py` e `validate_openpgp.py` atualizados para usar `pcsc_transport` por padrão (com fallback retrocompatível).
  - Testes unitários entregues e aprovados em `tests/test_pcsc_transport.py`. Dependência de `pyscard` (LGPL) eliminada.
- **Etapa 1.2: Portabilidade dos Validadores para Rust**
  - Portar progressivamente as suítes de validação de protocolo para dentro do crate `aegistoken-host`, utilizando o crate maduro `pcsc` (MIT).

---

### Eixo 2: Expansão do CLI de Host (`aegistoken-host` em Rust)
**Objetivo:** Evoluir o `aegistoken-host` de uma ferramenta básica de Management HID para um utilitário completo de diagnóstico, provisionamento e interação com os applets CCID.

- **Etapa 2.1: Integração com PC/SC (`pcsc` crate) — [CONCLUÍDA]**
  - Crate **`pcsc`** v2.9 (MIT) adicionado às dependências do workspace e do `aegistoken-host`.
  - Módulo `crates/aegistoken-host/src/card.rs` implementado com enumeração de leitores, detecção automática do AegisToken, consulta de status/ATR, seleção de AID (aliases para PIV, OATH e OpenPGP) e envio de APDUs arbitrários.
  - Novos subcomandos integrados ao CLI: `card-list`, `card-status [READER]`, `card-select <AID> [READER]` e `card-apdu <HEX> [READER]`.
  - Testes unitários entregues e aprovados (parsing de hex, resolução de aliases de AID, formatação).
- **Etapa 2.2: Suporte a APDUs ISO 7816 (`iso7816` crate) — [CONCLUÍDA]**
  - Crate **`iso7816`** v0.2.2 (`Apache-2.0 OR MIT`) adicionado às dependências do workspace e do `aegistoken-host`.
  - Integração do parser tipado `CommandView` para decodificação detalhada dos campos de instrução ISO/IEC 7816-4 (INS, P1, P2, Lc, Le) no subcomando `card-apdu`.
  - Mapeamento e formatação mnemônica rica de status words (`SW1 SW2`) via `iso7816::Status` (`format_iso_status`) nos comandos `card-select` e `card-apdu`.
  - Testes unitários entregues e aprovados cobrindo formatação de status e decodificação estruturada de comandos SELECT.
- **Etapa 2.3: Gestão de Certificados e Chaves Públicas PIV (`der` & `x509-cert`) — [CONCLUÍDA]**
  - Crate **`x509-cert`** v0.3.0 e **`der`** v0.8.2 (RustCrypto, `MIT OR Apache-2.0`) adicionados às dependências do workspace e do `aegistoken-host`.
  - Módulo `crates/aegistoken-host/src/piv_cmd.rs` implementado com:
    - `piv-list [READER]`: varredura dos slots 9A, 9C, 9D e 9E com extração do objeto `53` / `70` e decodificação estruturada do certificado X.509 (Subject, Issuer, Serial, Validade NotBefore/NotAfter, Algoritmo da chave pública e tamanho).
    - `piv-import-cert <SLOT> <CERT_FILE> [READER] [--key-stdin]`: importação de certificados X.509 (suporta arquivos PEM e DER binários), validação ASN.1 prévia, autenticação de Management Key e gravação via `PUT DATA`. A chave de gestão não padrão entra por stdin (`--key-stdin`), nunca em `argv`.
    - `piv-set-mgmt-key [--reader SUBSTR] [--alg ALG] [--key-stdin [--old-key-stdin]]`: substituição da chave de gestão com suporte a 3DES (24B), AES-128 (16B), AES-192 (24B) e AES-256 (32B) via protocolo Yubico extension `SET MANAGEMENT KEY`. A chave nunca vem em `argv`: entra por prompt oculto (TTY) ou por stdin (`--key-stdin`/`--old-key-stdin`, com pipe).
    - Autenticação de Management Key (`authenticate_mgmt`) implementada via desafio e decifragem de nonce ECB (3DES e AES).
  - 4 novos testes unitários adicionados cobrindo resolução de slots PIV, extração de TLV de certificado, decifragem TDES/AES e parsing de certificados PEM/DER. Total de 15 testes aprovados no `aegistoken-host` naquela etapa (hoje 33 no crate).
- **Etapa 2.4: Gestão de Contas OATH/TOTP — [CONCLUÍDA]**
  - Subcomando `aegistoken-host oath` implementado em `crates/aegistoken-host/src/oath_cmd.rs`:
    - `oath list`: listar contas configuradas.
    - `oath code <nome>`: calcular código TOTP (timestamp do host).
    - `oath add <uri>`: cadastrar novas credenciais TOTP/HOTP a partir de URIs `otpauth://`.
    - `oath delete <nome>` e `oath reset`: remover credencial / reiniciar o applet.
  - Parsing de `otpauth://` coberto por testes de host no crate `aegistoken-host`.
- **Etapa 2.5: Avaliação do `nusb` para eliminação de dependências C**
  - Avaliar a substituição do `rusb` (que compila a `libusb` C) pelo **`nusb`** (Rust puro, MIT OR Apache-2.0), simplificando cross-compilação e empacotamento em Windows/Linux/macOS sem toolchains C adicionais.

---

### Eixo 3: Criação do Desktop Manager (GUI Multiplataforma em Rust)
**Objetivo:** Desenvolver uma aplicação gráfica moderna, visualmente atraente e segura para o usuário final configurar e gerenciar seu AegisToken.

- **Etapa 3.1: Definição da Stack Tecnológica (100% Permissiva)**
  - **Framework GUI:** **`tauri` v2** (`MIT OR Apache-2.0`).
    - *Vantagens:* Backend 100% Rust, integrando diretamente com `rusb`, `pcsc` e `aegis-core`; interface frontend desacoplada, leve e moderna (HTML/CSS/JS sem navegadores pesados tipo Electron).
    - *Alternativa Utilitária:* **`egui`** (`MIT OR Apache-2.0`) caso se deseje um executável monolítico sem dependência do WebView do sistema operacional.
- **Etapa 3.2: Módulos Funcionais do Desktop Manager**
  1. **Painel de Boas-Vindas e Identidade:**
     - Exibição de Board Identity (modelo, revisão, fabricante) e MCU Identity (número de série OTP único do RP2350).
     - Estado de ciclo de vida (`Factory`, `Commissioning`, `Active`).
  2. **Configuração de Hardware & LED:**
     - Escolha de GPIO do LED (respeitando os pinos candidatos do perfil da placa).
     - Configuração de comportamento do LED, brilho e polaridade em tempo real.
     - Teste de presença do usuário (confirmação visual de toque no BOOTSEL/botão).
  3. **Módulo FIDO2 / Passkeys:**
     - Listagem de credenciais residentes (Relying Party ID, User Name, ID da credencial).
     - Remoção de passkeys com autenticação por PIN e toque físico.
     - Definição e alteração do PIN de autenticação (`clientPIN`).
  4. **Módulo Autenticador OATH (2FA / TOTP):**
     - Leitor e gerador de códigos TOTP/HOTP com barra de progresso do intervalo de tempo (30s).
     - Importação via leitura de QR Code ou digitação de segredo base32.
  5. **Módulo Smart Card / PIV:**
     - Visualização dos certificados digitais de autenticação, assinatura e decifra.
     - Assistente para geração de par de chaves no dispositivo e exportação de CSR (Certificate Signing Request).
     - Importação do certificado emitido para o slot PIV correspondente.
  6. **Atualização Segura de Firmware:**
     - Verificação de novas versões estáveis ou nightlies a partir do GitHub Releases oficial.
     - Upload do arquivo `.uf2` assinado via protocolo Management HID, com verificação de assinatura e anti-rollback pelo bootloader/OTP.

---

### Eixo 4: Criptografia e Preparação para o Futuro (PQC / RustCrypto)
**Objetivo:** Manter a criptografia do AegisToken moderna, padronizada e pronta para novos padrões da indústria.

- **Etapa 4.1: Consolidação dos Crates RustCrypto**
  - Padronizar todo o tratamento de primitivas no ecossistema de crates `RustCrypto` (`p256`, `p384`, `ed25519-dalek`, `x25519-dalek`, `crypto-bigint`, `der`, `aes-gcm`).
- **Etapa 4.2: Roadmap de Criptografia Pós-Quântica (PQC)**
  - Pesquisar e monitorar a maturidade das implementações Rust sob `MIT OR Apache-2.0` dos padrões FIPS 203 (ML-KEM) e FIPS 204 (ML-DSA) para futura inclusão no CTAP2 (extensões híbridas) e OpenPGP.

---

### Eixo 5: Governança, Rastreabilidade e Atualização Contínua de Status e Progresso do Ecossistema
**Objetivo:** Estabelecer uma arquitetura de dados e automação para rastrear, validar e publicar com fidelidade o status dos marcos (*milestones*), capacidades ativas, interfaces e progresso do firmware e ferramentas.

- **Etapa 5.1: Fonte Única da Verdade Estruturada (`docs/status.json`) — [CONCLUÍDA]**
  - Implementação de esquema canônico em JSON com metadados do projeto, status de cada milestone (M1 a M6), porcentagem de progresso, capacidades ativas, interfaces USB compostas, applets e políticas de governança (zero GPL/LGPL, não-exportabilidade de chaves).
  - Centralização de métricas: qualquer alteração de status parte obrigatoriamente deste arquivo.
- **Etapa 5.2: Motor de Renderização Vetorial Automatizado (`scripts/update_status_svg.py` & `docs/images/status.svg`) — [CONCLUÍDA]**
  - Criação do script em Python puro (`scripts/update_status_svg.py`), sem dependências externas (stdlib apenas), que consome `docs/status.json` e renderiza deterministicamente o painel visual SVG.
  - O painel exibe graficamente os 6 milestones em grade 2x3, barras proporcionais de progresso, badges semânticos coloridos, interfaces USB e versão do firmware.
- **Etapa 5.3: Gate de Validação Contínua no Pipeline de CI (`--check`)**
  - Adicionar a etapa de checagem ao workflow do GitHub Actions (`.github/workflows/ci.yml`):
    `python scripts/update_status_svg.py --check`
  - Se um pull request alterar `docs/status.json` sem atualizar `docs/images/status.svg` (ou vice-versa), o CI falha imediatamente com aviso explicativo, impedindo descompassos na documentação.
- **Etapa 5.4: Sincronização com o Ciclo de Release e Versionamento**
  - Conectar a automação de release (`scripts/build-uf2.ps1 -Release` e `.github/workflows/release.yml`) para verificar se a versão em `[workspace.package].version` do `Cargo.toml`, `version.md` e `docs/status.json` coincidem antes de gerar a tag final `v*`.
- **Etapa 5.5: Procedimento Operacional Padrão (SOP) de Atualização**
  1. *Ao concluir uma tarefa:* O desenvolvedor atualiza `progress_percent` e/ou `status` no marco em `docs/status.json`.
  2. *Execução local:* Roda `python scripts/update_status_svg.py` para sincronizar o vetor `docs/images/status.svg`.
  3. *Atualização do Markdown:* Marca os checkboxes em `docs/MILESTONES.md` (`- [x]`) e registra a evidência em `validation.md` / `roadmap.md`.
  4. *Validação:* Roda os gates (`cargo test`, `cargo fmt`, `python scripts/update_status_svg.py --check`).

---

## 3. Matriz de Rastreabilidade de Bibliotecas Adotadas

| Crate / Pacote | Linguagem | Licença | Finalidade no Projeto | Status de Adoção |
|---|---|---|---|---|
| **`rusb`** | Rust | `MIT` | Acesso USB ao Management HID via libusb embutida | Em uso no `aegistoken-host` |
| **`nusb`** | Rust | `MIT OR Apache-2.0` | USB assíncrono puro em Rust (sem runtime C) | Avaliação técnica (Eixo 2) |
| **`pcsc`** | Rust | `MIT` | Comunicação com leitores e applets CCID no host | **Entregue** (Etapa 2.1) |
| **`iso7816`** | Rust | `MIT OR Apache-2.0` | Modelagem tipada de APDUs e status words ISO 7816-4 | **Entregue** (Etapa 2.2) |
| **`webauthn-rs`** | Rust | `MIT OR Apache-2.0` | Tipos WebAuthn, atestação e estruturas de dados de auth | Planejado para testes e SDK de host |
| **`coset`** | Rust | `Apache-2.0` | Codificação e decodificação de COSE_Key / COSE_Sign1 | Planejado para SDK FIDO2 de host |
| **`der`** / **`x509-cert`** | Rust | `MIT OR Apache-2.0` | Parsing e manipulação de certificados X.509 em ASN.1 | **Entregue** (Etapa 2.3) |
| **`tauri`** v2 | Rust / Web | `MIT OR Apache-2.0` | Framework da interface gráfica do Desktop Manager | Planejado para o Desktop Manager (Eixo 3) |
| **`fido2`** (python-fido2) | Python | `Apache-2.0 AND BSD-2-Clause` | Validação de protocolo CTAP1/CTAP2 e FIDO HID | Em uso em `validate_fido.py` |
| **`cbor2`** | Python | `MIT` | Serialização e inspeção CBOR nos validadores | Em uso em `validate_management.py` |
| **`cryptography`** | Python | `Apache-2.0 OR BSD-3-Clause` | Validação de assinaturas criptográficas e certificados | Em uso nos testes de hardware |
| **`ctypes` (winscard/pcsclite)** | Python | `MIT OR Apache-2.0` | `scripts/pcsc_transport.py` (elimina `pyscard` LGPL) | **Entregue** (Etapa 1.1) |

---

## 4. Cronograma e Fases de Entrega

```
[Mês 1] Saneamento de Licenças & PC/SC Permissivo
 ├── Etapa 1.1: Eliminar pyscard dos validadores Python (via ctypes/fido2.pcsc)
 └── Etapa 2.1: Integrar crate `pcsc` e `iso7816` ao `aegistoken-host`

[Mês 2] CLI de Host Estendido & Gestão Completa
 ├── Etapa 2.2: Adicionar suporte PIV (certificados e chave de gestão via `x509-cert`)
 ├── Etapa 2.3: Adicionar suporte OATH/TOTP no CLI
 └── Etapa 2.4: Teste de compatibilidade de USB com `nusb`

[Mês 3] Desktop Manager (AegisToken Manager)
 ├── Etapa 3.1: Setup da arquitetura Tauri v2 com backend Rust
 ├── Etapa 3.2: Módulos de Identidade, Configuração de LED e Presença
 ├── Etapa 3.3: Módulo de Gestão FIDO2 (passkeys) e OATH (TOTP)
 └── Etapa 3.4: Assistente PIV (geração de CSR e importação de certificado)

[Mês 4] Polimento, Release e Validação E2E
 ├── Empacotamento de instaladores nativos (.msi, .deb, .dmg)
 ├── Validação contínua em hardware com CI automatizado
 └── Documentação de usuário final e guias de provisionamento
```

---

## 5. Critérios de Sucesso e Validação

1. **Conformidade de Licenciamento:** Todo o repositório e suas dependências de produção/distribuição auditados e livres de licenças copyleft (`GPL`/`LGPL`).
2. **Autonomia do Ferramental:** O `aegistoken-host` e o Desktop Manager conseguem inspecionar, provisionar e gerenciar 100% dos recursos do dispositivo (FIDO2, CCID/PIV, OATH, Management HID e Firmware Update).
3. **Qualidade de Código e Testes:** Todos os novos componentes passam nos gates de compilação estrita: `cargo fmt --all --check`, `clippy --all-targets -- -D warnings` e cobertura de testes automatizados.
4. **Rastreabilidade e Sincronismo de Status:** `docs/status.json` e o painel `docs/images/status.svg` mantidos 100% sincronizados em todos os commits, com validação automatizada via `python scripts/update_status_svg.py --check` no pipeline de CI.
