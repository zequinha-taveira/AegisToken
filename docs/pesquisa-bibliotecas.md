# Pesquisa de Bibliotecas Maduras (Python e Rust) — MIT OR Apache-2.0

Este documento consolida a pesquisa de bibliotecas de código aberto maduras, ativamente mantidas e com licenciamento permissivo estrito (**MIT**, **Apache-2.0** ou combinação **MIT OR Apache-2.0**) para uso no ecossistema **AegisToken**.

O objetivo é orientar a evolução das ferramentas de host (`aegistoken-host`), dos scripts de validação (`scripts/validate_*.py`), do futuro **Desktop Manager** e de eventuais integrações de clientes, assegurando conformidade de licença e evitando contaminação por licenças copyleft (GPL / LGPL).

---

## 1. Diretrizes de Seleção e Licenciamento

O projeto AegisToken adota licenciamento duplo permissivo:
- **`MIT OR Apache-2.0`**

### Critérios de aceitação para dependências:
1. **Licenciamento permissivo:** compatibilidade direta com `MIT` ou `Apache-2.0` (ou equivalentes permissivas como `BSD-2-Clause` / `BSD-3-Clause`). Nenhuma dependência `GPL` ou `LGPL` em ferramentas distribuídas.
2. **Maturidade e governança:** histórico comprovado de manutenção contínua, ampla adoção na comunidade, documentação de qualidade e testes automatizados.
3. **Segurança de memória e robustez:** ausência de vazamento de segredos em logs, proteção contra estouro de buffers e comportamento previsível em falhas de comunicação USB/smartcard.
4. **Suporte multiplataforma:** suporte nativo aos três sistemas operacionais principais (Windows, Linux e macOS).

---

## 2. Ecossistema Rust (Crates)

### 2.1. Comunicação USB e HID

| Crate | Licença | Maturidade / Status | Uso recomendado no AegisToken |
|---|---|---|---|
| **`rusb`** | `MIT` | Madura (wrapper sobre `libusb-1.0` com `features = ["vendored"]`). | **Atual** — Já utilizado pelo `aegistoken-host`. Comunicação direta com Management HID sem necessidade de WinUSB/Zadig no Windows (usa backend HID inbox). |
| **`nusb`** | `MIT OR Apache-2.0` | Moderna e em rápido crescimento (Rust puro, assíncrono). | **Futuro / Alternativa** — Não depende de compilação de código C (`libusb`), comunica nativamente com WinUSB no Windows, `io_uring`/`usbfs` no Linux e IOKit no macOS. Excelente para ferramentas modernas. |
| **`hidapi`** | `MIT` (bindings) | Madura (bindings Rust para a biblioteca C `hidapi`). | Útil se for necessário interagir diretamente via relatórios HID brutos sem libusb. |

### 2.2. Smart Card, CCID, PC/SC e APDU

| Crate | Licença | Maturidade / Status | Uso recomendado no AegisToken |
|---|---|---|---|
| **`pcsc`** (pcsc-rust) | `MIT` | Altamente madura e estável. | **Recomendada** — Bindings seguros e idiomáticos para PC/SC (`winscard.dll` no Windows, `libpcsclite` no Linux, `PCSC.framework` no macOS). Ideal para ferramentas de linha de comando ou Desktop Manager que validam PIV, OATH e OpenPGP via CCID. |
| **`iso7816`** | `MIT OR Apache-2.0` | Madura (`no_std` friendly). | **Recomendada** — Estruturas e enquadramentos de APDU de comando/resposta e status words conforme ISO 7816-4. Pode ser adotada para padronizar tipos entre host e applets. |

### 2.3. FIDO2, CTAP2 e WebAuthn

| Crate | Licença | Maturidade / Status | Uso recomendado no AegisToken |
|---|---|---|---|
| **`webauthn-rs`** / **`webauthn-rs-proto`** | `MIT OR Apache-2.0` | Altamente madura (mantida pelo projeto Kanidm). | **Recomendada** — Implementação de referência de tipos WebAuthn, parsing de `authenticatorData`, extensões e atestação. Essencial para testes de ponta a ponta e integrações de host. |
| **`coset`** | `Apache-2.0` | Altamente madura (Google). | **Recomendada** — Serialização e parsing de estruturas COSE (RFC 8152/9052 / COSE_Key / COSE_Sign1), padrão exigido pelas respostas CTAP2/WebAuthn. |
| **`ctap-types`** | `Apache-2.0` | Madura (Google OpenSK). | Tipos e enums CTAP2 para clientes FIDO2 em Rust. |

### 2.4. Criptografia e Estruturas de Dados (Host e `no_std`)

| Crate | Licença | Maturidade / Status | Uso recomendado no AegisToken |
|---|---|---|---|
| **`p256`**, **`p384`** | `MIT OR Apache-2.0` | Altamente maduras (RustCrypto). | **Atual** — Primitivas ECC constantes em tempo de execução para curvas NIST P-256 e P-384. |
| **`ed25519-dalek`**, **`x25519-dalek`** | `BSD-3-Clause` | Altamente maduras e auditadas. | **Atual** — Primitivas EdDSA (para `ed25519-sk` e OpenPGP) e troca de chaves. |
| **`der`** / **`x509-cert`** | `MIT OR Apache-2.0` | Altamente maduras (RustCrypto). | **Recomendada** — Parsing e emissão de certificados X.509 em ASN.1 DER (`no_std` compatível, sem alocação dinâmica obrigatória). Útil para validação de certificados PIV e atestação FIDO2. |
| **`ciborium`** | `Apache-2.0` | Muito madura (sucessor do `serde_cbor`). | Serialização e deserialização CBOR com suporte a Serde para ferramentas de host. |
| **`crypto-bigint`** | `MIT OR Apache-2.0` | Madura (RustCrypto). | **Atual** — Aritmética de inteiros de precisão arbitrária em tempo constante, usada na implementação RSA-2048 sem alocação dinâmica. |

### 2.5. Interface Gráfica (Desktop Manager)

| Crate | Licença | Maturidade / Status | Uso recomendado no AegisToken |
|---|---|---|---|
| **`tauri`** (v2.x) | `MIT OR Apache-2.0` | Líder de mercado, produção contínua. | **Recomendada para UI rica** — Permite criar um Desktop Manager multiplataforma e leve, com backend em Rust (comunicando com `rusb`/`pcsc`) e frontend web moderno (HTML/JS/CSS). Binários compactos e baixo consumo de memória. |
| **`egui`** | `MIT OR Apache-2.0` | Altamente madura e popular. | **Recomendada para UI nativa leve** — GUI em modo imediato, 100% Rust pura, sem dependências de C nem navegadores embarcados. Ideal para ferramentas de diagnóstico técnico e painéis utilitários. |
| **`iced`** | `MIT` | Madura (estilo Elm). | Alternativa reativa para interfaces desktop nativas em Rust. |

> **Nota sobre licenças:** bibliotecas como `slint` possuem licença GPLv3/Comercial e devem ser **evitadas** para não conflitar com a política permissiva do AegisToken.

### 2.6. CLI e Aquisição de Segredos

| Crate | Licença | Maturidade / Status | Uso recomendado no AegisToken |
|---|---|---|---|
| **`rpassword`** | `Apache-2.0` | Madura e pequena (dependência `rtoolbox`). | **Atual (host-only)** - Prompt de senha sem eco no terminal para o `aegistoken-host`. Entra apenas no crate de host; nunca no workspace de firmware (`aegis-core`/`aegis-applets` continuam `no_std`). Segredos não são aceitos em `argv`; o canal de automação é stdin. |

---

## 3. Ecossistema Python

O ecossistema Python é usado primariamente para validação de hardware, scripts de automação (`scripts/`) e ferramentas de diagnóstico rápido.

### 3.1. FIDO2 / WebAuthn

| Pacote | Licença | Maturidade | Observações |
|---|---|---|---|
| **`fido2`** (python-fido2) | `Apache-2.0 AND BSD-2-Clause` | Padrão da indústria (Yubico). | **Atual** — Utilizada em `scripts/validate_fido.py`. Cobre CTAP1, CTAP2, `authenticatorMakeCredential`, `authenticatorGetAssertion`, PIN/UV e negociação de canais HID. |
| **`webauthn`** (py_webauthn) | `BSD-3-Clause` | Madura (Duo Labs). | Permissiva e excelente para validação de fluxos WebAuthn de servidor/validação de RP. |

### 3.2. Serialização e Criptografia

| Pacote | Licença | Maturidade | Observações |
|---|---|---|---|
| **`cbor2`** | `MIT` | Padrão da indústria. | **Atual** — Utilizada em `scripts/validate_management.py` para codificação e decodificação dos relatórios e configurações CBOR do firmware. |
| **`cryptography`** | `Apache-2.0 OR BSD-3-Clause` | Padrão absoluto em Python. | **Atual** — Utilizada para validação de vetores criptográficos, verificação de assinaturas X.509 e RSA/ECDSA nos testes de hardware. |
| **`asn1crypto`** | `MIT` | Altamente madura (Python puro). | Excelente para inspecionar e validar DOs ASN.1 DER (PIV, certificados X.509 e chaves públicas) sem dependências binárias externas. |

### 3.3. Smart Card / PC/SC: Análise de Licença e Alternativas

> [!WARNING]
> **Alerta sobre o `pyscard`:**
> Atualmente, `scripts/validate_ccid.py`, `validate_piv.py`, `validate_oath.py` e `validate_openpgp.py` dependem de `pyscard`.
> O `pyscard` é licenciado sob **LGPL-2.1+**, o que impõe restrições de redistribuição.

#### Alternativas permissivas (MIT / Apache-2.0 / BSD) em Python:
1. **Camada nativa via `ctypes` (`winscard` / `pcsclite`):**
   - Criação de um módulo leve em Python puro (`scripts/pcsc_transport.py`) sob **MIT**, invocando `winscard.dll` no Windows e `libpcsclite.so.1` no Linux diretamente via `ctypes`. Elimina totalmente a dependência de bibliotecas compiladas externas e resolve o licenciamento LGPL.
2. **Submódulo `fido2.pcsc` do `python-fido2`:**
   - O pacote `python-fido2` (já licenciado sob `Apache-2.0 / BSD-2-Clause`) possui internamente um transporte PC/SC baseado em `ctypes` para comunicação com cartões e tokens sem depender do `pyscard`.
3. **Migração dos validadores para Rust (`aegistoken-host` + `pcsc-rust`):**
   - Incorporar os testes de conformidade CCID/PIV/OATH/OpenPGP diretamente no crate `aegistoken-host` em Rust, utilizando o crate `pcsc` (`MIT`), unificando o ferramental sob um único binário com licenciamento `MIT OR Apache-2.0`.

---

## 4. Matriz de Recomendações e Plano de Adoção

| Área | Abordagem Recomendada | Pacotes / Crates Escolhidos | Licença |
|---|---|---|---|
| **Host CLI (Gestão)** | Rust | `rusb` (atual) ou migração futura para `nusb` | `MIT` / `MIT OR Apache-2.0` |
| **Host CLI (CCID/Applets)** | Rust | `pcsc` + `iso7816` | `MIT` / `Apache-2.0` |
| **Desktop Manager (GUI)** | Rust | `tauri` v2 (UI rica) ou `egui` (UI utilitária) | `MIT OR Apache-2.0` |
| **Validação FIDO2** | Python | `fido2` (Yubico) + `cbor2` | `Apache-2.0` / `MIT` |
| **Validação CCID/Applets** | Python / Rust | Bridge `ctypes` própria ou integração em `aegistoken-host` | `MIT OR Apache-2.0` |
| **Manipulação ASN.1 / X.509** | Rust & Python | `der`/`x509-cert` (Rust) e `asn1crypto` (Python) | `MIT OR Apache-2.0` |
