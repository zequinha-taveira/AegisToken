# Roadmap — AegisToken Universal RP2350 Firmware

Mapa de execução do PRD do firmware universal para a família RP2350.
Documento vivo: cada fase é marcada conforme concluída e verificada.

## Estado atual

| Fase | Descrição | Status |
|------|-----------|--------|
| 0 | Workspace, toolchain, pipeline UF2, CI | Concluída |
| 1 | `aegis-core`: domínio testável em host | Concluída |
| 2 | `board-generic-rp2350`: descoberta de hardware | Concluída |
| 3 | USB: enumeração FIDO HID + Management HID | Concluída |
| 4 | Protocolo Management HID | Concluída |
| 5 | Storage persistente + armazenamento seguro | Concluída |
| 6 | User Presence contextual (BOOTSEL) | Concluída |
| 7 | FIDO (CTAP1/U2F + CTAP2) | Concluída (7a–7h) |
| 8 | Atualização segura de firmware | Concluída |
| 9 | Recovery + lifecycle completo | Concluída |
| 10 | Validação de hardware (AC-001..AC-015) | Concluída (bootrom/OTP pendentes) |
| 11 | `aegis-applets`: APDU, CCID e roteamento de applets | Concluída (hardware pendente) |
| 12 | PIV (NIST SP 800-73-4) | Concluída (hardware pendente; persistência selada entregue) |
| 13 | OATH (TOTP/HOTP) | Concluída (hardware pendente; persistência selada entregue) |
| 14 | OpenPGP card (v3.4) | Concluída (P-256 slice; hardware pendente; persistência selada entregue) |
| 15 | SSH/Git signing + Ed25519 no CTAP2 | Concluída (firmware; hardware pendente) |
| 16 | RSA (PIV/OpenPGP) | Em andamento (16a–16d em firmware; hardware pendente) |
| 17 | Conformidade e validação dos applets | Em andamento (firmware; hardware pendente) |
| 18 | Ferramental de host, Desktop Manager e pesquisa de bibliotecas (Python/Rust) | Em andamento (pesquisa de bibliotecas MIT/Apache-2.0 entregue em `docs/`) |

## Decisões arquiteturais fixadas

- **HAL/executor:** `embassy-rp` (assíncrono) + `embassy-usb` + `embassy-executor`.
- **Crates:** `aegis-core` (portátil/testável), `board-generic-rp2350` (hardware),
  `firmware-universal-rp2350` (bin), `aegistoken-host` (CLI de host).
- **Host:** `aegistoken-host` acessa o Management HID via **libusb** (crate
  `rusb`, libusb embutida), sem WinUSB/Zadig; no Windows usa o backend HID do
  libusb sobre o driver HID inbox.
- **Desktop Manager:** ainda não existe crate de Desktop Manager nem integração
  de "Ejetar" no repositório; por ora há apenas o CLI de host
  (`aegistoken-host`).
- **Pesquisa e conformidade de bibliotecas (Python e Rust — MIT OR Apache-2.0):**
  todas as dependências e ferramentas de apoio (tanto em Rust quanto em Python
  para validadores, CLI e Desktop Manager) devem ser maduras, ativamente
  mantidas e estritamente licenciadas sob **MIT OR Apache-2.0** (ou licenças
  permissivas equivalentes como BSD-2/3-Clause sem restrições virais).
  Dependências sob GPL/LGPL (como `pyscard` no ecossistema Python) devem ser
  substituídas ou encapsuladas sem contaminação, preservando o licenciamento
  duplo permissivo integral do AegisToken. Detalhes em `docs/pesquisa-bibliotecas.md`.
- **FIDO:** implementação independente com `minicbor` + RustCrypto
  (`p256`, `sha2`, `hmac`, `hkdf`, `aes-gcm`).
- **Validação de firmware / anti-rollback:** secure boot nativo do RP2350
  (ECDSA secp256k1 + hash da bootkey em OTP + versão de rollback na imagem).
- **Persistência:** escrita atômica com integridade (CRC-32), evoluindo para
  `sequential-storage` sobre `embedded-storage`.
- **Segredos:** nunca exportados; selados com chave derivada de OTP.
- **Identidade de placa / USB e provisionamento pós-flash:** o `DeviceManager`
  separa três entidades — `BoardIdentity` (fabricante, produto, placa, revisão,
  `vendor_id`/`product_id`), `BoardHardwareProfile` (LED, presença, flash) e
  `McuIdentity` (família, package, revisão, CHIPID). A imagem binária universal
  é única para todas as placas. Em estado de fábrica (`Factory`), aspectos como
  `product_string`, `vendor_id`, `product_id` e mapeamentos de GPIO podem ser
  provisionados pós-flash via Management HID (`aegistoken-host provision` ou
  Desktop Manager) sem recompilação. O firmware é a autoridade máxima sobre
  as capacidades (`GET_CAPABILITIES`), e o Manager adapta sua interface
  estritamente ao que o hardware expõe. Uma vez comissionado (`Active`), a
  identidade USB é selada contra adulterações não autorizadas. Ao comitar
  alterações na identidade USB (`COMMIT_CONFIGURATION`), o firmware executa
  soft-detach para re-enumeração com os novos descritores. No boot, o
  `DeviceManager` restaura a identidade provisionada persistida na flash,
  recaindo no padrão universal caso a flash esteja virgem. O número de série USB
  vem sempre da OTP do chip, não da placa.
- **Configuração de LED em runtime:** o `DeviceConfig` é aplicado ao hardware no
  boot e a cada `SET_CONFIGURATION` (pré-visualização) e
  `COMMIT_CONFIGURATION` (persistência). O GPIO do LED pode ser escolhido em
  runtime entre os pinos candidatos declarados pelo perfil da placa
  (`LedProfile::candidate_gpios`, expostos em
  `CapabilityReport.led_candidate_gpio_mask`); GPIO 0–5 (QSPI) nunca é
  candidato (assegurado em tempo de compilação). O pino é reivindicado por
  número via `AnyPin::steal`, justificado por existir um único dono por pino. A
  presença segue o perfil (`PresenceProfile`: BOOTSEL ou botão GPIO, com
  polaridade), assim como brilho, `enabled`, `behavior` e `active_low`. LEDs
   endereçáveis (WS2812/PWM) ainda não têm driver; brilho só é honrado onde a
   placa o declara.
- **Transporte dos applets (Fase 11):** PIV, OpenPGP e OATH são expostos por uma
  interface **USB CCID** (classe `0x0B`, ISO 7816-4/CCID rev 1.1), composta
  junto às HIDs existentes. `gpg`, OpenSC/`pkcs11-tool`, `pivy`,
  `yubico-piv-tool` e `ykman` falam com o dispositivo sem driver proprietário.
  Não há classe CCID pronta no `embassy-usb`: a classe é implementada no
  `board-generic-rp2350` e o enquadramento (APDU/CCID) fica testável em host.
- **Applets em crate próprio (Fase 11):** `aegis-applets` (`no_std`, `no_alloc`,
  testável em host) contém APDU, CCID (`PC_to_RDR_*`/`RDR_to_PC_*`), roteamento
  por AID e os applets PIV, OpenPGP e OATH; depende de `aegis-core` (traits,
  cripto, storage, selagem, presença) e nunca de HAL ou executor.
- **Cripto ECC primeiro (Fases 12–15):** P-256/ES256 já existe; entram Ed25519
  (EdDSA no CTAP2 para `ed25519-sk` e no OpenPGP) e P-384. RSA-2048/3072 fica
  isolado na Fase 16, com blinding obrigatório.
- **PINs e retries persistentes (Fase 11):** um framework único de PIN (retry
  counter, bloqueio, desbloqueio) é compartilhado por PIV (PIN/PUK), OpenPGP
  (PW1/PW3) e OATH (password opcional), persistido junto aos stores selados —
  o contador sobrevive a power cycle.
- **Chaves nunca exportáveis:** os applets geram chaves no dispositivo; não há
  importação de chave privada. Somente material público (certificados) pode ser
  importado e persistido.
- **Touch policy por operação:** assinatura, decifra e autenticação seguem a
  política configurada por slot/credencial (`touch required`), reusando
  `ContextualPresence` e o `PresenceAdapter` assíncrono do firmware.
- **Isolamento de caminhos:** o CCID nunca é alcançável a partir do caminho
  FIDO, e o Management HID segue separado; Recovery nega CCID assim como nega
  FIDO (exceto diagnóstico e update).
- **Storage por applet (Fase 11):** partições dedicadas no flash para chaves,
  DOs, certificados e credenciais OATH, com o mesmo registro atômico + CRC-32 e
  selagem AES-256-GCM derivada da OTP; `FlashLayout` ganha as regiões dos
  applets e o menor flash suportado (2 MiB) continua sendo o limite.

## Interfaces USB

O AegisToken implementa múltiplas interfaces USB HID, compostas em um único
dispositivo (composite) com funções independentes:

- **HID FIDO** (usage page `0xF1D0`): destinada exclusivamente à autenticação —
  CTAP1/U2F e CTAP2/FIDO2 (WebAuthn, passkeys).
- **HID Management** (vendor-defined `0xFF00`): gestão, configuração,
  diagnóstico e atualização de firmware.
- **HID OTP Lab** (vendor-defined `0xFF51`, só no perfil `yubikey5-lab`):
  diagnóstico experimental; não emite teclas nem manipula segredos.

**Invariantes**

- As interfaces devem permanecer **logicamente separadas**.
- Operações FIDO **nunca** dependem da interface Management ou OTP Lab.
- **Nenhuma interface de teclado é exposta.** O PRD previa uma HID Keyboard
  opcional, mas o produto decide não expô-la: uma interface de teclado ao
  lado de um autenticador FIDO reproduz a forma de um ataque *BadUSB*, e a
  separação lógica sozinha não basta. Se um dia existir, ela será opcional,
  desabilitada por padrão, governada pelo lifecycle e por User Presence, e
  nunca alcançável a partir do caminho de entrada FIDO.

**Estado:** HID FIDO, HID Management e HID OTP Lab implementadas (Fases 3 e
11). Nenhuma interface de teclado.

## Gates de verificação (todas as fases)

- `cargo fmt --all --check`
- `cargo clippy -p aegis-core --all-targets -- -D warnings`
- `cargo test -p aegis-core`
- `cargo clippy -p aegis-applets --all-targets -- -D warnings`
- `cargo test -p aegis-applets`
- `cargo clippy -p aegistoken-host --all-targets -- -D warnings`
- `cargo test -p aegistoken-host`
- `cargo build -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf --release`
- Geração de `rp2350-universal.uf2` via `scripts/build-uf2.ps1`

---

## Fase 0 — Fundação (concluída)

**Entregáveis**

- Workspace Cargo com os três crates e `default-members = ["crates/aegis-core"]`.
- `rust-toolchain.toml` fixando toolchain verificada e alvo
  `thumbv8m.main-none-eabihf`.
- Linker RP2350: `memory.x` + `build.rs` (sem `link-rp.x`, exclusivo do RP2040).
- `firmware-universal-rp2350`: binário `embassy-rp` mínimo (init + idle),
  capacidade de boot em RP2350A e artefato UF2.
- `scripts/build-uf2.ps1` e pipeline CI (`.github/workflows/ci.yml`).

**Critério de saída**

- Build de firmware para o alvo OK.
- `picotool info` reporta `target chip: RP2350`, `image type: ARM Secure`.
- `rp2350-universal.uf2` gerado.

---

## Fase 1 — Núcleo de domínio `aegis-core` (concluída)

**Entregáveis**

- `state.rs`: `ExecutionState` + tabela de transições, `boot_destination` e a
  regra `bootsel_allowed_as_presence` (somente `FidoWaitPresence`). PRD §17, §19.
- `lifecycle.rs`: `LifecycleState` + transições + `allows_config_change`. PRD §20.
- `capabilities.rs`: `DeviceCapabilities`, família/package e construtores
  `rp2350a/b`, `rp2354a/b`. PRD §9, §26.
- `configuration.rs`: `DeviceConfig` versionada em CBOR, validação
  (identidade/lifecycle/capability/faixa/consistência), registro com CRC-32 e
  `prepare_commit` (commit atômico). PRD §10, §11, §24, §27.
- `presence.rs`: controlador puro com debounce, detecção de borda, timeout,
  consume-once e anti-replay entre operações. PRD §16, §18.
- `error.rs`: taxonomia com códigos de wire estáveis. PRD §30.
- `traits.rs`: `Rp2350Hardware`, `Led`, `Storage`, `UserPresence` (object-safe).
  PRD §28.

**Critério de saída**

- 42 testes de host aprovados; `fmt` e `clippy -D warnings` limpos.

---

## Fase 2 — `board-generic-rp2350` (concluída)

**Entregáveis**

- Módulos de hardware: LED (`GPIO`), flash (QSPI, modo bloqueante), watchdog e
  presença (`Button`/`BootselButton`) encapsulados.
- Descoberta automática: `SYSINFO.CHIP_ID` (família/revisão) e
  `SYSINFO.PACKAGE_SEL` (QFN-60/QFN-80) combinados a um `BoardProfile` geram as
  `DeviceCapabilities` — sem seleção manual de placa.
- `aegis-core::discovery`: derivação de capabilities testável em host.
- `Board` implementa `Rp2350Hardware` e expõe `Led`/`Storage`/`UserPresence`.
- Firmware inicializa a placa, registra as capabilities descobertas e pisca o
  LED conforme `caps.led.available`, alimentando o watchdog.

**Requisitos/AC:** FR-001, FR-002, §7.1, §8, §28; base para AC-001.

**Critério de saída**

- Build de firmware para RP2350 (debug e release) com clippy limpo.
- 48 testes de host aprovados (inclui derivação de capabilities).
- `rp2350-universal.uf2` gerado.

**Limitação registrada**

- A leitura ao vivo do BOOTSEL no RP2350 exige assumir o pino de chip-select da
  QSPI a partir de uma rotina residente em RAM; o `embassy-rp` 0.10 só oferece
  esse helper para o RP2040. O adaptador existe, mas o leitor RP2350 fica para a
  Fase 6 (User Presence). O BOOTSEL continua governando o recovery no boot via
  bootrom.

---

## Fase 3 — USB e enumeração (concluída)

**Entregáveis**

- `aegis-core::ctaphid`: enquadramento CTAPHID (init/continuation, canais,
  INIT/PING/ERROR/WINK) e reassembler testável em host.
- `aegis-core::management`: enquadramento do Management HID (relatórios de 64
  bytes com header de 5 bytes) e reassembler testável.
- `board-generic-rp2350::usb`: dispositivo USB com duas funções HID —
  FIDO HID (usage page `0xF1D0`) e Management HID (vendor-defined `0xFF00`),
  ambas com relatórios de 64 bytes.
- Product String USB: `AegisToken FIDO2 USB Authenticator` (qualificador `USB`
  adicionado por direção de produto; PRD §2 original: `AegisToken FIDO2
  Authenticator`).
- Firmware: tarefa FIDO responde INIT/PING/WINK/ERROR e tarefa Management
  drena quadros; loop principal pisca LED e alimenta o watchdog.

**Requisitos/AC:** FR-006, FR-007, §12, §27; **AC-002, AC-003**.

**Critério de saída**

- Build de firmware para RP2350 com clippy limpo; 66 testes de host aprovados.
- `rp2350-universal.uf2` gerado.

**Pendência de verificação**

- A enumeração real das duas interfaces (AC-002/AC-003) ainda precisa ser
  confirmada em hardware/emulador USB; os descritores e o transporte estão
  implementados e compilando.

---

## Fase 4 — Protocolo Management HID (concluída)

**Entregáveis**

- `aegis-core::management_protocol`: `ManagementService` (autoridade sobre
  validação) e `ManagementCommand` com todas as operações:
  `GET_DEVICE_INFO`, `GET_CAPABILITIES`, `GET_CONFIGURATION`,
  `SET_CONFIGURATION`, `VALIDATE_CONFIGURATION`, `COMMIT_CONFIGURATION`,
  `GET_LIFECYCLE`, `COMMISSION_DEVICE`, `GET_STATUS`.
- Respostas CBOR precedidas de status; código de resposta = comando | `0x80`.
- Configuração: proposta → validação/staging → commit (persistência na Fase 5).
- Autorização: escrita só permitida quando o lifecycle permite
  (`Factory`/`Commissioning`/`Commissioned`); `COMMISSION_DEVICE` move
  `Factory` → `Commissioning`.
- Domínios isolados: nenhuma resposta expõe chave, credencial, seed, chave de
  atestação ou PIN. PRD §14, §25.

**Requisitos/AC:** FR-003..FR-005, §12–§14; **AC-004, AC-005, AC-006, AC-007,
AC-009**.

**Critério de saída**

- 80 testes de host aprovados (14 novos do protocolo), clippy limpo, build de
  firmware para RP2350 e `rp2350-universal.uf2` gerado.

**Pendência**

- Verificação em hardware das respostas às operações (AC-004..007, AC-009);
  a persistência efetiva da configuração chega na Fase 5.

---

## Fase 5 — Storage persistente e armazenamento seguro (concluída)

**Entregáveis**

- `aegis-core::storage`: `SlotStore` com dois slots alternados, número de
  sequência e CRC-32 por registro. O commit grava no slot inativo; uma escrita
  ou erase interrompido preserva o registro válido anterior.
- `ConfigStorage`: persistência da configuração com fallback automático.
- `SecretStorage`: persistência atômica de blob selado, sem API de exportação.
- `aegis-core::secret`: `AesGcmSealer` (AES-256-GCM) e `RootKeyProvider`.
- `board-generic-rp2350::otp`: leitura da chave mestra de 32 bytes a partir da
  OTP (linha `0x0E90`), falhando fechado quando não provisionada.
- Firmware: carrega a configuração persistida no boot (fallback para padrões de
  fábrica) e persiste a configuração no `COMMIT_CONFIGURATION`.

**Requisitos/AC:** FR-005, FR-011, §24, §25; **AC-008, AC-013**.

**Critério de saída**

- 94 testes de host aprovados (14 novos de storage/sealing), clippy limpo,
  build de firmware para RP2350 e `rp2350-universal.uf2` gerado.

**Pendências**

- Fusão (provisionamento) da chave mestra na OTP é etapa de produção com
  ferramental do vendor; o firmware apenas lê.
- AC-008 (persistência após power cycle) confirmado em lógica/host; validação
  física pendente.

---

## Fase 6 — User Presence contextual (concluída)

**Entregáveis**

- Leitor real de BOOTSEL no RP2350: rotina residente em RAM que libera o
  chip-select da QSPI, amostra `INFROM_PAD` e restaura o controle, executada em
  seção crítica (`board-generic-rp2350::presence`). Verificado no ELF: símbolo
  em `.data` (RAM, `0x20000039`).
- Abstração `Button` com `GpioButton` (botão externo) e `BootselButton`.
- `aegis-core::presence::ContextualPresence`: impõe a regra do §17 — presença só
  é armada/aceita em `FidoWaitPresence`; sair do estado desarma.
- Debounce, detecção de borda, timeout, consume-once e vínculo à operação já
  cobertos pelo controlador de presença.
- Firmware amostra o BOOTSEL no boot (log).

**Requisitos/AC:** FR-008, FR-009, §16–§18; **AC-010, AC-011, AC-012**.

**Critério de saída**

- 99 testes de host aprovados (5 novos contextuais), clippy limpo, build de
  firmware para RP2350 e `rp2350-universal.uf2` gerado.

**Pendências**

- AC-010 (BOOTSEL no boot) é atendido pelo bootrom, que entra no bootloader USB
  quando o botão é mantido; a Fase 6 apenas registra o estado.
- AC-011 completo depende do fluxo FIDO (Fase 7), que chamará
  `user_presence()` dentro de `FidoWaitPresence`.
- Validação elétrica/física do leitor BOOTSEL (o comportamento é fail-closed:
  leitura travada em qualquer nível não confirma presença).

---

## Fase 7 — FIDO (CTAP1/U2F + CTAP2)

Fase grande, dividida em fatias. Decisões fixadas: credenciais cifradas em
flash (seladas com a chave de OTP), atestação *packed self*, `clientPIN`
adiado.
### 7a — Núcleo do protocolo CTAP2 (concluída)

**Entregáveis**

- `aegis-core::ctap2`: códigos de comando e status CTAP2, `GetInfoResponse`
  (`versions`, `aaguid`, `options`, `maxMsgSize`), tipo COSE `Ec2PublicKey`
  (encode/decode) e parsing de requisições (`makeCredential`, `getAssertion`,
  `getInfo`, `reset`, etc.).
- Firmware: mensagens CTAPHID `CBOR` são roteadas para o handler CTAP2;
  `authenticatorGetInfo` responde; demais comandos retornam status CTAP2.
- Independência total do Management HID e do Desktop Manager.

**Critério de saída**

- 111 testes de host aprovados (12 novos), clippy limpo, build de firmware e
  `rp2350-universal.uf2` gerado.

### 7b — makeCredential / getAssertion (concluída)

**Entregáveis**

- `aegis-core::authenticator`: modelo de credencial, `CredentialStore` com
  implementação em memória, `make_credential` e `get_assertion`.
- P-256/ES256 (`p256` + `sha2`): geração de chave a partir do RNG, assinatura
  DER, montagem de `authData` e da chave pública COSE.
- Flags UP/UV (`up_confirmed` obrigatório; `uv` não suportado nesta fatia) e
  `excludeList`/`allowList`.
- Atestação *packed self* (alg ES256, assinatura pela chave da credencial).
- `board-generic-rp2350`: `rng::HardwareRng` (TRNG) e presença assíncrona
  (`presence::ButtonPresence::wait`, hoje via `PresenceAdapter::wait`).
- Firmware: `makeCredential`/`getAssertion` roteados com presença assíncrona
  (o perfil da placa decide se é BOOTSEL ou botão GPIO); `getInfo` já respondia.

**Critério de saída**

- 118 testes de host aprovados (7 novos), clippy limpo, build de firmware e
  `rp2350-universal.uf2` gerado. As assinaturas são verificadas com P-256.

**Pendências**

- Store de credenciais persistente e cifrado em flash: entregue na fatia 7c
  (`SealedCredentialStore`) e ligado ao firmware junto da persistência selada
  dos applets.
- `CTAPHID_KEEPALIVE` durante a espera de User Presence (a cada 100 ms no canal
  do pedido): entregue.
- Verificação em hardware com um cliente FIDO2 real.

### 7c — clientPIN / reset / credential management / store cifrado (concluída)

**Entregáveis**

- `aegis-core::credential_store`: `SealedCredentialStore` — banco de credenciais
  e estado de PIN serializados em CBOR, selados com AES-256-GCM sob a chave de
  OTP e persistidos atomicamente via `SecretStorage`, com nonce monotônico.
  `PinState` persistente e `CredentialStore` com `remove`.
- `aegis-core::pin`: PIN/UV auth protocol v1 — ECDH P-256, AES-256-CBC e
  HMAC-SHA-256, hash de PIN, contagem de tentativas, `getPINRetries`,
  `getKeyAgreement`, `setPIN` e `getPINToken`.
- `authenticatorReset` e `authenticatorCredentialManagement`
  (`getCredsMetadata`, `deleteCredential`).
- `getInfo` passa a anunciar `clientPin: true` e `pinProtocols: [1]`.
- Firmware: dispatch de `clientPIN`, `reset` e credential management.

**Critério de saída**

- 128 testes de host aprovados (10 novos de PIN/store), clippy limpo, build de
  firmware e `rp2350-universal.uf2` gerado.

**Pendências**

- ~~O firmware usa store em memória~~ **Entregue:** com a chave raiz
  provisionada, o firmware abre o `SealedCredentialStore` na região de applets
  (store `APPLET_STORE_COUNT`, dois slots de 4 KiB) e persiste credenciais/estado
  de PIN após power cycle; sem a chave, mantém o store volátil. O
  compartilhamento de flash usa o mesmo `RegionStorage` + mutex do CCID; store
  selado é a fonte de verdade quando disponível.
- Enumeração de credenciais (enumerateRPs/Credentials) e `changePIN` ficam para
  uma fatia incremental.

### 7d — CTAP1/U2F (concluída)

**Entregáveis**

- `aegis-core::u2f`: parsing de APDU estendido, palavras de status U2F e
  resposta `data || SW1 SW2`.
- `U2F_VERSION` (`U2F_V2`) e `U2F_AUTHENTICATE` nos modos check-only (P1=0x07)
  e sign (P1=0x03), este último exigindo User Presence e assinando
  `0x00 || appParam || UP || counter || challenge` com a chave da credencial.
- `authenticator::sign_message` compartilhado entre CTAP2 e U2F.
- Firmware: CTAPHID `MSG` roteado para o handler U2F; presença solicitada
  apenas no authenticate de assinatura; `getInfo` anuncia `U2F_V2`; CTAPHID
  passa a anunciar NMSG (capabilities `0x0D`).

**Critério de saída**

- 134 testes de host aprovados (6 novos de U2F, com verificação de assinatura),
  clippy limpo, build de firmware e `rp2350-universal.uf2` gerado.

**Pendência**

- `U2F_REGISTER` requer certificado de atestação (chave de atestação
  provisionada) e retorna `SW_INS_NOT_SUPPORTED`; fica para a fase de
  atestação/provisionamento.

### 7e — Credential management CTAP2.1 e `changePIN` (concluída)

**Entregue**

- `aegis-core::authenticator`: parsing de `authenticatorCredentialManagement`
  conforme a CTAP2.1 (`subCommand`, `subCommandParams`, `pinUvAuthProtocol`,
  `pinUvAuthParam`); `subCommandParams` é preservado byte a byte porque a
  plataforma o autentica. Layout legado (id do credential no topo) segue
  aceito.
- Subcomandos implementados: `getCredsMetadata` (0x01), `enumerateRPsBegin`
  (0x02) + `enumerateRPsGetNextRP` (0x03), `enumerateCredentialsBegin` (0x04) +
  `enumerateCredentialsGetNextCredential` (0x05) e `deleteCredential` (0x06).
  Respostas com as chaves da especificação (`rp` 0x03, `rpIDHash` 0x04,
  `totalRPs` 0x05, `user` 0x06, `credentialID` 0x07, `publicKey` 0x08,
  `totalCredentials` 0x09).
- `aegis-core::pin`: `changePIN` (0x04) — autentica `newPinEnc || pinHashEnc`
  com o segredo compartilhado, consome uma tentativa quando o PIN atual está
  errado, restaura o orçamento de tentativas e invalida o token no sucesso.
- Permissões de `pinUvAuthToken` (`mc` 0x01, `ga` 0x02, `cm` 0x04):
  `getPinUvAuthTokenUsingPinWithPermissions` (0x09) exige o bitfield, rejeita
  zero e permissões não suportadas (`UnauthorizedPermission` 0x40);
  `getPinToken` (0x05) concede `mc|ga` e rejeita `permissions`/`rpId`.
- **Correção de segurança:** todo subcomando de credential management (exceto
  `getCredsMetadata`) exige token com permissão `cm`; antes, `deleteCredential`
  não exigia autenticação alguma. Tokens do `getPinToken` legado também são
  aceitos (o PIN já foi provado) — **revisto na fatia 7g**: o token legado
  concede apenas `mc|ga` e nunca autoriza credential management.
- `getInfo` anuncia `pinUvAuthToken: true` e `credMgmt` apenas quando há PIN
  configurado (o token é obrigatório para enumerar).
- `setPIN`/`getPINToken` aceitam o `pinUvAuthParam` truncado em 16 bytes
  (forma da CTAP2.1) além dos 32 bytes completos.

**Verificação**

- 225 testes de host em `aegis-core` (14 novos: `changePIN` com PIN correto,
  errado, curto e sem PIN; permissões de token; parsing dos
  `subCommandParams`; listagem de RPs/credenciais; chaves das respostas),
  clippy limpo em host e alvo, build de firmware e UF2 gerados.

**Limitações registradas**

- O firmware anuncia `FIDO_2_0` (não `FIDO_2_1`): `makeCredential` com a opção
  `uv` não é exigida, e a mutação de *user information* (0x07) e o
  `largeBlobKey` (0x0B) não são implementados.
- ~~O par RP/credencial da plataforma é verificado pela permissão `cm` e, para
  tokens com `rpId` associado, apenas o escopo do RP é considerado.~~
  **Entregue na fatia 7g:** o token passa a ser escopado por operação e por
  RP (`enumerateRPsBegin` exige token sem vínculo; `deleteCredential` e
  `enumerateCredentialsBegin` ficam restritos ao RP vinculado).
- ~~`getCredsMetadata` (0x01) responde sem qualquer autenticação.~~
  **Entregue na fatia 7g:** todo subcomando de credential management exige
  token com a permissão `cm`; a ausência de `pinUvAuthParam` responde
  `PinRequired` (0x36).

### 7f — `getNextAssertion` e regra de User Verification (concluída)

**Entregue**

- `authenticatorGetNextAssertion` (0x08): a resposta de `getAssertion` passa a
  informar `numberOfCredentials` (0x05) e o firmware guarda os candidatos
  (credencial, RP e *client data hash*) para servir os demais, um por
  comando, como a CTAP2.1 determina. Sem estado anterior, o comando responde
  `NoCredentials`.
- `aegis-core::authenticator`: `assertion_candidates` (ordem da allow list;
  sem allow list, todas as credenciais residentes do RP) e `sign_assertion`
  (assinatura de uma credencial específica).
- **Correção de segurança e de conformidade:** o `pinUvAuthParam` inválido
  passou a ser rejeitado (`PinAuthInvalid` 0x33) em vez de ser ignorado
  silenciosamente, e, com PIN configurado, `makeCredential`/`getAssertion`
  exigem a prova do PIN (`PinRequired` 0x36) — como em um autenticador real.
  Sem PIN, o fluxo continua somente com User Presence.

**Aditivo (entregue junto das fatias 7g/7h)**

- `aegis-core::assertion` (`PendingAssertion`): o estado da asserção pendente
  passa a ser **vinculado ao canal CTAPHID** que iniciou o pedido — outra
  aplicação no mesmo host não consegue continuar uma asserção que não pediu —
  e só é criado quando a asserção produziu assinatura (4 testes de host; total
  da fatia: 228 → 232, antes dos +16 da 7g e dos +10 da 7h).

**Verificação**

- 228 testes de host em `aegis-core` (3 novos: ordem dos candidatos, contagem
  de credenciais e assinatura do próximo candidato), clippy limpo em host e
  alvo, build de firmware e UF2 gerados.
- `scripts/validate_fido.py --pin <PIN>` prova o PIN em todas as operações e
  exercita a rotação e a enumeração em hardware.

**Limitações registradas**

- Com PIN configurado, clientes que não provem o PIN recebem `PinRequired`:
  é o comportamento esperado, mas exige que o validador use `--pin`.

### 7g — Escopo e ciclo de vida do `pinUvAuthToken` (CTAP2.1) (concluída)

**Entregue**

- **Correção de segurança:** o token deixa de ser um segredo opaco. A
  verificação de HMAC, a **permissão exigida pela operação** e o **escopo de
  RP** passam a ser decididos em um único lugar —
  `aegis-core::pin::ClientPin::authorize` — com o resultado
  `Result<bool, Ctap2Status>`: `Ok(true)` (verificado), `Ok(false)` (sem
  token/parâmetro: a operação segue só com User Presence) e `Err` com o status
  CTAP2 correto (`PinAuthInvalid` 0x33, `PinRequired` 0x36).
- **Escopo de RP no primeiro uso** (§6.5.5.7): token emitido sem *permissions
  RP ID* é vinculado ao RP da **primeira** operação `mc`/`ga`; a partir daí,
  outro RP é recusado com 0x33. Token com `cm` e sem `rpId` permanece sem
  vínculo (opera no dispositivo inteiro) — token com `cm` e `rpId` é recusado
  em `getCredsMetadata`/`enumerateRPsBegin` (0x33).
- **Regra única para o token legado:** `getPinToken` (0x05) concede `mc|ga` e
  **nunca** autoriza credential management; a permissão `cm` explícita
  (0x09) é o caminho suportado.
- **Redução das permissões** (§6.5.5.7): após uma `makeCredential` ou
  `getAssertion` **bem-sucedida** que testou User Presence usando o token, o
  token fica **sem permissões** e sem vínculo de RP; qualquer uso posterior é
  recusado com 0x33. Operação que falhou (`NoCredentials`,
  `CredentialExcluded`, `UpRequired`) ou que não usou `pinUvAuthParam` mantém
  as permissões.
- **Ciclo de vida:** `changePIN` e `authenticatorReset` invalidam o token
  ativo (segredo, permissões e vínculo de RP); o `authenticatorReset` deixa
  de deixar o token sobreviver em RAM.
- `getCredsMetadata` (0x01) passa a exigir token com `cm`: sem
  `pinUvAuthParam` → `PinRequired` (0x36).
- `aegis-core::pin`: `TokenOperation`, `ManagementScope`, `TokenRequest`,
  `authorize`, `close_user_presence_operation` e `invalidate_token`. As
  primitivas dispersas (`verify_scoped_auth_param`,
  `allows_credential_management`, `verify_credential_management_param`,
  `allows_enumerate_rps`, `allows_enumerate_credentials`,
  `allows_delete_credential`) foram **substituídas** pela API única; o estado
  `legacy_token` saiu do `ClientPin` (as permissões concedidas passam a ser
  o estado real do token).
- `aegis-core::authenticator`: `delete_credential_scoped` resolve o RP da
  credencial alvo **no store** e autoriza a operação; `reset` invalida o
  token.

**Verificação**

- 258 testes de host em `aegis-core` (16 novos nesta fatia — 13 em `pin.rs`:
  emissão sem `rpId`, token legado, escopo por operação, escopo por RP,
  vínculo no primeiro uso, `cm` por subcomando, escopo de
  `enumerateCredentialsBegin`, redução de permissões, manutenção em operação
  com erro e invalidação por `changePIN`; e 3 em `authenticator.rs`:
  `deleteCredential` restrito ao RP, token sem vínculo de RP apaga qualquer
  credencial e invalidação pelo reset), clippy limpo em host e alvo, build de
  firmware gerado.
- Gate de hardware (`scripts/validate_fido.py --pin <PIN>`) **pendente**:
  não há RP2350 físico nesta sessão. O validador **já cobre** os casos
  negativos desta fatia (token legado em credential management → 0x33; token
  `cm` com `rpId` → `enumerateRPsBegin` recusado; token `mc` vinculado a
  `example.com` em `getAssertion` de outro RP → 0x33) e busca um **token novo
  por operação**, já que o token é consumido por uma operação com User
  Presence bem-sucedida (§6.5.5.7). Falta apenas a execução física.

**Limitações registradas**

- **Interoperabilidade CTAP2.0:** o token de `getPinToken` (0x05) não
  autoriza mais credential management. O comando de credential management
  (0x0A) é CTAP2.1 e o dispositivo anuncia `FIDO_2_0`, então o risco prático
  é baixo — mas é a mudança de comportamento mais visível desta fatia.
- **`getCredsMetadata` passou a exigir autenticação:** a contagem de
  credenciais residentes era informação sem autenticação. Clientes que não
  enviam `pinUvAuthParam` para 0x01 recebem 0x36 (o `python-fido2` sempre
  envia).
- **Sem expiração por tempo:** o *usage timer* (§6.5.2.1) continua não
  implementado; o token vive enquanto a sessão CTAPHID viver, desde que não
  seja usado numa operação com presença.
- **Redução só em caso de sucesso:** a CTAP2.1 não diz se a redução ocorre
  quando a operação com presença falha; reduzir só no sucesso evita punir
  retentativas legítimas da plataforma (ex.: `excludeList`).
- **Divergência documentada:** o token sem *permissions RP ID* é vinculado no
  primeiro uso, como manda a nota de §6.5.5.7, em vez de a emissão ser
  recusada — recusar quebraria plataformas que pedem `mc`/`ga` sem `rpId`.
- **O vínculo de RP é feito na autorização**, como o algoritmo da CTAP2.1
  (§6.1.2, passo 6: a associação do `rp.id` ao token acontece durante a
  operação). Uma operação que depois falha deixa o token vinculado àquele RP:
  a plataforma precisa de um token novo para operar em outro RP.
- **O *wiring* da redução de permissões** após operação com presença
  (`main.rs`: `close_user_presence_operation(uv, resultado.is_ok())`) é
  verificado apenas por build e inspeção — o teste de host cobre o auxiliar em
  `aegis-core::pin`, não a chamada no firmware. O gate de hardware continua
  pendente.

### 7h — Gating por destino de boot (`BootPlan`) (concluída)

**Entregue (mesmo conjunto de mudanças da fatia 7g)**

- `aegis-core::state::BootPlan`: política única do boot, derivada do destino
  (`aegis_core::state::boot_destination`). Só `Active` habilita FIDO e CCID;
  `Management` (diagnóstico e update) e a HID OTP de laboratório ficam
  disponíveis em todos os destinos; qualquer estado que não seja destino de
  boot produz o plano fechado.
- Firmware: as tarefas `fido_task`/`ccid_task` só arrancam quando o plano
  autoriza, e os stores selados (credenciais do FIDO e applets) só são abertos
  no caminho habilitado — o que fecha o invariante "Recovery nega FIDO/CCID e
  credenciais" (AGENTS.md), que antes valia só no domínio e não no *wiring*.

**Verificação**

- 258 testes de host em `aegis-core` (10 novos nesta fatia — 8 em
  `aegis-core::state`, 1 em `recovery.rs` e 1 em `management_protocol.rs`, os
  dois do relatório de diagnóstico), clippy limpo em host e alvo, build de
  firmware gerado.
- O relatório de diagnóstico (`GET_DIAGNOSTICS`) passou a expor o destino do
  boot e os caminhos servidos (`boot_destination`, `fido_enabled`,
  `ccid_enabled`), para que um dispositivo silenciado pelo plano possa ser
  distinguido de um dispositivo quebrado.
- A leitura do BOOTSEL no boot passou a exigir um nível estável (3 amostras,
  1 ms de intervalo): uma leitura instável é tratada como "solto" e
  registrada em log, para que um falso positivo não mute o produto.

**Limitações registradas**

- As interfaces FIDO/CCID **continuam enumerando** em `Recovery`/`Locked`: elas
  não respondem, mas o host ainda as vê. Suprimir a enumeração exige mudar a
  descritorização USB, o que fica para uma fatia própria.

### 7i — Contagem de credenciais conforme a CTAP 2.1 (concluída)

**Entregue**

- `numberOfCredentials` (chave CBOR 5) passou a ser um membro **opcional**:
  `aegis-core::authenticator::number_of_credentials(count, has_allow_list)`
  decide a presença conforme a CTAP 2.1 — presente só quando mais de uma
  credencial correspondeu e a requisição **não** trouxe `allowList`; ausente com
  `allowList`, com uma única correspondência e nas respostas de
  `authenticatorGetNextAssertion`. Antes, o firmware fixava `1` e emitia o
  membro onde a norma o proíbe.
- A lista de candidatos parou de truncar em silêncio: `assertion_candidates`
  devolve `Result` e responde `LimitExceeded` (0x15) quando o store tem mais
  credenciais correspondentes que o limite — a contagem não pode mais
  subnotificar os candidatos.

**Verificação**

- 261 testes de host em `aegis-core` (3 novos nesta fatia), clippy limpo em host
  e alvo, build de firmware gerado. Spec: `specs/ctap2-number-of-credentials.md`.

**Limitações registradas**

- Sem RP2350 físico, a enumeração com duas contas do mesmo RP continua
  pendente de validação em hardware.

## Fase 7 — requisitos

**Requisitos/AC:** FR-006, §15; **AC-013**.

---

## Fase 8 — Atualização segura de firmware (concluída)

**Entregáveis**

- `aegis-core::update`: formato de pacote (magic, versão de formato, contador de
  rollback, versão semântica, tamanho e SHA-256 da imagem e assinatura ECDSA
  ES256 sobre `SHA-256(header || image)`).
- `verify_package`: valida integridade, assinatura e anti-rollback.
- `UpdateSession`: recepção em blocos para uma região de staging separada da
  imagem em execução, com verificação de integridade e assinatura no `finish`;
  atualização interrompida não destrói o firmware instalado (fail-safe).
- Firmware: comandos de update no Management HID (`BEGIN`/`WRITE`/`FINISH`/
  `ABORT`, códigos `0x10`–`0x13`), fluxo separado do protocolo de configuração.

**Requisitos/AC:** FR-012, FR-013, §21–§23; **AC-014, AC-015**.

**Critério de saída**

- 142 testes de host aprovados (8 novos de update), clippy limpo, build de
  firmware e `rp2350-universal.uf2` gerado.

**Pendências**

- A execução de firmware inválido é impedida pelo secure boot nativo do RP2350
  (bootrom, secp256k1 + bootkey em OTP); o selo das imagens de produção com
  `picotool seal` e a fusão de OTP são etapas de produção.
- A troca atômica da partição de boot / reinício pós-update depende do
  esquema de partições e do bootrom; nesta fase a imagem é validada e deixada
  em staging.
- `VENDOR_PUBLIC_KEY` no firmware é um placeholder de desenvolvimento e deve ser
  substituído pela chave de release. **Endereçado por gate de build:** o
  `build.rs` falha quando `AEGIS_RELEASE=1` (usado por
  `scripts/build-uf2.ps1 -Release` e pelo job de release versionada do CI) e a
  chave embutida seria a de desenvolvimento — a política vive em
  `crates/aegis-build-support` (`specs/release-requires-vendor-key.md`).

---

## Fase 9 — Recovery e lifecycle completo (concluída)

**Entregáveis**

- `aegis-core::lifecycle::LifecycleManager`: fluxo completo
  `Factory → Commissioning → Commissioned → Provisioning → Provisioned →
  Active ↔ Suspended → Decommissioned → Factory`, com operações nomeadas e
  rejeição de ordem inválida.
- `aegis-core::recovery`: `RecoverySession` que permite firmware update,
  diagnóstico e recuperação de dispositivo, e **nega** FIDO, User Presence e
  acesso a credenciais/segredos (invariantes testados). `DiagnosticsReport`.
- `aegis-core::state::fido_allowed`: FIDO nunca é servido em Recovery/Locked.
- Management HID: `GET_DIAGNOSTICS` (`0x0A`), `DECOMMISSION_DEVICE` (`0x0B`) e
  `FACTORY_RESET` (`0x0C`); `COMMISSION_DEVICE` passa a usar o
  `LifecycleManager`.
- Firmware: registra o destino de boot (Active vs Recovery) via
  `boot_destination`.
- `aegis-core::state::BootPlan`: plano de boot derivado do destino
  (`Active`/`Recovery`/`Locked`) que diz, por caminho, o que o firmware pode
  servir (FIDO, CCID, Management, HID OTP de laboratório) e quais stores
  selados podem ser abertos. Falha fechada: só `Active` habilita FIDO/CCID.
- Firmware: o boot consulta o plano e **não inicia** as tarefas FIDO/CCID
  quando o caminho é negado; os pontos de abertura dos stores selados também
  são condicionados ao plano. Management (diagnóstico e firmware update)
  permanece em todos os destinos.

**Requisitos/AC:** FR-010, FR-014, §20–§22.

**Critério de saída**

- 154 testes de host aprovados (12 novos de lifecycle/recovery), clippy limpo,
  build de firmware e `rp2350-universal.uf2` gerado.

**Pendências**

- O firmware entra em Recovery pelo bootrom (BOOTSEL); a execução de
  `RecoverySession` on-device e a limpeza de credenciais no factory reset
  dependem do refactor de compartilhamento de storage.
- O *gating* por destino de boot está entregue: em `Recovery`/`Locked` o
  firmware não serve FIDO nem CCID e não abre stores selados. Permanecem
  pendentes a execução on-device da `RecoverySession`, a limpeza de
  credenciais no factory reset e a supressão da enumeração USB (hoje as
  interfaces FIDO/CCID continuam enumerando, mas não respondem).

---

## Fase 10 — Validação de hardware (harness entregue)

**Entregáveis**

- Autoteste on-target no boot (`src/selftest.rs`) com checks de capacidades,
  HID, TRNG, `getInfo`, resposta do Management HID e leitura de BOOTSEL;
  teste destrutivo do store selado sob a feature `selftest`.
- `scripts/validate_management.py`: valida AC-003..AC-009 pelo Management HID
  (descoberta por usage page `0xFF00`, reassembly de relatórios, CBOR).
- `scripts/validate_fido.py`: valida AC-002/AC-011/AC-013 via `python-fido2`
  (enumeração, getInfo, U2F VERSION, makeCredential/getAssertion com UP,
  clientPIN).
- `validation.md`: matriz AC-001..AC-015 com método e status.

**Critério de saída**

- **AC-001** a **AC-015** verificados em hardware.

**Pendência**

- **Validado em hardware RP2350A real:**
  - Management HID **12/12** (AC-003, AC-004, AC-005, AC-006, AC-007, AC-009);
    AC-001 confirmado (`gpio_count=30`).
  - FIDO HID **13/13** (AC-002, `getInfo`, U2F VERSION, AC-011
    `makeCredential` packed + `getAssertion` com BOOTSEL, `clientPIN`, AC-013).
- Bugs de transporte encontrados e corrigidos durante a validação: INIT no canal
  de broadcast; prefixo de status CTAP2; chaves de texto em entidades WebAuthn
  (rp/user/descriptor). Ver `validation.md`.
- Pendentes de bootrom/produção: AC-010, AC-014 e AC-015 (selo `picotool` +
  fusão de OTP); AC-008 aguarda ciclo físico de energia. Procedimento completo
  em **`production.md`**; a chave de update de release é gerada por
  **`scripts/gen-update-key.py`** e injetada via `AEGIS_UPDATE_VENDOR_PUBKEY`.

---

## Fase 11 — `aegis-applets`: APDU, CCID e roteamento (concluída)

**Entregáveis**

- Novo crate `aegis-applets` no workspace (`no_std`, `no_alloc`, host-testável):
  - `apdu`: ISO 7816-4 — casos 1–4, APDU curto e estendido, chaining (`61xx`/
    `6Cxx`), SW1/SW2 canônicos (`9000`, `6A82`, `6D00`, `6982`, `6985`, `63Cx`).
  - `ccid`: mensagens `PC_to_RDR_*`/`RDR_to_PC_*` (IccPowerOn, XfrBlock,
    GetSlotStatus, SetParameters, Escape), limites e reassembly testável.
  - `router`: seleção por AID (DF name), `SELECT` por AID/applet, resposta
    `6A82` para AID desconhecido, `6D00` para INS não suportada e `6E00` para
    CLAss inválida.
  - `pin`: framework de PIN/retry compartilhado (estado persistente selado,
    decremento em falha, bloqueio, unblock, `63Cx`), reusado por PIV/OpenPGP/
    OATH.
- `aegis-core::hardware_profile`/`FlashLayout`: regiões de storage dos applets
  (chaves, DOs, certificados, credenciais OATH) com layout padrão que caiba em
  2 MiB.
- `board-generic-rp2350::ccid`: classe USB CCID (bulk OUT/IN + notificação
  interrupt opcional), descritores da classe, slot/ICC status e leitura dos
  endpoints em `embassy-usb`.
- Firmware: quarta interface USB (CCID) composta às HIDs; tarefa que drena os
  bulk endpoints e entrega APDUs ao router, com presença assíncrona disponível
  para os applets.
- Enumeração verificada com OpenSC (`opensc-tool -l`, `pcsc_scan`).

**Requisitos/AC:** USB CCID rev 1.1, ISO 7816-4; **AC-016**.

**Critério de saída**

- Testes de host do codec APDU/CCID e do roteador; `opensc-tool -l` lista o
  dispositivo; `SELECT` de AID conhecido responde `9000` e desconhecido `6A82`;
  gates de `fmt`/`clippy`/testes e UF2 gerado.

**Entregue**

- Crate `aegis-applets` (`no_std`, `no_alloc`, host-testável) com `apdu`,
  `ccid`, `router`, `pin`, `card`, `aid` e `placeholder`, cobrindo APDU curto e
  estendido, chaining `61xx`/`GET RESPONSE`, enquadramento `PC_to_RDR_*`/
  `RDR_to_PC_*` com reassembly de pacotes bulk, roteamento por AID (prefixo),
  framework de PIN com retry persistente e `63Cx`/`6983`, e a máquina de estado
  de slot (power-on com ATR `3B 00`, `SetParameters` T=0, `XfrBlock`).
- `aegis-core::hardware_profile::FlashLayout` ganha a região de applets
  (192 KiB, 24 stores de dois slots) entre a configuração e o staging.
- `board-generic-rp2350::ccid`: classe USB CCID (descritor funcional de 54
  bytes, bulk OUT/IN, requisições de classe Abort/GetClockFrequencies/
  GetDataRates) sobre `embassy-usb`.
- Firmware: quarta interface USB composta; tarefa CCID que drena os endpoints,
  reassembla mensagens e despacha APDUs para o roteador com PIV, OpenPGP e OATH
  registrados como placeholders.
- `scripts/validate_ccid.py` (AC-016) e matriz de validação atualizada.

**Critério de saída — verificação**

- 74 testes de host novos em `aegis-applets` (258 no total com `aegis-core`),
  clippy limpo em host e no alvo embarcado, build de firmware e UF2 gerados.

**Pendências**

- **AC-016 em hardware:** a enumeração PC/SC real (`opensc-tool -l`,
  `validate_ccid.py`) ainda não foi executada em dispositivo físico; o
  transporte e o roteamento estão cobertos por testes de host.
- **APDU estendido no transporte:** o descritor anuncia
  `dwMaxCCIDMessageLength = 271` e exchange level *short APDU*; comandos
  estendidos (ex.: `PUT DATA` de certificados PIV > 255 B) serão habilitados na
  Fase 12, quando os applets persistirem DOs grandes.
- **Endpoint de notificação:** o CCID admite um interrupt IN opcional para
  mudanças de slot; não foi implementado (não exigido pelos stacks PC/SC
  usuais).
- **PIN persistente:** o framework está ligado ao armazenamento selado via
  `aegis-applets::sealed` (ver Persistência selada dos applets); contadores de
  PIN/PUK/PW sobrevivem a power cycle em dispositivo provisionado.
- **Placeholders:** removidos nas fases 12–14; PIV, OATH e OpenPGP (slice P-256)
  são applets reais registrados no roteador CCID.

---

## Fase 12 — PIV (concluída)

**Entregáveis**

- `aegis-applets::piv` (NIST SP 800-73-4, AID `A000000308000010000100`):
  - `SELECT`, `GET DATA`/`PUT DATA` (CHUID `5FC102`, CCC `5FC107`, certificado
    de autenticação `5FC105`, assinatura `5FC10A`, gestão `5FC10B`, histórico
    de chaves, `5FC109` etc.), `GET RESPONSE`.
  - `VERIFY` (PIN/PUK), `CHANGE REFERENCE DATA`, `RESET RETRY COUNTER` com
    contadores persistentes.
  - `GENERATE ASYMMETRIC KEY PAIR` (P-256 e P-384, geração on-device) e
    `AUTHENTICATE: GENERAL`/`SIGN` com assinatura ECDSA.
  - Management key: autenticação 3DES (padrão) e AES-128/192/256, modos
    simples e mútuo, com o protocolo verificável por ferramentas padrão.
  - Importação de certificados (público) por slot; chave privada nunca sai.
  - Touch policy por slot para `SIGN`/`AUTHENTICATE`, via presença contextual.
- Validação: `pivy`, OpenSC (`pkcs11-tool` com módulo PIV) e script Python
  próprio com `pyscard`; assinaturas verificadas fora do dispositivo.

**Requisitos/AC:** NIST SP 800-73-4/-78; extensões Yubico PIV; **AC-017**.

**Critério de saída**

- PIN/PUK com retries persistindo após power cycle; assinatura P-256 verificada
  por OpenSSL; `pkcs11-tool --test` limpo; testes de host do applet.

**Entregue**

- `aegis-applets::tlv`: leitor/escritor BER-TLV (`Iterator`, tags multi-byte,
  comprimentos longos), base dos três applets.
- `aegis-applets::piv`: applet completo com `PivStore` (persistência),
  `MemoryPivStore` (RAM), defaults de fábrica (PIN `123456`, PUK `12345678`,
  management key 3DES `0102..08`), provisionamento e recarga de estado a cada
  `SELECT`, políticas de PIN (`never`/`once`/`always`) e de touch
  (`never`/`always`/`cached`), e enforcement de administrador em
  `PUT DATA`/`GENERATE ASYMMETRIC KEY PAIR`.
- Cripto: ECDSA P-256/P-384 com assinatura sobre o *prehash* fornecido pelo
  host (padding à esquerda quando menor que a curva) e ponto público SEC1
  não comprimido em `7F49 { 86 }`; 3DES e AES em ECB de bloco único para o
  management key (validado contra traces reais do yubico-piv-tool).
- Presença compartilhada: `Applet::process` recebe o RNG; respostas
  `Sw::PRESENCE_REQUIRED` viram `Outcome::PresenceRequired` no `Card`, e o
  firmware resolve com `PresenceAdapter` sob mutex — FIDO e CCID dividem a
  mesma fonte física de presença e o mesmo TRNG (`Mutex` em `Board` e
  `DeviceManager`).
- Firmware: applet PIV registrado no roteador CCID (OpenPGP/OATH seguem como
  placeholders) com `MemoryPivStore`.
- `scripts/validate_piv.py` (AC-017): SELECT, GET DATA (CCC/CHUID), retries do
  PIN, autenticação mútua do management key (3DES), `GENERATE`/`SIGN` P-256 e
  verificação externa da assinatura com `cryptography`.

**Verificação**

- 98 testes de host em `aegis-applets` (24 novos de TLV/PIV), incluindo
  assinatura P-256 verificada com a crate `p256` e round-trip do management
  key 3DES; clippy limpo em host e no alvo embarcado, build de firmware e UF2.

**Pendências**

- **AC-017 em hardware:** a validação PC/SC real (`validate_piv.py`,
  `pivy`/`pkcs11-tool`) ainda não foi executada em dispositivo físico.
- **PIN/PUK persistentes no firmware:** entregue via `SealedPivStore`
  (ver Persistência selada dos applets); em placa sem chave raiz provisionada
  o firmware usa `MemoryPivStore` como antes.
- **RSA (Fase 16):** slots/`GENERATE` com algoritmos RSA respondem `6A81`.
- **Fora do escopo desta fase:** `9D`/ECDH, slots aposentados (`82`–`95`),
  `PUT DATA` de objetos não certificado já é aceito, mas `GET METADATA` e
  `SET PIN RETRIES` (extensões Yubico) respondem `6D00`;
  `pkilint`/metadata de touch policy dependem dessas extensões.
  `SET MANAGEMENT KEY` (`00 FF FF FF|FE`, TDES/AES) entregue para
  provisionamento com segurança total (ver `specs/piv-set-mgmt-key.md`).
- **Atestação PIV** (`AUTHENTICATE` com `9A`/`9E` para `INTERNAL AUTHENTICATE`)
  usa o mesmo caminho de assinatura, mas não há certificado de fábrica
  provisionado.

---

## Fase 13 — OATH (TOTP/HOTP) (concluída)

**Entregáveis**

- `aegis-applets::oath` (AID `A0000005272101`):
  - `PUT` (HOTP/TOTP, algoritmo SHA-1/256/512, 6/8 dígitos, período),
    `DELETE`, `LIST`, `CALCULATE`, `CALCULATE ALL`, `SEND REMAINING`,
    `SET CODE` e `VALIDATE` (opcionais), password com retries.
  - Cálculo TOTP/HOTP no dispositivo (truncation RFC 4226/6238); o host fornece
    o timestamp no challenge de 8 bytes — o dispositivo não tem RTC.
  - Segredos OATH selados com a chave da OTP e nunca devolvidos ao host
    (listagem expõe apenas nome/tipo/algoritmo/dígitos/período).
  - Touch policy por credencial (`touch required`) via presença contextual.
- Validação: vetores RFC 6238/4226 no host e script Python com `pyscard`;
  `ykman oath` quando o VID/PID permitir.

**Requisitos/AC:** protocolo OATH (Yubico), RFC 4226/6238; **AC-018**.

**Critério de saída**

- Códigos TOTP conferem com os vetores RFC; `CALCULATE` com touch negado
  retorna `6982`; segredos não aparecem em nenhuma resposta; testes de host.

**Entregue**

- `aegis-applets::oath` (`A0000005272101`) com `PUT`, `DELETE`, `LIST`,
  `CALCULATE`, `CALCULATE ALL`, `SET CODE`, `VALIDATE` e `RESET`; `SEND
  REMAINING` é tratado pelo roteador como continuação de resposta CCID.
- HOTP/TOTP com HMAC-SHA1/SHA-256/SHA-512, 6/7/8 dígitos, contador HOTP,
  período TOTP derivado do identificador (`30/issuer:account`), IMF, property
  `only increasing`/`touch required` e timestamp/moving factor fornecido pelo
  host.
- Access code OATH com desafio/resposta HMAC, estado serializado e
  `MemoryOathStore`; segredos nunca aparecem em `LIST`, `CALCULATE ALL` ou
  respostas de erro.
- Firmware: OATH real registrado no CCID; OpenPGP continua placeholder.
- 6 testes novos de ciclo de vida/access code/touch e vetores RFC 4226/6238,
  totalizando **104 testes** em `aegis-applets`.
- `scripts/validate_oath.py` (AC-018) com PC/SC, PUT/LIST/CALCULATE/DELETE e
  vetor RFC 6238.

**Pendências**

- **AC-018 em hardware:** validação com `validate_oath.py`, `ykman oath` e
  `pcscd`/`usbccid` ainda pendente.
- **Persistência selada:** entregue via `SealedOathStore`
  (ver Persistência selada dos applets); sem chave raiz o firmware usa
  `MemoryOathStore` como antes.
- O access code implementa o handshake OATH; PBKDF2/derivação de senha fica
  no host (`ykman` envia a chave derivada), e a extensão de rename fica para
  uma fase posterior.

---

## Fase 14 — OpenPGP card v3.4 (concluída: P-256 slice)

**Entregáveis**

- `aegis-applets::openpgp` (AID `D27600012401...`, versão 3.4):
  - `SELECT`, `GET DATA`/`PUT DATA` (AID, histórico, fingerprints, timestamp,
    key attributes `C1/C2/C3`, contador de assinatura, URL `5F50`, login data,
    PIN status `C4`), `ACTIVATE FILE`, `TERMINATE DF`.
  - `VERIFY`, `CHANGE REFERENCE DATA`, `RESET RETRY COUNTER` (PW1/PW3) com
    contadores persistentes; PUK/`unblock`.
  - `PSO: COMPUTE DIGITAL SIGNATURE` (SIG), `PSO: DECIPHER` (DEC, ECDH),
    `INTERNAL AUTHENTICATE` (AUT), `GENERATE ASYMMETRIC KEY PAIR`.
  - Chaves ECDSA/ECDH P-256 primeiro (um par por slot), key generation
    on-device; Ed25519/X25519 chegam na Fase 15 e RSA na Fase 16.
- Validação: `gpg --card-status`, `gpg --card-edit` (generate/set-url),
  assinatura (`gpg -u`), decifra (`gpg -d`) e SSH via `gpg-agent`
  (`enable-ssh-support`).

**Requisitos/AC:** OpenPGP card spec 3.4, CCID; **AC-019**.

**Critério de saída**

- `gpg --card-status` reconhece o cartão; assinatura e decifra P-256
  verificadas fora do dispositivo; contadores de PIN sobrevivem a power cycle.

**Entregue**

- `aegis-applets::openpgp` com AID OpenPGP v3.4, PW1/PW3, retry counters,
  `VERIFY`, `CHANGE REFERENCE DATA`, `RESET RETRY COUNTER`, `GET DATA`,
  `PUT DATA`, `SELECT DATA`, `ACTIVATE FILE` e estado serializado via
  `MemoryOpenPgpStore`.
- Application Related Data (`6E`) com AID, histórico, extended length,
  algorithm attributes `C1/C2/C3` para ECDSA/ECDH P-256, PW status `C4`,
  fingerprints/key-info e security support template `7A/93`.
- P-256 key generation (`GENERATE ASYMMETRIC KEY PAIR`), ECDSA
  `PSO:COMPUTE DIGITAL SIGNATURE`, P-256 `INTERNAL AUTHENTICATE` e raw P-256
  ECDH em `PSO:DECIPHER`; assinatura e shared secret são verificados em host.
- Firmware: OpenPGP real registrado no CCID junto de PIV/OATH.
- `scripts/validate_openpgp.py` (AC-019) com PC/SC, PW1/PW3, C1/C4,
  keygen e assinatura P-256 verificada por `cryptography`.
- 7 testes novos de OpenPGP; `aegis-applets` totaliza **111 testes**.

**Pendências**

- **AC-019 em hardware:** `validate_openpgp.py`, `gpg --card-status` e
  `gpg --card-edit` ainda não foram executados em um dispositivo físico.
- **Persistência selada:** entregue via `SealedOpenPgpStore`
  (ver Persistência selada dos applets); sem chave raiz o firmware usa
  `MemoryOpenPgpStore` como antes.
- **Interoperabilidade futura:** GnuPG/OpenSC podem exigir o aggregate DO
  exato, certificados `7F21`, `GET NEXT DATA`, command chaining e key
  fingerprints RFC 4880; estes campos têm suporte estrutural, mas ainda
  precisam de validação externa.
- **Cripto fora desta slice:** RSA, Ed25519/EdDSA e X25519/KDF OpenPGP ficam
  para as Fases 15–16.
- **ECDH OpenPGP (S1 e S2 entregues, interop pendente):** o applet **não devolve
  mais o shared secret** ao host. As primitivas da RFC 6637 (KDF de concatenação
  NIST SP 800-56A com SHA-256, AES Key Wrap da RFC 3394 e o bloco de
  parâmetros do §8) estão em `aegis-applets::ecdh`, com os vetores da RFC
  3394 e um vetor de referência da KDF. Na etapa S2 o cartão executa o fluxo
  completo: `S = r·V` → KEK → desembrulho da chave de sessão → decifra dos
  dados com a camada simétrica do OpenPGP (`aegis-applets::pgp_sym`, CFB da
  RFC 4880 §13.9 com *resync*, *quick check* e MDC), validada contra uma
  implementação de referência independente. O material importado é cifrado
  (`PUT DATA 0xD2`, formato **provisório**); a chave privada do slot nunca é
  importada. **Pendente:** alinhar o *key import* ao OpenPGP Card 3.4 e
  validar `gpg -d` em hardware. Spec: `specs/openpgp-rfc6637-ecdh.md`.

## Persistência selada dos applets (entregue)

- `aegis-applets::sealed`: `SealedCell` (um registro selado por shard),
  `SealedPivStore` (mapa de metadados + 1 shard por objeto), `SealedBlob`
  (blob fragmentado em N shards + shard de commit) e os adaptadores
  `SealedOathStore` (2+1 shards) / `SealedOpenPgpStore` (4+1 shards),
  implementando `PivStore`/`OathStore`/`OpenPgpStore` sem mudar os applets.
- `aegis-core::credential_store::SealedCredentialStore` usa o mesmo esquema
  (blob CBOR de credenciais + estado de PIN selado com nonce monotônico) no
  store `19` da região de applets, aberto pela tarefa FIDO quando a chave raiz
  está provisionada.
- Formato por shard: `[nonce:12][gen:u64][body][tag:16]`, nonce =
  `gen || applet || shard`; geração sempre `max(observado)+1`, lida do flash a
  cada escrita — nonce nunca reutilizado, mesmo após escrita interrompida.
- Saves multi-shard compartilham uma geração e gravam o commit por último;
  loads aceitam a geração mais nova presente em *todos* os shards, com fallback
  para a anterior — escrita interrompida recupera a geração completa anterior.
- Flash: 19 two-slot stores de 8 KiB na região de applets (`0..18`: meta PIV,
  10 objetos PIV, OATH 2+commit, OpenPGP 4+commit); o store `19` guarda o banco
  de credenciais/PIN do FIDO selado; 4 stores livres. Limite garantido em build
  por `const assert` contra `FlashLayout`.
- Compartilhamento: `Board.storage` atrás de `CriticalSectionMutex<RefCell<…>>`;
  housekeeping, CCID e FIDO usam `RegionStorage` (janela com base) com lock por
  chamada; cada região tem um único escritor.
- Sem chave raiz provisionada (placa de desenvolvimento), o firmware usa os
  stores em memória como antes; com a chave, abre os selados e registra em log.
  Falha de autenticação no `open` falha fechado (log + fallback), nunca
  exporta segredo.
- Limitações registradas: rollback de flash para o slot anterior é inerente ao
  esquema two-slot (igual ao `SealedCredentialStore`); sem contadores
  monotônicos em OTP. Tombstones tornam `erase` atômico.

---

## Fase 15 — SSH/Git signing e Ed25519 no CTAP2 (concluída: firmware; hardware pendente)

**Entregáveis**

- CTAP2: EdDSA (COSE alg `-8`) além de ES256 — `makeCredential`/`getAssertion`
  com chaves Ed25519 conforme o algoritmo pedido pelo RP, atestação
  correspondente e `getInfo` atualizado.
- Fluxo completo com OpenSSH: `ssh-keygen -t ed25519-sk` (residente e
  não-residente), `ssh -i`, `ssh-agent` e `ssh-keygen -Y sign` para assinatura
  de commits/tags do Git (`gpg.format = ssh`).
- OpenPGP: Ed25519 (EdDSA) e X25519 (ECDH) para os slots SIG/DEC/AUT.
- `docs/`: guia de uso para SSH/Git (Linux, macOS e Windows).

**Requisitos/AC:** CTAP2.0/2.1 (EdDSA), OpenSSH FIDO; **AC-020**.

**Critério de saída**

- `ssh-keygen -t ed25519-sk` registra credencial; login e assinatura Git
  funcionam com `ssh-agent`; `git log --show-signature` valida o commit;
  regressão CTAP2/ES256 mantida.

**Entregue (firmware + host)**

- CTAP2: `pubKeyCredParams` passa a ser interpretado (ordens do cliente
  respeitadas); EdDSA (`-8`) com chaves Ed25519 geradas no dispositivo,
  asserções de 64 bytes e atestação `packed` correspondente. Sem `-8`/`-7`
  na lista, o autenticador responde `UnsupportedAlgorithm` (`0x26`).
- Credenciais ganham o algoritmo COSE persistido (mapa CBOR estendido com
  chave `6`; registros antigos sem a chave decodificam como ES256).
  U2F/CTAP1 ignora credenciais EdDSA (só define ES256).
- OpenPGP: slots com algoritmo próprio (`PUT DATA C1/C2/C3` com PIN de
  admin; ECDSA/ECDH P-256, Ed25519, X25519; trocar o algoritmo apaga a
  chave), `GENERATE`/`PSO`/`INTERNAL AUTHENTICATE` por algoritmo, assinaturas
  ECDSA em `r||s` bruto (formato que o GnuPG espera), fingerprints RFC 4880
  (`C5`/`C7`–`C9`) e migração de estado v1→v2.
- `docs/ssh-git.md`: guia `ed25519-sk`/`ecdsa-sk`, residente/não-residente,
  `ssh-agent`, assinatura Git via `gpg.format ssh` e alternativa OpenPGP.
- Validadores estendidos: `validate_fido.py` (AC-020 make/assert Ed25519) e
  `validate_openpgp.py` (atributos Ed25519/X25519, assinatura e ECDH
  verificados com `cryptography`).
- Testes de host: 193 `aegis-core` + 128 `aegis-applets`, incluindo
  negociação de algoritmos, assinatura/verificação Ed25519 e ECDH X25519
  fim a fim (via dalek) e regressão ES256/U2F; clippy limpo, build de
  firmware e UF2 gerados.

**Pendências**

- Suporte de RP a EdDSA (muitos provedores ainda usam ES256);
  `ed25519-sk` exige resident key opcional, já suportada pelo store atual.
- **AC-020 em hardware:** fluxos `ssh-keygen`/`ssh-agent`/Git e
  `gpg --card-status` com chaves Ed25519/X25519 ainda não foram executados
  em dispositivo físico.

---

## Fase 16 — RSA para PIV/OpenPGP (em andamento: 16a–16d entregues em firmware; hardware pendente)

**Entregue (firmware + host)**

- 16a — `aegis-applets::rsa`: RSA-2048 sobre `crypto-bigint` (`U1024`/`U2048`,
  Montgomery `FixedMontyForm`, sem `alloc`, sem `unsafe`): geração de primos
  (trial division + Miller-Rabin 12 rounds), EMSA-PKCS1-v1_5 (SHA-256 e
  `DigestInfo` genérico), operação privada com CRT (Garner) + blinding
  multiplicativo, verificação pós-assinatura (fault guard), unpad type-2 em
  passe único. `rsa` crate avaliado e descartado (exige `alloc`).
- 16b — PIV: `GENERATE` com `ALG_RSA_2048` (resposta `7F49 { 81 n, 82 e }`),
  `SIGN`/`AUTHENTICATE` (9A/9C/9E) como operação privada crua sobre bloco de
  256 B (entradas curtas com left-pad, como o prehash ECC); presença adiada
  recebe RNG (`Applet::confirm_presence` passa a tomar `rng`, com
  `Card`/`Router`/firmware atualizados). Registro de 1162 B, dentro do limite
  de 1536 B do `SealedPivStore` sem mudanças.
- 16c — OpenPGP: atributos `C1`–`C3` RSA (`01 || 0800 || 0020`, forma de 6
  bytes com import-format aceita e ignorada), `GENERATE`/`READ PUBLIC`
  (`7F49 { 81, 82 }`), `PSO:CDS` dual (bloco EM de 256 B ou `DigestInfo` com
  EMSA on-card), `INTERNAL AUTHENTICATE` cru (desafios SSH nunca reinterpretados),
  `PSO:DECIPHER` cru (`00|02`-prefixo, bloco nu ou MPI; GnuPG remove o padding),
  fingerprint RFC 4880 com `MPI(n)+MPI(e)`, estado v3 (slots de 1156 B, migração
  v1/v2, 7325 B < 8192 B e < 9072 B do blob selado).
- Validadores estendidos: `validate_openpgp.py` (AC-021: attrs, keygen,
  assinatura verificada por `cryptography`, decifra, fingerprint) com
  `find_tlv` corrigido (tags de 2 bytes, comprimentos longos) e APDUs
  estendidas.
- 16d — `validate_piv.py` com RSA (paridade AC-021, host-only): re-`VERIFY`
  explícito antes do RSA, `GENERATE`+`SIGN` nos dois slots (9A + 9C),
  check cru `s^e mod n` por slot e round-trip `DigestInfo`/EMSA-PKCS1-v1_5
  verificado com `cryptography` (mesmo padrão do OpenPGP); EM DigestInfo
  validado off-card (`DigestInfo EM round-trip OK`).
- RSA-3072 e PSS: adiados com o produto funcional em ECC+RSA-2048
  (exigiriam tipos `U1536`/`U3072`, estouro do registro PIV de 1536 B,
  rebalance do estado OpenPGP e revisão de watchdog; ver `rsa.rs`).
- Testes de host: 147 `aegis-applets` (inclui round-trip contra `public_op`,
  equivalência CRT vs potência cheia, determinismo sob blinding, vetores
  didáticos `n=3233`, rejeição de paddings/atributos); clippy limpo, build de
  firmware e UF2.

**Pendências**

- **AC-021 em hardware:** `validate_openpgp.py`, `gpg --card-edit`/`pkcs11-tool`
  com chaves RSA-2048 ainda não executados em dispositivo físico (Fase 17).
- Suposições de interop a confirmar em hardware: GnuPG remove o padding da
  resposta do `DECIPHER`; `PSO:CDS` aceita bloco EM e `DigestInfo`.

**Entregáveis**

- RSA-2048/3072 on-device para PIV (`ALG_RSA_2048`) e OpenPGP (`rsa2048`,
  `rsa3072`): geração de chave, CRT, PKCS#1 v1.5 e PSS opcional, decifra e
  assinatura.
- Modexp com Montgomery e **blinding obrigatório**; sem dependência de
  alocação dinâmica e com verificação de tempos quando possível.
- Avaliação/adoção de crate `no_std` (`rsa`/`crypto-bigint`); se não atender,
  implementação própria com vetores de teste.
- Validação: OpenSSL, PKCS#11 (PIV) e GPG (OpenPGP) com chaves RSA.

**Requisitos/AC:** PKCS#1 v1.5, RFC 8017; NIST SP 800-73-4; **AC-021**.

**Critério de saída**

- Assinatura RSA-2048 verificada por OpenSSL/GPG; decifra RSA-2048 funciona;
  nenhum caminho de chave privada exporta material; testes de host com vetores.

**Riscos**

- Fase isolada e opcional: é o maior risco do projeto (tempo, tamanho de
  código e canal lateral). O produto permanece funcional apenas com ECC se a
  fase for adiada.

---

## Fase 17 — Conformidade e validação dos applets (em andamento: firmware; hardware pendente)

**Entregue (firmware + host)**

- `validation.md`: matriz **AC-016..AC-021** com método, evidência e
  limitações; seção de evidência dos applets em host e procedimento AC-021
  para hardware (mais interop `pivy`/OpenSC/GnuPG).
- `scripts/`: `validate_piv.py` com seção AC-021 (GENERATE 9A + SIGN +
  `s^e mod n` em Python puro) e APDUs estendidas; `validate_openpgp.py` com
  AC-021 (fase 16c); `validate_ccid.py` com docstring atualizada (applets
  reais) e check de INS corrigido (`00 01`, já que `CB` é suportado pelo PIV);
  `find_tlv` do OpenPGP corrigido (tags de 2 bytes, comprimentos longos).
- Autoteste on-target estendido: `applet-select` no boot (SELECT PIV/OpenPGP/
  OATH por AID, AID desconhecido `6A82`, CCC padrão do PIV e `C1` do OpenPGP
  via `Router`, log via RTT; sem keygen — RSA on-device fica nos validadores).
- `docs/`: `README` (RSA entregue, scripts AC-021, matriz AC-001..AC-021),
  `architecture.md` (primitivas RSA), `security-model.md` (disciplina
  constant-time atualizada + canais residuais), `production.md`
  (provisionamento de PINs/DOs/certificados e management key fixa),
  `development.md` (inventário dos validadores PC/SC).
- Regressão completa: gates de `fmt`/`clippy`/testes e build de
  firmware/UF2 verdes (147 `aegis-applets`, 193 `aegis-core`, 5 host).

**Pendência (exige hardware RP2350 real)**

- AC-016..AC-021 em dispositivo físico (`opensc-tool -l`, `validate_ccid/
  piv/oath/openpgp.py`, `pivy`/`pkcs11-tool`, `gpg --card-edit`, OpenSSH);
  suposições de interop a confirmar: padding do `DECIPHER` no GnuPG e formas
  de entrada do `PSO:CDS`; tempo de keygen RSA no alvo vs watchdog da
  tarefa CCID.

**Entregáveis**

- `validation.md`: novos critérios **AC-016..AC-021** (CCID, PIV, OATH,
  OpenPGP, SSH/Git, RSA) com método, evidência e limitações.
- `scripts/`: validadores Python por applet (`validate_piv.py`,
  `validate_oath.py`, `validate_openpgp.py`) e regressão CTAP2 existente
  mantida; vetores RFC 6238/4226 e NIST para PIV.
- Autoteste on-target estendido: enumeração CCID, `SELECT` por AID e sanidade
  dos applets no boot (log via RTT).
- `docs/`: atualização de `architecture.md`, `security-model.md`,
  `development.md` e `production.md` (provisionamento de PINs/DOs e
  certificados) e README (interfaces USB e capacidades).
- Regressão completa: gates de `fmt`/`clippy`/testes e build de firmware/UF2.

**Critério de saída**

- AC-016..AC-021 verificados em hardware RP2350 real (ou limitações registradas
  com evidência), suíte de host e de scripts verde, documentação atualizada.

---

## Fase 18 — Ferramental de host, Desktop Manager e pesquisa de bibliotecas (Python/Rust)

**Objetivo**

Mapear, avaliar e integrar bibliotecas maduras nos ecossistemas Python e Rust
licenciadas sob **MIT OR Apache-2.0** (ou permissivas compatíveis), eliminando
dependências LGPL (como `pyscard`) dos validadores, expandindo o ferramental de
linha de comando (`aegistoken-host`) e estruturando a base tecnológica do futuro
**Desktop Manager**.

**Entregue (pesquisa, especificações e primeiras etapas de código)**

- `docs/pesquisa-bibliotecas.md`: levantamento comparativo de crates Rust e
  pacotes Python maduros categorizados por camada técnica.
- `docs/plano-desenvolvimento.md`: plano de desenvolvimento estruturado em 4 eixos
  com matriz de rastreabilidade de bibliotecas adotadas.
- **Etapa 1.1 entregue:** `scripts/pcsc_transport.py` implementado via `ctypes`
  puro (`winscard.dll`/`libpcsclite`), eliminando dependência do `pyscard` (LGPL)
  nos validadores de hardware (`validate_ccid.py`, `validate_piv.py`,
  `validate_oath.py`, `validate_openpgp.py`). Testes em `tests/test_pcsc_transport.py`.
- **Etapa 2.1 entregue:** Crate `pcsc` integrado ao `aegistoken-host` com novo
  módulo `crates/aegistoken-host/src/card.rs` e subcomandos `card-list`,
  `card-status`, `card-select` e `card-apdu`.
- **Etapa 2.2 entregue:** Crate `iso7816` integrado para decodificação tipada de
  comandos APDU (`CommandView`) e formatação amigável de status words (`iso7816::Status`).
- **Etapa 2.3 entregue:** Gestão de certificados PIV e chaves públicas integrada ao
  `aegistoken-host` via `x509-cert` e `der` (RustCrypto). Módulo `piv_cmd.rs` com
  comandos `piv-list` (inspeção X.509 detalhada dos slots 9A, 9C, 9D, 9E), `piv-import-cert`
  (importação PEM/DER com autenticação de chave de gestão) e `piv-set-mgmt-key`
  (troca de Management Key 3DES/AES). 15 testes unitários aprovados no host CLI.

**Pendências e próximos passos**

- **Etapa 2.4 entregue:** subcomando OATH/TOTP no CLI (`oath list|code|add|delete|reset`
  em `crates/aegistoken-host/src/oath_cmd.rs`, com parsing de `otpauth://` e testes de
  host).
- **Etapa 2.5:** Avaliação do `nusb`.
- **Eixo 3:** Protótipo do Desktop Manager em Rust (`tauri` v2).

**Critério de saída**

- Documentação e pesquisa de bibliotecas concluídas; ferramental de host
  100% aderente à política de licenciamento duplo permissivo `MIT OR Apache-2.0`;
  zero dependências com restrições copyleft distribuídas.

---

## Riscos e observações

- `embassy-rp` ainda é pré-1.0; a construção isola a HAL em
  `board-generic-rp2350` para conter quebras.
- Secure boot exige fusão permanente de OTP; builds de desenvolvimento
  permanecem não assinados até o provisionamento.
- RP2354A/B (flash empilhado de 2 MiB) agora são um alvo de build selecionável
  (`rp2354a`/`rp2354b`); a família do MCU é escolhida pelo alvo do chip
  (`MCU_FAMILY`) e não pelo perfil da placa. A validação física do flash
  empilhado permanece pendente.
- **CCID:** não há classe CCID no `embassy-usb` 0.6; a classe é implementada no
  projeto e precisa de validação PC/SC real em Windows (driver `usbccid` inbox)
  e Linux (`ccid`/`pcsc-lite`), incluindo tempos de resposta e chaining de
  APDU.
- **RSA (Fase 16):** maior risco do projeto (tempo de CPU, tamanho de código e
  canal lateral); mantida isolada e opcional, com o produto funcional em ECC.
- **Orçamento de flash:** as regiões dos applets (chaves, certificados, DOs,
  credenciais OATH) precisam caber em 2 MiB junto ao firmware, aos dois slots
  de configuração e à região de staging.
- **Ferramental de validação:** `ykman` restringe alguns comandos a VID/PID
  Yubico; a validação primária usa OpenSC/`pyscard`, com as ferramentas padrão
  como complemento.
- **Compatibilidade Yubico:** o requisito é protocolar — FIDO HID, OATH/YKOATH
  e PIV sobre CCID — e não uma imitação permanente da identidade comercial da
  Yubico. A matriz YUB-001..YUB-010 está em
  `docs/yubico-compatibility.md`; a validação física com Yubico Authenticator e
  `ykman` permanece pendente até registrar versões de ferramenta e resultados.
- **TOTP sem RTC:** o dispositivo não mantém relógio; o timestamp vem do host
  no `CALCULATE`, como nos tokens OATH padrão.
