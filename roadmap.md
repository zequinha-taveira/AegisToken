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
| 7 | FIDO (CTAP1/U2F + CTAP2) | Concluída (7a–7d) |
| 8 | Atualização segura de firmware | Concluída |
| 9 | Recovery + lifecycle completo | Concluída |
| 10 | Validação de hardware (AC-001..AC-015) | Concluída (bootrom/OTP pendentes) |

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
- **FIDO:** implementação independente com `minicbor` + RustCrypto
  (`p256`, `sha2`, `hmac`, `hkdf`, `aes-gcm`).
- **Validação de firmware / anti-rollback:** secure boot nativo do RP2350
  (ECDSA secp256k1 + hash da bootkey em OTP + versão de rollback na imagem).
- **Persistência:** escrita atômica com integridade (CRC-32), evoluindo para
  `sequential-storage` sobre `embedded-storage`.
- **Segredos:** nunca exportados; selados com chave derivada de OTP.

## Interfaces USB

O AegisToken implementa múltiplas interfaces USB HID, compostas em um único
dispositivo (composite) com funções independentes:

- **HID FIDO** (usage page `0xF1D0`): destinada exclusivamente à autenticação —
  CTAP1/U2F e CTAP2/FIDO2 (WebAuthn, passkeys).
- **HID Keyboard** (HID Keyboard convencional): permite ao firmware emitir
  eventos de teclado ao host quando uma funcionalidade específica do produto
  solicitar.
- **HID Management** (vendor-defined `0xFF00`): gestão, configuração,
  diagnóstico e atualização de firmware.

**Invariantes**

- As interfaces devem permanecer **logicamente separadas**.
- Operações FIDO **nunca** dependem da interface Keyboard nem da Management.
- A interface HID Keyboard é **opcional e desabilitada por padrão**; sua
  habilitação é governada pelo lifecycle e por User Presence e nunca é
  alcançável a partir do caminho de entrada FIDO. (Uma interface de teclado ao
  lado de um autenticador FIDO reproduz a forma de um ataque *BadUSB*; a
  separação lógica sozinha não basta.)

**Estado:** HID FIDO e HID Management implementadas na Fase 3. HID Keyboard
planejada (ainda não implementada).

## Gates de verificação (todas as fases)

- `cargo fmt --all --check`
- `cargo clippy -p aegis-core --all-targets -- -D warnings`
- `cargo test -p aegis-core`
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
- `board-generic-rp2350`: `rng::HardwareRng` (TRNG) e `presence::await_bootsel`
  assíncrono.
- Firmware: `makeCredential`/`getAssertion` roteados com presença BOOTSEL;
  `getInfo` já respondia.

**Critério de saída**

- 118 testes de host aprovados (7 novos), clippy limpo, build de firmware e
  `rp2350-universal.uf2` gerado. As assinaturas são verificadas com P-256.

**Pendências**

- Store de credenciais persistente e cifrado em flash (fatia 7c); hoje o
  firmware usa store em memória (volátil).
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

- O firmware usa store em memória: o `SealedCredentialStore` exige posse do
  `Storage`, que hoje pertence ao `Board` (compartilhado com o Management HID).
  Ligar o store selado on-device requer um refactor de compartilhamento de
  storage (tarefa ou mutex de flash).
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
  substituído pela chave de release.

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

**Requisitos/AC:** FR-010, FR-014, §20–§22.

**Critério de saída**

- 154 testes de host aprovados (12 novos de lifecycle/recovery), clippy limpo,
  build de firmware e `rp2350-universal.uf2` gerado.

**Pendências**

- O firmware entra em Recovery pelo bootrom (BOOTSEL); a execução de
  `RecoverySession` on-device e a limpeza de credenciais no factory reset
  dependem do refactor de compartilhamento de storage.

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

## Riscos e observações

- `embassy-rp` ainda é pré-1.0; a construção isola a HAL em
  `board-generic-rp2350` para conter quebras.
- Secure boot exige fusão permanente de OTP; builds de desenvolvimento
  permanecem não assinados até o provisionamento.
- RP2354A/B (flash empilhado de 2 MiB) agora são um alvo de build selecionável
  (`rp2354a`/`rp2354b`, ver `BoardProfile::GENERIC_RP2354`); a validação física
  do flash empilhado permanece pendente.
