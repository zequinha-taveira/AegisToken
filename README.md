# AegisToken — Universal RP2350 Firmware

Firmware universal para a família **RP2350** que implementa um autenticador
**FIDO2/WebAuthn (CTAP2)** e **CTAP1/U2F** com uma interface de gestão
proprietária, sobre um único dispositivo USB composto. O mesmo binário roda em
RP2350A/B (flash QSPI externa) e RP2354A/B (2 MiB de flash no encapsulamento),
com **descoberta automática de hardware** — sem seleção manual de placa.

- Produto USB: `AegisToken FIDO2 USB Authenticator` (VID `0x1209`, PID `0x0001`)
- Família de firmware: `Universal RP2350 Firmware`
- Artefato de release: `rp2350-universal.uf2`

## Interfaces USB

O dispositivo compõe três funções HID, com separação lógica estrita:

| Interface | Usage Page | Finalidade |
|-----------|-----------|------------|
| **FIDO HID** | `0xF1D0` | Autenticação: CTAP2/FIDO2 (passkeys) e CTAP1/U2F |
| **Management HID** | vendor-defined `0xFF00` | Gestão, configuração, diagnóstico e atualização de firmware |
| **HID Keyboard** | padrão | Emissão de teclas; **opcional e desabilitada por padrão** |

> Operações FIDO **nunca** dependem das interfaces Keyboard ou Management. A
> interface HID Keyboard, quando habilitada, é governada pelo lifecycle e por
> User Presence e nunca é alcançável a partir do caminho de entrada FIDO.

## Funcionalidades

- **FIDO2/CTAP2**: `authenticatorGetInfo`, `makeCredential`, `getAssertion`,
  `clientPIN` (protocolo v1), `reset` e credential management.
- **U2F/CTAP1**: `U2F_VERSION` e `U2F_AUTHENTICATE` (check-only e sign).
- **User Presence** contextual via botão BOOTSEL, com debounce, timeout,
  consume-once e anti-replay; presença só é aceita em `FidoWaitPresence`.
- **Configuração** versionada em CBOR, com validação, integridade (CRC-32) e
  commit atômico em dois slots alternados (power-fail-safe).
- **Segredos selados** com AES-256-GCM sob a chave mestra lida da OTP; nunca
  exportáveis.
- **Lifecycle** completo (`Factory → Commissioning → Commissioned → … →
  Decommissioned`) e modo **Recovery**, que nega FIDO e acesso a credenciais.
- **Atualização segura** de firmware: pacote assinado (P-256/ES256), SHA-256 e
  anti-rollback, com staging separado da imagem em execução.
- **Secure boot/anti-rollback** nativos do RP2350 (ECDSA secp256k1 + hash da
  bootkey em OTP) — selagem e fusão de OTP são etapas de produção.

## Arquitetura

Workspace Cargo com quatro crates:

| Crate | Papel |
|-------|-------|
| [`crates/aegis-core`](crates/aegis-core) | Domínio portátil `no_std`/`no_alloc`, testável em host (máquinas de estado, protocolos, cripto, storage). |
| [`crates/board-generic-rp2350`](crates/board-generic-rp2350) | Abstração de hardware da família RP2350 (GPIO, BOOTSEL, LED, flash, OTP, TRNG, USB). |
| [`crates/firmware-universal-rp2350`](crates/firmware-universal-rp2350) | Binário `embassy-rp` que amarra tudo e implementa as tarefas USB. |
| [`crates/aegistoken-host`](crates/aegistoken-host) | CLI de host em Rust sobre **libusb** para o Management HID. |

O `aegis-core` não depende de HAL, executor ou placa — por isso roda e é testado
no host. A HAL fica isolada em `board-generic-rp2350`.

## Pré-requisitos

- Toolchain Rust fixada em `rust-toolchain.toml` (canal `1.97.1`), com os
  componentes `rustfmt` e `clippy` e o alvo `thumbv8m.main-none-eabihf`.
- [`probe-rs`](https://probe.rs) — flash e RTT.
- [`picotool`](https://github.com/raspberrypi/picotool) — conversão de UF2 e
  `picotool info`.
- Python 3 com `fido2`, `hidapi` e `cbor2` para os scripts de validação.

O host tool compila a libusb embutida (`vendored`), então **não** requer WinUSB
nem Zadig. No Windows a libusb usa o backend HID sobre o driver `hidusb` inbox.

## Build e flash

```powershell
# Testa e verifica o núcleo (host)
cargo fmt --all --check
cargo clippy -p aegis-core --all-targets -- -D warnings
cargo test -p aegis-core

# Build do firmware + geração do UF2 (rp2350a por padrão)
& scripts/build-uf2.ps1

# Outros alvos de placa
& scripts/build-uf2.ps1 -Board rp2350b
& scripts/build-uf2.ps1 -Board rp2354a
& scripts/build-uf2.ps1 -Board rp2354b

# Flash + RTT
probe-rs run --chip RP2350 target/thumbv8m.main-none-eabihf/release/firmware-universal-rp2350
```

Aliases úteis em `.cargo/config.toml`: `cargo build-fw`,
`cargo build-fw-release`, `cargo clippy-fw`, `cargo test-core`, entre outros.

O autoteste on-target roda no boot (log via defmt/RTT) e cobre capacidades,
HID, TRNG, `getInfo`, resposta do Management HID e leitura de BOOTSEL. Para o
teste destrutivo do store selado:

```powershell
cargo build -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf --features selftest
```

## Ferramenta de host

O crate `aegistoken-host` fala com o Management HID via libusb:

```powershell
cargo run -p aegistoken-host -- list          # enumera dispositivos/interfaces
cargo run -p aegistoken-host -- info          # GET_DEVICE_INFO
cargo run -p aegistoken-host -- capabilities  # GET_CAPABILITIES
cargo run -p aegistoken-host -- config        # GET_CONFIGURATION
cargo run -p aegistoken-host -- validate      # AC-003..AC-009 (Management HID)
```

Opções globais: `--vid`/`--pid` (padrão `0x1209:0x0001`), `--interface N` e
`--timeout MS`. Rode `cargo run -p aegistoken-host -- --help` para a lista
completa de comandos.

## Validação

```powershell
python scripts/validate_management.py   # Management HID (AC-003..AC-009)
python scripts/validate_fido.py         # FIDO2/U2F (AC-002, AC-011, AC-013)
python scripts/set_pin.py               # define/altera o PIN do clientPIN
```

Os scripts imprimem `[PASS]/[FAIL]` por critério (AC) e retornam código de saída
diferente de zero em falha. No Windows, a interface FIDO é reivindicada pelo
driver `fidohid`, que a mantém com exclusividade; veja
[`validation.md`](validation.md) para as opções de acesso (WebAuthn no navegador
ou remapeamento para o driver HID genérico).

## Documentação

- [`roadmap.md`](roadmap.md) — fases do projeto, decisões arquiteturais e status.
- [`validation.md`](validation.md) — matriz AC-001..AC-015, evidências e
  limitações conhecidas.
- [`production.md`](production.md) — provisionamento: secure boot, OTP, chave de
  update e atestação.

## Segurança

- Segredos nunca são exportados nem registrados em log; são selados com chave
  derivada da OTP.
- Chaves privadas e material sensível são ignorados pelo `.gitignore`
  (`*.pem`, `*.key`, etc.). Nunca faça commit de chaves.
- Sem `AEGIS_UPDATE_VENDOR_PUBKEY`, o build embute uma chave de
  **desenvolvimento** e registra um aviso — não libere imagens assim.

## Licença

MIT OR Apache-2.0.
