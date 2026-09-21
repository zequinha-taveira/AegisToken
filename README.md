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

O dispositivo compõe três funções HID e uma interface CCID, com separação
lógica estrita:

| Interface | Classe | Finalidade |
|-----------|--------|------------|
| **FIDO HID** | usage page `0xF1D0` | Autenticação: CTAP2/FIDO2 (passkeys) e CTAP1/U2F |
| **Management HID** | vendor-defined `0xFF00` | Gestão, configuração, diagnóstico e atualização de firmware |
| **HID Keyboard** | padrão | Emissão de teclas; **opcional e desabilitada por padrão** |
| **CCID** | `0x0B` | Applets ISO 7816: PIV, OpenPGP e OATH (ECC + RSA-2048) |

> Operações FIDO **nunca** dependem das interfaces Keyboard, Management ou
> CCID. A interface HID Keyboard, quando habilitada, é governada pelo lifecycle
> e por User Presence e nunca é alcançável a partir do caminho de entrada FIDO.

## Identidade e perfil de hardware

O `DeviceManager` do firmware mantém três entidades separadas, para que a marca
da placa, o chip instalado e a fiação não se misturem:

- **Board Identity** — fabricante, produto, modelo da placa, revisão de hardware
  e o par USB `vendor_id`/`product_id` declarados pelo perfil. Exposta no
  descritor USB e em `GET_DEVICE_INFO`.
- **Board Hardware Profile** — parâmetros que variam por placa sem tocar no
  núcleo do firmware: LED (driver, GPIO, polaridade, pinos candidatos,
  brilho), User Presence (BOOTSEL ou botão externo, GPIO, polaridade, debounce,
  timeout) e flash (capacidade e layout). A tarefa FIDO aguarda a presença de
  forma assíncrona (`PresenceAdapter::wait`); o perfil decide se isso é BOOTSEL
  ou um botão GPIO, também sem travar o executor.
- **MCU Identity** — variante do RP2350 (família, package, revisão de silício) e
  o identificador único de 64 bits fundido na OTP, usado como número de série
  USB. Vem do chip instalado, então trocar a placa não confunde a identidade.

Uma nova placa, PCB própria ou placa de terceiros só precisa de um novo
`BoardProfile` (identidade + hardware profile); o firmware universal não muda.

O perfil genérico `AegisToken` usa `VID:PID = 1209:0001` (id próprio no
pid.codes). As placas
de terceiros usam o `vendor_id` `2E8A` sublicenciado pela Raspberry Pi e o
`product_id` alocado ao fabricante, conforme a lista oficial
[raspberrypi/usb-pid](https://github.com/raspberrypi/usb-pid); o `manufacturer`
passa a ser o fabricante da placa e o `product` permanece o produto AegisToken.

### Placas RP2350 de terceiros

Cada `BoardProfile` declara a identidade da placa e seu `product_id`:

| Fabricante | Placa | USB VID:PID |
|------------|-------|-------------|
| Waveshare | RP2350-Zero | `2E8A:10B0` |
| Waveshare | RP2350-Plus | `2E8A:10B1` |
| Waveshare | RP2350-Tiny | `2E8A:10B2` |
| Waveshare | RP2350-LCD-1.28 | `2E8A:10B3` |
| Waveshare | RP2350-Touch-LCD-1.28 | `2E8A:10B4` |
| Waveshare | RP2350-One | `2E8A:10B5` |
| Waveshare | RP2350-GEEK | `2E8A:10B6` |
| Waveshare | RP2350-LCD-0.96 | `2E8A:10B7` |
| Waveshare | RP2350-ETH | `2E8A:10C3` |
| Pimoroni | Pico Plus 2 | `2E8A:10A3` |
| Pimoroni | Tiny 2350 | `2E8A:10A4` |
| Pimoroni | Plasma 2350 | `2E8A:10A5` |
| Pimoroni | PGA2350 | `2E8A:10A6` |
| Datanoise | PicoADK v2 | `2E8A:10AE` |
| Soldered | NULA Max RP2350 | `2E8A:10EC` |
| Invector Labs | Challenger+ RP2350 NB-IoT | `2E8A:110D` |

O perfil é selecionado em tempo de build por `AEGIS_BOARD` (ou `-BoardProfile`
em `scripts/build-uf2.ps1`); o padrão `generic` mantém a identidade AegisToken.
O número de série USB continua vindo da OTP do chip, não da placa.

> A identidade USB YubiKey que `ykman` / Yubico Authenticator reconhecem
> automaticamente é um build opt-in (`VIDPID=Yubikey5`), apenas para testes
> locais — não distribuir.

## Funcionalidades

- **FIDO2/CTAP2**: `authenticatorGetInfo`, `makeCredential`, `getAssertion`,
  `clientPIN` (protocolo v1), `reset` e credential management — ES256 e
  EdDSA (`ed25519-sk`, pronta para SSH/Git; ver `docs/ssh-git.md`).
- **U2F/CTAP1**: `U2F_VERSION` e `U2F_AUTHENTICATE` (check-only e sign, ES256).
- **CCID / ISO 7816** (Fases 11–12, 16): transporte CCID (classe `0x0B`), APDU
  ISO 7816-4 (curto e estendido), roteamento por AID e framework de PIN/retry.
  O applet **PIV** (NIST SP 800-73-4) implementa `VERIFY`/`CHANGE`/`RESET`,
  `GET DATA`/`PUT DATA`, `GENERATE ASYMMETRIC KEY PAIR` (P-256/P-384 e
  RSA-2048), `GENERAL AUTHENTICATE` (management key 3DES/AES e assinatura
  ECDSA ou RSA crua) e touch policy por slot. O applet **OATH** (YKOATH)
  implementa HOTP/TOTP com HMAC-SHA1/SHA-256/SHA-512, access code,
  LIST/CALCULATE e RFC 4226/6238; o applet **OpenPGP Card** implementa o
  slice v3.4 com P-256, Ed25519, X25519 e RSA-2048 (PW1/PW3, DOs, keygen,
  ECDSA/EdDSA, internal auth crua, ECDH/decifra RSA e fingerprints
  RFC 4880); PIV com P-256/P-384. Sem brainpoolP512r1 / X448 / Ed448
   (sem aritmética `no_std` madura em Rust); brainpoolP256r1 e P384r1
   seguem suportados. RSA-3072/PSS e KDF OpenPGP completo ficam fora de escopo.
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

Workspace Cargo com onze crates:

| Crate | Papel |
|-------|-------|
| [`crates/security-key-core`](crates/security-key-core) | Scaffold para o domínio portátil de autenticação, credenciais, chaves, presença e estado. |
| [`crates/security-key-crypto`](crates/security-key-crypto) | Scaffold para as primitivas e traits criptográficos. |
| [`crates/security-key-storage`](crates/security-key-storage) | Scaffold para as abstrações e implementações de storage. |
| [`crates/security-key-ctap`](crates/security-key-ctap) | Scaffold para CTAP2, CTAPHID, CBOR e U2F. |
| [`crates/security-key-usb`](crates/security-key-usb) | Scaffold para os transportes USB HID, FIDO e Management. |
| [`crates/security-key-hal`](crates/security-key-hal) | Scaffold para as fronteiras de abstração de hardware. |
| [`crates/aegis-core`](crates/aegis-core) | Domínio portátil `no_std`/`no_alloc`, testável em host (máquinas de estado, protocolos, cripto, storage). |
| [`crates/aegis-applets`](crates/aegis-applets) | APDU, CCID, roteamento por AID, TLV e applets PIV/OATH/OpenPGP (`no_std`, testável em host). |
| [`crates/board-generic-rp2350`](crates/board-generic-rp2350) | Abstração de hardware da família RP2350 (GPIO, BOOTSEL, LED, flash, OTP, TRNG, USB HID/CCID). |
| [`crates/firmware-universal-rp2350`](crates/firmware-universal-rp2350) | Binário `embassy-rp` que amarra tudo e implementa as tarefas USB. |
| [`crates/aegistoken-host`](crates/aegistoken-host) | CLI de host em Rust sobre **libusb** para o Management HID. |

Os seis crates `security-key-*` são apenas scaffolds nesta fase: nenhum código
foi movido. O `aegis-core` e o `aegis-applets` são a fonte da implementação
durante a migração, não dependem de HAL, executor ou placa e por isso rodam e
são testados no host. A HAL atual permanece isolada em `board-generic-rp2350`.

## Pré-requisitos

- Toolchain Rust fixada em `rust-toolchain.toml` (canal `1.97.1`), com os
  componentes `rustfmt` e `clippy` e o alvo `thumbv8m.main-none-eabihf`.
- [`probe-rs`](https://probe.rs) — flash e RTT.
- [`picotool`](https://github.com/raspberrypi/picotool) — conversão de UF2 e
  `picotool info`.
- Python 3 com `fido2`, `hidapi`, `cbor2` e `pyscard` para os scripts de
  validação.

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

# Placa de terceiros (identidade e USB VID:PID da placa)
& scripts/build-uf2.ps1 -BoardProfile waveshare-rp2350-zero
& scripts/build-uf2.ps1 -BoardProfile pimoroni-tiny-2350

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

## Pipeline de releases

O fluxo de CI/CD em [`.github/workflows/release.yml`](.github/workflows/release.yml) publica os artefatos UF2 automatizados conforme o branch ou tag:

```text
push development
       ↓
Nightly Development

push main
       ↓
Nightly Stable

git tag v
       ↓
Version  → Latest
```

| Gatilho | Release / Tag GitHub | Status | Artefato UF2 | Descrição |
|---|---|---|---|---|
| `push` em `development` | `nightly-development` | Pre-release | `AegisToken-nightly-development.uf2` | Build contínuo dos últimos avanços em desenvolvimento. Destinado a testes. |
| `push` em `main` | `nightly-stable` | Pre-release | `AegisToken-nightly-stable.uf2` | Build contínuo do branch principal e estável. |
| `git tag v*` (ex.: `v0.2.1`) | `vX.Y.Z` | **Latest** | `AegisToken-vX.Y.Z.uf2` | Release oficial versionada. Requer a tag apontando para o commit atual de `main` e o secret `AEGIS_UPDATE_VENDOR_PUBKEY`. Sufixos pré-lançamento (ex.: `-rc1`) são mantidos como Pre-release. |

> **Vantagem das rolling tags (`nightly-development` e `nightly-stable`)**:
> - **Link permanente e previsível**: o link de download para quem testa é sempre o mesmo e nunca quebra (ex.: `releases/tag/nightly-development`), sem poluir a aba de releases com centenas de tags diárias.
> - **Download sempre do último commit**: toda vez que um push ou merge de PR entra na branch correspondente, o artefato UF2 é substituído (`gh release upload --clobber`) e a tag é apontada para o novo commit de forma transparente.

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
`--timeout MS`. Um firmware construído com um perfil de terceiros enumera com o
VID/PID da placa (ex.: `--vid 0x2E8A --pid 0x10B0`); rode
`cargo run -p aegistoken-host -- --help` para a lista completa de comandos.

## Validação

```powershell
python scripts/validate_management.py   # Management HID (AC-003..AC-009)
python scripts/validate_fido.py         # FIDO2/U2F + Ed25519 (AC-002, AC-011, AC-013, AC-020)
python scripts/validate_ccid.py         # CCID (AC-016)
python scripts/validate_piv.py          # PIV (AC-017) + RSA-2048 (AC-021)
python scripts/validate_oath.py         # OATH/TOTP/HOTP (AC-018)
python scripts/validate_openpgp.py      # OpenPGP ECC + RSA-2048 (AC-019, AC-021)
python scripts/set_pin.py               # define/altera o PIN do clientPIN
```

Os scripts imprimem `[PASS]/[FAIL]` por critério (AC) e retornam código de saída
diferente de zero em falha. No Windows, a interface FIDO é reivindicada pelo
driver `fidohid`, que a mantém com exclusividade; veja
[`validation.md`](validation.md) para as opções de acesso (WebAuthn no navegador
ou remapeamento para o driver HID genérico).

## Documentação

- [`roadmap.md`](roadmap.md) — fases do projeto, decisões arquiteturais e status.
- [`validation.md`](validation.md) — matriz AC-001..AC-021, evidências e
  limitações conhecidas.
- [`docs/ssh-git.md`](docs/ssh-git.md) — SSH (`ed25519-sk`/`ecdsa-sk`),
  `ssh-agent` e assinatura Git via SSH.
- [`production.md`](production.md) — provisionamento: secure boot, OTP, chave de
  update e atestação.

## Segurança

- Sem secure element: OTP + secure boot são endurecimento real, mas ataques
  físicos estão fora de escopo.
- Backup de seed cobre só a identidade determinística — passkeys residentes e
  chaves OpenPGP/PIV não sobrevivem à troca de placa.
- Segredos nunca são exportados nem registrados em log; são selados com chave
  derivada da OTP.
- Chaves privadas e material sensível são ignorados pelo `.gitignore`
  (`*.pem`, `*.key`, etc.). Nunca faça commit de chaves.
- Sem `AEGIS_UPDATE_VENDOR_PUBKEY`, o build embute uma chave de
  **desenvolvimento** e registra um aviso — não libere imagens assim.

## Licença

MIT OR Apache-2.0.
