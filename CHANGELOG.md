# Histórico de releases

Referência de todas as releases publicadas do **AegisToken Universal RP2350
Firmware**. O esquema de versionamento (SemVer), o nome dos artefatos, a
compatibilidade/anti-rollback e o processo de release estão em
[`version.md`](version.md); a versão canônica vive no `Cargo.toml` da raiz.

O workflow `.github/workflows/release.yml` publica o artefato automaticamente
ao empurrar uma tag `v*`. Este arquivo lista somente as releases publicadas.

## Não liberado (canal `nightly-development`)

O estado de `development` é construído automaticamente como
`AegisToken-nightly-development.uf2` (pre-release, **não** selada: embute a
chave de update de desenvolvimento). O que já está no canal desde a v0.2.1 e
ainda não entrou em uma release versionada:

- **OpenPGP Card** — decifração no cartão pela RFC 6637 (ECDH, MDC e
  quick-check em tempo constante), hardening fail-closed do ciclo S2–S12
  (`AC-022..AC-027`), desbloqueio de PW1 autenticado, `CHANGE REFERENCE DATA`
  do PW3 sob sessão de admin e interop ECDH fim a fim com GnuPG.
- **OATH** — leitura, RESET e janela de contagem/pendings fail-closed
  (store ilegível fecha o applet com `6F00`; desarme observável na falha).
- **PIV** — persistência fail-closed de PIN/PUK com *sticky floor* por slot
  (chão de tentativas que nunca rebaixa).
- **CLI de host** (`aegistoken-host`) — ligação dos comandos Management,
  PIV e OATH; segredos nunca em argv (prompt oculto/stdin), incluindo o PIN
  do validador FIDO.
- **Build** — `scripts/build-uf2.ps1` falha sem `picotool >= 2.0` e não
  reporta UF2 antigo como válido.
- **aegis-core** — o plano de boot do serviço de management começa fechado.

## [0.2.1] — Latest

- **Data:** 2026-09-17 · **Tag:** `v0.2.1` · **Release:** AegisToken v0.2.1
- **Artefato:** `AegisToken-0.2.1.uf2` (imagem **universal** única)
- **Destaques**
  - Novo formato de distribuição: o artefato por placa (`-pico2`, `-rp2350b`,
    `-rp2354a`, `-rp2354b` — 0.2.0) é *superseded* por um único UF2 que roda
    nas quatro variantes (RP2350A/B + RP2354A/B), com detecção de pacote em
    runtime via `SYSINFO.PACKAGE_SEL` e layout flash conservador de 2 MiB.
  - Atualização executada com `scripts/build-uf2.ps1 -Release`
    (chave de update de release, não a de DEV).
- Notas oficiais: `github.com/zequinha-taveira/AegisToken/releases/tag/v0.2.1`

## [0.2.0]

- **Data:** 2026-09-17 · **Tag:** `v0.2.0` · **Release:** AegisToken v0.2.0
- **Artefatos:** `AegisToken_pico2-0.2.0.uf2`,
  `AegisToken_rp2350b-0.2.0.uf2`, `AegisToken_rp2354a-0.2.0.uf2`,
  `AegisToken_rp2354b-0.2.0.uf2` (build por placa)
- **Destaques**
  - **Applets CCID (ISO 7816-4)**: applets **PIV** (NIST SP 800-73-4),
    **OATH** (TOTP/HOTP) e **OpenPGP Card v3.4** com chaves RSA-2048 e
    conformidade fase 17 (PR #20).
  - Estrutura inicial do workspace com crates separados e CI completa:
    workflows de `development` e `release`, Dependabot, CodeQL e política de
    segurança (SECURITY.md).
  - Fix de compatibilidade da crate `p256` e eliminação dos alertas CodeQL
    de valor criptográfico hard-coded.
  - CI de release garante imagem versionada: a variável
    `AEGIS_UPDATE_VENDOR_PUBKEY` vazia é tratada como ausente.
- Notas oficiais: `github.com/zequinha-taveira/AegisToken/releases/tag/v0.2.0`

## [0.1]

- **Data:** 2026-09-11 · **Tag:** `v0.1`
- **Artefato:** `AegisToken_pico2-0.1.uf2`
- **Destaques**
  - Primeira release declarada estável: firmware FIDO2/CTAP2 + CTAP1/U2F com
    Management HID sobre USB composto, ainda sem secure boot selado (imagem
    de desenvolvimento) e build só para RP2350A / Pico 2.
- Notas oficiais: `github.com/zequinha-taveira/AegisToken/releases/tag/v0.1`

## [0.0] — Pre-release

- **Data:** 2026-09-11 · **Tag:** `v0.0`
- **Artefato:** `AegisToken_pico2-0.0.uf2`
- **Destaques**
  - Primeira release pública (**pre-release**) do projeto; mesmo commit e
    artefato-base da v0.1, marcando o ponto de partida do ciclo FIDO2.
- Notas oficiais: `github.com/zequinha-taveira/AegisToken/releases/tag/v0.0`

## Canais automáticos

| Canal | Tag | Artefato | Aviso |
|-------|-----|----------|-------|
| Nightly development | `nightly-development` | `AegisToken-nightly-development.uf2` | Chave de update **de DEV** — só para teste |
| Nightly stable | `nightly-stable` | `AegisToken-nightly-stable.uf2` | Idem, construído a partir de `main` |

Tags locais de snapshot (ex.: `local/snapshot-2026-10-21`) não são publicadas
e não constam aqui.
