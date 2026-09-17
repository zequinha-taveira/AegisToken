# Versionamento — AegisToken Universal RP2350 Firmware

Documento de referência de versões, esquema de numeração e histórico de
releases.

## Esquema de versão

O firmware segue **SemVer** (`MAJOR.MINOR.PATCH`) e a versão canônica vive em
`[workspace.package].version` no `Cargo.toml` da raiz. Todos os crates herdam
essa versão via `version.workspace = true`.

- `MAJOR` — mudanças incompatíveis de protocolo, storage ou identidade USB.
- `MINOR` — novas funcionalidades compatíveis (ex.: nova fatia FIDO/Management).
- `PATCH` — correções compatíveis.

A versão também é exposta em runtime por `aegis_core::VERSION`.

## Nome dos artefatos

`scripts/build-uf2.ps1` gera a imagem universal (`-Board universal`, padrão) a
partir da versão do workspace:

```
AegisToken-<versão>.uf2
```

A imagem universal roda nas quatro variantes (RP2350A/B + RP2354A/B): usa o
subconjunto comum de pinos com detecção de pacote em runtime
(`SYSINFO.PACKAGE_SEL`) e layout flash conservador de 2 MiB. Builds por placa
(`-Board rp2350a|rp2350b|rp2354a|rp2354b`, `AegisToken_<produto>-<versão>.uf2`)
continuam disponíveis para debug.

O artefato de release é publicado automaticamente pelo workflow
`.github/workflows/release.yml` ao empurrar uma tag `v*`.

## Histórico de releases

| Versão | Tag | Data | Artefato | Status |
|--------|-----|------|----------|--------|
| 0.2.1 | `v0.2.1` | 2026-09-17 | `AegisToken-0.2.1.uf2` | Latest |
| 0.2.0 | `v0.2.0` | 2026-09-17 | `AegisToken_pico2-0.2.0.uf2` (+ rp2350b/rp2354a/rp2354b) | Superseded |
| 0.1 | `v0.1` | 2026-09-11 | `AegisToken_pico2-0.1.uf2` | Superseded |
| 0.0 | `v0.0` | 2026-09-11 | `AegisToken_pico2-0.0.uf2` | Pre-release |

> A versão compilada no binário é a do `Cargo.toml` (`0.2.1`).

## Compatibilidade e anti-rollback

- **Usuários:** Secure boot nativo exige que o contador de rollback
  (`--rollback`) **cresça a cada release**; imagens com versão anterior são
  rejeitadas pelo boot ROM. Ver `production.md`.
- **Atualização de firmware:** pacotes (`aegis-core::update`) são assinados com
  P-256/ES256 e comparados contra `INSTALLED_ROLLBACK`; um rollback menor é
  recusado.
- **Formato de configuração e storage:** versionados em CBOR; mudanças de
  formato exigem compatibilidade ou migração explícita.

## Processo de release

1. Atualize `version` no `Cargo.toml` (e este documento).
2. Garanta os checks verdes: `cargo fmt --all --check`,
   `cargo clippy -p aegis-core --all-targets -- -D warnings`,
   `cargo test -p aegis-core`.
3. (Opcional) Defina o segredo `AEGIS_UPDATE_VENDOR_PUBKEY` com a chave de
   update de release.
4. Crie e empurre a tag, por exemplo:
   ```powershell
   git tag v0.2.0
   git push origin v0.2.0
   ```
5. O workflow `release` compila todas as placas e publica os UF2 na release da
   tag. Tags com hífen (ex.: `v0.2.0-rc1`) saem como **pre-release**.
