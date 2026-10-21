---
name: aegis-gates
description: Roda os gates de validação do AegisToken (cargo fmt, clippy -D warnings e testes de aegis-core/aegis-applets/aegistoken-host, build de firmware no alvo thumbv8m e geração de UF2) e devolve a evidência pass/fail de cada comando.
license: MIT
compatibility: opencode
metadata:
  audience: maintainers
  workflow: verification
  opencode/slash: "true"
  opencode/autoinvoke: "false"
---

# Skill: aegis-gates

Use para **verificar** o estado do repositório contra os gates do `AGENTS.md`
(→ "How to validate"). É o passo 4 do loop de melhoria.

## Comandos (host, nesta ordem)

```powershell
cargo fmt --all --check
cargo clippy -p aegis-core --all-targets -- -D warnings
cargo test -p aegis-core
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
cargo clippy -p aegistoken-host --all-targets -- -D warnings
cargo test -p aegistoken-host
```

## Comandos adicionais (firmware/HAL tocado)

```powershell
cargo clippy-fw
cargo build-fw
& scripts/build-uf2.ps1
```

Alias disponíveis em `.cargo/config.toml`: `build-fw`, `build-fw-release`, `clippy-fw`,
`test-core`, `clippy-core`, `test-applets`, `clippy-applets`.

## Regras

- Execute de verdade; **nunca** reporte verde sem ter executado o comando.
- Pare no primeiro gate vermelho e reporte a saída real (primeiras ~40 linhas) com
  `arquivo:linha` quando a mensagem apontar.
- Registre a contagem de testes por crate.
- Não edite código para "fazer passar" — o conserto é do `impl`, que volta a rodar os
  gates.
- Build de firmware é lento: use timeout generoso (ex.: 15 min para `build-fw`).

## Saída esperada

Tabela comando → PASS/FAIL, contagem de testes, artefato gerado (UF2) e o primeiro
erro real quando houver.
