# Spec — Build de release exige chave de update de produção (gate `AEGIS_RELEASE=1`)

## Ameaça

A chave de assinatura de firmware de **desenvolvimento** é a chave privada 1 do
P-256 — o ponto gerador `G` — e portanto pública por definição. Ela está
estática em `crates/firmware-universal-rp2350/build.rs:17-23`
(`DEV_VENDOR_PUBLIC_KEY`). Qualquer pessoa com o repositório assina pacotes de
atualização ES256 que os devices aceitam.

Hoje a única defesa é um **aviso**:

- `crates/firmware-universal-rp2350/build.rs:69-74` — `cargo:warning` quando a
  chave DEV é usada;
- `crates/firmware-universal-rp2350/src/main.rs:180-181` — aviso no boot
  (`warning: development firmware-update vendor key in use`);
- `scripts/build-uf2.ps1:63-66` — `Write-Warning "… Do not ship it."`;
- `.github/workflows/release.yml:48-51` — o job de release falha **somente**
  quando o segredo `AEGIS_UPDATE_VENDOR_PUBKEY` do job está vazio **e** a
  ref é tag versionada. A checagem é do **segredo**, não do **artefato**.

Consequência: uma imagem local "de release" (ou um nightly) com a chave DEV é
construída sem qualquer bloqueio, e o CI não valida o artefato resultante.

## Invariantes em risco

- **INV-1 — Release nunca embute a chave DEV.** Uma imagem destinada a
  distribuição não pode conter a chave de update de desenvolvimento, venha ela
  da ausência de variável ou de hex explícito igual ao ponto `G`.
- **INV-2 — O gate é do artefato, não da intenção.** A verificação acontece na
  construção da imagem (build script), não apenas na checagem de segredo do
  job de CI.
- **INV-3 — Desenvolvimento e nightlies não quebram.** Sem `AEGIS_RELEASE=1` o
  comportamento atual (aviso) é preservado byte a byte.
- **INV-4 — Falhas são acionáveis e silenciosas quanto ao segredo.** A mensagem
  nomeia a variável e o formato esperado (130 hex, 65 bytes, SEC1 `04||X||Y`)
  e **nunca** imprime o valor da chave.
- **INV-5 — Escopo mínimo.** Nenhum outro crate, caminho (FIDO/CCID/Recovery) ou
  formato de pacote é tocado.

## Escopo e decisões normativas

- **D1 — Gate no `build.rs`.** Nova variável `AEGIS_RELEASE`. O gate fica
  **ativo** quando o valor (após `trim`) é exatamente `1`; **inativo** para
  `""`, `"0"` e `"false"` (case-insensitive); qualquer outro valor é **erro de
  build** (fail-closed contra erro de digitação que desabilitaria o gate por
  acidente). `build.rs` deve emitir
  `cargo:rerun-if-env-changed=AEGIS_RELEASE` para que togglar a variável
  re-dispare o build script.
- **D2 — Sem `AEGIS_RELEASE=1`, nada muda.** Ausência/vazio da
  `AEGIS_UPDATE_VENDOR_PUBKEY` → chave DEV + `cargo:warning` (comportamento de
  `build.rs:57-74`).
- **D3 — Detecção da chave DEV por bytes.** A chave é comparada byte a byte com
  `DEV_VENDOR_PUBLIC_KEY` **mesmo quando fornecida explicitamente**. Efeito
  intencional (mudança de comportamento a registrar): antes, passar o hex da
  DEV key resultava em `is_dev = false` silencioso; agora resulta em
  `is_dev = true` + aviso, e em **falha** se `AEGIS_RELEASE=1`.
- **D4 — Validação de formato endurecida.** `AEGIS_UPDATE_VENDOR_PUBKEY` deve
  ter exatamente 130 caracteres hex e o primeiro byte deve ser `0x04` (ponto
  SEC1 não comprimido). Valor malformado = erro de build (já é o caso hoje para
  comprimento/hex, `build.rs:62-66`; o prefixo `0x04` é acréscimo).
- **D5 — `scripts/build-uf2.ps1 -Release`.** Novo switch `-Release`:
  - falha **antes** de `cargo build` (`scripts/build-uf2.ps1:70`) se
    `AEGIS_UPDATE_VENDOR_PUBKEY` estiver ausente/vazio, malformada ou igual à
    chave DEV, com mensagem clara e sem imprimir a chave;
  - exporta `AEGIS_RELEASE=1` para o processo `cargo build`;
  - sem `-Release`: comportamento atual (aviso em `build-uf2.ps1:63-66`),
    development.
- **D6 — CI.** `.github/workflows/release.yml:73-77` passa a invocar
  `scripts/build-uf2.ps1 -Board universal -Release` **quando
  `github.ref_type == 'tag'`** (release versionada) e permanece sem `-Release`
  nos nightlies de branch (`release.yml:79-109`), que seguem com o aviso nas
  notas (`release.yml:96-98`). A checagem de segredo de `release.yml:48-51` é
  **mantida** (defesa em profundidade); a checagem do artefato é o gate novo.
- **D7 — Decisão testável em Rust puro (host).** `cargo test -p
  firmware-universal-rp2350` **não é viável**: o crate depende de `embassy-rp`,
  que não compila para o host (`error[E0433]: cannot find 'msplim' in 'register'`
  — verificado). Além disso, `#[cfg(test)] mod tests` dentro de `build.rs`
  **nunca é executado**: o cargo compila build scripts como binários host,
  sem harness de teste. Portanto a lógica de decisão é extraída para um crate
  host-only, sem dependências, com testes unitários:
  - **novo** `crates/aegis-build-support/` (`aegis-build-support`), lib host,
    `default-members` do workspace, sem dependências;
  - API mínima:
    ```rust
    pub const DEV_VENDOR_PUBLIC_KEY: [u8; 65];
    pub struct VendorKey { pub bytes: [u8; 65], pub is_dev: bool }
    pub fn parse_release_flag(value: Option<&str>) -> Result<bool, String>;
    pub fn resolve_vendor_key(env_value: Option<&str>, release: bool)
        -> Result<VendorKey, String>;
    ```
  - `crates/firmware-universal-rp2350/build.rs` passa a depender dele via
    `[build-dependencies]` e delega a resolução; o `DEV_VENDOR_PUBLIC_KEY` sai
    de `build.rs:17-23` e passa a ter fonte única no crate novo.
  - Rejeitado: colocar a função em `aegis-core` (mistura política de build em
    crate de domínio `no_std`) e deixar a lógica só em `build.rs` (sem
    cobertura de teste unitário, contrariando a regra de "testes obrigatórios").
- **D8 — Mensagens.** Textos fixos, acionáveis e sem material de chave:
  - gate: `AEGIS_RELEASE=1 requires a production firmware-update vendor key, but
    the DEVELOPMENT key would be embedded. Set AEGIS_UPDATE_VENDOR_PUBKEY to
    exactly 130 hex characters (65-byte uncompressed SEC1 P-256 point,
    04||X||Y) as printed by scripts/gen-update-key.py, or unset AEGIS_RELEASE
    for development builds.`
  - formato: `AEGIS_UPDATE_VENDOR_PUBKEY must be exactly 130 hex characters
    (65-byte uncompressed SEC1 P-256 point, 04||X||Y); got N characters.`
  - flag inválido: `AEGIS_RELEASE must be '1' to enable the release gate; got
    '<valor>'.`
  - nenhuma mensagem imprime o valor da chave (nem em warning, erro ou
    `cargo:warning`).

## Não-objetivos

- Não gerar, rotacionar ou guardar chaves; não tocar em
  `scripts/gen-update-key.py` além de referência.
- Não trocar a chave DEV — ela é pública por definição e serve de armadilha
  para detectar builds errados; permanece a armadilha do gate.
- Não alterar o formato do pacote de atualização (`aegis-core::update`), a
  verificação de assinatura em runtime nem a semântica de `VENDOR_KEY_IS_DEV`
  no firmware.
- Não tocar no secure boot do bootrom, no anti-rollback nem na fusão de OTP.
- Não bloquear nightlies; não bloquear o fluxo de desenvolvimento; não
  introduzir assinatura de artefato no CI (o gate é local, no build).
- Não exigir `AEGIS_RELEASE` em builds que não são de release (perfil cargo
  `release` **não** é discriminador — nightlies usam `--release`).

## Critérios de aceitação (observáveis)

- **AC-001** — Build com `AEGIS_RELEASE=1` e **sem** `AEGIS_UPDATE_VENDOR_PUBKEY`
  **falha** (exit ≠ 0) com a mensagem de gate de D8; nenhum `vendor_key.rs` com
  `VENDOR_KEY_IS_DEV=true` é gerado.
- **AC-002** — Build com `AEGIS_RELEASE=1` e chave de produção válida (130 hex,
  prefixo `04`) **passa**; `vendor_key.rs` gerado com `VENDOR_KEY_IS_DEV=false`
  e bytes iguais à chave fornecida.
- **AC-003** — Build **sem** `AEGIS_RELEASE` e **sem** a chave **passa**, com o
  `cargo:warning` de dev key preservado e `VENDOR_KEY_IS_DEV=true`.
- **AC-004** — Build **sem** `AEGIS_RELEASE` mas com o hex da **DEV key**
  explícito **passa** com aviso e `VENDOR_KEY_IS_DEV=true` (D3).
- **AC-005** — Build com `AEGIS_RELEASE=1` e o hex da **DEV key** explícito
  **falha** com a mensagem de gate (D3).
- **AC-006** — Build com `AEGIS_RELEASE=1` e chave malformada (comprimento ≠
  130, não-hex, ou prefixo ≠ `04`) **falha** com a mensagem de formato de D8.
- **AC-007** — Build com `AEGIS_RELEASE` em valor inválido (ex.: `true`) **falha**
  com a mensagem de flag inválido de D8 (fail-closed).
- **AC-008** — `scripts/build-uf2.ps1 -Release` sem `AEGIS_UPDATE_VENDOR_PUBKEY`
  **falha antes** de invocar `cargo build` (nenhum artefato/UF2 novo em
  `target/`), com mensagem nomeando a variável e o formato.
- **AC-009** — `scripts/build-uf2.ps1 -Release` com chave de produção válida
  define `AEGIS_RELEASE=1`, compila e gera o UF2.
- **AC-010** — `scripts/build-uf2.ps1` **sem** `-Release` e sem a chave mantém o
  comportamento atual: aviso `Do not ship it.` e build bem-sucedido.
- **AC-011** — O job de release versionada do CI constrói o artefato **com o
  gate ativo** (`-Release`): se o segredo faltar, o build falha; se estiver
  presente, a imagem é publicada. O job de nightly **não** usa `-Release`.
- **AC-012** — `cargo test -p aegis-build-support` cobre, no mínimo: chave DEV
  ausente (dev/release), chave DEV explícita (dev/release), chave de produção
  válida, formato inválido (3 casos) e valor inválido de `AEGIS_RELEASE`; e
  nenhuma mensagem de erro contém o valor da chave.

## Plano de teste (comandos exatos)

```powershell
# 0. Chaves de teste
$devKey  = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"  # ponto G (DEV)
$prodKey = "04" + ("a1" * 64)   # material público descartável, não-DEV, formato válido

# 1. Dev: sem AEGIS_RELEASE, sem chave -> PASSA com warning (AC-003)
$env:AEGIS_RELEASE = $null
$env:AEGIS_UPDATE_VENDOR_PUBKEY = $null
cargo check -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf 2>&1 |
  Tee-Object dev.log
if ($LASTEXITCODE -ne 0) { throw "esperava sucesso" }
Select-String -Path dev.log -Pattern "vendor key is the DEVELOPMENT key"

# 2. Gate sem chave -> FALHA com a mensagem de gate (AC-001)
$env:AEGIS_RELEASE = "1"
cargo check -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf 2>&1 |
  Tee-Object gate.log
if ($LASTEXITCODE -eq 0) { throw "gate nao disparou" }
Select-String -Path gate.log -Pattern "AEGIS_RELEASE=1 requires a production firmware-update vendor key"

# 3. Gate com a DEV key explicita -> FALHA (AC-005)
$env:AEGIS_UPDATE_VENDOR_PUBKEY = $devKey
cargo check -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf 2>&1 |
  Tee-Object devkey.log
if ($LASTEXITCODE -eq 0) { throw "gate nao disparou" }

# 4. Gate com chave de producao -> PASSA (AC-002)
$env:AEGIS_UPDATE_VENDOR_PUBKEY = $prodKey
cargo check -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf
if ($LASTEXITCODE -ne 0) { throw "esperava sucesso" }

# 5. Dev com a DEV key explicita -> PASSA com warning (AC-004)
$env:AEGIS_RELEASE = $null
$env:AEGIS_UPDATE_VENDOR_PUBKEY = $devKey
cargo check -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf 2>&1 |
  Tee-Object devonly.log
Select-String -Path devonly.log -Pattern "vendor key is the DEVELOPMENT key"

# 6. AEGIS_RELEASE invalido -> FALHA (AC-007)
$env:AEGIS_RELEASE = "true"
cargo check -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf 2>&1 |
  Tee-Object badflag.log
if ($LASTEXITCODE -eq 0) { throw "esperava falha" }

# 7. Script: -Release sem chave -> FALHA antes do cargo build (AC-008)
$env:AEGIS_RELEASE = $null; $env:AEGIS_UPDATE_VENDOR_PUBKEY = $null
& scripts/build-uf2.ps1 -Release   # deve falhar antes de compilar

# 8. Script: -Release com chave -> compila e gera UF2 (AC-009)
$env:AEGIS_UPDATE_VENDOR_PUBKEY = $prodKey
& scripts/build-uf2.ps1 -Release -Board universal

# 9. Script sem -Release e sem chave -> aviso, build ok (AC-010)
$env:AEGIS_UPDATE_VENDOR_PUBKEY = $null
& scripts/build-uf2.ps1 -Board universal

# Gates do repositorio
cargo fmt --all --check
cargo clippy -p aegis-build-support --all-targets -- -D warnings
cargo test -p aegis-build-support
cargo clippy -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf --release -- -D warnings
cargo build -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf --release
```

> Nota: o gate roda no `build.rs`, ou seja, **após** compilar as dependências
> (`embassy-*`). Nos casos negativos, use `cargo check` para reduzir o custo;
> rode ao menos um `cargo build` completo (passo 4/8) para validar o artefato.

## Arquivos afetados

| Arquivo | Mudança |
|---|---|
| `crates/aegis-build-support/Cargo.toml` (novo) | crate host-only, sem deps; member + `default-members` do workspace (`Cargo.toml:3-19`) |
| `crates/aegis-build-support/src/lib.rs` (novo) | `DEV_VENDOR_PUBLIC_KEY`, `VendorKey`, `parse_release_flag`, `resolve_vendor_key` + testes unitários |
| `crates/firmware-universal-rp2350/Cargo.toml` | seção `[build-dependencies]` para `aegis-build-support` |
| `crates/firmware-universal-rp2350/build.rs:13-23` | constante da chave DEV sai do arquivo (fonte única no crate novo) |
| `crates/firmware-universal-rp2350/build.rs:25-35` | `parse_sec1_hex` passa a viver no crate novo, com validação de prefixo `04` |
| `crates/firmware-universal-rp2350/build.rs:57-74` | resolução delegada + gate `AEGIS_RELEASE` + `rerun-if-env-changed=AEGIS_RELEASE` + mensagens de D8 |
| `crates/firmware-universal-rp2350/src/main.rs:113-115,180-181` | **sem mudança de comportamento** (aviso no boot permanece) |
| `scripts/build-uf2.ps1:25-29` | novo switch `-Release` |
| `scripts/build-uf2.ps1:63-66` | validação antecipada da chave em modo `-Release`; aviso preservado no modo dev |
| `scripts/build-uf2.ps1:68-71` | exporta `AEGIS_RELEASE=1` em modo `-Release` |
| `scripts/build-uf2.ps1:1-23` | cabeçalho de uso documentando `-Release` |
| `.github/workflows/release.yml:73-77` | build com `-Release` quando `github.ref_type == 'tag'` |
| `.github/workflows/release.yml:79-98` | nightly inalterado (sem `-Release`, aviso nas notas) |
| `.github/workflows/ci.yml:44-65` | novo step/job `release-gate` exercitando o gate (falha esperada e sucesso com chave de teste) |
| `Cargo.toml:3-19` | `crates/aegis-build-support` em `members` e `default-members` |
| `.cargo/config.toml` | alias `test-build-support = "test -p aegis-build-support"` |

## Documentação

- `production.md:101-116` (seção "Chave de update do firmware (P-256)") —
  documentar o gate: `& scripts/build-uf2.ps1 -Release`, o erro esperado sem a
  chave, e que o CI usa `-Release` nas tags versionadas.
- `README.md:200-215` (build/flash) e `README.md:320` (chave DEV) — registrar
  o gate e o comando de release; remover a leitura de "apenas um aviso é
  suficiente".
- `AGENTS.md:64` (regra de segredo/chave DEV) — acrescentar: builds de release
  exigem `AEGIS_RELEASE=1` / `build-uf2.ps1 -Release`; nunca publicar imagem
  com a chave DEV.
- `roadmap.md` — marcar a pendência de `VENDOR_PUBLIC_KEY` placeholder
  (Fase 8, `roadmap.md:686-689`) como endereçada pelo gate (o placeholder
  estrutural do firmware permanece, mas a release passa a exigir chave real).
- `docs/security-model.md:7-16` — invariante nova: *"A release embute apenas
  chave de update de produção; o gate de build impede a chave DEV"*.
- `SECURITY.md:63-66` e `CONTEXT.md:39` — alinhar a descrição do fluxo de
  release com o gate.
- `version.md:62-64` — passo 3 do processo de release: exigir
  `AEGIS_UPDATE_VENDOR_PUBKEY` **e** o build com o gate ativo.
- `CHANGELOG.md` — **não aplicável**: o arquivo é reservado a entradas futuras
  (`CHANGELOG.md:1-3`); o changelog do projeto é `version.md`.

## Riscos e limitações

- **Gate é opt-in por variável de ambiente.** Builds de terceiros que não
  definam `AEGIS_RELEASE=1` continuam embutindo a chave DEV com aviso; o gate
  não é uma política, é uma barreira explícita contra erro humano no fluxo de
  release.
- **Release local exige disciplina.** Quem constrói uma release local precisa
  passar `-Release` (ou `AEGIS_RELEASE=1`); o caminho padrão do script
  (`build-uf2.ps1` sem flag) segue sendo de desenvolvimento.
- **O aviso no boot continua sendo a defesa para imagens já flashadas**
  (`main.rs:180-181`): o gate atua antes da gravação, não substitui o aviso.
- **Custo de CI.** O step `release-gate` adiciona um build de firmware ao CI
  (o build falho compila as dependências antes de o `build.rs` rodar); usar
  `cargo check` no caso negativo.
- **Mudança de comportamento deliberada (D3):** passar explicitamente o hex da
  DEV key passa a marcar `VENDOR_KEY_IS_DEV=true` e a falhar em release — antes
  era aceito como chave "de produção" sem aviso.
- **Validação de prefixo `04` (D4)** rejeita chaves que não sejam ponto SEC1
  não comprimido; chaves geradas por `scripts/gen-update-key.py` já são nesse
  formato.
- **Não é uma barreira criptográfica.** A chave DEV continua pública; o gate
  apenas impede que uma imagem com ela seja construída como release.
