# Spec — Recovery nega FIDO/CCID (gating de boot por plano de execução)

> Origem: achado do `sec-audit` (severidade **ALTO**).
> Fatia: transformar o destino de boot em uma **decisão de política no núcleo**,
> consultada pelo firmware antes de servir qualquer interface.
> Sem hardware disponível neste ciclo: os ACs são de host + verificação estática
> do firmware; a validação física fica como pendência registrada em
> `validation.md`.

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- `crates/firmware-universal-rp2350/src/main.rs:181-186` — `bootsel_held` é lido
  e o destino (`aegis_core::state::boot_destination(bootsel_held)`) é **apenas
  logado**. Nenhuma decisão decorre dele.
- `crates/firmware-universal-rp2350/src/main.rs:221-243` — o `join3(...)` inicia
  **sempre** `fido_task` (com o `SealedCredentialStore` das credenciais),
  `ccid_task` (PIV/OATH/OpenPGP com stores selados), `housekeeping` (Management
  HID) e `otp_task`.
- `crates/aegis-core/src/state.rs:92` — `fido_allowed` existe e nega FIDO em
  `Recovery`/`Locked`, mas **nunca é consultado** por ninguém no firmware.
- `crates/aegis-core/src/recovery.rs:142-163` — a `RecoverySession` nega FIDO,
  User Presence, acesso a credenciais e exportação de segredos (invariante
  testada no núcleo), mas **não é executada on-device**.

### 1.2 Quem se beneficia e como

O vetor não é o PIN: **o `pinUvAuthToken` não é a única barreira**. Um device
que entre em Recovery continua servindo FIDO e CCID, o que significa que a
única barreira restante para extração de material é o PIN do FIDO (quando
configurado) — e nenhuma para PIV/OATH/OpenPGP, cujas PINs são separadas e
opcionais.

Cenários concretos:

1. **Boot com BOOTSEL mantido.** O bootrom do RP2350 usa BOOTSEL para o
   recovery/bootloader. Com a tecla mantida, o firmware sobe no modo "normal"
   (não no recovery do bootrom, porque o bootrom já o consumiu) e serve
   **FIDO + CCID + credenciais** — exatamente o oposto do que a invariante do
   projeto exige ("Recovery nega FIDO/CCID/credenciais; só diagnóstico e
   update").
2. **Device deixado em Recovery.** Um dispositivo que entrou em recovery por
   falha de firmware, por update staged ou por pedido explícito do owner e foi
   deixado sobre a mesa (ou em bancada de laboratório, ou conectado a um host
   hostil) continua respondendo `getAssertion`/`makeCredential` e operações
   CCID com chaves privadas residentes.
3. **Bypass do "modo seguro" do owner.** O owner que restaurou o dispositivo
   seguindo o procedimento de recovery acredita que, enquanto o device está em
   Recovery, nenhuma credencial pode ser usada. A garantia é falsa: as
   interfaces de autenticação continuam vivas.

**Impacto:** exposição de passkeys/resident credentials (FIDO), de chaves
privadas PIV/OpenPGP e de segredos OATH (CCID) — sem conhecimento do owner e
sem exigir KNOWLEDGE (o PIN), apenas posse física breve do dispositivo. A
falha também derruba a separação de caminhos: em Recovery o dispositivo passa
a se comportar como um autenticador e um smartcard completos.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | "Recovery denies FIDO/CCID/credentials (diagnostics + update only)" | `AGENTS.md:61` | **violado no firmware** (apenas respeitado no núcleo) |
| I2 | "Recovery denies CCID the same way it denies FIDO (diagnostics and firmware update remain available)" — "Transport paths stay isolated" | `docs/security-model.md:76-79` | **violado no firmware** |
| I3 | "Isolamento de caminhos: … Recovery nega CCID assim como nega FIDO (exceto diagnóstico e update)" | `roadmap.md:107-109` | **violado no firmware** |
| I4 | "`aegis-core::state::fido_allowed`: FIDO nunca é servido em Recovery/Locked" | `roadmap.md:646` | função existe e é testada, **sem consumidor** |
| I5 | "Recovery denies FIDO/CCID/credentials" | `CONTEXT.md:20` | **violado no firmware** |
| I6 | `Recovery` ⇒ "Apenas diagnósticos e atualização de firmware" | `docs/architecture.md:100` | **violado no firmware** |
| I7 | Recovery nega FIDO, User Presence, credenciais e segredos | `aegis-core::recovery.rs:141-163` | respeitado **no núcleo**, ignorado **no firmware** |

---

## 3. Escopo

### 3.1 Núcleo (`aegis-core`) — a decisão

Introduzir em `aegis-core::state` (mesmo módulo de `boot_destination` e
`fido_allowed`; um módulo novo, ex. `aegis-core::boot`, só se `state` ficar
coeso demais) um **plano de boot**: o valor derivado do `ExecutionState` de
destino que diz, **por caminho**, o que o firmware pode servir.

Comportamento exigido (o nome exato dos itens é do implementador):

- O plano é derivado **apenas** do destino de boot (`Active`, `Recovery`,
  `Locked`) — o mesmo destino de `boot_destination(bootsel_held)`.
- O plano expõe, por caminho:
  - **FIDO** — habilitado apenas em `Active`;
  - **CCID** — habilitado apenas em `Active`;
  - **Management** — habilitado em **todos** os destinos (diagnóstico e
    firmware update são o que o Recovery precisa oferecer);
  - **HID OTP de laboratório** — mantido habilitado em todos os destinos
    (é diagnóstico, não expõe segredo; decisão registrada nos riscos).
- O plano expõe também, de forma redundante e explícita, a autorização de
  **abrir stores selados**: store selado de credenciais FIDO e stores selados
  dos applets. Ambos só são autorizados quando o respectivo caminho está
  habilitado.
- **Fail-closed**: qualquer `ExecutionState` que não seja um destino de boot
  (`Boot`, `FidoWaitPresence`, `FidoOperation`, `Management`, `FirmwareUpdate`)
  produz um plano sem FIDO e sem CCID, mantendo Management. A função é total
  (sem `Option`) para que o firmware não possa "esquecer" um caso.
- O plano **não habilita FIDO** em nenhum estado onde `fido_allowed` nega, e
  **habilita e desabilita FIDO e CCID juntos** nos destinos (eles não divergem
  nesta fatia).

### 3.2 Firmware (`firmware-universal-rp2350`) — a execução

- No boot, calcular `destino = boot_destination(bootsel_held)` e
  `plano = plano_para(destino)`.
- Usar o plano para **não iniciar** `fido_task` e `ccid_task` quando o caminho
  está negado. A tarefa não é iniciada: o store selado **não é aberto** porque
  a abertura acontece dentro da tarefa (`main.rs:522` para as credenciais;
  `main.rs:299-308` para PIV/OATH/OpenPGP).
- **Defesa em profundidade**: o ponto de abertura do store selado deve também
  ser condicionado ao plano (ou seja, mesmo que a tarefa seja iniciada por
  engano, ela não abre store selado e não serve requisições nesse caminho).
- `housekeeping` (Management HID) e `otp_task` **continuam sempre ativos**.
- O Management HID em Recovery deve continuar respondendo `GET_STATUS`
  (`0x09`) e `GET_DIAGNOSTICS` (`0x0A`), e o caminho de firmware update
  (`FIRMWARE_UPDATE`) permanece disponível.
- **Nenhuma decisão de segurança nova nasce no firmware**: o firmware apenas
  lê o plano e obedece.

### 3.3 Fora do alcance desta fatia (mantido explicitamente)

O firmware não decide, não pode decidir e não precisa decidir nada além de
"iniciar ou não iniciar" cada caminho.

---

## 4. Não-objetivos

1. **Execução on-device da `RecoverySession`** — `aegis-core::recovery.rs`
   **não é tocado**. A sessão já nega FIDO/credenciais no núcleo; executá-la
   on-device (com auditoria, sessão de recovery explícita e saída do estado)
   é escopo maior e depende do refactor de compartilhamento de storage.
2. **Factory reset limpando credenciais** — a limpeza de credenciais no
   `FACTORY_RESET` segue pendente (depende do mesmo refactor).
3. **Supressão da enumeração USB** — os descritores e a composição de
   interfaces **não mudam**. As interfaces FIDO/CCID **continuam enumerando**
   em Recovery; o efeito observável é **não responder**. Suprimir a
   enumeração exigiria alterar descritores (não-objetivo 4) e é tratado como
   item de follow-up.
4. **Mudança de descritores USB / re-enumeração**.
5. **Política distinta entre `Locked` e `Recovery`** — além do gating, os dois
   estados têm a mesma política nesta fatia (negam FIDO/CCID, mantêm
   Management). Diferenças de política entre os dois (ex.: `Locked` bloquear
   update) ficam para uma fatia própria.
6. **Reclassificação do HID OTP de laboratório** — continua diagnóstico e
   sempre ativo (ver riscos).
7. **Alterar a máquina de estados** (`ExecutionState::can_transition` /
   `transition`) — `Boot → Active|Recovery|Locked` já é legal
   (`crates/aegis-core/src/state.rs:42`).
8. **Qualquer refactor do `authenticator.rs` ou do caminho FIDO** — há outra
   sessão do loop mexendo nesses arquivos (ver riscos de concorrência).

---

## 5. Critérios de aceitação

Cada AC é observável em teste de host, exceto quando marcado como
*(firmware/estático)* ou *(hardware pendente)*.

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | O plano de boot do destino `Active` habilita FIDO, CCID e Management (e o HID OTP de laboratório) | teste de host em `crates/aegis-core/src/state.rs` |
| **AC-2** | O plano de boot do destino `Recovery` **desabilita** FIDO e CCID e **mantém** Management habilitado | teste de host em `crates/aegis-core/src/state.rs` |
| **AC-3** | O plano de boot do destino `Locked` **desabilita** FIDO e CCID e **mantém** Management habilitado | teste de host em `crates/aegis-core/src/state.rs` |
| **AC-4** | Coerência interna: nos destinos, FIDO e CCID são habilitados ou desabilitados **juntos** (não divergem), e o plano nunca habilita FIDO onde `fido_allowed(state)` nega | teste de host em `crates/aegis-core/src/state.rs` (cobre `Active`, `Recovery`, `Locked` e os estados não-destino) |
| **AC-5** | **Fail-closed**: para todo `ExecutionState` que não é destino de boot (`Boot`, `FidoWaitPresence`, `FidoOperation`, `Management`, `FirmwareUpdate`), o plano nega FIDO e CCID e mantém Management | teste de host em `crates/aegis-core/src/state.rs` (varredura de todos os estados) |
| **AC-6** | O destino de boot é sempre um sucessor **legal** de `Boot`: `ExecutionState::Boot.transition(boot_destination(b))` é `Ok(...)` para `b ∈ {true, false}`; o firmware executa essa transição ao expressar o destino do boot | teste de host em `crates/aegis-core/src/state.rs` |
| **AC-7** | **Stores selados**: em `Recovery`/`Locked` o plano **não autoriza** abrir o store selado de credenciais FIDO nem os stores selados dos applets; em `Active` autoriza. No firmware, a chamada de abertura só ocorre quando o caminho está habilitado — isto é, em Recovery/Locked **nenhum** `SealedCredentialStore::open` / `SealedPivStore::open` / `SealedOathStore::open` / `SealedOpenPgpStore::open` é executado | teste de host (flags do plano) + *(firmware/estático)*: `fido_task`/`ccid_task` não são iniciados quando o plano nega o caminho, e o ponto de abertura é condicionado ao plano (revisão + `cargo build-fw`) |
| **AC-8** | O Management HID **não é afetado** pelo gating: continua habilitado no plano de todos os destinos, e os testes existentes de `GET_STATUS` (`0x09`) e `GET_DIAGNOSTICS` (`0x0A`) continuam verdes (diagnóstico e firmware update permanecem disponíveis em Recovery) | teste de host: suíte existente de `crates/aegis-core/src/management_protocol.rs` + flags do plano |
| **AC-9** | *(firmware/estático)* O boot do firmware com BOOTSEL mantido **não inicia** `fido_task` nem `ccid_task`, **mantém** `housekeeping` e `otp_task`, e registra no log de boot o destino e o plano aplicado; nenhum caminho de store selado é alcançado. O boot normal (sem BOOTSEL) é **inalterado** — FIDO e CCID seguem ativos | `cargo clippy-fw` + `cargo build-fw` + grep documentado dos pontos de abertura + log de boot |
| **AC-10** | *(hardware pendente)* Com BOOTSEL mantido no boot: as interfaces FIDO e CCID **enumeram mas não respondem**; o Management HID responde `GET_STATUS` e `GET_DIAGNOSTICS`; após um power cycle normal, FIDO volta a responder normalmente | procedimento em `validation.md` (pendente de RP2350 físico) |
| **AC-11** | **Diagnóstico do plano**: `GET_DIAGNOSTICS` (0x0A) informa o destino do boot e os caminhos servidos — `boot_destination` (chave CBOR 0x08, código de `ExecutionState`), `fido_enabled` (0x09) e `ccid_enabled` (0x0A) — para que um dispositivo silenciado pelo plano seja distinguível de um dispositivo quebrado. Sem plano registrado, o relatório é **fechado** (`fido_enabled`/`ccid_enabled` falsos) | teste de host em `crates/aegis-core/src/management_protocol.rs` (`diagnostics_report_shows_the_boot_plan`) e em `crates/aegis-core/src/recovery.rs` (`diagnostics_report_shows_the_denied_paths_in_recovery`) |
| **AC-12** | **Leitura estável do BOOTSEL**: o destino do boot é decidido por 3 amostras do pad (1 ms de intervalo); uma leitura instável é tratada como "solto" e registrada em log, para que um falso positivo não coloque o dispositivo em `Recovery` e o deixe mudo. A escolha é *fail-open* deliberada em direção a `Active` — o Recovery continua acessível pelo bootrom (BOOTSEL mantido no reset) | *(firmware/estático)*: `read_bootsel_stable` em `crates/firmware-universal-rp2350/src/main.rs` + `cargo clippy-fw` + `cargo build-fw` |

---

## 6. Plano de teste

### 6.1 Onde ficam os testes

Todos os testes de host desta fatia ficam em **`crates/aegis-core/src/state.rs`**
(módulo `#[cfg(test)] mod tests`), ao lado dos testes existentes de
`boot_destination` / `fido_allowed` — é o mesmo tipo de dado e o mesmo
módulo. Os AC-11 acrescenta dois testes de host: um em
`crates/aegis-core/src/management_protocol.rs` (o serviço publica o plano) e um
em `crates/aegis-core/src/recovery.rs` (o relatório carrega o plano). O AC-12 é
estático: a rotina de leitura estável vive no firmware, que não é
host-testável.

### 6.2 Como os casos são montados

- O caso é **puramente funcional**: constrói-se o destino (`Active`,
  `Recovery`, `Locked`) e verifica-se o plano derivado. Sem HAL, executor,
  storage ou mock de USB.
- Varredura de estados: usa-se a lista de todos os `ExecutionState` (o padrão
  já existente `ALL` em `state.rs`) para o AC-5 e para o AC-4 (coerência com
  `fido_allowed`).
- Reuso do par de funções já testado
  (`boot_destination(true) == Recovery`, `boot_destination(false) == Active`)
  para o AC-6 e para derivar os casos `Active`/`Recovery` a partir do mesmo
  destino que o firmware usa.
- Nomes de teste sugeridos (sugestões; o implementador pode ajustar):
  - `boot_plan_active_enables_fido_ccid_management`
  - `boot_plan_recovery_denies_fido_ccid_keeps_management`
  - `boot_plan_locked_denies_fido_ccid_keeps_management`
  - `boot_plan_fido_and_ccid_never_diverge`
  - `boot_plan_never_enables_fido_where_fido_allowed_denies`
  - `boot_plan_is_fail_closed_for_non_destination_states`
  - `boot_destination_is_always_a_legal_successor_of_boot`
  - `boot_plan_denies_sealed_stores_outside_active`
- O Management HID não precisa de teste novo: a suíte existente de
  `aegis-core::management_protocol` (`GET_STATUS`, `GET_DIAGNOSTICS`) é a
  evidência do AC-8 (regressão verde).

### 6.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-core --all-targets -- -D warnings
cargo test -p aegis-core
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
cargo clippy -p aegistoken-host --all-targets -- -D warnings
cargo test -p aegistoken-host
```

Firmware (a fatia toca `firmware-universal-rp2350/src/main.rs`):

```powershell
cargo clippy-fw
cargo build-fw
```

Verificação estática do AC-7/AC-9 (registrada no relatório de gates):

```powershell
rg -n "SealedCredentialStore::open|SealedPivStore::open|SealedOathStore::open|SealedOpenPgpStore::open" crates/firmware-universal-rp2350/src/main.rs
```

O resultado esperado é que **todas** as ocorrências estejam dentro de
`fido_task` / `ccid_task` e condicionadas ao plano; nenhuma abertura
ocorre quando o caminho está negado.

---

## 7. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-core/src/state.rs` | **Novo** tipo de plano de boot (decisão de política) + flags de autorização de store selado + testes de host dos AC-1..AC-6 |
| `crates/aegis-core/src/recovery.rs` | **Relatório de diagnóstico**: novos campos `boot_destination` (0x08), `fido_enabled` (0x09) e `ccid_enabled` (0x0A) + o plano no construtor do relatório (AC-11) |
| `crates/aegis-core/src/management_protocol.rs` | O serviço de Management recebe o plano do boot (`set_boot_plan`) e o publica no diagnóstico; o plano padrão é **fechado** (AC-11) |
| `crates/firmware-universal-rp2350/src/main.rs` | **Região de boot** (`main()`): calcular destino → plano, logar, e **não iniciar** `fido_task`/`ccid_task` quando negados; condicionar a abertura dos stores selados; leitura estável do BOOTSEL (AC-12); registrar o plano no serviço de Management (AC-11). Não tocar nas regiões de caminho FIDO (outra sessão) |
| `roadmap.md` | Fase 9 "Pendências": registrar que o gating por destino de boot foi entregue; registrar o que permanece (execução on-device da `RecoverySession`, limpeza de credenciais no factory reset) |
| `validation.md` | Nova linha na matriz de AC + subseção da fatia com o AC de hardware e o procedimento; registrar a limitação "interfaces enumeram mas não respondem" |
| `docs/security-model.md` | Confirmar/reforçar a invariante de Recovery: "Recovery nega FIDO/CCID/credenciais"; declarar que a deny-list é aplicada no boot pelo plano e que Management (diagnóstico + update) permanece |
| `CONTEXT.md` | Known gaps: o gap "Recovery nega FIDO/CCID" **fecha no nível de boot**; permanecem abertos a execução on-device da `RecoverySession`, a limpeza de credenciais no factory reset e a supressão da enumeração USB |
| `docs/architecture.md` | Opcional: alinhar o diagrama/tabela de caminhos com o gating de boot (somente se o implementador já estiver na área) |

Nada é alterado em `crates/aegis-core/src/authenticator.rs`,
`crates/aegis-applets/**` ou `crates/board-generic-rp2350/**`.

---

## 8. Documentação a atualizar (na mesma mudança)

1. **`roadmap.md` (Fase 9 — "Pendências", `roadmap.md:660-664`)** — o item
   "a execução de `RecoverySession` on-device e a limpeza de credenciais no
   factory reset dependem do refactor de compartilhamento de storage" passa a
   ser **parcialmente resolvido**: o *gating* (Recovery/Locked não servem
   FIDO/CCID e não abrem stores selados) está entregue nesta fatia; a
   *execução da sessão de recovery* e a *limpeza de credenciais* continuam
   pendentes. Registrar também o item entregue em "Entregáveis" (plano de boot
   no núcleo + gating no boot do firmware).
2. **`validation.md`** — adicionar o AC da fatia à matriz (método = testes de
   host de `aegis-core::state` + build/estático do firmware) e uma subseção
   "Recovery/Locked não servem FIDO/CCID (host; hardware pendente)" com o
   procedimento físico:
   - flash do firmware (`scripts/build-uf2.ps1`);
   - **manter BOOTSEL pressionado durante o power cycle**;
   - esperar a enumeração e registrar que as interfaces FIDO (usage page
     `0xF1D0`) e CCID enumeram;
   - `python scripts/validate_fido.py` → **deve falhar/timeout** (sem
     resposta);
   - `python scripts/validate_ccid.py` (ou `opensc-tool -l` + seleção de AID)
     → **deve falhar/timeout**;
   - `python scripts/validate_management.py` → `GET_STATUS` e
     `GET_DIAGNOSTICS` **devem responder**;
   - power cycle **sem** BOOTSEL → `validate_fido.py` volta a passar.
   Registrar explicitamente a limitação: **as interfaces continuam
   enumerando**; a supressão da enumeração é não-objetivo.
3. **`docs/security-model.md`** — reforçar a invariante de isolamento de
   caminhos: a deny-list de Recovery/Locked é aplicada **no boot**, antes de
   qualquer abertura de store selado, e cobre FIDO e CCID; Management
   (diagnóstico + update) permanece disponível.
4. **`CONTEXT.md`** — atualizar o bloco "Known gaps" (o gap de Recovery/FIDO/
   CCID fecha no nível de boot; os demais permanecem) e, se útil, uma linha
   em "Key facts for edits" sobre o plano de boot.
5. **`AGENTS.md`** — apenas se a regra de "Recovery nega FIDO/CCID" precisar
   de um ponteiro para o mecanismo (plano de boot em `aegis-core::state`);
   leitura opcional.

---

## 9. Riscos e limitações

### 9.1 Riscos de implementação

- **R1 — Concorrência de edição em `main.rs`.** Outra sessão do loop altera
  `crates/firmware-universal-rp2350/src/main.rs` (caminhos FIDO) e
  `roadmap.md`/`validation.md`. Esta fatia toca **apenas** a região de boot
  (cálculo do destino/plano e o `join3`) e deve evitar as regiões de caminho
  FIDO. Risco de conflito de merge → resolver no rebase, sem sobrescrever
  trabalho alheio.
- **R2 — `roadmap.md`/`validation.md` editados pelas duas sessões.**
  Convergir para o mesmo par de arquivos: usar diffs pequenos e localised
  (inserções pontuais), sem reescrita de seções inteiras, e reconciliar no
  rebase.
- **R3 — Regressão de comportamento no boot normal.** O caminho `Active` é o
  mais comum; qualquer erro no gating deixa o dispositivo sem FIDO/CCID após
  um update. Mitigação: o plano em `Active` habilita tudo (AC-1) e o boot
  normal é coberto por `validate_fido.py` / `validate_ccid.py` em hardware
  (pendente) e pelos testes de host.
- **R4 — Recuperação do usuário a partir do Recovery.** Com o gating, um
  device em Recovery **não** volta a servir FIDO/CCID por "esperar a USB
  reenumerar". Como se sai do Recovery? O caminho de saída previsto é o
  **power cycle sem BOOTSEL mantido** (o destino volta a ser `Active`), ou o
  firmware update signed (que já é permitido em Recovery) seguido de reboot.
  Isso precisa estar documentado em `README.md`/`validation.md` para não
  gerar a impressão de que o dispositivo "travou em Recovery". Requisito de
  UX, não de código, nesta fatia.
- **R5 — Compatibilidade com o update de firmware.** O caminho de update
  (Management HID → `FIRMWARE_UPDATE`) roda em Recovery e **não** é afetado
  pelo gating; a imagem nova é validada e deixada em staging, e o próximo boot
  sem BOOTSEL sobe em `Active`. O update não pode ser usado como caminho para
  reabilitar FIDO/CCID dentro da mesma sessão de Recovery — isso é
  intencional (não-objetivo 5).
- **R6 — Store selado aberto por outro caminho.** `selftest.rs:182` também
  abre um `SealedCredentialStore` (teste destrutivo, atrás da feature
  `selftest`). Confirmar que o selftest destrutivo **não** roda em produção
  e que ele não é uma via de leitura de credenciais em Recovery; se o
  implementador identificar risco, tratar como slice própria.

### 9.2 Limitações

- **L1 — Sem hardware neste ciclo.** Os ACs são de host/estático; a
  verificação em dispositivo físico (boot com BOOTSEL mantido → FIDO/CCID sem
  resposta, Management respondendo) fica como **pendência em
  `validation.md`**, com o procedimento descrito.
- **L2 — As interfaces continuam enumerando.** O efeito observável é
  "enumerado e mudo": um host ainda vê o dispositivo FIDO/CCID no USB e pode
  tentar falar com ele (com timeout). Suprimir a enumeração exigiria mexer
  nos descritores/composição de interfaces — **não-objetivo**.
- **L3 — O HID OTP de laboratório continua ativo em Recovery.** É diagnóstico
  read-only (`otp_lab::handle_report`) e não expõe segredo, mas é uma
  interface acesa que não é estritamente "diagnóstico + update" no sentido do
  Management. Decisão consciente, registrada aqui; se a política for
  "Recovery só serve Management", isso vira slice própria.
- **L4 — `Locked` e `Recovery` compartilham a mesma política** (negam
  FIDO/CCID, mantêm Management). `Locked` ainda **não** é alcançável pelo
  firmware nesta fatia: o destino de boot é `Active` ou `Recovery`
  (`boot_destination`); `Locked` é coberto pela política e pelos testes, e
  passa a ser observável quando o fluxo de lockout for implementado.
- **L5 — A `RecoverySession` continua sem execução on-device.** O gating
  garante o isolamento de caminhos, mas não substitui a sessão de recovery
  (auditoria, transições, saída do estado) — follow-up maior.
- **L6 — Sem segredo novo, sem material novo.** O plano de boot não lida com
  chaves; a raiz de OTP continua sendo a única fonte de material selado, e o
  plano apenas decide se os stores selados são abertos.

### 9.3 Impacto no produto (comportamento observável)

- Um device em Recovery passa a **não responder** em FIDO e CCID. Clientes
  que dependiam indevidamente da interface viva nesse estado verão timeouts
  em vez de respostas CTAP/CCID — que é exatamente o comportamento exigido,
  mas deve ser comunicado nas notas de release (`CHANGELOG.md`).
- Management HID, diagnóstico e update **não** mudam.
- O boot normal **não** muda.
