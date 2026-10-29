# Spec — PIV: persistência de PIN/PUK fail-closed (`6A84` + piso sticky por slot)

> **Origem:** achado **MÉDIO** do `sec-audit` (loop de hardening de segurança),
> registrado como follow-up na Fase 14 do `roadmap.md` ao entregar a fatia
> irmã OpenPGP S5.
> **Risco:** MÉDIO — uma falha de gravação na store do PIV baixa o estado do
> applet **fail-open**: o decremento do PIN/PUK (ou o hash novo, ou o unblock)
> vive só em RAM e o próximo `SELECT` recarrega o estado persistido anterior,
> que é **mais permissivo**; pior, duas operações confirmam `9000` sem que a
> mutação tenha sobrevivido. Fatia única, fechada, em `aegis-applets`; todos os
> ACs são de host (a indução de falha de flash em hardware não é exercida neste
> ciclo — pendência registrada em `validation.md`).

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- **A store pode falhar e ninguém vê.** `PivStore::write` retorna `bool`
  (`piv.rs`, trait `PivStore`); `write_pin_slot` propaga o resultado do encode
  e da escrita (`piv.rs`, `fn write_pin_slot`). `persist_pin` clona os dois
  slots, grava **os dois records** e **descarta os dois booleanos**
  (`piv.rs`, `fn persist_pin`):
  `self.write_pin_slot(RECORD_PIN, &pin); self.write_pin_slot(RECORD_PUK, &puk);`.
  A falha real existe: `SealedPivStore::write` devolve `false` quando
  `load_meta`/`store_meta` falham (`sealed.rs`, `impl PivStore for
  SealedPivStore`); `MemoryPivStore::write` só falha por capacidade/tamanho
  (`piv.rs`, `impl PivStore for MemoryPivStore`) — por isso **nenhum teste
  atual vê falha de gravação**: a suíte PIV usa exclusivamente
  `MemoryPivStore`.
- **O reload é programático, não só power cycle.** `Piv::select` →
  `select_response` → `load_state`, que reprovisiona e relê `RECORD_PIN`,
  `RECORD_PUK` e `RECORD_MGMT_KEY` (`piv.rs`, `fn select_response`,
  `fn load_state`). Uma pilha CCID seleciona o AID a cada operação: o
  "power cycle" do ataque é um `SELECT` — não há piso sticky que segure o
  contador consumido na sessão.
- **`VERIFY`** (INS `0x20`; `piv.rs`, `fn verify`): em `REF_PIN`, decrementa
  via `PinSlot::verify` e chama `persist_pin()` incondicionalmente — **inclusive
  no sucesso e no `VERIFY` vazio**, quando nada persistível mudou — e devolve o
  SW do slot; em `REF_PUK`, idem. Com a gravação falhando, a resposta é
  `63Cx` (ou `9000`) e o contador persistido continua cheio.
- **`CHANGE REFERENCE DATA`** (INS `0x24`; `fn change_reference_data`):
  `slot.change(current, new)` (que consome uma tentativa no corrente errado e,
  no sucesso, troca o hash e restaura o contador) seguido de `persist_pin()`
  descartado e `9000`. Duas consequências: (a) o hash novo não persiste e o
  **PIN antigo volta a valer** após o próximo `SELECT` — o operador foi
  informado de uma troca que não sobreviveu; (b) o decremento do corrente
  errado não persiste e o orçamento volta.
- **`RESET RETRY COUNTER`** (INS `0x2C`; `fn reset_retry_counter`):
  - o `verify` do PUK no corpo decrementa o contador de PUK em falha e chama
    `persist_pin()` descartado → `63Cx` sem persistência do decremento
    (orçamento de PUK ressuscitado por `SELECT`);
  - a recusa de comprimento do PIN novo responde `6985` **depois** de um save
    que não tinha nada a gravar (o `verify` do PUK no sucesso não repõe
    contador);
  - `pin.unblock` + `persist_pin()` descartado + `9000`: o operador vê o
    desbloqueio confirmado, mas o estado persistido continua **bloqueado** —
    lockout do usuário após um `RESET` "bem-sucedido".
- **Não há backoff/lockout próprio do PIV.** O único bloqueio é
  `PinSlot::retries_remaining == 0` (`pin.rs`, `PinSlot::is_blocked`) →
  `6983` nas tentativas seguintes; não existe temporizador de backoff,
  `SET PIN RETRIES` nem estado de bloqueio paralelo. O domínio de PIN do PIV é
  o mesmo do OpenPGP (`PinSlot`, `PIV_PIN_POLICY` = 6–8 bytes, 3 tentativas,
  SHA-256).
- **O contrato persistido existe:** `docs/security-model.md:137-139` —
  *"PIN state is persistent and fail-closed… every failed attempt decrements
  before any other work"* — e a fatia OpenPGP S5 já materializou o lado
  OpenPGP (`docs/security-model.md:164-176`), deixando o PIV como follow-up.

### 1.2 Caminho de exploração

1. O atacante tem o dispositivo e fala CCID com o applet PIV.
2. A gravação do estado falha (flash desgastado, interrupção, erro de escrita).
   Hoje isso é **silencioso**: o `bool` de `write_pin_slot` é jogado fora.
3. Chuta o PIN errado: a resposta é `63C2`/`63C1`/`63C0` e o usuário bloqueia;
   mas o contador decrementado morreu em RAM.
4. Qualquer `SELECT` do AID (a próxima ferramenta, o próximo `ykman`) relê o
   contador cheio. Repetindo (chute ×3 → `SELECT`), o palpite do PIN é
   **ilimitado** — e o mesmo vale para o PUK no corpo do `RESET RETRY COUNTER`,
   cujo decremento também não persiste.
5. Nas mutações confirmadas: `CHANGE` responde `9000` com o hash novo só em
   RAM (o PIN antigo ressuscita no `SELECT` seguinte) e `RESET RETRY COUNTER`
   responde `9000` sem levantar o bloqueio persistido — o usuário fica
   trancado fora do cartão achando que o desbloqueou.

**Impacto:** quebra do *fail-closed* do ciclo de PIN do PIV — o dispositivo
aceita um fluxo de mutação que não é cumulativo com o estado persistido e a
falha é invisível para o operador. A gravidade é limitada por: a falha exige um
evento físico adverso (flash real que falha), `MemoryPivStore` nunca falha e o
`RESET` já exige o PUK (`PinSlot::unblock` documenta que a autorização é do
chamador). Por isso **MÉDIO** e não ALTO/CRÍTICO — mas o custo de correção é
baixo e a mecânica já está provada na fatia irmã.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | "PIN state is persistent and fail-closed… every failed attempt decrements before any other work" | `docs/security-model.md:137-139` | **violada** — o decremento acontece antes, mas o estado que o materializa na store pode falhar em silêncio |
| I2 | Contadores/bloqueio/unblock selados sobrevivem a power cycles e são cumulativos | `docs/security-model.md:137-139`, `roadmap.md` Fase 11 | **violada em falha de escrita** — o reload pode devolver contador mais permissivo que o já consumido na sessão |
| I3 | Autorização de unblock é do chamador (PIV verifica o PUK); `PinSlot` não faz I/O | `docs/security-model.md:146-148`, `pin.rs` (`PinSlot::change`/`unblock`) | respeitada na divisão de papéis, **falha na propagação** do resultado da persistência |
| I4 | Nenhuma mutação de PIN é confirmada sem persistir (padrão da fatia OpenPGP S5) | `docs/security-model.md:164-176`, `specs/openpgp-pin-persistence.md` | **violada** no `CHANGE` e no `RESET RETRY COUNTER` |

---

## 3. Decisões de política (documentadas nesta spec)

**1 — Forma do retorno: `bool` na primitiva de persistência, mapeado para
`Sw` no handler.** `persist_pin` passa a devolver o resultado da gravação
(`bool`, como `write_pin_slot` já faz e como o `persist_state() -> bool` da
fatia OpenPGP S5 — padrão do crate). O handler traduz `false` em
`Sw::NOT_ENOUGH_MEMORY` (`0x6A84`). `Result<(), Sw>` foi considerado e
rejeitado: colocaria política de APDU dentro do auxiliar de store e divergiria
do precedente OpenPGP/PIV (`put_data`/`set_mgmt_key` também mapeiam `bool` da
store para `6A84` em `piv.rs`). O `PinSlot` continua sem I/O e sem mudança de
assinatura.

**2 — Um record por save, escolhido pelo slot que mutou.** O PIV serializa
cada slot no seu próprio record (`RECORD_PIN`/`RECORD_PUK`,
`PivStore::write`), ao contrário do blob único do OpenPGP. Hoje
`persist_pin` reescreve **os dois** records em toda mutação (e mesmo quando
nada mudou — `VERIFY` bem-sucedido, `VERIFY` vazio, `PUK` correto no
`RESET`). A fatia grava **somente o record do slot mutado**, pela referência
que mudou (PIN ou PUK). Ganhos: (a) uma falha de save é atribuível a um record
só — não existe estado meio-gravado entre os dois slots; (b) menos desgaste;
(c) nenhum erro espúrio no caminho feliz de leitura. Consequência aceita:
**não há "heal" oportunista** — o record divergente só se reancora no próximo
save bem-sucedido que o escreva (o piso cobre o gap, decisão 3).

**3 — Piso sticky por slot: SIM, isomórfico ao OpenPGP S5.** Dois campos
voláteis de sessão — piso do PIN e piso do PUK — inicializados com o máximo da
política (`PIV_PIN_POLICY.max_attempts`), **não** persistidos e **não**
zerados por `SELECT`:

- a cada evento mutante de slot (decremento que consome tentativa, `change` ok,
  `unblock` ok) tenta-se gravar o record do slot;
  - **save ok** → o piso do slot assenta no contador atual da RAM (a verdade
    persistida é ele);
  - **save falhou** → piso do slot = `min(piso, contador atual da RAM)`;
- no reload (`load_state`, depois do `provision`) cada slot decodificado é
  clampeado para `min(restaurado, piso)`.

*Fundamento no PIV:* sem o piso, o ataque precisa de **um `SELECT`**, não de um
power cycle — o `select_response` relê a store sempre, e as pilhas CCID
selecionam o AID por operação. O PIV não tem backoff, temporizador nem estado
de bloqueio alternativo (o bloqueio é `retries_remaining == 0` → `6983`), logo
não há mecanismo concorrente que justifique outro desenho: o domínio é o mesmo
`PinSlot` do OpenPGP e a regra do piso é a mesma. Efeito-alvo: um unblock que
não persistiu **não pode subir o piso** (`min(0, máximo) = 0`), então o
`SELECT` seguinte volta a bloquear — o operador nunca fica "desbloqueado" sem
persistência; e um save ok subsequente reancora o piso. Entre power cycles o
piso zera e o estado persistido governa — resíduo consciente (§10 L1).

**4 — Persistir só quando houve mutação persistível; recusas não gravam.**
Regras por handler:

- `VERIFY`: grava **apenas** se o contador do slot mudou (snapshot antes/depois
  da chamada ao slot). Sucesso (`9000`) e `VERIFY` vazio (`63Cx` de leitura) não
  gravam; recusa por bloqueio (`6983`, sem decremento) não grava.
- `CHANGE`: grava se o resultado do slot é `Ok` (hash mudou) **ou** o contador
  diminuiu (corrente errado consumiu tentativa). Recusa por bloqueio
  (`6983`, sem decremento) e recusas de parâmetro/comprimento/formatos
  anteriores não gravam.
- `RESET RETRY COUNTER`: no `verify` do PUK, grava só se o contador do PUK
  diminuiu; no unblock, grava só se ele foi `Ok`. As recusas de `P1`/`P2`,
  comprimento e comprimento do PIN novo não gravam — **inclusive o save atual
  depois da recusa `6985`** (nada mudou: o `verify` do PUK no sucesso não repõe
  contador) é removido.

Com flash saudável o comportamento observável é o de hoje; com flash doente, a
resposta deixa de confirmar mutação não persistida (decisão 5).

**5 — SW exatos: só `0x6A84` é novo, e só na falha de persistência.** A falha
de save **substitui** o SW da operação (nunca se devolve `63Cx`/`9000` com a
gravação negada), como no S5. Os demais SWs e a **ordem dos checks atuais** são
preservados (autenticação/P1 → P2 → comprimento do corpo → formato do PIN novo
→ slot → persistência):

| Caminho | Hoje | Depois |
|---------|------|--------|
| `VERIFY` `P1≠0x00`, `P2` desconhecido | `6A86` | `6A86`, sem save |
| `VERIFY` vazio (`P2`=`80`/`81`) | `63Cx` + save inútil | `63Cx`, sem save |
| `VERIFY` len ≠ 8 | `6700` | `6700`, sem save |
| `VERIFY` PIN/PUK errado (consome) | `63Cx` + save silencioso | `63Cx` se persistiu; **`6A84`** se não |
| `VERIFY` PIN/PUK correto | `9000` + save inútil | `9000`, sem save |
| `VERIFY` slot bloqueado | `6983` + save inútil | `6983`, sem save |
| `CHANGE` `P1≠0x00` | `6A86` | `6A86`, sem save |
| `CHANGE` `P2∉{80,81}` | `6A88` | `6A88`, sem save |
| `CHANGE` len ≠ 16 | `6A80` | `6A80`, sem save |
| `CHANGE` PIN novo < 6 (após `FF`) | `6985` | `6985`, sem save |
| `CHANGE` corrente errado (consome) | `63Cx` + save silencioso | `63Cx` se persistiu; **`6A84`** se não |
| `CHANGE` slot bloqueado | `6983` + save inútil | `6983`, sem save |
| `CHANGE` sucesso | `9000` + save silencioso | `9000` se persistiu; **`6A84`** se não |
| `RESET` `P1≠0x00`/`P2≠0x80` | `6A86` | `6A86`, sem save |
| `RESET` len ≠ 16 | `6A80` | `6A80`, sem save |
| `RESET` PUK errado (consome) | `63Cx` + save silencioso | `63Cx` se persistiu; **`6A84`** se não |
| `RESET` PUK bloqueado | `6983` + save inútil | `6983`, sem save |
| `RESET` PUK ok, PIN novo < 6 | `6985` + save inútil | `6985`, sem save |
| `RESET` unblock `Ok` | `9000` + save silencioso | `9000` se persistiu; **`6A84`** se não |

Flags de sessão seguem o resultado do **slot**, não o do save: um `CHANGE`
bem-sucedido em RAM mantém `pin_verified = true` (o hash novo está na RAM e o
dono apresentou o corrente) mesmo respondendo `6A84`; um `RESET` não
persistido mantém `pin_verified = false` como hoje.

**6 — Nada de novo no formato persistido.** O piso é volátil de sessão; os
records, o encoding de `PinSlot` (`PinSlot::encode`/`decode`) e a API de
`PivStore`/`SealedPivStore` não mudam. Sem novo record, sem bump de versão, sem
migração, sem depender de HAL.

---

## 4. Escopo

- `piv.rs`:
  - **dois campos de piso de sessão** (nomes à escolha do implementador, ex.
    `pin_floor`/`puk_floor`), inicializados em `Piv::new` com
    `PIV_PIN_POLICY.max_attempts` (mantendo `new` como `const fn`), não
    persistidos e não zerados por `select_response`;
  - `persist_pin`: passa a receber **qual** slot gravar (referência/record
    mutado), devolver o resultado (`bool`) e ancorar o piso desse slot (sobe a
    `contador da RAM` no sucesso, `min(piso, contador)` na falha);
  - `write_pin_slot`/`provision`: inalterados em comportamento (o
    provisionamento continua gravando os defaults e sendo clampeado no load);
  - `load_state`: após decodificar `pin`/`puk`, clampar cada slot ao seu piso
    (`min(restaurado, piso)`); o resto do load (reprovisionar, `mgmt`, retorno
    `false` → `6F00`) fica como está;
  - `verify`: grava só o slot cujo contador mudou e responde `6A84` na falha
    de save (nunca `63Cx`/`9000`); `VERIFY` vazio/correto/bloqueado e recusas
    de `P1`/`P2`/comprimento não gravam;
  - `change_reference_data`: grava só o record do `P2` mutado e responde
    `6A84` na falha (nunca `9000`/`63Cx`); recusas anteriores intactas;
  - `reset_retry_counter`: grava o PUK só se o `verify` do PUK consumiu
    tentativa; grava o PIN só no `unblock` `Ok`; remove o save após a recusa
    `6985`; responde `6A84` na falha de save no lugar do SW do slot.
- Testes de host no módulo `#[cfg(test)]` de `piv.rs` (AC-1..AC-8, §6):
  wrapper de store falhável (`FailingPivStore`) delegando a
  `MemoryPivStore`, com flag de falha de escrita e contador de escritas por
  record; helpers de teste (`run`, `get_data`, `authenticate_management`,
  `generate_key`) passam a ser genéricos sobre `PivStore` (mesmos argumentos,
  call sites existentes inalterados) para aceitar a wrapper.

## 5. Não-objetivos

1. **`OATH RESET` fail-closed** — fatia seguinte deliberada (mesma mecânica de
   persistência, arquivo próprio); **não** entra aqui.
2. **Mudar `PivStore::write` para `Result`** (nem o colapso
   `Result→bool` de `SealedPivStore::write`): a perda de detalhe da causa é
   aceita; mudança de API é fatia própria.
3. **Gravar a cada tentativa (write-ahead).** Rejeitado por desgaste de flash,
   como no S5; o piso cobre o gap intra-sessão e o resíduo entre power cycles
   é documentado (§10).
4. **Backoff/temporizador de lockout do PIV** (`SET PIN RETRIES`, delay
   progressivo, bloqueio global do cartão): o PIV não tem esse mecanismo hoje e
   esta fatia **não** o introduz — o bloqueio continua sendo
   `PinSlot` + `6983`.
5. **Persistir o piso** ou incluir estado novo no formato dos records: não.
6. **Defaults NIST** (`DEFAULT_MGMT_KEY`, `DEFAULT_PIN`, `DEFAULT_PUK` em
   `piv.rs`) e a política de PIN/PUK: intocados; são valores de interop
   (SP 800-73-4), não segredos vazados.
7. **FIDO/core/firmware/HAL**, despacho CCID, OTP/flash, `aegistoken-host`,
   scripts de validação: nenhum código tocado.
8. **Novos SWs além do `6A84` na falha de persistência**; `6982`, `6983`,
   `63Cx`, `6A80`, `6A81`, `6A82`, `6A86`, `6A88`, `6985`, `6700` preservados.
9. **Dependências novas, `unsafe` ou `std`** no crate: não.
10. **Estimativa de tentativas via resposta diferente** (`6A84` não expõe
    quantas restam): decisão consciente — a falha de gravação é reportada como
    erro de cartão, não como "PIN errado".

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host no módulo `#[cfg(test)]` de
`crates/aegis-applets/src/piv.rs`, com `MemoryPivStore` (caminho feliz) e
`FailingPivStore` (falha de escrita); nenhum exige hardware. A exceção é o
AC-8 (doc/regressão estática).

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | `VERIFY` do PIN que **consome tentativa** com store em falha: resposta `0x6A84` (nunca `63Cx`); o contador em **RAM** fica decrementado (`VERIFY` vazio → `63C2`; após três falhas, `VERIFY` com PIN → `6983`); com store íntegra o mesmo fluxo responde `63C2` e persiste | teste de host em `piv.rs` |
| **AC-2** | **Piso sticky entre re-seleções:** no cenário do AC-1, `select()` **não** ressuscita o contador (vazio → `63C2`; esgotado → `6983`); o piso do PUK é independente (o decremento do PUK também sobrevive ao `select()` e o do PIN não é afetado); com store íntegra o re-`select` mantém o comportamento atual (persistido governa) | teste de host em `piv.rs` |
| **AC-3** | **Clamp no carregamento:** um applet com piso `X` e store contendo contador `Y > X` carrega `X` (`min(Y, X)`), para PIN e PUK, inclusive sobre os defaults do `provision`; com piso no máximo o load não muda nada | teste de host em `piv.rs` (via `load_state`/`select_response`) |
| **AC-4** | `CHANGE` (PIN e PUK) com save falhando → `0x6A84`, **nunca `9000`**; na sessão o PIN novo verifica; após `select()` o **PIN antigo** volta a verificar e o novo não (estado persistido governa); corrente errado com save falhando → `6A84` com decremento em RAM (não `63Cx`); recusas de `P2`/comprimento/formato mantêm `6A88`/`6A80`/`6985` | teste de host em `piv.rs` |
| **AC-5** | `RESET RETRY COUNTER` com PUK correto e save falhando → `0x6A84`; na sessão o PIN novo verifica; após `select()` na mesma instância o PIN está **bloqueado** (`6983` — o unblock não subiu o piso), e um save bom depois do dreno re-ancora o piso (o re-`select` seguinte não gera lockout falso); o PUK não é tocado; PUK errado com save falhando → `6A84` (não `63Cx`); com store íntegra → `9000` e o desbloqueio sobrevive ao `select()` | teste de host em `piv.rs` |
| **AC-6** | **Só records mutados são escritos** (contagem por record na wrapper): `VERIFY` bem-sucedido = 0 escritas; `VERIFY` vazio = 0; `CHANGE` com corrente errado = 1 escrita em `RECORD_PIN` (ou `RECORD_PUK`) e 0 no outro; `RESET` ok = 1 em `RECORD_PIN` e 0 em `RECORD_PUK`; recusas de parâmetro/comprimento/formato/bloqueio (`6983`) = 0 escritas | teste de host em `piv.rs` |
| **AC-7** | **Superfície de SW preservada:** bloqueio (`6983`) responde `6983` mesmo com store em falha e **sem** escrita; recusas `6A86`/`6A88`/`6A80`/`6985`/`6700` inalteradas; caminho feliz com `MemoryPivStore` idêntico ao atual (`63Cx` persistido, `9000` em `CHANGE`/`RESET`, contadores sobrevivem a um applet novo sobre a mesma store); **regressão zero** na suíte existente de `aegis-applets` | teste de host em `piv.rs` + `cargo test -p aegis-applets` |
| **AC-8** | Documento de contrato atualizado: `docs/security-model.md` inclui o PIV na regra de persistência observável e do piso por slot; `roadmap.md` registra a fatia na Fase 12 e ajusta o follow-up citado na Fase 14; `validation.md` ganha a subseção PIV com a tabela de ACs (host) e a pendência física | revisão estática |

## 7. Plano de teste

### 7.1 Onde ficam

No módulo `#[cfg(test)] mod tests` existente em
`crates/aegis-applets/src/piv.rs`, reutilizando os helpers atuais: `applet()`
(cria o applet com `MemoryPivStore` + `select()`), `command()`, `run()`,
`get_data()`, `authenticate_management()`, `generate_key()` e `TestRng`. A
wrapper `FailingPivStore` vive no mesmo módulo: delega `read`/`erase` a um
`MemoryPivStore`, aceita um flag de falha de escrita, mantém contadores de
escritas por record e implementa `Default` (saudável, contadores zerados) para
permitir `core::mem::take(piv.store_mut())` na simulação de power cycle. Ela
**não** é código de produção (fica em `#[cfg(test)]`). Como `run` et al. hoje
são tipados em `Piv<MemoryPivStore>`, eles passam a ser genéricos sobre
`S: PivStore` — mudança mecânica, sem alterar asserções.

### 7.2 Como os casos são montados

- **AC-1/AC-2:** `FailingPivStore` com escrita em falha; `VERIFY` PIN errado →
  `6A84`; `VERIFY` vazio → `63C2`; `select_response()` (mesma instância; o piso
  é volátil e sobrevive) → `VERIFY` vazio → `63C2`; mais duas falhas → `6A84` e
  `VERIFY` com PIN → `6983`. Variante PUK: `VERIFY` PUK errado → `6A84`;
  `select()` → vazio do PUK → `63C2`, e o PIN segue com o contador da sessão.
  Obs.: a instanciação de um `Piv::new` novo sobre a mesma store simula o power
  cycle e **deve** repor o contador persistido — resíduo documentado no AC-8,
  não um erro.
- **AC-3:** montar um applet saudável, consumir tentativas de PIN e PUK
  (persistidas), extrair a store e criar `Piv::new(store)`; no mesmo módulo,
  assentar `pin_floor`/`puk_floor` abaixo do persistido e `select()`:
  `VERIFY` vazio reporta o valor clampeado e `VERIFY` cheio responde `6983`
  quando o piso é 0. Variante: store vazia (o `provision` grava defaults cheios)
  com piso rebaixado → o load já vem clampeado.
- **AC-4:** com falha de escrita, `CHANGE` PIN com `atual‖novo` → `6A84`; o PIN
  novo verifica in-session; `select()` → o antigo verifica (`9000`) e o novo
  `63Cx`. Variante PUK (`P2=0x81`); variante corrente errado → `6A84` e vazio
  depois → `63C2`.
- **AC-5:** com store íntegra, esgotar o PIN (persistido); ligar a falha; `RESET`
  com PUK correto + PIN novo → `6A84`; o PIN novo verifica in-session;
  `select_response()` na mesma instância → `VERIFY` (novo ou qualquer) → `6983`; o simétrico: dreno com falha + `RESET` saudável → `select()` → o PIN novo verifica (piso re-ancorado); `VERIFY` vazio do PUK
  mostra o PUK intacto. Variante saudável: `RESET` → `9000` e um `Piv::new` novo
  sobre a store aceita o PIN novo. Variante PUK errado com falha → `6A84`.
- **AC-6:** zerar os contadores da wrapper depois do `applet()` (o `provision`
  do primeiro `select` escreve 3 records); exercitar cada caminho e comparar
  `writes(RECORD_PIN)`/`writes(RECORD_PUK)`. Inclui `CHANGE` com corrente
  errado (1 escrita no slot alvo), `VERIFY` correto (0) e as recusas (0).
- **AC-7:** rede de regressão: repetir com `MemoryPivStore` os fluxos de
  `verify_accepts_the_default_pin_and_tracks_retries`,
  `change_pin_requires_the_current_value`,
  `reset_retry_counter_unblocks_with_the_puk` e
  `retry_counter_survives_a_reopen` (persistência comprovada por applet novo
  sobre a mesma store), além de `6983`/`6A86`/`6A88`/`6A80`/`6985` com store em
  falha.
- Nomes sugeridos (o implementador pode ajustar):
  `verify_with_failing_store_reports_the_save_error_and_keeps_the_ram_counter`,
  `pin_floor_survives_reselect`,
  `puk_floor_survives_reselect_independently`,
  `reload_never_climbs_above_the_session_floor`,
  `change_with_failing_store_never_fakes_success`,
  `reset_with_failing_store_never_confirms_the_unblock`,
  `refusals_do_not_write_pin_records`,
  `successful_verify_does_not_write`,
  `blocked_slot_answers_6983_without_writing`,
  `happy_path_persists_the_three_handlers`.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

(Somente `aegis-applets` é tocado em código; os gates dos demais crates seguem
verdes por regressão. Nenhum arquivo de firmware/HAL muda, então
`cargo build-fw` não é exigido por esta fatia.)

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/piv.rs` | Campos de piso de sessão em `Piv`; `persist_pin` por record com retorno e ancoragem do piso; clamp em `load_state`; `verify`/`change_reference_data`/`reset_retry_counter` gravam só o slot mutado e respondem `6A84` na falha; testes de host AC-1..AC-7 e a wrapper `FailingPivStore` |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | Documentação na mesma mudança (§9) |

Nada é alterado em `crates/aegis-core/**`,
`crates/firmware-universal-rp2350/**`, `crates/board-generic-rp2350/**` ou
`crates/aegistoken-host/**`; nenhum despacho de firmware e nenhuma mudança de
API de store (`sealed.rs` fica como está — não-objetivo 2).

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — na invariante "PIN state is persistent and
   fail-closed" (`security-model.md:137-176`), estender a regra de persistência
   observável ao PIV: `VERIFY` que consome tentativa, `CHANGE REFERENCE DATA`
   e `RESET RETRY COUNTER` respondem **`6A84`** quando a gravação do record
   falha; o estado em RAM nunca sobe acima do último persistido/consumido da
   sessão (**piso sticky por slot**, aqui por record — PIN e PUK independentes);
   `VERIFY` bem-sucedido e recusas não gravam. Registrar os trade-offs
   (piso intra-sessão; entre power cycles o persistido governa; write-ahead
   rejeitado por desgaste) como **comportamento**, não como gap.
2. **`roadmap.md`** — na Fase 12 (PIV), acrescentar a sub-fatia de persistência
   fail-closed entregue (piso sticky + `6A84`, save por record, remoção do save
   inútil no `RESET`) com a contagem de testes; na Fase 14 (bullet "OpenPGP S5"),
   ajustar a frase que registra o PIV como follow-up para "entregue em
   `specs/piv-pin-persistence.md`", mantendo a rastreabilidade.
3. **`validation.md`** — na seção "PIV (Fase 12)" (~`validation.md:162`),
   adicionar a subseção da fatia com a tabela de ACs (método: testes de host de
   `aegis-applets::piv`; status **Verificado em host**) e registrar a pendência
   física: a falha de gravação não é induzida em hardware (o
   `validate_piv.py` não simula flash doente), ficando pendente o caso
   "mutação de PIN/PUK com gravação negada → `6A84`" e a observação de que a
   interop `pivy`/OpenSC segue a mesma dos ACs de host; nada muda no script
   neste ciclo.

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Interoperabilidade do novo SW.** Sob flash doente, o `VERIFY` deixa de
  devolver `63Cx` e responde `6A84`; `pivy`/OpenSC/`yubico-piv-tool` tratam
  como erro do cartão (não como "PIN errado") — correto e defensável, mas a
  confirmação fica para a validação física (`validate_piv.py`).
- **R2 — Granularidade da store selada.** `SealedPivStore` mapeia os records
  1/2/3 no **mesmo** cell de metadados: cada `write` serializa o mapa inteiro
  (`sealed.rs`, `impl PivStore for SealedPivStore`). Gravar um record já
  reescreve o cell de meta, então o ganho de desgaste é "uma escrita em vez de
  duas" por mutação — não "uma célula só". A atribuição de falha continua por
  record (o applet só pede um), mas o formato físico não muda nesta fatia.
- **R3 — Concorrência de edição.** Outras sessões tocam `roadmap.md` e
  `validation.md`; manter diffs pontuais. `piv.rs` é grande e a suíte PIV é
  extensa: a genericização dos helpers de teste é mecânica, mas deve ser feita
  sem tocar asserções (AC-7 é a rede).
- **R4 — `CHANGE`/`RESET` respondendo `6A84` no corrente errado.** O host perde
  a contagem `63Cx` daquele comando quando a gravação falha; é intencional
  (não se confirma estado não persistido), porém muda o que ferramentas
  exibem numa store doente. Documentado e coberto pelo AC-4/AC-5.

### 10.2 Limitações

- **L1 — Piso cobre a sessão, não o ciclo de energia.** Um power cycle zera o
  piso e o estado persistido governa; se a gravação de uma tentativa falhou
  repetidamente, o atacante com disposição a ciclos de energia recupera aquele
  orçamento. Mitigação: a falha é observável (`6A84`) e qualquer save
  bem-sucedido reancora o piso; o trade-off (desgaste) está no não-objetivo 3 e
  em `docs/security-model.md` — é o modelo de degradação física, não um furo
  novo.
- **L2 — Sem hardware neste ciclo.** ACs exclusivamente de host; nenhum
  `cargo build-fw` (nada de firmware/HAL é tocado). A indução de falha de
  escrita em flash real fica pendente em `validation.md`.
- **L3 — `MemoryPivStore` nunca falha** por construção; os ACs exigem a wrapper
  `FailingPivStore`, que não entra no build normal do crate.
- **L4 — Sem segredo novo e sem material novo.** A fatia não adiciona estado
  persistente, não muda o encoding de `PinSlot` nem a API de `PivStore`; só
  adiciona estado volátil de sessão e um erro observável. Os defaults NIST
  (`DEFAULT_PIN`/`DEFAULT_PUK`/`DEFAULT_MGMT_KEY`) permanecem como estão.
- **L5 — Fronteira de autoridade do `RESET` inalterada.** A autorização
  continua sendo o PUK no corpo (`PinSlot::unblock` documenta que a autorização
  é do chamador); nenhuma sessão administrativa nova é introduzida.
