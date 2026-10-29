# Spec — OpenPGP: persistência de PIN/contador fail-open (piso sticky e SW de erro)

> **Origem:** achado **MÉDIO** do `sec-audit` (loop de hardening de segurança).
> **Risco:** MÉDIO — uma falha de gravação na store selada baixa o estado do
> applet **fail-open**: o contador de tentativas (ou o PIN trocado, ou o unblock)
> fica só em RAM, e um reload restaura o estado persistido anterior, que é
> **mais permissivo**. Fatia única, fechada, em `aegis-applets`; todos os ACs
> são de host (a indução de falha de flash em hardware não é exercida neste
> ciclo — pendência registrada em `validation.md`).

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- **A store pode falhar e ninguém vê.** `OpenPgpStore::save` retorna `bool`
  (`crates/aegis-applets/src/openpgp.rs:105`); `save_state` devolve esse valor
  (`openpgp.rs:407-435`). Quatro handlers de mutação **descartam** o resultado:
  - `verify` (INS `0x20`; `openpgp.rs:584-609`) — após `slot.verify(...)`
    (decremento do contador em falha), chama `self.save_state()` (`openpgp.rs:599`),
    incondicionalmente e sem usar o valor;
  - `verify_change` (CHANGE REFERENCE DATA, INS `0x21`; `openpgp.rs:1549-1561`) —
    idem (`openpgp.rs:1559`);
  - `reset_retry` (INS `0x2C`; `openpgp.rs:1563-1582`, já reescrito pela fatia
    `openpgp-unblock-auth`, que exige `pw3_verified` em `openpgp.rs:1573-1575`) —
    idem (`openpgp.rs:1580`);
  - `put_data` (INS `0xDA`; `openpgp.rs:960-986`) — persiste DOs aceitos
    (name/language/sex/URL/certificado/algo/D2) e descarta o save
    (`openpgp.rs:980-982`). Nota de correção ao achado: **não existe** caminho
    de PUT DATA para o PW status (`0x00C4` é só GET DATA, `openpgp.rs:647`);
    o fail-open do `put_data` vale para os DOs aceitos e para `put_algo`/D2.
- **O reload é programático, não só power cycle.** `select()` reseta `loaded`
  e recarrega o estado do store (`openpgp.rs:1590-1592`; `ensure_loaded`,
  `openpgp.rs:391-405`; `decode_state` restaura `self.pw1`/`self.pw3` em
  `openpgp.rs:572-573`). Ou seja: o "power cycle" do ataque é apenas um
  **SELECT** — qualquer pilha de OpenPGP o envia a cada abertura de aplicação.
- **Precedente de referência já existe no próprio crate.** No applet OpenPGP os
  caminhos de escrita de chave e de assinatura **já propagam** a falha de
  `save_state()` com `Sw::NOT_ENOUGH_MEMORY` (`openpgp.rs:1125-1127`,
  `1146-1148`, `1237-1239`, `1258-1260`, `1285-1287`). O OATH propaga na
  maioria dos mutadores (`oath.rs:384`, `401`, `503`, `526`, `557`, `585`). O
  PIV é fail-open igual — `persist_pin()` retorna `()`
  (`piv.rs:528-533`) — e **não** é o padrão a copiar aqui (fica registrado
  como follow-up em `roadmap.md`, fora desta fatia).
- O contrato persistido existe: `docs/security-model.md:137-139` —
  *"PIN state is persistent and fail-closed. Retry counters, blocked states and
  unblock flows are sealed with the OTP-derived key and survive power cycles;
  every failed attempt decrements before any other work."*
- Contadores: `PinSlot::verify` decrementa em falha (`pin.rs:220-221`), sucesso
  **não** restaura o contador (`pin.rs` testes, `a_successful_verify_does_not_reset_retries`);
  `set`/`unblock` restauram o máximo da política (`pin.rs:193-198`).

### 1.2 Caminho de exploração

1. O atacante tem o dispositivo e fala CCID com o applet OpenPGP.
2. A gravação do estado selado falha (flash desgastado, interrupção, erro de
   escrita). Hoje isso é **silencioso**: `save_state()` devolve `false` e é
   descartado.
3. O atacante chuta o PW1 errado até o bloqueio observado (`6983`). O decremento
   morreu em RAM; a store ainda contém o contador cheio.
4. Um `SELECT` do AID recarrega o estado do store — contador restaurado. O
   atacante não precisa nem de power cycle: basta re-selecionar.
5. Repetindo (chute ×3 → SELECT), o palpite é **ilimitado** apesar do contador
   de política de 3 tentativas. No caso de `reset_retry`: um unblock autenticado
   que não persiste vira in-session-hack de reabilitação do PW1; no caso de
   `verify_change`, o PIN novo vive só em RAM (estado divergente, sem erro
   reportado ao operador).

**Impacto:** quebra do *fail-closed* do ciclo de PIN do applet OpenPGP — o
dispositivo aceita um fluxo de mutação de PIN que **não** é cumulativo com o
estado persistido, e a falha é invisível para o operador. A gravidade é limitada
por: a falha de gravação exige um evento físico adverso (flash real que falha),
a store `MemoryOpenPgpStore` nunca falha e o unblock exige `pw3_verified` — por
isso **MÉDIO** e não ALTO/CRÍTICO. Mas o custo de correção é baixo e a mecânica
do piso ("o estado restaurado nunca sobe acima do último persistido/consumido")
também.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | "PIN state is persistent and fail-closed… every failed attempt decrements before any other work" | `docs/security-model.md:137-139` | **violada** — o decremento acontece antes, mas o estado que o materializa na store pode falhar em silêncio |
| I2 | Contadores/bloqueio/unblock selados sobrevivem a power cycles e são cumulativos | `docs/security-model.md:137-139`, `roadmap.md:1043-1052` | **violada em falha de escrita** — o reload pode devolver um contador mais permissivo que o já consumido na sessão |
| I3 | A persistência do applet pertence ao handler; `PinSlot` não faz I/O | `AGENTS.md` (fronteiras `aegis-applets`), `piv.rs`/`oath.rs` como padrão do crate | respeitada na divisão de papéis, **falha na propagação** do resultado |

---

## 3. Decisões de política (documentadas nesta spec)

**1 — SW de erro: `Sw::NOT_ENOUGH_MEMORY` (`0x6A84`), não `0x6581`.** O achado
sugeria `0x6581 MEMORY_FAILURE` ou `0x6985`; **`0x6581` não existe na tabela
`Sw` do repositório** (`crates/aegis-applets/src/apdu.rs:38` define
`NOT_ENOUGH_MEMORY = 0x6A84`) — e o applet OpenPGP já usa `0x6A84` para falha
de persistência em `generate`/`sign` (`openpgp.rs:1125-1127` et seq.),
igualmente PIV (`piv.rs:609`/`833`) e OATH (`oath.rs:384+`). Consistência vence:
**toda** falha de `save_state()` nos quatro handlers responde `0x6A84`.
O `0x6A84` substitui o SW da operação (não se devolve `63Cx` ou `9000` com
falha de gravação subjacente): a falha tem de ser **observável** — o
operador/dono vê o erro e o atacante não recebe "nada aconteceu".

**2 — Sticky restritivo, não rollback.** Ao falhar o save, o estado em RAM do
slot (contador decrementado, hash novo de `verify_change`, unblock) **permanece
na RAM** — não volta ao persistido. Motivo: reverter para o estado persistido
poderia *elevar* o contador (mais permissivo = pior) e exigiria uma máquina de
rollback sem ganho de segurança; manter a RAM é restritivo e sem
custo. A divergência de hash (PIN trocado não persistido) desaparece no próximo
persist bem-sucedido ou no reload — nunca gera upgrade fantasma de autoridade,
porque o reload sempre traz o estado persistido (ver decisão 3).

**3 — Piso sticky de contador (sticky floor), recarregado por slot.** Novo
estado **volátil de sessão** (não persistido; sobrevive a `select()`, não
sobrevive a power cycle — decisão consciente): para `pw1` e `pw3`, o maior
contador **garantido persistido-ou-consumido** da sessão. Regras:

- inicialização: `máximo da política` do slot (o mais permissivo válido);
- a cada evento mutante de slot (verificação falha que consome tentativa,
  `change`, `set` via unblock, `put_algo`/D2/C1-C3… via `put_data`): tenta-se
  `save_state()`;
  - **save ok** → piso do slot passa a ser o contador atual da RAM (a verdade
    persistida é ele), para **ambos** os slots serializados;
  - **save falhou** → piso = `min(piso, contador atual da RAM)` — o decremento
    é lembrado mesmo sem persistir;
- no reload (`ensure_loaded` → `decode_state`): o contador restaurado é
  clampeado para `min(restaurado, piso)`, para `pw1` e `pw3`. *(Nada no reload
  pode pular acima do piso.)*

Efeito-alvo (mecânica): com falha persistente de gravação, o re-SELECT **não**
ressuscita tentativas; com um persist ok subsequente (operador presencial,
flash de volta saudável), o piso sobe para o estado persistido — operação legítima
volta ao normal. Entre power cycles o piso zera e o estado persistido governa —
resíduo aceito (ver §10 L1/R3).

**4 — Save condicional, não incondicional, em `verify`.** Hoje `verify` chama
`save_state()` mesmo em verificação bem-sucedida (`openpgp.rs:599`) — um
caminho em que **nada persistível mudou** (o sucesso não restaura contador e os
flags são de sessão). A fatia passa a persistir apenas quando o estado do slot
efetivamente mudou (tentativa consumida, `change`, unblock) e nos caminhos
aceitos de `put_data`. Com flash saudável, `VERIFY` bem-sucedido segue `9000`
— e com flash falhando, `VERIFY` bem-sucedido **continua** `9000` (a
verificação não depende de persistência). Isso reduz desgaste e exclui sinais
de erro indesejáveis no caminho feliz.

**5 — Granularidade do rótulo.** `save_state()` serializa os dois slots de uma
vez; um save ok/falho afeta os pisos de ambos os slots. Regra de implementação:
em falha de save, ambos os pisos recebem `min(piso, contador da RAM)`; em save
bem-sucedido, ambos assentam ao valor corrente da RAM. Sofisticação por-slot é
desnecessária e não é exigida por nenhum AC.

---

## 4. Escopo

- `openpgp.rs`:
  - **dois campos de piso de sessão** (`pw1_floor`/`pw3_floor`, nomes à escolha
    do implementador; não persistidos, não zerados por `select()`),
    inicializados com o máximo da política do respectivo slot;
  - `verify` (`584-609`): quando a tentativa consome contador (`verify` errado),
    propaga a falha de `save_state()` como `0x6A84` (em vez do `63Cx`) e aplica
    a regra de piso (decisão 3); verificação bem-sucedida **não** emite save
    (decisão 4) e segue `9000`;
  - `verify_change` (`1549-1561`): propaga a falha de save como `0x6A84`
    (jamais `9000` mutação falsamente confirmada) e aplica o piso;
  - `reset_retry` (`1563-1582`): o unblock autenticado, que hoje confirma
    `9000` com o save descartado (`1580`), passa a responder `0x6A84` quando a
    persistência falha; o piso segue a regra 3 (não sobe ao máximo se a
    persistência não confirmou);
  - `put_data` (`960-986`): em caminho aceito, propaga a falha de save como
    `0x6A84`; caminho rejeitado (`WRONG_DATA`) não emite save (como hoje);
    aplica a regra 3 nos slots afetados via `put_algo`/D2;
  - `ensure_loaded`/`decode_state` (`391-405`, `471-582`): clamp de contador
    restaurado ao piso por slot (decisão 3).
- **`pin.rs` — apenas documentação.** Um parágrafo no doc-comment do módulo (ou
  de `PinSlot`): a persistência pertence ao *handler do applet*; o slot não
  sabe de store; quem muta deve **propagar** o resultado da persistência —
  padrão já adotado no OATH e nas rotas de chave/assinatura do OpenPGP. Nada de
  assinatura ou comportamento novo em `pin.rs`.
- Testes de host (AC-1..AC-8, §6) no módulo `#[cfg(test)]` de `openpgp.rs`,
  com uma wrapper de testes de store (`save` falhável delegando para
  `MemoryOpenPgpStore` — nome à escolha, ex. `FlakyOpenPgpStore`).

## 5. Não-objetivos

1. **Gravar a cada tentativa (write-ahead).** Rejeitado de propósito (desgaste
   de flash); o piso cobre o gap intra-sessão e o resíduo entre sessões é
   documentado (§10).
2. **Mudar `OpenPgpStore::save` para `Result`** (nem o colapso
   `Result→bool` de `SealedOpenPgpStore::save`, `sealed.rs:865-867`): a
   perda de detalhe da causa é aceita aqui; mudança de API difusa é fatia
   própria.
3. **`verify_change` de PW3 (P2=0x83) sem `pw3_verified`** — hoje o handler
   **não checa** autoridade (`openpgp.rs:1550-1553`); gap adjacente de
   autoridade, fatia própria (mesmo estilo do "unblock"), registro em
   `roadmap.md`.
4. **Validação de `kdf_hash` no PUT DATA D2** — fatia própria.
5. **MDC constante-tempo** — fora do escopo.
6. **Política de comprimento de PW** — não é tocada.
7. **Resetting Code (BC)** — continua fora (fato da fatia `openpgp-unblock-auth`).
8. **FIDO/PIV/OATH** — nenhum código é tocado; o PIV é registrado como
   follow-up (mesma mecânica, arquivo próprio) na Fase 14 do `roadmap.md`.
9. **Provisionamento de default em `ensure_loaded`** (`openpgp.rs:402-404`) —
   valores de interop, sempre públicos; o `save` falhado ali fica como está.

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host no módulo `#[cfg(test)]` de
`crates/aegis-applets/src/openpgp.rs` (nenhum exige hardware); a exceção estática
é AC-8 (doc).

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | `VERIFY` que **consome tentativa** com store em modo falha: a resposta é `0x6A84` (nunca `63Cx`); o contador na **RAM** permanece decrementado (VERIFY vazio → `63C2`, bloqueio em `6983` quando esgota) | teste de host em `openpgp.rs` |
| **AC-2** | **Piso sticky entre re-seleções:** no cenário do AC-1, um `select()` subsequente **não** restaura o contador — VERIFY vazio → `63C2`; com store íntegra, o re-SELECT mantém o comportamento atual (persiste o decremento) | teste de host em `openpgp.rs` |
| **AC-3** | `CHANGE REFERENCE DATA` com save falhando → `0x6A84` (nunca `9000`); na **sessão** o PIN novo verifica (sticky); após `select()` o **estado persistido** governa (PIN antigo volta a verificar) — nenhum upgrade fantasma | teste de host em `openpgp.rs` |
| **AC-4** | `RESET RETRY COUNTER` (P1=`0x02`, P2=`0x81`, `pw3_verified`) com save falhando → `0x6A84`; após `select()` o PW1 retorna ao **estado persistido** (bloqueado → `6983`); o unblock só fica definitivo sob persistência ok (com store íntegra: `9000` + persiste como hoje) | teste de host em `openpgp.rs` |
| **AC-5** | `PUT DATA` aceito com save falhando → `0x6A84`; `select()` recupera o DO persistido **antigo**; `PUT DATA` rejeitado (`WRONG_DATA`) não emite save nem muda estado | teste de host em `openpgp.rs` |
| **AC-6** | **Clamp no carregamento:** um applet construído com piso `X` e store contendo contador `Y > X` carrega o contador `X` (`min(Y, X)`), para `pw1` e `pw3`; sob store íntegra o caminho atual não muda (piso igual ao máximo → sem efeito) | teste de host em `openpgp.rs` (via `decode_state`/`ensure_loaded`) |
| **AC-7** | **Caminho feliz inalterado** (store `MemoryOpenPgpStore`): `VERIFY` errado persiste o decremento (re-SELECT mantém); `verify_change`, `reset_retry` e `put_data` respondem `9000` e persistem; `VERIFY` bem-sucedido **não** emite save (ex.: com store falhável em save, um `VERIFY` bem-sucedido ainda `9000`) | teste de host em `openpgp.rs` |
| **AC-8** | Documento de contrato: `pin.rs` declara que a persistência é do handler e deve ser propagada (doc-comment); `docs/security-model.md` registra o trade-off (piso intra-sessão; entre power cycles o persistido governa; write-ahead rejeitado por desgaste) | revisão estática |

## 7. Plano de teste

### 7.1 Onde ficam

No módulo `#[cfg(test)] mod tests` existente em `crates/aegis-applets/src/openpgp.rs`
(`openpgp.rs:1781`), reutilizando os helpers já estabelecidos: `applet()`
(`openpgp.rs:1815`, cria o applet com `MemoryOpenPgpStore` + `select()`),
`frame()` (`openpgp.rs:1821`) e `run()` (`openpgp.rs:1840`). A wrapper de
store falhável vive no mesmo módulo de testes (implementa `OpenPgpStore`
delegando a um `MemoryOpenPgpStore` com um flag, ex.
`FlakyOpenPgpStore::set_save_fails(true)`).

### 7.2 Como os casos são montados

- **AC-1/AC-2:** applet com `FlakyOpenPgpStore` em modo falha; `VERIFY` PW1
  errado → `0x6A84`; VERIFY vazio P2=`0x81` → `63C2`; `applet.select()`.
  Obs.: para testar o AC-2 usa-se a **mesma instância** (o piso é volátil e
  sobrevive a `select()`); uma segunda instanciação + `select()` simula o power
  cycle e **deve** repor o contador — comportamento documentado como resíduo
  (AC-8), não um erro.
- **AC-3:** com save falhando, `CHANGE REFERENCE DATA` P2=`0x81` com
  `atual||novo` → `0x6A84`; o PIN novo verifica in-session e após `select()` o
  PIN antigo volta. Com store íntegra: fluxo de sucesso persiste (re-SELECT
  mantém o PIN novo).
- **AC-4:** com `Flaky` em modo falha: consumir o PW1 até o bloqueio **com a
  store íntegra primeiro** (decremento persistido), depois ligar o save falhável
  e `VERIFY` PW3 (`0x83`) → `9000`; `RESET RETRY COUNTER` P1=`0x02` P2=`0x81`
  com PIN novo → `0x6A84`; `select()` → `VERIFY` PW1 → `6983` (persistido
  manda). Variante saudável: store íntegra → unblock responde `9000` e persiste.
- **AC-5:** `PUT DATA` com tag de DO e autoridade PW3: com save falhando →
  `0x6A84` e após `select()` o DO antigo; com `WRONG_DATA` (tag desconhecida) →
  nenhuma operação de store (verificação por contador de chamadas da wrapper).
- **AC-6:** montar `decode_state`/`ensure_loaded` com o piso no valor
  decrementado e a store persistindo um valor mais alto (ex.: capturar os bytes
  persistidos por um applet saudável e recarregá-los em um applet com piso
  rebaixado — solução à escolha do implementador) e assentar o resultado do
  load clamped.
- **AC-7:** rede de regressão (todos os comportamentos atuais sob store
  íntegra — a "regressão de nada mudou"); verificar com o contador de chamadas
  da wrapper que `VERIFY` bem-sucedido **não** chama `save`.
- Nomes sugeridos (o implementador pode ajustar):
  `verify_failure_with_failing_store_reports_the_save_error`,
  `sticky_floor_survives_reselect`,
  `change_with_failing_store_reports_the_save_error_and_never_fakes_success`,
  `unblock_with_failing_store_keeps_the_persisted_blocked_state`,
  `put_data_with_failing_store_reports_the_save_error`,
  `reload_never_climbs_above_the_session_floor`,
  `happy_path_persists_and_successful_verify_skips_save`.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

(Somente `aegis-applets` é tocado em código; os gates dos demais crates são
regressão e seguem verdes.)

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/openpgp.rs` | Campos de piso de sessão; `verify`/`verify_change`/`reset_retry`/`put_data` propagam `0x6A84` na falha de save e aplicam o piso; clamp no `ensure_loaded`/`decode_state`; save condicional em `verify`; testes de host AC-1..AC-7 |
| `crates/aegis-applets/src/pin.rs` | Doc-comment: persistência é do handler do applet; `PinSlot` não faz I/O; mutação → propagação do resultado da persistência (só documentação) |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | Documentação na mesma mudança (§9) |

Nada é alterado em `crates/aegis-core/**`, `crates/firmware-universal-rp2350/**`
ou `crates/board-generic-rp2350/**` (nenhum despacho de firmware; a store
selada `sealed.rs` não muda de API — não-objetivo 2).

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — na invariante de applets
   ("PIN state is persistent and fail-closed", `security-model.md:137-139`),
   registrar o trade-off decidido: falha de persistência de mutação de PIN no
   OpenPGP responde `0x6A84` (observável), o estado em RAM nunca sobe acima do
   último valor persistido/consumido da sessão (piso sticky), e a gravação por
   tentativa (write-ahead) é deliberadamente rejeitada — **resíduo**:
   power cycle pode restaurar o contador persistido quando a gravação da
   tentativa falhou (piso só cobre a sessão; a decisão é de desgaste, não de
   design não-intencionado). Documentá-lo como comportamento, não como gap.
2. **`roadmap.md`** — Fase 14 (OpenPGP, `roadmap.md:1043`): registrar a
   sub-fatia de persistência fail-closed entregue (piso sticky + `0x6A84`) e o
   follow-up do PIV (mesma mecânica, `persist_pin` fail-open) que **não** é
   novo; manter a linha de status "Concluída (…)".
3. **`validation.md`** — na seção "OpenPGP Card v3.4" (~`validation.md:208`),
   adicionar os ACs da fatia (método: testes de host de `aegis-applets::openpgp`;
   status **Verificado em host**) e registrar a pendência física: em hardware
   a falha de gravação não é induzida (nenhum procedimento do
   `validate_openpgp.py` simula flash doente) — fica pendente o caso
   "mutação de PIN com gravação negada → `0x6A84`", para quando houver método
   de indução ou RP2350 físico; nada muda no script neste ciclo.

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Piso e defaults de `ensure_loaded`** (`openpgp.rs:402-404`). No
  fallback de store vazia/inválida, os defaults de interop (`123456`/
  `12345678`) são provisionados in-RAM com o save descartado — comportamento
  mantido (não-objetivo 9): o piso começa no máximo da política, então esse
  caminho não diverge do piso e não pode regredir; cobrir com a regressão do
  AC-7.
- **R2 — Concorrência de edição.** A fatia `openpgp-unblock-auth` está
  recém-chegada na árvore (`reset_retry` reescrito para já exigir
  `pw3_verified`); a mudança em `reset_retry` é **apenas** a propagação do save
  (`1580`) — manter o diff cirúrgico e reconciliar no rebase. Outras sessões
  mexem em `roadmap.md`/`validation.md` — diffs pontuais.
- **R3 — Resíduo entre power cycles.** O piso zera no boot: um atacante com
  disposição a ciclos de energia (e uma gravação que falha de forma
  persistente) pode restaurar o contador **persistido**. Mitigações: a falha é
  observável (`0x6A84`), e qualquer persistência bem-sucedida subsequente
  reancora o piso; o trade-off (desgaste) está registrado no não-objetivo 1 e
  em `docs/security-model.md` — não é um furo novo, é o modelo documentado de
  degradação física.
- **R4 — Interoperabilidade do novo SW no `VERIFY` falho.** Sob flash doente,
  `VERIFY` deixa de devolver `63Cx` e responde `0x6A84`. Pilhas gpg/OpenSC o
  tratam como erro do cartão (não como "PIN errado") — correto e defensável;
  validar em hardware quando disponível (`validate_openpgp.py`/GnuPG).
- **R5 — gap de autoridade adjacente não corrigido aqui.** `verify_change`
  continua sem exigir `pw3_verified` para trocar o PW3 (`openpgp.rs:1550-1553`)
  — fora do escopo (não-objetivo 3), registrado em `roadmap.md` como fatia
  própria de autoridade de sessão.

### 10.2 Limitações

- **L1 — Piso cobre a sessão, não o ciclo de energia** (ver R3). O
  fail-closed fim a fim (persistir por tentativa) fica deliberadamente em
  aberto por custo de desgaste — decisão registrada como não-objetivo 1 e em
  `docs/security-model.md`.
- **L2 — Sem hardware neste ciclo.** ACs exclusivamente de host; nada de
  `cargo build-fw` (nenhum arquivo de firmware/HAL é tocado).
- **L3 — `MemoryOpenPgpStore` nunca falha** por construção (`openpgp.rs:141-148`) —
  os ACs exigem a wrapper `Flaky` de teste; a wrapper **não** é código de
  produção e não entra no build normal de applet (fica em `#[cfg(test)]`).
- **L4 — Sem segredo novo, sem material novo.** A fatia não adiciona estado
  persistente e não muda o formato (`STATE_VERSION`) — só adiciona estado
  volátil de sessão e erros observáveis.
