# Spec — OATH `pending` com bound: índice validado e mutação de credenciais desarma o toque

> **Origem:** achado do `sec-audit` (loop de hardening de segurança) e follow-up
> explícito **não-objetivo 1** da fatia `specs/oath-load-fail-closed.md` (§5:
> "Bounds e ciclo de vida de `pending` — informacional adjacente, fatia própria")
> e **não-objetivo 2** da fatia `specs/oath-reset-fail-closed.md` (§5: "`delete`
> não limpa `pending`"), também registrado como pendência da Fase 13 em
> `roadmap.md`. HEAD de referência: `9a52f75`.
> **Risco:** BAIXO — o defeito é real (indexação fora do bound e `pending` que
> sobrevive ao `delete`), mas **não é alcançável pelo loop CCID embarcado**:
> `Card::poll` recusa frames novos enquanto há presença pendente e o firmware
> resolve a presença antes de voltar a ler (`main.rs`). O impacto, se alcançado,
> é ALTO em duas direções — o token inteiro para (panic em `no_std` para o
> firmware até reset físico) e um código de outra credencial sai sob um toque
> concedido para a primeira —, mas hoje só um chamador direto da API do applet
> (harness de host, transporte futuro, refatoração do `Card`) o exercita. É uma
> invariante **local** do applet sustentada por sorte de transporte, e a correção
> custa três linhas em `oath.rs`. Fatia única, fechada, em `aegis-applets`; todos
> os ACs são de host e não há pendência física nova (o interleaving não existe em
> hardware).

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- **O pedido de toque guarda um índice cru.** `struct PendingCalculation`
  (`crates/aegis-applets/src/oath.rs`) carrega `index: usize` — posição em
  `Oath::credentials`, um `heapless::Vec` —, além de `challenge` e `truncated`.
  `Oath::calculate` preenche esse índice a partir de `Oath::find(name)` e só
  arma o pedido para credenciais com `PROPERTY_TOUCH`, respondendo
  `Sw::PRESENCE_REQUIRED` (`0x6FF0`, interno, nunca vai ao fio).
- **`confirm_presence` indexa sem checar o bound.** Depois da guarda de estado e
  de `self.pending.take()`, chama `self.calculate_index(pending.index, …)`.
  `Oath::calculate_index` acessa `self.credentials[index]` para computar o
  código, para testar `kind == TYPE_HOTP` e, no caso HOTP, para incrementar e
  persistir o contador. Não existe `get`, `len` nem comparação: o índice é
  confiado por construção **enquanto nada mexer no vetor**.
- **`delete` mexe no vetor e não toca em `pending`.** `Oath::delete` valida
  `require_auth`, exige `TAG_NAME`, resolve com `find` e remove com
  `self.credentials.swap_remove(index)`, seguido de `save_state`. Nenhum dos
  caminhos de saída (`6982`, `6A80`, `6984`, `6A84`, `9000`) limpa `pending`.
- **`swap_remove` tem geometria própria, e só duas geometrias são perigosas.**
  `swap_remove(i)` remove a posição `i` e move o **último** elemento para lá; os
  elementos entre `i+1` e `len-2` não se deslocam. Como `pending.index` é
  comparado com o vetor já mutado:
  - **G1 — `pending.index == índice removido`.** Se o removido não é o último, o
    último passa a ocupar aquela posição: `confirm_presence` devolve o **código
    de outra credencial**. Se o removido é o último, `len` diminui e
    `pending.index == len` → **panic na indexação**.
  - **G2 — `pending.index == len-1` (a credencial armada é a última) e o
    `DELETE` remove outra posição.** A armada é movida para a posição removida e
    `len` diminui: o índice guardado fica igual ao novo `len` → **panic**.
  - **G0 — qualquer outro caso.** O índice continua denotando a mesma
    credencial; hoje não há defeito. Registrar isso importa: a fatia **não**
    pode afirmar que "todo `DELETE` desloca" — só essas duas geometrias o fazem.
- **O panic não fica no applet.** O applet é `no_std`/`no_alloc`; indexar um
  `heapless::Vec` fora do bound entra no `panic_handler` do binário
  (`panic_probe`, `crates/firmware-universal-rp2350/src/main.rs`). O firmware é
  **um** binário com FIDO2/CTAP2, Management HID, PIV, OpenPGP e OATH: o halt
  derruba todas as interfaces até um reset físico, não apenas o applet OATH.
- **Os demais mutadores do vetor, revalidados um a um:**
  - `Oath::put` substitui in-place (`self.credentials[index] = credential`) ou
    faz `push` (append) — **não** desloca índices existentes. Mas pode trocar
    segredo/propriedade/contador **da própria credencial armada**, e aí um toque
    concedido para o material antigo computa o material novo.
  - `Oath::calculate_all` é somente leitura sobre `credentials`: percorre, emite
    `TAG_NAME`, responde HOTP com `TAG_HOTP` sem computar (portanto sem
    incrementar contador) e só grava em `self.out`. Não invalida índice.
  - `Oath::calculate_index` muta apenas `counter` da credencial que acabou de
    computar, **depois** de `confirm_presence` já ter feito `take()` — não pode
    invalidar um pedido armado.
  - `Oath::set_code`/`Oath::validate` não tocam `credentials`.
  - `Oath::reset` (`pending = None` antes do `clear`) e
    `Oath::reset_volatile_state` (chamado por `load_state`/`close`) já limpam
    `pending`; `Oath::select_response` também, e todo `SELECT` passa por ele.
    Esses são os caminhos já entregues nas fatias irmãs — a fatia **não** os
    altera.
- **Não é alcançável pelo loop embarcado.** `Card::poll`
  (`crates/aegis-applets/src/card.rs`) devolve `Ok(None)` enquanto
  `self.pending_sequence.is_some()`, isto é, **nenhum frame novo é processado**
  entre o `PRESENCE_REQUIRED` e a resolução; `Card::complete_presence` consome a
  sequência e chama `Router::confirm_presence`, que despacha para o applet
  selecionado. O `main.rs` do firmware, no braço
  `Ok(Some(Outcome::PresenceRequired))`, espera `wait_presence` e chama
  `complete_presence` antes de voltar ao laço — logo um `DELETE` do host só é
  processado depois de a presença ter sido resolvida (a confirmada responde, a
  negada faz `deny_presence` → `pending = None`). Não há interleaving CCID.
- **Nenhum teste cobre os caminhos ruins.** O teste de toque existente,
  `touch_required_calculation_uses_card_presence_flow`, cobre só o caminho feliz
  (`CALCULATE` → `PRESENCE_REQUIRED` → `confirm_presence` → `9000` →
  `deny_presence` → `6982`). `reset_drops_the_pending_touch_in_both_paths` cobre
  o `RESET`. Não há caso com `DELETE`, nem com índice fora do `len`, nem com
  `PUT` entre o arm e a confirmação.

### 1.2 Caminho de exploração

1. Uma credencial `A` com `PROPERTY_TOUCH` está armada (`CALCULATE` → `6FF0`) e o
   host está autenticado (ou o applet não tem access code).
2. **Antes** de a presença ser resolvida, um `DELETE` chega ao applet:
   - `DELETE A` (G1): a credencial remove `A`; `confirm_presence` devolve o
     código da credencial que estava por último — a política de toque **de B**
     não foi exigida para o código de B (e, se B for HOTP, o contador de B é
     incrementado e persistido por `calculate_index` → `save_state`);
   - `DELETE A` com `A` na última posição, ou `DELETE B` com `A` na última (G2):
     `confirm_presence` entra em panic, o firmware para e **todas** as interfaces
     do token ficam mudas até reset físico.
3. Impacto: (i) bypass da política de toque de uma credencial por um toque
   concedido para outra; (ii) mutação silenciosa de estado de outra credencial
   (contador HOTP); (iii) negação de serviço total do token. A gravidade real é
   limitada porque o passo 2 não existe no firmware atual — o `Card` serializa
   presença e comando. Mas o applet não pode depender de o transporte continuar
   correto: a invariante é local e o custo é baixo. Por isso **BAIXO**, com
   escalada condicional registrada em §10 R3.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | "Each signing operation honours its touch policy" — o código devolvido pertence à credencial cujo toque foi pedido | `docs/security-model.md` ("the applet arms the contextual presence machine") | **violada** em G1: o toque de `A` libera o código de `B` |
| I2 | A resposta de `confirm_presence` pertence ao pedido que a armou; nenhuma credencial é mutada sem comando que a nomeie | `oath.rs` (`calculate` arma o índice, `confirm_presence` consome), protocolo YKOATH | **violada** em G1 (contador HOTP de outra credencial sobe e persiste) |
| I3 | Estado volátil inconsistente nunca vira panic: o applet não pode derrubar o firmware | `oath.rs` (suíte trata o retorno, não o pânico), `no_std` + `panic_probe` em `main.rs` | **violada** em G1-último e G2 |
| I4 | Recusa não vira oráculo: um pedido que não existe mais não é distinguível de um pedido nunca armado | fatias irmãs (`6F00` sem vazar estado), protocolo YKOATH | respeitada; **preservada** (decisão 1 colapsa no SW já usado) |
| I5 | As recusas já entregues continuam com prioridade: applet fechado → `6F00` antes de qualquer outra checagem | `specs/oath-load-fail-closed.md` (AC-5 inclui `confirm_presence`) | respeitada; **preservada** (a guarda de estado continua antes do bound) |

---

## 3. Decisões de política (documentadas nesta spec)

**1 — SW do índice inválido: `Sw::CONDITIONS_NOT_SATISFIED` (`0x6985`), colapsado
no mesmo SW de "não há pedido pendente".** É a resposta que `Oath::confirm_presence`
já dá quando `self.pending.take()` devolve `None`, e a mesma que
`Router::confirm_presence`/`Router::deny_presence` dão quando não há applet
selecionado. Fundamento:

- **Semântica:** o que faltou não é parâmetro do comando atual — `confirm_presence`
  não recebe APDU nenhum, não há `P1`/`P2` a corrigir. `0x6A86`
  (`Sw::INCORRECT_PARAMETERS`) descreveria uma condição que não existe e seria um
  SW novo neste applet (nenhum handler OATH o usa hoje).
- **Consistência interna:** `0x6985` é exatamente "as condições de uso não estão
  satisfeitas" — o pedido de toque que o host quer confirmar não existe mais. Um
  host que trate `6985` como "toque cancelado/expirado" (o caso de
  `deny_presence` e do timeout) já trata este caso corretamente.
- **Sem oráculo:** distinguir "a credencial foi apagada" de "nunca houve pedido"
  revelaria ao chamador um fato sobre o conjunto de credenciais. Colapsar é a
  escolha das fatias irmãs (recusa sem detalhe) e aqui é de graça: quem apagou
  foi o próprio host.
- **`0x6F00` não serve:** no applet ele significa "estado indisponível" (applet
  fechado por leitura falha, ou falha interna de cálculo). Usá-lo para um índice
  velho confundiria uma condição recuperável por reseleção com o fechamento
  entregue em `oath-load-fail-closed`, e faria o host tentar `RESET` para
  recuperar algo que não está quebrado.
- **`0x6984` também não serve:** é o SW de objeto OATH inexistente **e** de
  `AUTH_NOT_ENABLED` **e** de `AUTHENTICATION_FAILED` em
  `crates/aegis-applets/src/apdu.rs` (três constantes com o mesmo valor). Não
  seria nem um sinal limpo, e sugeriria "autenticação" para um problema de
  índice.

Nenhum SW novo é introduzido: `9000`, `6FF0`, `6982`, `6985`, `6A80`, `6A84`,
`6984`, `6D00`, `6F00` mantêm o significado atual.

**2 — `delete` desarma `pending` incondicionalmente, na entrada do handler,
antes de autenticação, de `TAG_NAME` e do `swap_remove`.** Uma linha, sem
ramo:

*Por quê na entrada (e não "antes/depois do `swap_remove`"):* (a) o gatilho é a
**intenção** de mudar o conjunto de credenciais, não o sucesso da gravação — se
o `save_state` falhar (`6A84`) ou o nome não existir (`6984`), a RAM já mudou ou
pode mudar, e o pedido armado não pode sobreviver a nenhum dos dois; (b) uma
limpeza condicionada a `find`/`require_auth` cria um caminho que um refactor
futuro pode reordenar e quebrar em silêncio — a limpeza incondicional é auditável
por leitura; (c) o custo é o host reemitir o `CALCULATE`, e no firmware atual
esse interleaving nem acontece; (d) limpar **antes** de `swap_remove` garante que
nenhuma indexação futura (inclusive a de um `calculate_index` chamado no meio)
veja o índice deslocado.

Consequências aceitas: um `DELETE` recusado por autenticação (`6982`), por dado
malformado (`6A80`), por nome inexistente (`6984`) ou por falha de gravação
(`6A84`) **também** desarma; o `confirm_presence` seguinte responde `6985`.

**3 — Regra única: qualquer handler que altera o conjunto de credenciais desarma
`pending`; `calculate_all` e `calculate_index` não.** `put` entra na regra pelo
mesmo motivo do `delete`, ainda que não desloque índices: ele pode substituir
segredo/propriedade/contador **da credencial armada**, e um toque concedido para
o material antigo não pode computar o material novo. Regra enunciada para o
código e para o `docs/`:

> `pending` é desarmado por `put`, `delete`, `reset`, `select_response` e por
> qualquer normalização de RAM (`reset_volatile_state`); ele **não** é desarmado
> por comandos que não alteram o conjunto (`list`, `calculate_all`,
> `set_code`, `validate`) nem pelo incremento de contador de um HOTP que
> `calculate_index` faz depois de o pedido já ter sido consumido.

`calculate_all` fica fora porque foi revalidado como somente leitura (HOTP é
respondido com `TAG_HOTP` sem computar, então nem contador muda). Se um dia ele
passar a computar HOTP, a regra de desarme precisa ser estendida: não há teste
hoje que arme um toque e rode `CALCULATE ALL` (o teste de AC-1 não cobre isso),
então o comportamento atual é garantido por inspeção e por essa nota.

**4 — Bound check como segunda camada, depois da guarda de estado.**
`confirm_presence` passa a recusar `pending.index >= self.credentials.len()`
**antes** de qualquer indexação, com o mesmo `6985`. Ordem obrigatória, para não
regredir a fatia irmã: `state_available()` (fechado → `6F00`) → `take()` (sem
pedido → `6985`) → bound (índice inválido → `6985`) → `calculate_index`. O
`take()` já ocorreu, então chamadas repetidas respondem `6985` sem laço e sem
reprocessar o pedido.

*Onde implementar:* a checagem pode viver em `confirm_presence` (diff mínimo, um
único chamador com índice não derivado de `find` na mesma chamada) ou,
equivalentemente, tornar `calculate_index` total (`get` em vez de indexação) —
o comportamento exigido é o mesmo e `Oath::calculate` continua passando índices
vindos de `find`, sempre em bounds. Não mudar a assinatura de `calculate_index`
nem o caminho feliz.

**5 — Caminho feliz e recusa existente intactos.** `CALCULATE` de credencial com
toque → `6FF0`; `confirm_presence` → `9000` com o código (truncado ou completo
conforme `P2`); sem `pending` → `6985` (hoje); `deny_presence` → `6982`; applet
fechado → `6F00`. Nada disso muda, e os testes que os cobrem passam **sem
edição** (`touch_required_calculation_uses_card_presence_flow`,
`reset_drops_the_pending_touch_in_both_paths`,
`repeated_failed_loads_stay_closed_without_leaking_ram`).

**6 — Nada de novo no formato, nas dependências ou no build.** Sem estado
persistente novo (o `pending` continua volátil e não serializado), sem bump de
`STATE_VERSION`, sem mudança em `save_state`/`decode_state`, sem dependência, sem
`unsafe`, sem `std`/alocação. Nenhum default OATH (`DEFAULT_CHALLENGE`,
`DEVICE_ID`, políticas de toque, `MAX_CREDENTIALS`, comprimentos) muda. O
protocolo muda só na **recusa** de um `confirm_presence` que hoje ou devolve o
código errado ou entra em panic — e a recusa usa um SW que o applet já emite.

**Tabela de comportamento por caminho**

| Caminho | Hoje | Depois |
|---|---|---|
| `CALCULATE` de credencial com toque | `6FF0` + `pending` armado | idêntico |
| `CALCULATE` sem toque / outras credenciais | `9000` com o código | idêntico (não arma, não mexe em `pending`) |
| `confirm_presence` com `pending` válido | `9000` + código | idêntico |
| `confirm_presence` sem `pending` | `6985` | idêntico |
| `confirm_presence` com applet fechado | `6F00` | idêntico (`6F00` tem prioridade sobre o bound) |
| `PUT`/`DELETE` entre o arm e a confirmação | `9000`/`6A80`/`6984`/`6A84` e `pending` **fica armado** | mesmo SW, `pending` desarmado; `confirm_presence` → `6985`, sem código |
| `DELETE` da própria credencial armada, não-última (G1) | próximo `confirm_presence` devolve o código **da última credencial** (e sobe o contador dela se for HOTP) | `6985`, nenhum código, nenhuma escrita |
| `DELETE` da armada que é a última (G1) / de outra com a armada na última posição (G2) | **panic** → firmware parado até reset | `6985`, applet utilizável |
| `confirm_presence` com índice fora do `len` (construído por chamador direto) | **panic** | `6985`, 0 escritas, estado intacto |
| `deny_presence` / `SELECT` / `RESET` | `6982` / `9000` / `9000` ou `6A84`, `pending` descartado | idêntico |

---

## 4. Escopo

- `crates/aegis-applets/src/oath.rs`:
  - `Oath::confirm_presence`: bound check de `pending.index` contra
    `self.credentials.len()` antes de `calculate_index`, recusando com
    `Sw::CONDITIONS_NOT_SATISFIED`, preservando a ordem `6F00` → `6985` (sem
    pedido) → `6985` (índice inválido).
  - `Oath::delete`: `self.pending = None;` na entrada do handler, antes de
    `require_auth`, com o comentário da regra (decisão 2/3).
  - `Oath::put`: o mesmo `self.pending = None;` na entrada, pelo mesmo motivo
    (decisão 3).
  - Comentário de módulo/invariante curto sobre a regra (uma frase; o texto
    longo fica no `docs/security-model.md`).
  - Testes de host no módulo `#[cfg(test)]` existente, reutilizando
    `applet()`, `applet_with`, `run`, `frame`, `put_data`, `calculate_data`,
    `code`, `put_totp`, `RFC_SECRET` e `FailingOathStore` (sem infra nova;
    helpers locais de teste como `put_touch_totp`, `arm_touch` e
    `assert_touch_disarmed`, sem novo estado ou abstração de store).
- Documentação (§9) na mesma mudança.

## 5. Não-objetivos

1. **Trocar a representação de `pending` por identidade (nome da credencial) ou
   por um `Credential` clonado.** Seria mais robusto contra `PUT`, mas é
   re-arquitetura do fluxo de presença, aumenta o struct (`MAX_NAME` na pilha) e
   continuaria precisando do bound check. A regra de desarme (decisão 3) entrega
   a mesma garantia com diff menor.
2. **Centralizar toda mutação de `credentials` numa função única** que desarme
   `pending` por construção. Desejável a longo prazo, mas mexe na estrutura dos
   handlers (o `put` muta em dois pontos) e amplia o diff desta fatia; a regra
   fica documentada e coberta por teste até essa refatoração existir.
3. **`Card::poll`/`Card::complete_presence`, `Router` e o firmware** — não são
   tocados. A serialização atual (que hoje impede o interleaving) é evidência de
   não-alcançabilidade, não o mecanismo da correção.
4. **PIV (`pending_sign`) e OpenPGP**: o PIV usa um slot fixo e relê o registro
   da store no `confirm_presence`, falhando com `6A88` quando ele não existe —
   representação diferente, sem indexação de vetor. Nada muda fora do OATH.
5. **Mudar o SW de `DELETE`/`CALCULATE` de credencial inexistente (`0x6984`)** ou
   acrescentar qualquer distinção "apagada vs. nunca armada": sem oráculo
   (decisão 1).
6. **Alterar `calculate_all`** para desarmar `pending`: ele não muta o vetor
   (verificado); incluí-lo seria política sem ameaça e quebraria o uso legítimo
   de `CALCULATE ALL` no meio de uma sessão de toques.
7. **Persistir o estado do pedido de toque, contadores ou marcadores** no blob:
   `pending` continua volátil e não serializado.
8. **Pendência física nova.** O interleaving (`DELETE` entre arm e confirm) não é
   alcançável em hardware com o loop atual; não há caso a validar no
   `validate_oath.py` (script intocado).
9. **`aegis-core`, `board-generic-rp2350`, firmware, HAL, `aegistoken-host`,
   `scripts/`, PIV/OpenPGP/FIDO** — nenhum arquivo.
10. **Dependências novas, `unsafe` ou `std`** no crate: não.

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host no módulo `#[cfg(test)]` de
`crates/aegis-applets/src/oath.rs`, com `MemoryOathStore` e `FailingOathStore`;
nenhum exige hardware. A exceção é o AC-7 (documentação/regressão estática).

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | **`DELETE` de outra credencial desarma, mesmo sem deslocar índice (G0):** com `A` (toque, primeira) e `B` (TOTP sem toque, última), `CALCULATE A` → `6FF0`; `DELETE B` → `9000` (o `swap_remove` só trunca: o índice de `A` continua válido); `confirm_presence` → **`6985`** com **dados vazios** (nenhum código, nem de `A` nem de `B`); um novo `CALCULATE A` → `6FF0` e `confirm_presence` → `9000` com **o mesmo código de `A`** obtido antes do `DELETE` | teste de host em `oath.rs` |
| **AC-2** | **`DELETE` da própria credencial armada não devolve código de outra nem entra em panic (G1):** duas variantes, ambas com uma segunda credencial `C` (sem toque) — (a) `A` não é a última: hoje o `confirm_presence` devolveria o código de `C`; depois → `6985` sem dados; (b) `A` é a última: hoje panic; depois → `6985` sem dados. Nas duas, `LIST` não contém mais `A`, `C` continua calculando (`CALCULATE` → `9000`) e o applet não ficou inutilizável | teste de host em `oath.rs` |
| **AC-3** | **`DELETE` de outra credencial com a armada na última posição não entra em panic (G2):** `A` (toque) na última posição, `CALCULATE A` → `6FF0`, `DELETE B` → `9000`; `confirm_presence` → `6985` (nunca panic, nunca código); `A` continua listável e um novo `CALCULATE A` → `6FF0` → `confirm_presence` → `9000` | teste de host em `oath.rs` |
| **AC-4** | **Recusas de `DELETE` e `PUT` também desarmam:** `DELETE` de nome inexistente → `6984` e `confirm_presence` → `6985`; `DELETE` sem `TAG_NAME` → `6A80` e → `6985`; `DELETE` com `save_state` falhando (`FailingOathStore::set_save_fails`) → `6A84` e → `6985`, com `clears() == 0`; `PUT` de **outra** credencial e `PUT` que **substitui** a credencial armada → `9000` e `confirm_presence` → `6985` (nenhum código do material antigo ou novo) | teste de host em `oath.rs` |
| **AC-5** | **Índice fora do `len` responde fechado, sem panic e sem escrita:** com uma credencial, armar `oath.pending = Some(PendingCalculation { index: len, … })` e também `index = MAX_CREDENTIALS`/`99` (campos acessíveis ao módulo de testes) → `confirm_presence` → `6985` com dados vazios, **sem panic**, `credentials` inalterado (`len` e nomes), 0 `save` e 0 `clear`; segunda chamada → `6985`; em seguida `CALCULATE` normal → `9000` (applet utilizável) | teste de host em `oath.rs` |
| **AC-6** | **Caminho feliz e SW existentes intactos:** `confirm_presence` sem `pending` continua `6985`; `deny_presence` continua `6982`; applet fechado continua `6F00` em `confirm_presence`; `touch_required_calculation_uses_card_presence_flow` e `reset_drops_the_pending_touch_in_both_paths` passam **sem edição**; suíte de `aegis-applets` sem regressão (**254** hoje + os casos novos) | testes de host em `oath.rs` + `cargo test -p aegis-applets` |
| **AC-7** | **Documento de contrato atualizado na mesma mudança:** `docs/security-model.md` ganha a cláusula OATH de presença pendente (índice com bound, regra "mutação do conjunto desarma", `6985` colapsado, sem oráculo); `roadmap.md` registra a sub-fatia na Fase 13 e remove o follow-up dos bounds; `validation.md` ganha a subseção OATH correspondente, a linha **AC-033** e nenhuma pendência física nova | revisão estática |

## 7. Plano de teste

### 7.1 Onde ficam

No módulo `#[cfg(test)] mod tests` já existente em
`crates/aegis-applets/src/oath.rs`. Nada de infraestrutura nova:

- `applet()`, `applet_with`, `run`, `frame`, `put_data`, `calculate_data`,
  `code`, `put_totp` e `RFC_SECRET` já existem e são genéricos sobre
  `S: OathStore` onde é preciso.
- Um helper opcional `put_touch_totp(&mut oath, &mut rng, name)` — só açúcar
  sobre `put_data(name, TYPE_TOTP, ALGORITHM_SHA1, 6, secret, None,
  PROPERTY_TOUCH)`; sem ele, os testes escrevem a chamada como
  `touch_required_calculation_uses_card_presence_flow` já faz.
- `FailingOathStore` (já com `set_save_fails`, `set_clear_fails`,
  `set_load_fails` e contadores `saves()`/`clears()`/`loads()`) cobre o
  `6A84` do AC-4.
- `PendingCalculation` é privado do módulo, mas o `mod tests` é filho: constrói
  o struct diretamente para o AC-5 (dois testes existentes já leem
  `oath.pending`/`oath.credentials`).
- **Códigos esperados sem vetor externo:** `compute_credential` usa o challenge
  como moving factor para TOTP, então o código para um challenge fixo é estável;
  cada teste aprende o código de `A` com um `confirm_presence` inicial (ou com
  `CALCULATE` sem toque numa credencial gêmea) e compara depois.

### 7.2 Como os casos são montados

- **AC-1:** `PUT` de `A` (toque, `RFC_SECRET`, **primeira**) e de `B` (TOTP sem
  toque, segredo distinto, **última**, de modo que o `DELETE B` apenas trunque o
  vetor e o índice de `A` continue válido — geometria G0);
  `CALCULATE A` (challenge `1u64`, `P2=0x01`) → `6FF0`; `confirm_presence` →
  `9000`, guardar o código truncado como esperado; `CALCULATE A` de novo → `6FF0`;
  `DELETE B` (`TAG_NAME = B`) → `9000`; `confirm_presence` → `6985` e
  `response.data.is_empty()`; `CALCULATE A` → `6FF0`; `confirm_presence` →
  `9000`, `code` igual ao esperado.
- **AC-2:** variante (a): `PUT A` (toque, primeira) e `PUT C` (sem toque,
  última) — armar `A`; `DELETE A` (G1, `C` é movida para o índice 0);
  `confirm_presence` → `6985` com dados vazios, `LIST` só com `C`, `CALCULATE C`
  → `9000`. Variante (b): `PUT C`, `PUT A` (nessa ordem, `A` última); armar `A`;
  `DELETE A` → hoje panic (o `len` cai e o índice fica igual ao novo `len`);
  depois → `6985`, `LIST` só com `C`, `CALCULATE C` → `9000`.
- **AC-3:** `PUT B`, `PUT A` (nessa ordem, `A` última); armar `A`; `DELETE B`;
  `confirm_presence` → `6985`; `LIST` contém `A`; `CALCULATE A` → `6FF0` →
  `confirm_presence` → `9000`.
- **AC-4:** quatro blocos no mesmo teste ou em dois: (i) `DELETE` de
  `b"absent"` → `6984`, `confirm_presence` → `6985`; (ii) `DELETE` com corpo
  vazio → `6A80`, → `6985`; (iii) `FailingOathStore`, `set_save_fails(true)`,
  `DELETE` da credencial não armada → `6A84`, `saves() == 1`, `clears() == 0`,
  → `6985` (religar o save depois); (iv) `PUT` de outra credencial → `9000`,
  → `6985`; armar de novo, `PUT` da mesma credencial com segredo novo → `9000`,
  → `6985`.
- **AC-5:** applet com uma credencial; `oath.pending = Some(PendingCalculation {
  index: oath.credentials.len(), challenge: [0u8; 8], truncated: true })`;
  `oath.store_mut().reset_calls()`; `confirm_presence` → `6985`, dados vazios,
  `saves() == 0`, `clears() == 0`, `oath.credentials.len() == 1`; repetir com
  `index = 99`; depois `CALCULATE` sem toque → `9000` e `confirm_presence` →
  `6985`.
- Nomes sugeridos (o implementador pode ajustar):
  `delete_of_another_credential_disarms_the_armed_touch`,
  `deleting_the_armed_credential_never_returns_another_code_or_panics`,
  `deleting_another_credential_while_the_armed_one_is_last_does_not_panic`,
  `refused_delete_and_put_disarm_the_armed_touch`,
  `out_of_bounds_pending_answers_6985_without_touching_the_store`.
  São **5 testes novos** (total esperado **259**); a contagem real deve ser
  registrada em `roadmap.md`/`validation.md` na mesma mudança.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

Suíte atual de `aegis-applets`: **254** testes (medido no HEAD `9a52f75`,
confirmado por contagem de `#[test]` no crate). Somente `aegis-applets` é
tocado em código; `cargo build-fw` não é exigido (nenhum arquivo de firmware/HAL
muda e nenhuma assinatura pública muda).

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/oath.rs` | `confirm_presence`: bound check do `pending.index` (`6985`, depois da guarda de estado); `delete` e `put`: `pending = None` na entrada (regra única, comentada); testes AC-1..AC-6 |
| `roadmap.md` | Fase 13: sub-fatia entregue e remoção do follow-up dos bounds (§9) |
| `validation.md` | Subseção OATH da presença pendente e linha **AC-033** (§9) |
| `docs/security-model.md` | Cláusula OATH de presença pendente (§9) |

Nada é alterado em `crates/aegis-applets/src/card.rs`/`router.rs`/`sealed.rs`,
`crates/aegis-core/**`, `crates/firmware-universal-rp2350/**`,
`crates/board-generic-rp2350/**`, `crates/aegistoken-host/**` nem `scripts/**`;
nenhum despacho de firmware muda.

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — em "Applet security invariants", no parágrafo
   do OATH e logo depois da cláusula de leitura fail-closed, acrescentar a
   cláusula de **presença pendente**, registrando como decisões aceitas:
   (a) `pending` guarda um índice no vetor de credenciais e o `confirm_presence`
   valida o bound antes de indexar, respondendo `6985` em vez de panicar (o
   panic, em `no_std`, pararia o firmware inteiro); (b) **qualquer handler que
   altera o conjunto de credenciais desarma o pedido** (`put`, `delete` e, como
   já era, `reset`/`SELECT`/normalização de RAM), inclusive quando o comando é
   recusado ou a gravação falha — a autorização de um toque não sobrevive à
   mudança da credencial que a pediu; (c) `calculate_all` não muta o conjunto e
   não desarma; (d) o índice inválido **colapsa** no mesmo `6985` de "sem pedido
   pendente", sem distinguir "apagada" de "nunca armado" (sem oráculo), e o SW
   não é novo; (e) a serialização de presença em `Card::poll`/`main.rs` impede o
   interleaving em hardware hoje — a garantia aqui é local do applet, não
   dependente do transporte. Mencionar que é robustez defensiva (risco BAIXO),
   não uma exposição alcançável.
2. **`roadmap.md`** — Fase 13 (OATH), seção **Entregue**: acrescentar a sub-fatia
   de `pending` com bound e desarme na mutação (índice validado → `6985`,
   `put`/`delete` desarmam incondicionalmente, 5 testes novos) e o total da
   suíte. Na seção **Pendências**: **remover** o item "bounds/ciclo de vida de
   `pending` em `confirm_presence` (índice não checado) e `delete` (não limpa
   `pending`)" — entregue aqui —, mantendo `AC-018 em hardware`, o follow-up do
   fallback de firmware para `MemoryOathStore` e o da robustez do `SealedBlob`.
   Não criar pendência física nova.
3. **`validation.md`** — na seção "OATH / TOTP / HOTP (Fase 13)", depois da
   subseção "leitura fail-closed", adicionar "Presença pendente com bound (fatia
   `specs/oath-pending-bounds.md`)" com a tabela de ACs (método: testes de host
   de `aegis-applets::oath`; status **Verificado em host**) e a nota de que
   **não há pendência física**: o interleaving `DELETE`-entre-arm-e-confirmação
   não é alcançável pelo loop CCID atual (`Card::poll` serializa presença) e o
   `validate_oath.py` não muda. Na tabela de critérios, acrescentar a linha
   **AC-033** com o resumo da fatia.

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Desarmar no `PUT` pode surpreender um host que intercala.** Um host que
  arme um toque e faça `PUT` (de qualquer credencial) antes de confirmar passa a
  receber `6985` e precisa reemitir o `CALCULATE`. No firmware atual isso não
  acontece (presença serializada); se um transporte futuro permitir, a resposta
  é a restritiva e o host já trata `6985` como toque cancelado.
- **R2 — As duas camadas cobrem coisas diferentes e ambas são necessárias.** O
  desarme fecha o caminho do **código errado** (AC-1..AC-4); o bound check fecha
  o do **panic** para qualquer chamador que construa um índice inválido
  (AC-5). Reverter uma sem a outra deixa metade do defeito em pé; o comentário
  no código e a cláusula do `docs/` devem dizer isso.
- **R3 — O risco é condicional ao transporte.** Se um dia `Card::poll` deixar de
  serializar presença (ou um harness/CLI chamar o applet direto e intercalar),
  o defeito deixa de ser teórico: panic derruba o token inteiro e o toque de uma
  credencial libera o código de outra. É exatamente por isso que a invariante
  deve ser local, e não herdada do laço de polling.
- **R4 — `delete` continua mutando a RAM antes de saber o resultado da
  gravação.** O `6A84` deixa a credencial removida em RAM e presente no flash
  (comportamento pré-existente, fora desta fatia). O desarme garante apenas que
  o pedido armado não seja confirmado contra esse estado não persistido; a
  reconciliação RAM/store do `delete` é assunto de outra fatia.
- **R5 — Concorrência de edição.** `oath.rs` é grande e as fatias irmãs mexeram
  no mesmo módulo de testes e na documentação; manter o diff cirúrgico (duas
  linhas de desarme, um `if` de bound, os testes) e reconciliar no rebase. AC-6
  é a rede de regressão.

### 10.2 Limitações

- **L1 — Sem hardware neste ciclo e sem pendência física nova.** ACs
  exclusivamente de host; não há `cargo build-fw` (nada de firmware/HAL) e não
  há caso novo para o `validate_oath.py`, porque o interleaving não existe no
  laço embarcado.
- **L2 — A recusa é indistinguível de "toque não pedido/cancelado".** É
  deliberado (decisão 1): o host não descobre pelo SW que a credencial foi
  apagada. Ferramentas que mostrem "touch cancelled" para `6985` mostrarão o
  mesmo para este caso — o que é verdadeiro do ponto de vista do pedido.
- **L3 — O PIV tem máquina análoga com representação mais forte** (slot fixo +
  releitura do registro no `confirm_presence`, falha `6A88` quando o registro
  sumiu) e **não** é afetado; o OATH mantém o índice por decisão de escopo
  (não-objetivo 1), compensando com a regra de desarme.
- **L4 — Sem estado novo, sem segredo novo.** A fatia não persiste nada, não
  muda `save_state`/`decode_state`, não muda `STATE_VERSION` e não cria SWs.
- **L5 — A regra depende de disciplina dos handlers.** Um handler novo que mute
  `credentials` sem desarmar `pending` reabre o defeito; até a refatoração do
  não-objetivo 2, a defesa é a regra escrita no `docs/` e nos comentários, mais
  os testes de AC-1..AC-4. O bound check continua impedindo o panic nesse
  cenário, mas não o código errado.
