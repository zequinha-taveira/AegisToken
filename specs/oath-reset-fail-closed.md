# Spec — OATH `RESET` fail-closed: erase observável (`6A84`, uma escrita)

> **Origem:** achado **MÉDIO** do `sec-audit` (loop de hardening de segurança),
> registrado como follow-up deliberado na fatia irmã
> `specs/piv-pin-persistence.md` (§5, não-objetivo 1: "`OATH RESET` fail-closed —
> fatia seguinte deliberada"), cuja entrega é o commit `6fc80bd`. Mesma mecânica
> de persistência, arquivo próprio.
> **Risco:** MÉDIO — `reset` limpa a RAM, descarta o resultado de `clear()` e de
> `save_state()` e responde `9000` incondicionalmente. Se **as duas** gravações
> falharem, o host recebe "All credentials erased" enquanto as credenciais **e o
> access code** seguem no flash; o próximo `SELECT` recarrega tudo. Fatia única,
> fechada, em `aegis-applets`; todos os ACs são de host (a indução de falha de
> flash em hardware não é exercida neste ciclo — pendência em `validation.md`).

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- **A ordem é "muta a RAM, depois tenta persistir, e não olha o resultado".**
  `Oath::reset` (`oath.rs`, `fn reset`) limpa `credentials`, `auth_key`,
  `authenticated`, `auth_challenge` e `pending` e em seguida executa
  `let _ = self.store.clear();` e `let _ = self.save_state();`, retornando
  `Response::status(Sw::OK)` **sem condicional**. O despacho
  (`INS_RESET if apdu.p1 == 0xDE && apdu.p2 == 0xAD => self.reset()`,
  `fn process`) não tem autenticação: é o `RESET` YKOATH do protocolo.
- **As duas escritas são falíveis, e nenhuma é observada.** `OathStore::clear`
  devolve `bool` (`oath.rs`, `trait OathStore`) e `save_state` devolve `bool`
  (`oath.rs`, `fn save_state`). `SealedOathStore::clear` é
  `self.inner.save(&[]).is_ok()` (`sealed.rs`, `impl OathStore for
  SealedOathStore`) — ou seja, **a mesma primitiva de gravação** de um save
  normal, com `OATH_SHARDS = 2` shards de dados + cell de commit, commit escrito
  por último (`sealed.rs`, `SealedBlob::save`). `SealedOathStore::save` também é
  `is_ok()` (`sealed.rs`).
- **A mentira exige as duas falhas, mas o código não consegue distingui-las.**
  `clear()` grava um commit com `total = 0`; `save_state()` serializa a RAM já
  limpa num blob válido de 77 bytes (versão, contagem 0, "sem access code",
  algoritmo, `DEFAULT_CHALLENGE`). Os dois representam o mesmo estado vazio após
  o reload, mas são gravações distintas: hoje o `9000` só é falso quando
  **ambas** falham. O ponto do achado é que o applet **não olha nenhum dos dois
  booleanos** e o host não tem como saber qual caminho aconteceu.
- **O erase é torn-safe, e por isso o booleano é exato.** O commit é escrito
  depois dos shards; uma escrita interrompida deixa a geração anterior como a
  mais nova do cell (dois slots de geração — `SealedCell`/`SecretStorage`), e
  `SealedBlob::load` devolve a geração anterior completa (comportamento coberto
  por `sealed_oath_blob_persists_across_reopen` e
  `sealed_blob_torn_save_recovers_previous_generation` em `sealed.rs`). Um
  `clear()` que devolve `false` significa, portanto, "o estado anterior continua
  carregável" — não "meio apagado".
- **O reload é programático, não só power cycle.** `select()`/`select_with_rng`
  (`impl Applet for Oath`) zeram `loaded` e chamam `load_state`, que lê a store
  e `decode_state` repõe `credentials` + `auth_key` + `auth_challenge`
  (`oath.rs`, `fn load_state`, `fn decode_state`). Qualquer pilha PC/SC
  re-seleciona o AID a cada abertura: o "power cycle" do ataque é um `SELECT`.
- **O access code vazio é o lado permissivo.** `require_auth` devolve `Ok`
  quando `self.auth_key.is_empty() || self.authenticated` (`oath.rs`, `fn
  require_auth`). Consequência central desta fatia: com `reset` limpando a RAM
  **antes** de saber se o erase persistiu, o applet fica numa sessão em que o
  access code antigo ainda existe no flash mas o applet o considera ausente —
  `LIST`/`CALCULATE` passam sem autenticação e qualquer `PUT` subsequente
  grava um estado **sem** access code, convertendo uma falha de erase em remoção
  silenciosa e não autorizada da autoridade.
- **Nenhum teste vê a falha.** `reset_removes_credentials_and_authentication`
  (`oath.rs`, `#[cfg(test)] mod tests`) usa `MemoryOathStore`, cujo `clear` é
  `data.fill(0); len = 0; true` (`oath.rs`, `impl OathStore for
  MemoryOathStore`) — nunca falha, e o teste não reabre a store: prova a RAM,
  não a persistência.

### 1.2 Caminho de exploração

1. O dono tem o dispositivo com credenciais OATH e um access code configurado
   (ou o applet recebe credenciais de outra pessoa e é entregue depois).
2. Antes de entregar/passar o token, o dono roda `ykman oath reset` (ou o
   Authenticator) — `00 04 DE AD`, sem autenticação.
3. A gravação falha (flash desgastado, interrupção, energia) nas duas tentativas.
   O host recebe `9000`. `ykman` reporta o reset como concluído.
4. Qualquer `SELECT`/reabertura recarrega o blob antigo: as credenciais TOTP
   voltam a gerar códigos e o access code antigo volta em silêncio — inclusive
   o `TAG_CHALLENGE` da resposta de `SELECT`, que só é emitido quando
   `auth_key` não está vazio.
5. **Pior variante intra-sessão:** enquanto o applet não for re-selecionado, a
   RAM diz "sem access code" e o flash diz "com access code". Um `PUT`/`DELETE`
   (ou um `CALCULATE` HOTP, que chama `save_state`) persiste o estado sem o
   access code — a falha de erase vira downgrade de autoridade, não apenas
   segredo residual.

**Impacto:** quebra do *fail-closed* da store e da regra "o estado que um
comando aceito grava sobrevive à sessão" (`docs/security-model.md`, "Applet
security invariants"). A gravidade é limitada por: a falha exige um evento
físico adverso e **duas** gravações negadas na mesma chamada; `MemoryOathStore`
nunca falha; e o `RESET` só remove (não revela) — o impacto de confidencialidade
depende de o dispositivo ser entregue depois. Mas o custo de correção é baixo, a
mecânica já está provada nas fatias irmãs PIV/OpenPGP e o `9000` incondicional é
uma garantia falsa. Por isso **MÉDIO**.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | "The state an accepted command writes survives the session" — o `9000` só pode ser dado depois de a gravação ter sobrevivido | `docs/security-model.md` ("Applet security invariants", cláusula *The state an accepted command writes survives the session*, ~l. 195-204) | **violada** — o `RESET` confirma o erase sem ler nenhum dos dois booleanos |
| I2 | Store selada é fail-closed: nenhuma mutação é confirmada sem persistir (padrão `put`/`delete`/`set_code`/`validate`/`calculate_index`, que respondem `6A84`) | `oath.rs` (`fn put`, `fn delete`, `fn set_code`, `fn validate`, `fn calculate_index`), `specs/piv-pin-persistence.md`, `specs/openpgp-pin-persistence.md` | **violada** só no `RESET` — é o único mutador do applet que descarta o `bool` |
| I3 | O access code OATH governa `LIST`/`CALCULATE`/`PUT`/`DELETE`; `require_auth` não pode ser desativado por um comando que falhou | `oath.rs` (`fn require_auth`), `docs/security-model.md` (*Secrets are sealed at rest*) | **violada** por construção: a RAM é limpa antes de a persistência ser conhecida |
| I4 | `INS_RESET` (`DE AD`) é o `RESET` YKOATH, sem autenticação, e não revela segredo | protocolo YKOATH, `fn process` | respeitada; **preservada** (fronteira de autoridade inalterada) |

---

## 3. Decisões de política (documentadas nesta spec)

**1 — Ordem: a store é apagada ANTES da mutação volátil, e `save_state()` sai do
`reset`.** Nova sequência de `reset`:

1. `self.pending = None;` — o pedido de toque armado é descartado **antes** da
   persistência (decisão 3), nos dois caminhos;
2. `if !self.store.clear() { return Response::status(Sw::NOT_ENOUGH_MEMORY); }`
   — **única** gravação do comando;
3. só então a limpeza da RAM (`credentials`, `auth_key`, `authenticated`,
   `auth_challenge = DEFAULT_CHALLENGE`);
4. `Response::status(Sw::OK)`.

*Por que o `save_state()` é removido (e o que ele faria):* `save_state`
serializa a **RAM** (`oath.rs`, `fn save_state`: versão, contagem de
credenciais, presença/len/algoritmo do access code, `auth_challenge` e cada
credential). Depois de um `clear()` bem-sucedido ele gravaria um blob de 77
bytes com contagem 0 e sem access code — **não** o mesmo blob que o `clear`
acabou de apagar (`clear` = `inner.save(&[])`, commit com `total = 0`), mas o
mesmo estado **observável** após o reload: nenhuma credencial, nenhum access
code, e os únicos valores não vazios são `auth_algorithm = SHA1` e
`DEFAULT_CHALLENGE`, que `Oath::new` já fornece em qualquer boot. Nada de
significativo é preservado por essa segunda escrita. Em troca, ela adiciona:
(a) uma segunda escrita de flash por `RESET` (o `SealedBlob` regrava shards +
commit: hoje o `RESET` faz ~6 escritas de storage, passaria a 3); (b) uma
**segunda fonte de falha** cujo resultado não tem tratamento correto possível:
se o `clear` persistiu e o `save` falha, reportar `6A84` é espúrio (o erase
aconteceu) e reportar `9000` exige ignorar o booleano do save; (c) para que o
`save_state` represente o estado vazio ele teria de rodar **depois** da limpeza
da RAM, isto é, exatamente a ordem que produz o split-brain da decisão 2.
Alternativa "tenta as duas e aceita se qualquer uma funcionar" foi considerada e
rejeitada: `clear()` já é uma tentativa **atômica e completa** do erase (commit
por último, geração anterior preservada em caso de escrita interrompida), logo
o `bool` dele é exato — `true` = o commit vazio é o mais novo; `false` = o
estado anterior continua o mais novo. Duas tentativas não aumentam a garantia,
só o número de caminhos de erro. **Mantido:** o estado inteiro do applet
(credenciais, access code, algoritmo/challenge HMAC). **Removido:** esse mesmo
estado — RAM e o blob mais novo do flash; a rotação de slots pode conservar
gerações anteriores seladas até serem sobrescritas (propriedade pré-existente
do `SealedBlob`, §10 L2).

**2 — Estado da RAM na falha: não há rollback nem recarga — credenciais, access
code e flags de autenticação não são tocados antes de a persistência ser
confirmada (só o `pending`, decisão 3).** Rejeitadas as duas variantes
"clássicas":

- *manter a RAM vazia depois do `6A84`* (o análogo literal do "RAM restritiva"
  do PIV) é **fail-open aqui**: `require_auth` trata `auth_key` vazio como
  "sem autenticação necessária", então uma RAM vazia com flash intacto desliga
  o access code na sessão e permite que o próximo `save_state` (PUT/DELETE/
  CALCULATE HOTP) persista um estado sem access code;
- *recarregar do store no caminho de falha* (`loaded = false; load_state()`)
  destrói a sessão (perde `authenticated`, repõe `auth_challenge`) e, se a
  própria leitura falhar, cai no mesmo estado vazio acima — `load_state` trata
  erro de leitura como "sem estado" (informacional, fora do escopo).

A escolha fail-closed é a **ordem** da decisão 1: a operação é transacional do
ponto de vista volátil — ou o erase persistiu e a RAM é limpa, ou nada mudou e o
host recebe `6A84`. Consequências explícitas após um `RESET` que respondeu
`6A84`:

| Comando | Resposta depois do `6A84` |
|---|---|
| `LIST` | idêntico ao estado anterior ao `RESET`: `6982` se há access code e a sessão não validou; senão `9000` com a lista antiga |
| `CALCULATE` | idêntico ao anterior: `9000` com o código (credencial ainda existe) ou `6982` sem autenticação |
| `PUT`/`DELETE`/`SET CODE` | sujeitos ao mesmo `require_auth` de antes; nenhuma autoridade nova |
| `SELECT` seguinte | recarrega a store: credenciais antigas **e** access code antigo (o blob anterior continua o mais novo); um `RESET` saudável depois disso limpa de verdade |
| `pending` (toque armado) | descartado (decisão 3) |

**3 — Estado de sessão: `pending` é descartado nos dois caminhos; o resto da
sessão segue o resultado da persistência.** `pending` (pedido de toque de um
`CALCULATE` com `touch required`, `struct PendingCalculation`) é estado volátil
apontando para um índice de credencial. Um `RESET` invalida a intenção do
host; manter o pedido armado faria um `confirm_presence` posterior liberar um
código de uma credencial que o host pediu para apagar. A linha `self.pending =
None` que já existe é preservada e passa a valer **também** no caminho de
falha (é a única mutação volátil que pode acontecer antes do `clear`, e é
restritiva: força o host a reemitir o `CALCULATE`). `authenticated` e
`auth_challenge` só mudam no sucesso (limpeza), como hoje; no sucesso,
`auth_algorithm` fica como está em RAM (não é persistido — não há blob) e volta
a `SHA1` no próximo boot, sem efeito funcional porque `SET CODE` sempre define
algoritmo e chave. `loaded` não é tocado (o `SELECT` seguinte recarrega).

**4 — SW exatos: só `Sw::NOT_ENOUGH_MEMORY` (`0x6A84`) é novo, e só na falha de
persistência.** É o SW que o próprio applet já usa para falha de gravação em
`put`, `delete`, `calculate_index`, `set_code` e `validate`, e o mesmo das
fatias PIV/OpenPGP. O `6A84` **substitui** o `9000`: nunca se confirma um erase
que não persistiu. Nenhum outro SW é introduzido; a ordem dos checks atuais
(`P1`/`P2` no despacho, nenhuma autenticação) é preservada:

| Caminho | Hoje | Depois |
|---|---|---|
| `P1≠0xDE` ou `P2≠0xAD` | `6D00` (fallback `_`), sem store | `6D00`, sem store (0 `clear`, 0 `save`) |
| `DE AD`, store íntegra | `9000`, **2** chamadas de gravação (`clear` + `save_state`) | `9000`, **1** (`clear`); RAM limpa |
| `DE AD`, `clear` falha e `save_state` falha | `9000` — **mentira** (credenciais e access code no flash) | **`6A84`**; credenciais/access code/flags intactos; só o `pending` cai (decisão 3) |
| `DE AD`, `clear` falha e `save_state` funcionaria | `9000` (verdade por acidente) | **`6A84`** — não existe mais a segunda tentativa; ver decisão 1 |
| `DE AD`, `clear` ok e `save_state` falharia | `9000` (verdade; o erase persistiu) | `9000` sem esse caminho |

**5 — Repetição é obrigatória e idempotente.** Depois de um `6A84`, um novo
`RESET` com a store recuperada deve responder `9000` e deixar lista vazia e
access code removido — não existe "meio reset" nem estado que impeça a segunda
tentativa. O caminho de falha não grava marcador, contador nem flag: nada
persistido muda.

**6 — Nada de novo no formato, nas dependências ou no build.** Sem novo estado
persistente, sem bump de `STATE_VERSION`, sem migração, sem dependência, sem
`unsafe`, sem `std`/alocação (tudo `no_std`/`no_alloc` como hoje). Nenhum
default OATH/TOTP (`DEFAULT_CHALLENGE`, `DEVICE_ID`, políticas de touch,
comprimentos) é alterado.

---

## 4. Escopo

- `crates/aegis-applets/src/oath.rs`:
  - `reset`: passa a checar o resultado da **única** gravação (`store.clear()`),
    responder `Sw::NOT_ENOUGH_MEMORY` na falha e só então limpar a RAM; remove a
    chamada e o descarte de `save_state()`; `pending = None` nos dois caminhos;
    `9000` só no sucesso. Nada mais no handler muda (`load_state`, `decode_state`,
    `put`, `delete`, `calculate`, `set_code`, `validate`, `calculate_all`,
    `confirm_presence`/`deny_presence` intactos).
  - Testes de host no módulo `#[cfg(test)]` existente: wrapper `OathStore`
    falível (só em `#[cfg(test)]`) delegando a `MemoryOathStore`, com flag de
    falha de `clear` e contadores de chamadas (`clear`/`save`/`load`);
    `run()`/helpers passam a ser genéricos sobre `S: OathStore` (mesmos
    argumentos, call sites atuais inalterados) para aceitar a wrapper; helper
    para configurar o access code reaproveitado de
    `access_code_validate_round_trips`.
- Nada mais.

## 5. Não-objetivos

1. **`load_state` tratando erro de leitura como estado vazio** (e o blob de
   zero bytes decodificando como "sem estado") — informacional adjacente,
   fatia própria. Esta spec não toca `load_state`/`decode_state`.
2. **Bounds e ciclo de vida de `pending`** (`confirm_presence` indexa
   `self.credentials[pending.index]` sem checar o índice; `delete` não limpa
   `pending`) — informacional adjacente, fatia própria. Aqui só se garante que
   o `RESET` descarta `pending` e não piora nada.
3. **Autenticar o `INS_RESET`.** O `RESET` YKOATH é um comando sem autenticação
   por protocolo; adicionar gate quebraria `ykman`/Authenticator e mudaria a
   fronteira de autoridade. Preservado (aceito como operação de
   disponibilidade: apaga, não revela).
4. **Mudar `OathStore`/`SealedOathStore` para `Result`** ou revisar a
   atomicidade do `SealedBlob`: a API e o desenho da store ficam como estão.
5. **Revisar os demais mutadores** (`put`, `delete`, `set_code`, `validate`,
   `calculate_index` já propagam `6A84`); não há mudança de comportamento neles.
6. **PIV, OpenPGP, FIDO, `aegis-core`, firmware, HAL, `aegistoken-host`,
   scripts Python** — nenhum arquivo tocado.
7. **OTP/flash, partições, layout do `SealedBlob`** — intocados.
8. **Novos SWs** além do `6A84` na falha de persistência: `9000`, `6D00`,
   `6982`, `6984`, `6985`, `6A80` preservados.
9. **Dependências novas, `unsafe` ou `std`** no crate: não.

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host no módulo `#[cfg(test)]` de
`crates/aegis-applets/src/oath.rs`, com `MemoryOathStore` (caminho feliz) e a
wrapper falível (falha de `clear`); nenhum exige hardware. A exceção é o AC-7
(doc/regressão estática).

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | `RESET` (`DE AD`) com `clear` falhando → **`0x6A84`** (nunca `9000`); a RAM **não** confirma o erase: `LIST` devolve exatamente o que devolvia antes do comando (com access code e sessão não validada → `6982`; sem access code → `9000` com a credencial antiga) e `CALCULATE` da credencial antiga continua respondendo `9000` com o código | teste de host em `oath.rs` |
| **AC-2** | **Recuperação/idempotência:** com a store recuperada, o `RESET` seguinte responde `9000`; `LIST` devolve vazio; o access code antigo não existe mais (após `select()` a resposta de `SELECT` não traz `TAG_CHALLENGE` e `LIST` responde `9000` vazio) — um novo `SET CODE` volta a ser possível | teste de host em `oath.rs` |
| **AC-3** | **A resposta não mentiu:** depois do `6A84`, um `select()` na mesma instância **e** um applet novo sobre a mesma store mostram exatamente o estado persistido — credencial antiga presente (`LIST`/`CALCULATE`) e access code ainda exigido (`6982` antes de `VALIDATE`); o teste demonstra lendo a store (`OathStore::load` devolve `Some(n)` com `n > 0`) além de reabrir o applet | teste de host em `oath.rs` |
| **AC-4** | **Caminho feliz e superfície de SW preservados:** com store íntegra, `RESET` responde `9000`, `LIST` devolve vazio e um applet reaberto sobre a mesma store também (erase persistido); `reset_removes_credentials_and_authentication` continua passando **sem edição**; `P1`/`P2` fora de `DE AD` respondem `6D00` e não chamam a store (0 `clear`, 0 `save`) | teste de host em `oath.rs` + `cargo test -p aegis-applets` |
| **AC-5** | **Contagem de escritas:** cada `RESET` faz exatamente **1** chamada de `clear` e **0** de `save`, tanto no sucesso quanto na falha (wrapper com contadores); não existe caminho de falha de `save` separado no `RESET` (asserção explícita de `saves == 0`), e o `RESET` não faz leitura (`loads == 0`) | teste de host em `oath.rs` |
| **AC-6** | **`pending` não piora:** com credencial `touch required` e toque armado (`CALCULATE` → `PRESENCE_REQUIRED`), um `RESET` com `clear` falhando → `6A84` e `confirm_presence` responde `6985` (nenhum índice velho alcança `calculate_index`); no sucesso idem (`6985`); nenhum dos dois caminhos entra em pânico e a credencial segue calculável depois de um novo `CALCULATE` | teste de host em `oath.rs` |
| **AC-7** | **Documento de contrato atualizado na mesma mudança:** `docs/security-model.md` ganha a cláusula OATH (erase persistido antes da RAM, `6A84` observável, uma escrita, `INS_RESET` sem autenticação e erase lógico); `roadmap.md` registra a sub-fatia na Fase 13 e mantém os follow-ups; `validation.md` ganha a subseção OATH com a tabela de ACs e a pendência física, e a linha **AC-031** | revisão estática |

## 7. Plano de teste

### 7.1 Onde ficam

No módulo `#[cfg(test)] mod tests` já existente em
`crates/aegis-applets/src/oath.rs`, reutilizando `applet()`, `frame()`,
`run()`, `put_data()`, `calculate_data()`, `code()` e `TestRng`. Duas mudanças
mecânicas:

- `run()` hoje é tipado em `Oath<MemoryOathStore>`; passa a ser genérico sobre
  `S: OathStore` (mesmos argumentos; call sites atuais inalterados). Um helper
  novo cria o applet sobre uma store dada (`Oath::new(store)` + `select()`).
- wrapper de teste `FailingOathStore` (nome à escolha do implementador)
  implementando `OathStore`: delega `load`/`save`/`clear` a um
  `MemoryOathStore`, tem `set_clear_fails(bool)` e contadores `clears()`,
  `saves()`, `loads()`, além de um `Default` saudável para permitir
  `core::mem::take(oath.store_mut())` na simulação de reabertura. Ela **não** é
  código de produção; fica em `#[cfg(test)]`.
- o handshake de access code de `access_code_validate_round_trips`
  (`SET CODE` com `TAG_KEY`/`TAG_CHALLENGE`/`TAG_RESPONSE`) é extraído num
  helper de teste (ex. `set_access_code(&mut oath, &key)`), sem alterar as
  asserções do teste existente.

### 7.2 Como os casos são montados

- **AC-1:** applet com wrapper saudável; `PUT` de uma credencial TOTP e (variante
  A) nada mais / (variante B) access code configurado — atenção: `SET CODE`
  termina com `authenticated = true`, então a variante B chama `select()` antes
  do `RESET` para exigir o access code de novo; `set_clear_fails(true)`;
  `RESET` → `6A84`; `LIST` → `9000` com o nome (A) ou `6982` (B); `CALCULATE` →
  `9000` + código (A). Repetir com `MemoryOathStore` para provar que só a falha
  injetada muda o SW.
- **AC-2:** continuação do AC-1: `set_clear_fails(false)`; `RESET` → `9000`;
  `LIST` vazio; `select()` → resposta sem `TAG_CHALLENGE`; `LIST` → `9000`
  vazio; `SET CODE` aceito (o access code anterior sumiu de fato).
- **AC-3:** montar estado persistido saudável (credencial + access code), zerar
  contadores, ligar a falha de `clear`, `RESET` → `6A84`; `oath.select()` →
  `LIST` ainda `6982`; validar o access code antigo (HMAC sobre o challenge do
  `SELECT`) → `LIST` com o nome antigo; em seguida `core::mem::take` da store e
  `Oath::new(store)` + `select()` → mesmo resultado. Ler a store diretamente
  (`store_mut().load(&mut buf)`) e afirmar `Some(n)` com `n > 0`.
- **AC-4:** `reset_removes_credentials_and_authentication` sem edição; novo caso
  com `MemoryOathStore`: `PUT` → `RESET` → `9000` → reabrir a store →
  `LIST` vazio; `RESET` com `P1=0x00`/`P2=0x00` e `P1=0xDE`/`P2=0x00` →
  `6D00` com `clears() == 0` e `saves() == 0`.
- **AC-5:** zerar contadores depois do setup; `RESET` (sucesso) → `clears() == 1`,
  `saves() == 0`, `loads() == 0`; repetir com falha → mesmos contadores e
  `6A84`.
- **AC-6:** `PUT` com `PROPERTY_TOUCH`; `CALCULATE` → `PRESENCE_REQUIRED`;
  `RESET` com falha → `6A84`; `confirm_presence()` → `6985`; variante sucesso →
  `9000` e `confirm_presence()` → `6985`; depois, `CALCULATE` novamente
  (credencial intacta no caminho de falha) → `PRESENCE_REQUIRED` e
  `confirm_presence()` → `9000`.
- Nomes sugeridos (o implementador pode ajustar):
  `reset_with_failing_store_reports_6a84_and_keeps_the_session_state`,
  `reset_retries_successfully_after_the_store_recovers`,
  `failed_reset_leaves_the_persisted_state_reachable_from_a_reload`,
  `successful_reset_persists_the_erase_across_reopen`,
  `reset_writes_once_and_never_saves`,
  `reset_drops_the_pending_touch_in_both_paths`,
  `reset_parameters_outside_de_ad_do_not_touch_the_store`.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

Suíte atual de `aegis-applets`: **238** testes (medido após a fatia PIV); a
contagem final deve ser registrada em `roadmap.md`/`validation.md` na mesma
mudança. Somente `aegis-applets` é tocado em código; `cargo build-fw` não é
exigido (nenhum arquivo de firmware/HAL muda).

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/oath.rs` | `reset`: `store.clear()` checado **antes** da limpeza da RAM, `save_state()` removido, `pending` descartado nos dois caminhos, `6A84` na falha e `9000` só no sucesso; testes AC-1..AC-6, wrapper `FailingOathStore` e generalização de `run`/helpers |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | Documentação na mesma mudança (§9) |

Nada é alterado em `crates/aegis-applets/src/sealed.rs` (nem API, nem layout do
`SealedBlob`), `crates/aegis-core/**`, `crates/firmware-universal-rp2350/**`,
`crates/board-generic-rp2350/**`, `crates/aegistoken-host/**` ou `scripts/**`.

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — em "Applet security invariants", depois do
   parágrafo do PIV (que fecha a regra de persistência observável), acrescentar
   a cláusula do OATH: o `RESET` (`P1=0xDE, P2=0xAD`) é *fail-closed* — a
   gravação (`clear`) é commitada **antes** da limpeza volátil e uma recusa da
   store responde `6A84` em vez de `9000`; o motivo da ordem é que o estado
   volátil vazio do OATH é o lado **permissivo** (`require_auth` libera com
   `auth_key` vazio), ao contrário do piso restritivo do PIV/OpenPGP — por isso
   aqui não há piso nem rollback: ou o erase persistiu e a RAM é limpa, ou nada
   muda. Registrar que o caminho feliz é **uma** escrita (sem `save_state`
   redundante), que o estado removido é o blob inteiro (credenciais, access
   code, algoritmo/challenge HMAC) e que `P1`/`P2` fora do par canônico
   respondem `6D00` sem tocar a store. Registrar também o que é aceito, não
   como gap: `INS_RESET` segue sem autenticação (YKOATH; apaga, não revela) e o
   erase é **lógico** — a rotação de slots do `SealedBlob` pode conservar
   gerações anteriores seladas até serem sobrescritas.
2. **`roadmap.md`** — Fase 13 (OATH), seção **Entregue**: acrescentar a
   sub-fatia de persistência fail-closed do `RESET` (`6A84` observável, uma
   escrita, ordem persistência→RAM, `save_state` redundante removido) com a
   contagem de testes novos e o total da suíte. Na seção **Pendências** da mesma
   fase, manter `AC-018 em hardware` e registrar explicitamente os follow-ups
   deixados de fora desta fatia (leitura da store tratada como estado vazio no
   `load_state`; bounds/ciclo de vida de `pending` em `confirm_presence`/
   `delete`), sem promovê-los a "gap novo".
3. **`validation.md`** — na seção "OATH / TOTP / HOTP (Fase 13)" (~l. 218),
   adicionar a subseção "`RESET` fail-closed (fatia
   `specs/oath-reset-fail-closed.md`)" com a tabela de ACs (método: testes de
   host de `aegis-applets::oath`; status **Verificado em host**) e a pendência
   física: a falha de gravação não é induzida em hardware (`validate_oath.py`
   não simula flash doente), ficando pendente o caso "`RESET` com gravação
   negada → `6A84` e credenciais intactas" em dispositivo real; nada muda no
   script neste ciclo. Na tabela de critérios (~l. 752-764), acrescentar a linha
   **AC-031** com o resumo da fatia e ajustar o texto de status do **AC-018**
   para incluir "`RESET` fail-closed".

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Representação persistida do "vazio" muda.** Hoje, depois de um `RESET`
  saudável, o blob mais novo é o header de 77 bytes do `save_state`; com a
  fatia, é o commit com `total = 0` do `clear`. O comportamento observável é
  idêntico (reabertura lista vazio, sem access code) e não há migração
  (`STATE_VERSION` intacto), mas qualquer teste futuro que compare **bytes** da
  store após `RESET` precisa saber disso. Documentado no AC-4 (comportamento,
  não bytes).
- **R2 — `6A84` no `RESET` muda o que a ferramenta mostra.** Sob flash doente,
  `ykman oath reset`/Yubico Authenticator passam a exibir erro de cartão em vez
  de sucesso — correto e defensável (a operação não aconteceu), mas a
  confirmação visual fica para a validação física (`validate_oath.py`).
- **R3 — Uma escrita em vez de duas reduz a redundância de erase.** Antes, um
  `clear` falho podia ser compensado por um `save_state` bem-sucedido; agora a
  falha do único write é reportada. É a troca desejada: um `bool` exato e
  observável vale mais que uma segunda tentativa cujo resultado não tem
  tratamento correto (decisão 1). O modelo de atomicidade do `SealedBlob`
  (commit por último, geração anterior preservada) é o que sustenta a leitura
  `false ⇒ estado anterior intacto`; a suíte de `sealed.rs` já cobre esse
  caminho.
- **R4 — Concorrência de edição.** `oath.rs` é grande e outras fatias mexem em
  `roadmap.md`/`validation.md`; manter o diff cirúrgico (o handler e o módulo de
  testes) e reconciliar no rebase. A generalização de `run()` é mecânica e deve
  ser feita sem tocar asserções (AC-4 é a rede).

### 10.2 Limitações

- **L1 — Sem hardware neste ciclo.** ACs exclusivamente de host; nenhum
  `cargo build-fw` (nada de firmware/HAL é tocado). A indução de falha de
  escrita em flash real fica pendente em `validation.md`.
- **L2 — O erase é lógico, não físico.** `clear()` grava uma nova geração vazia
  (commit `total = 0`) e passa a ser a mais nova; gerações anteriores seladas
  podem permanecer na rotação de slots até serem sobrescritas. É o modelo do
  `SealedBlob` (chave derivada da OTP, resposta nunca exporta segredo), não um
  efeito desta fatia; qualquer endurecimento físico (wipe de regiões) é fatia
  própria de store/flash.
- **L3 — `MemoryOathStore` nunca falha** por construção; os ACs exigem a wrapper
  de teste, que não entra no build normal do crate.
- **L4 — Store ilegível é caso degenerado.** Se a leitura também falhar, o
  `SELECT` seguinte pode não recuperar o estado antigo (`load_state` trata erro
  como "sem estado" — informacional fora do escopo). Nesse cenário o `6A84` já
  sinalizou a falha, a RAM da sessão permaneceu como estava (access code ainda
  exigido na sessão) e a degradação é do meio físico, não um caminho novo do
  applet.
- **L5 — `INS_RESET` continua sem autenticação.** Um processo PC/SC local pode
  apagar credenciais (disponibilidade). É o protocolo YKOATH e está preservado
  de propósito (não-objetivo 3); a fatia garante que o apagamento, quando
  confirmado, aconteceu.
- **L6 — Sem segredo novo e sem estado novo.** A fatia não adiciona estado
  persistente, não muda a serialização (`fn save_state`/`fn decode_state`) nem
  cria SWs além do `6A84`.
