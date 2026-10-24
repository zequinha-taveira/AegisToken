# Spec — OpenPGP: RESET RETRY COUNTER exige PW3 verificado (unblock fail-closed)

> **Origem:** achado **CRÍTICO** do `sec-audit` (loop de hardening de segurança).
> **Risco:** CRÍTICO — um host não autenticado redefine o PW1 e adquire a
> autoridade completa do applet OpenPGP (decifra + autenticação interna).
> Fatia única, fechada, em `aegis-applets`; nenhum teste de hardware neste ciclo
> (os ACs são de host; a validação física fica pendente em `validation.md`).

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- `crates/aegis-applets/src/openpgp.rs:1563-1570` — `reset_retry` (INS
  `RESET_RETRY_COUNTER` = `0x2C`, constante em `openpgp.rs:32`; o audit citou
  "0x2E", o valor real é `0x2C`) só valida `apdu.p2 == 0x81` e
  `apdu.data.len() == 8` e então chama **`self.pw1.unblock(apdu.data)`** — sem
  consultar `pw3_verified`, sem Resetting Code, sem qualquer autoridade. Na
  sequência chama `save_state()` e devolve o resultado. Não há teste algum para
  essa instrução (grep em `openpgp.rs` confirma: nenhum `#[test]` cobre `0x2C`).
- `crates/aegis-applets/src/pin.rs:224-230` — `PinSlot::unblock` delega a
  `set()` (`pin.rs:189-198`), que substitui o hash e restaura o contador. O
  doc-comment diz que "o chamador deve ter verificado a autoridade antes"
  (`pin.rs:226-227`), mas **nada é exigido ou enforceado** — o slot não conhece
  sessão. Existe um precedente correto no mesmo crate: o PIV autentica o unblock
  com PUK antes de chamar `pin.unblock(...)`
  (`crates/aegis-applets/src/piv.rs:722-741`, coberto pelo teste
  `piv.rs:1832-1861`).
- `crates/aegis-applets/src/openpgp.rs:584-609` — o handler de `VERIFY` mostra o
  padrão de sessão que a fatia segue: `pw3_verified` é falso por padrão
  (`openpgp.rs:348`), fica `true` só após um `VERIFY` PW3 bem-sucedido
  (`openpgp.rs:604`) e é limpo em `select()` (`openpgp.rs:1578-1585`). Handlers
  administrativos existentes já seguem esse padrão (`openpgp.rs:961-962`,
  `openpgp.rs:1074-1075`).

### 1.2 Caminho de exploração

1. O atacante tem o dispositivo em mãos (CCID enumerado) e seleciona o applet
   OpenPGP pelo AID — nenhum conhecimento é preciso.
2. Envia `00 2C 00 81 08 || 8 bytes quaisquer` (RST RETRY COUNTER). O handler
   hoje aceita e executa `pw1.unblock(data)`: o hash do PW1 passa a ser
   **escolhido pelo atacante** e o contador de tentativas do PW1 é restaurado.
3. `VERIFY` P2=0x81 com os 8 bytes escolhidos → `9000`
   (`pw1_signature_verified = true`, `openpgp.rs:602`).
4. Com isso o atacante executa `PSO: COMFIRM DIGITAL SIGNATURE` (falsifica a
   identidade do dono), `PSO: DECIPHER` (descriptografa com a chave DEC — o
   ECDH devolve o segredo compartilhado ao cartão só depois de PW1 modo 82, mas
   o RSA cru devolve a decifra) e `INTERNAL AUTHENTICATE` (a chave AUT responde
   qualquer desafio — roubo de identidade SSH/Git).

**Impacto:** aquisição da autoridade PW1 sem conhecimento do segredo — quebra
do fail-closed do ciclo de PIN. Uma única APDU não autenticada transforma o
"bloqueio" (retries = 0 → `0x6983`) em um botão de reset para o atacante. O furo
é agravado porque o caminho legítimo de desbloqueio é o único que deveria
existir e hoje é um caminho público.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | "PIN fail-closed e persistente; contadores de tentativa persistentes; bloqueio/unblock fail-closed" | `AGENTS.md` (regras do projeto), `docs/security-model.md:132-139` ("PIN state is persistent and fail-closed... unblock flows sealed") | **violada** — o unblock do OpenPGP não exige autoridade |
| I2 | A OpenPGP Card spec v3.4 exige autoridade para `RESET RETRY COUNTER`: o comando é executável com PW3 verificado (`P1=0x02`) ou com o Resetting Code (`P1=0x00`) | OpenPGP Card v3.4, §7.2.14 | **violada** — o comando é executável sem nenhuma das duas |
| I3 | O PIV do mesmo crate só desbloqueia com PUK verificado (`piv.rs:722-741`) | padrão de referência do repositório | OpenPGP diverge do padrão |

---

## 3. Decisão de política (documentada nesta spec)

**Autoridade.** O Resetting Code (BC) **não é provisionado** nesta fundação.
O caminho de autenticação por BC fica recusado com `FUNCTION_NOT_SUPPORTED`
(`0x6A81`) até que uma fatia própria implemente o BC. O único caminho de
desbloqueio desta fatia é o administrador: **`pw3_verified == true`** no momento
do comando. Para P2=0x81 (reset do PW1) sem PW3 verificado a resposta é
`SECURITY_STATUS_NOT_SATISFIED` (`0x6982`) e **nenhum estado é modificado**.

**P1 vs P2 (leitura da referência).** O parágrafo de política do audit usa
`P2` onde a card spec usa os dois campos com papéis distintos — confirmado na
spec (§7.2.14) e no código: **`P2` seleciona o PW a ser resetado** (`0x81` =
PW1; é o que o handler já faz) e **`P1` seleciona a autoridade** (`0x00` =
Resetting Code nos dados; `0x02` = PW3 previamente verificado). A leitura
"tratar como function_not_supported (0x6A81)" aplica-se ao **caminho do
Resetting Code (P1=0x00)**, não ao reset do PW1 em si — caso contrário os
critérios AC-2/AC-4/AC-5 seriam autocontraditórios. Portanto:

- `P1=0x02`, `P2=0x81`: caminho admin — exige `pw3_verified` (§ AC-1/AC-2).
- `P1=0x00` (Resetting Code nos dados): `0x6A81`, estado inalterado (AC-5).
- `P2 ≠ 0x81`: `INCORRECT_PARAMETERS` (`0x6A86`) — hoje o handler devolve
  `WRONG_DATA` (`0x6A80`) para P2 desconhecido (`openpgp.rs:1564-1565`); a
  fatia troca para o SW correto da spec (AC-4). Erro de comprimento
  (`data.len() != 8`) continua `WRONG_DATA`, como hoje.

**A sessão de PW3 não é consumida.** A OpenPGP Card 3.4 (§7.2.14) determina que
um `RESET RETRY COUNTER` autenticado por PW3 **não encerra** o estado de
verificação do PW3. Decisão registrada: o handler **não** limpa
`pw3_verified` nem consome a verificação após um desbloqueio bem-sucedido —
operação administrativa subsequente continua funcionando sem novo `VERIFY` PW3
(AC-3). Isso é o oposto do PIV, que limpa `pin_verified` após o unblock do PIN
(`piv.rs:739`): ali a autoridade (PUK) é outra PIN; aqui a spec explicita a
persistência da sessão de PW3.

**Ordem de checagem (fail-closed).** `P1`/`P2` válidos → autoridade
(`0x6982`) → comprimento (`0x6A80`) → `unblock`. Pedidos não autorizados nunca
alcançam o slot e nunca disparam `save_state()`.

---

## 4. Escopo

- `reset_retry` (`openpgp.rs:1563-1570`) passa a exigir `pw3_verified == true`
  no caminho `P1=0x02, P2=0x81`; negativa → `0x6982` **sem modificar nada**
  (contador, hash e flags intocados; sem `save_state()`).
- `P1=0x00` → `0x6A81` (Resetting Code não provisionado nesta fundação);
  `P1` desconhecido → `0x6A86`; `P2 ≠ 0x81` → `0x6A86`.
- Desbloqueio bem-sucedido: `pw1.unblock(novo)` restaura o contador do PW1 para
  o máximo da política (`PW_POLICY`, 3 tentativas — comportamento já de
  `PinSlot::set`, `pin.rs:193-198`) e persiste o estado na primeira escrita da
  flash; o contador do **PW3 nunca é alterado** por este comando.
- `pw3_verified` **permanece** verdadeiro após o comando (sessão não consumida)
  e continua sendo limpo apenas em `select()` (`openpgp.rs:1578-1585`) — nenhum
  flag de sessão vira estado persistente.
- `crates/aegis-applets/src/pin.rs`: a exigência de autoridade fica no **handler
  do applet** (levantada para quem conhece a sessão); `PinSlot::unblock`
  recebe a documentação de módulo reforçada sobre quem pode chamá-lo (PUK no
  PIV, PW3 no OpenPGP) e que o enforcement pertence ao chamador — mudança de
  documentação, não de assinatura nem de comportamento.
- Testes de host obrigatórios (AC-1..AC-6, §6) no módulo de testes existente de
  `openpgp.rs`.

## 5. Não-objetivos

1. **Fail-open de `save_state()`** — o resultado de `store.save` é descartado
   (`openpgp.rs:407-435`); persistência que falha silenciosamente é fatia
   própria.
2. **Validação de `kdf_hash` no D2** — fatia própria.
3. **MDC em tempo constante** — fora do escopo.
4. **Política de comprimento de PW do CHANGE REFERENCE DATA** — não é tocada.
5. **Resetting Code (BC)** — provisão, verificação e contadores próprios do BC
   ficam para uma fatia futura; aqui o caminho é recusado com `0x6A81`.
6. **Qualquer mudança em FIDO/PIV/OATH** — `piv.rs`, `oath.rs`, FIDO e roteador
   não são alterados (o PIV permanece como o padrão de referência).
7. **`select()`, máquina de sessão ou formato do estado persistente**
   (`STATE_VERSION`) — inalterados.

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host no módulo `#[cfg(test)]` de
`crates/aegis-applets/src/openpgp.rs` (nenhum exige hardware).

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | `RESET RETRY COUNTER` (P1=0x02, P2=0x81) **sem** `pw3_verified` → `0x6982`, e estado **inalterado**: o PW1 ainda verifica com o PIN original (e **não** com os 8 bytes do pedido), o contador do PW1 (visível no `VERIFY` sem dados, `63Cx`) e o flag de sessão PW1 sig (recusa de `PSO` com `0x6982`) permanecem exatamente como antes | teste de host em `openpgp.rs` |
| **AC-2** | Com **PW3 verificado** (`VERIFY` P2=0x83 primeiro), o mesmo comando define o novo PW1: `VERIFY` com o PIN novo → `0x9000`, contador do PW1 restaurado para o máximo da política (3 — `63C3` no `VERIFY` vazio) e **PW3 inalterado**: com o seu PIN original o PW3 ainda verifica e seu contador permanece intacto | teste de host em `openpgp.rs` |
| **AC-3** | O comando **não encerra a sessão de PW3**: após um desbloqueio bem-sucedido, uma operação administrativa subsequente (ex.: `PUT DATA`, que exige `pw3_verified` em `openpgp.rs:961-962`) continua respondendo sem novo `VERIFY` PW3 | teste de host em `openpgp.rs` |
| **AC-4** | `P2` desconhecido (≠ `0x81`) → `0x6A86`, estado inalterado (comportamento muda do `0x6A80` atual para o SW correto da spec) | teste de host em `openpgp.rs` |
| **AC-5** | Caminho do Resetting Code (`P1=0x00`) → `0x6A81` (`FUNCTION_NOT_SUPPORTED`), estado inalterado — o BC não existe nesta fundação | teste de host em `openpgp.rs` |
| **AC-6** | `select()` limpa a sessão: depois de um ciclo select→unblock→select, um novo `RESET RETRY COUNTER` sem `VERIFY` PW3 volta a recusar com `0x6982` (e só volta a funcionar após novo `VERIFY` PW3) | teste de host em `openpgp.rs` |
| **AC-7** | **PW1 bloqueado permanece bloqueado até o unblock autenticado**: após esgotar as tentativas, `VERIFY` → `0x6983`; um `RESET RETRY COUNTER` não autenticado → `0x6982` e o slot **continua** bloqueado — e **não** com o PIN atropelado; só após `VERIFY` PW3 + reset o PW1 novo verifica | teste de host em `openpgp.rs` |
| **AC-8** | `pin.rs` documenta o contrato do `unblock`: a autorização é obrigação do chamador (handler do applet que verificou PUK/PW3), com referência cruzada aos dois chamadores (PIV `reset_retry_counter`, OpenPGP `reset_retry`) | revisão do doc-comment (estático) |

## 7. Plano de teste

### 7.1 Onde ficam

No módulo `#[cfg(test)] mod tests` existente em
`crates/aegis-applets/src/openpgp.rs` (`openpgp.rs:1770`), reutilizando os
helpers já estabelecidos: `applet()` (`openpgp.rs:1803-1807`, cria o applet com
`MemoryOpenPgpStore` e faz `select()`), `frame()` (`openpgp.rs:1809-1826`) e
`run()` (`openpgp.rs:1828-1838`). É o mesmo padrão do PIV para o unblock
verificado (`piv.rs:1832-1861`).

### 7.2 Como os casos são montados

- **AC-1 / AC-7:** `verify` com PIN errado até o contador 0 (`63C0`); então
  `RESET RETRY COUNTER` (P1=2, P2=0x81) **antes** de qualquer `VERIFY` PW3 →
  `0x6982`; em seguida verificar que `VERIFY` PW1 com o PIN original ainda dá
  `0x9000` (hash intacto) ou `0x6983` (no caso em que ele estava bloqueado),
  que `VERIFY` com os 8 bytes do pedido falha com `63Cx`, e que `PSO` recusa
  com `0x6982` (flag de sessão intacto).
- **AC-2 / AC-3:** `VERIFY` P2=0x83 → `9000`; `RESET RETRY COUNTER` com o
  primeiro PIN errado → `63Cx` (parcial: conectado ao gate — ver §7.3);
  segundo com PIN novo de 8 bytes → `9000`; `VERIFY` PW1 novo → `9000`;
  `VERIFY` vazio P2=0x81 → `63C3` (contador restaurado); PW3 continua
  aceitando o PIN original e um `PUT DATA` administrativo funciona **sem**
  re-verificação (AC-3).
- **AC-4 / AC-5:** APDUs com `P2=0x82`/`0x83` e com `P1=0x00` → `0x6A86` /
  `0x6A81`, com o estado conferido antes/depois (mesma verificação do AC-1).
- **AC-6:** flush completo (unblock com sucesso) → `applet.select()` →
  `RESET RETRY COUNTER` sem PW3 → `0x6982`.
- Nomes sugeridos (o implementador pode ajustar):
  `reset_retry_requires_pw3_and_leaves_state_untouched`,
  `reset_retry_with_pw3_sets_new_pw1_and_restores_retries`,
  `reset_retry_does_not_end_the_pw3_session`,
  `reset_retry_rejects_unknown_p2`,
  `reset_retry_rejects_the_resetting_code_path`,
  `select_clears_pw3_and_reset_retry_requires_it_again`,
  `blocked_pw1_stays_blocked_until_authenticated_unblock`.

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
| `crates/aegis-applets/src/openpgp.rs` | `reset_retry` (§1563): gate de `pw3_verified`, P1 `0x00`→`0x6A81`, P2 desconhecido→`0x6A86`, sem `save_state()` na negativa; testes de host AC-1..AC-7 |
| `crates/aegis-applets/src/pin.rs` | Doc-comment do módulo e de `PinSlot::unblock` (§§189-230): quem pode chamar (PUK no PIV, PW3 no OpenPGP) e onde o enforcement vive (handler). Sem mudança de assinatura/behavior |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | Documentação na mesma mudança (§9) |

Nada é alterado em `crates/aegis-core/**`, `crates/firmware-universal-rp2350/**`
ou `crates/board-generic-rp2350/**` (nenhum despacho de firmware muda — o FIDO
não vê CCID e o roteador CCID não muda de API).

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — na seção de invariantes dos applets
   ("PIN state is persistent and fail-closed", ~`security-model.md:132-139`),
   declarar explicitamente: no OpenPGP, `RESET RETRY COUNTER` exige PW3
   verificado (`pw3_verified`), o caminho do Resetting Code responde `0x6A81`
   enquanto o BC não existe, a sessão de PW3 não é consumida pelo comando, e a
   autorização é enforceada no handler do applet (o slot grava sem conhecer
   sessão).
2. **`roadmap.md`** — registrar a sub-fatia de hardening na Fase 14 (OpenPGP),
   no mesmo estilo das fatias nomeadas do histórico (`7g`/`7h`, `16a-16d`):
   item em "Entregue" com o gate de `pw3_verified` no `RESET RETRY COUNTER`,
   caminho BC recusado (`0x6A81`) e a referência a esta spec. A linha de status
   da Fase 14 na tabela inicial permanece "Concluída (…)".
3. **`validation.md`** — na seção "OpenPGP Card v3.4" (~`validation.md:208`),
   adicionar o AC da fatia (método: testes de host de `aegis-applets::openpgp`;
   status: **Verificado em host**; hardware pendente) e registrar a pendência
   física: estender `scripts/validate_openpgp.py` com o caso "RST RETRY COUNTER
   sem PW3 → `0x6982`" (hoje o script não exerce `0x2C`), para rodar quando
   houver RP2350 físico.

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Persistência fragil (`save_state` fail-open).** O resultado de
  `store.save` é descartado (`openpgp.rs:407-435`); um unblock autenticado pode
  não sobreviver a power cycle em caso de falha de escrita. Fora do escopo
  (não-objetivo 1), mas **atento**: o gate de autoridade nesta fatia não piora
  o cenário — a negativa não chama `save_state()` de fato.
- **R2 — Interoperabilidade do P1.** Hoje `P1` é ignorado; clientes que enviavam
  `P1=0` (caminho do Resetting Code, ex.: pilhas que preenchem o BC vazio)
  passam a receber `0x6A81`. É o comportamento prescrito pela card spec
  (§7.2.14) quando o BC não existe; risco de interop é baixo, mas a mudança é
  externamente visível — cobrir com AC-5 e validar em hardware quando houver
  dispositivo (`validate_openpgp.py` / `gpg`).
- **R3 — PW3 padrão provisionado.** `ensure_loaded` instala PW1 `123456` e PW3
  `12345678` (`openpgp.rs:402-403`) — valores de interop da OpenPGP Card, no
  mesmo espírito dos defaults NIST do PIV (regra do `AGENTS.md`: não marcar
  como leak, não randomizar). O hardening não muda isso; um atacante que
  conhece o default pode se autenticar como admin — é uma decisão de produto
  de interop, fora do escopo desta fatia.
- **R4 — Concorrência de edição.** O loop de hardening tem outras sessões
  tocando `pin.rs`/`roadmap.md`/`validation.md`; manter os diffs pontuais
  (doc-comment e item novo) e reconciliar no rebase.

### 10.2 Limitações

- **L1 — Sem hardware neste ciclo.** Todos os ACs são de host; a verificação
  física (extensão do `validate_openpgp.py` com o caso de `0x6982` sem PW3)
  fica registrada em `validation.md`.
- **L2 — O BC continua inexistente.** Até a fatia do Resetting Code, o
  desbloqueio do PW1 exige a senha admin; usuários que perderiam o PW1 precisam
  do PW3 — coerente com "unblock fail-closed", mas deve constar nas notas de
  lançamento.
- **L3 — Sem segredo novo, sem material novo.** A fatia só restringe uma
  instrução existente; nenhuma chave, nenhum segredo e nenhum estado persistente
  novo.
