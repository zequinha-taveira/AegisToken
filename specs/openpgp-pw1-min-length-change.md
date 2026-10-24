# Spec — OpenPGP: `CHANGE REFERENCE DATA` do PW1 aceita corpo de comprimento variável (o default de 6 octetos pode ser trocado)

> **Origem:** gap **L4** registrado na limitation da fatia S10
> (`specs/openpgp-pw3-change-authority.md` §7.2, AC-5, e no comentário do teste
> `pw1_change_still_works_without_a_session` em `openpgp.rs`). **Risco:** MÉDIO —
> não é escalada de privilégio (a rota permanece fail-closed), mas um **buraco
> de interop/funcionalidade com viés administrativo**: todo cartão
> OpenPGP real permite ao dono trocar o próprio PW1 de fábrica (`123456`) na
> porta pública `0x24`; no AegisToken esse comando recusa o corpo que o
> scdaemon envia, e a saída hoje é **forçar o usuário a atravessar a porta
> admin** (`RESET RETRY COUNTER`) para conseguir instalar um PW1 trocável.
> Fatia única, fechada, em `aegis-applets`; nenhum teste de hardware neste
> ciclo (os ACs são de host; a validação física fica pendente em
> `validation.md`).

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- `crates/aegis-applets/src/openpgp.rs:1645-1669` — `verify_change`
  (INS `CHANGE REFERENCE DATA` = `0x24`, constante em `openpgp.rs:31`) mapeia
  `apdu.p2`: `0x81`/`0x82` → slot PW1, `0x83` → slot PW3 (`P2` desconhecido →
  `INCORRECT_PARAMETERS`, `0x6A86`; o gate de sessão da S10 protege `0x83`).
  Depois filtra **`apdu.data.len() != 16`** → `WRONG_DATA` (`0x6A80`),
  fatia o corpo em `atual(8) + novo(8)` **em posições fixas** e chama
  `slot.change(&apdu.data[..8], &apdu.data[8..])`, seguido de
  `persist_state()` (piso S5; save falho → `NOT_ENOUGH_MEMORY`, `0x6A84`).
- `crates/aegis-applets/src/pin.rs` — `PinHash::verify` (`pin.rs:115-118`)
  compara o SHA-256 do PIN **exatamente como apresentado** (sem padding);
  `PinSlot::change` (`pin.rs:221-224`) é `verify(atual)` + `set(novo)`;
  `set` (`pin.rs:206-211`) enforceia a política `check_length`
  (`pin.rs:300-305`, `min_len`/`max_len` → `Sw::WRONG_LENGTH` = `0x6700`).
  A política do applet é `PW_POLICY: PinPolicy::new(6, 127, 3, Sha256)`
  (`openpgp.rs:66`) — PW1 e PW3 compartilham.
- `ensure_loaded` (`openpgp.rs:411-412`) instala os defaults de interop:
  **PW1 `123456` (6 octetos)** e PW3 `12345678` (8). O slot PW1 só sai do
  tamanho 6 por duas rotas: `RESET RETRY COUNTER` da S4
  (`reset_retry`, `openpgp.rs:1671-1694`, corpo fixo de 8 → PW1 vira 8) ou
  a própria troca — **que exige o corpo de 16 fatiado em 8+8**.
- O estado do slot não informa o comprimento do PIN guardado: o encoding
  versionado de `PinSlot` (`pin.rs:256-298`) carrega só versão, formato,
  contador, flag e hash. Logo o applet **não sabe** (`pin.rs` não expõe um
  comparador de candidata sem decremento — a única comparação publicada, o
  `PinSlot::verify`, consome tentativa).

### 1.2 Caminho de exploração (interop quebrada, não escalação)

1. Usuário honesto com `gpg --card-edit` → `passwd` → "change PIN": o
   scdaemon entra em `do_change_pin` (`scd/app-openpgp.c`, caminho de teclado
   para cartões v2): pede o PW1 antigo e o novo via pinentry,
   passa pelos `pin2hash_if_kdf` (no-op sem KDF de PIN) e chama
   `iso7816_verify(0x80+chvno, old)` e depois
   `iso7816_change_reference_data(0x80+chvno, old, new)`.
2. `iso7816_change_reference_data` (`scd/iso7816.c`) monta o corpo como a
   **concatenação exata** `old‖new` (`memcpy(buf, old, oldlen)` +
   `memcpy(buf+oldlen, new, newlen)`) e envia `Lc = oldlen+newlen` — **sem
   delimitador e sem padding**. A OpenPGP Card spec (§7.2.3 CHANGE REFERENCE
   DATA) fecha o mesmo desígnio: *"the actual PW is part of the command data
   and will be verified first by the card. **The length of the existing
   password is known in the card**, so that neither a delimiter nor padding
   for filling up fixed formats is necessary. The length of the new password
   therefore computes **Lnew = Lc − Lold**"* — mínimo do novo PW1 é 06, máximo
   é o anunciado no DO `C4` (o nosso `pw_status`, `openpgp.rs:888-898`,
   reporta `0x7F` = 127, coerente com `PW_POLICY.max_len`).
3. **Com o PW1 de fábrica (6 octetos), o corpo do GnuPG tem Lc = 6+6 = 12 —
   o handler recusa com `0x6A80`** (o filtro exige 16). Corpo de
   6+8 (usuário escolhe 8) → recusado igual. Ou seja: **na porta pública o
   PW1 default é imutável**.
4. Consequência funcional: o único jeito de trocar o PW1 é instalar um PIN de
   8 octetos via `RESET RETRY COUNTER` com a sessão de admin — ou seja, a
   rota de usuário comum da card spec não existe: toda a segurança do
   fail-closed da casa preservada, mas o produto não faz o que a spec e
   todo o ecossistema esperam. É também a limitação L4 que fechou o AC-5 da
   S10 (o teste da S10 precisa **instalar** um PW1 de 8 antes de exercitar a
   troca; o comentário em `openpgp.rs:4300-4301` registra isso).
5. O mesmo buraco existe **em potencial** para o PW3 (um admin entre
   `ENABLE UNLOCK`… com PW3 maior que 8 não poderia trocar), mas na fundação
   atual o PW3 é **invariantemente 8 octetos** (default 8; a troca exige
   corpo 16 → `novo` sempre 8; o unblock da S4 só toca o PW1) — o corpo fixo
   de 16 do `0x83` é correto e fica intacto (§3.3).

**Impacto:** divergência de interop com o caminho oficial de troca de PIN; o
usuário que não conhece a sutileza não consegue modificar o PIN de fábrica
pelo caminho canônico (`6A80` inexplicável). Risco de segurança adicional nenhum: as rotas fail-closed
da casa (gate S10, piso S5, contadores) não são atravessadas — o comando
recusa antes de tocar o slot.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | "PIN state is persistent and fail-closed": validação enforceada em cada handler; contadores persistentes; falha de save observável (`6A84`) | `docs/security-model.md:137-169` (invariantes dos applets, redigidas nas fatias S4/S5) | preservada — esta fatia não mexe em nada além do formato do corpo; a recusa de formato continua sem tocar slot/contadores/store |
| I2 | PW1 troca por conhecimento do corrente nos dados, sem sessão de admin (comportamento da card spec/ecossistema, sancionado pela S10) | `docs/security-model.md:155-156`, `specs/openpgp-pw3-change-authority.md` §3.2 | preservada — nenhum gate de sessão novo é adicionado ao `0x81`/`0x82` |
| I3 | A troca do PW3 (`0x83`) exige `pw3_verified`; corpo 16 normativo | fatia S10 (`roadmap.md:1241-1260`, `validation.md` AC-027) | preservada — nenhum comportamento do `0x83` muda |
| I4 | Interop GnuPG no domínio OpenPGP: o fluxo real (`VERIFY` → operação) deve funcionar | `roadmap.md` (Fase 14), `validation.md`, `gnupg_interop.rs` | **violada na porta `0x24`** — o caminho de teclado do scdaemon envia `Lc` variável, que hoje não passa |

---

## 3. Decisão de política (documentada nesta spec)

### 3.1 Corpo = concatenação `atual‖novo`, delimitação resolvida pelo comprimento conhecido

A card spec define a troca por **Lnew = Lc − Lold** com *"the length of the
existing password is known in the card"*. Na fundação o slot guarda só o
hash — mas isso basta: como o hash é do PIN exato apresentado, existe um **L
candidato** (e efetivamente único: a colisão de SHA-256 entre corpos de
comprimento distinto é desconsiderada, mesma impossibilidade que o `pin.rs`
já assume para comparação de hash) tal que `SHA-256(body[..L]) == hash
guardado`. O applet passa a
**determinar o Lold por varredura** nos comprimentos possíveis e aplica
`Lnew = Lc − Lold`. A varredura implementa exatamente o "comprimento
conhecido no cartão" da card spec sem alterar o formato persistente do slot —
**nenhum bump de versão de encoding**, nada no formato do estado
(`PinSlot`/`save_state` inalterados como dados).

### 3.2 Regra completa do corpo para `P2 = 0x81`/`0x82`

Ordem fail-closed de checagens (as duas primeiras idênticas ao estado atual):

1. `P2 ∈ {0x81, 0x82}` (desconhecido → `0x6A86`); **nenhum gate de sessão**
   nos dois modos — a autoridade do corrente nos dados permanece (I2).
2. **Formato**: `2 * PW_POLICY.min_len ≤ body.len() ≤ 2 * PW_POLICY.max_len`
   (ou seja, `12 ≤ Lc ≤ 254`); fora disso → `WRONG_DATA` (`0x6A80`) **antes
   de qualquer interação com o slot** — nenhuma tentativa consumida,
   nenhum save. Corpos de 0 e 11 (o caso do teste da S10) continuam
   recusados como hoje para estas larguras; 15 já entra na janela
   normativa e segue a mecânica do item 3 (delimitação/negativa).
3. **Delimitação**: dentro do alcance de split válido (`L ≥ min_len`,
   `L ≤ max_len`, `L ≥ Lc − max_len`, `L ≤ Lc − min_len`), procurar o `L` cujo
   `body[..L]` verifica contra o hash guardado **sem decrementar o contador**
   (comparação de leitura). 
   - **Match** ⇒ `novo = body[L..]`; a troca prossegue pelo caminho atual
     (`slot.change`, que re-verifica o corrente — sem decremento adicional
     neste caso —, `set(novo)` restaura contador para 3 e re-hashiza);
     sucesso `9000`; `persist_state()` sob as regras S5 (`0x6A84` em falha).
   - **Sem match em nenhum `L`** ⇒ o comando **consome exatamente uma
     tentativa** do PW1 e responde `63Cx` com persist (contrato atual de
     adjudicação de PIN: um comando de troca com corrente errada sempre
     custou uma tentativa — a varredura não amplia o orçamento de
     bruteforça, e o caso `Lc=16` de hoje tem exatamente essa semântica).
   - Slot **bloqueado** → `0x6983` sem tocar nada (a comparação de leitura
     se comporta como o `verify` nos diagnósticos que não consomem:
     unset → `CONDITIONS_NOT_SATISFIED` — PW1 é sempre instalado nesta
     fundação, mas o contrato é defensivo).
4. As flags de sessão PW1 (`pw1_signature_verified`/`pw1_other_verified`)
   **não são mexidas pela troca** — como hoje; a única porta que as limpa
   continua sendo o `select()`.

O oráculo permanece zero: a varredura em si não expõe mais do que o
corrente errado já expõe; recomendação de implementação: varrer **todo** o
alcance antes de decidir (volume de trabalho constante e independente do
`L` encontrado) — o único vazamento possível (posição do match) revela o
comprimento do corrente, que o remetente legítimo conhece.

### 3.3 PW3 (`0x83`) — formato fixo de 16 permanece normativo

O formato variável **não** se aplica ao `0x83` hoje: o corpo continua
`atual(8) + novo(8)` (qualquer `Lc ≠ 16` com sessão → `0x6A80`). Fundamento:
o PW3 é **invariantemente 8 octetos** nesta fundação — default de fábrica 8
(`openpgp.rs:412`), o próprio `0x83` com corpo fixo 16 só produz `novo = 8`,
e o unblock da S4 só toca o PW1. Logo o corpo 16 é suficiente para
**todas** as trocas reais de PW3 existentes. O gate `pw3_verified` da S10
fica **intacto**. Se uma fundação futura admitir PW3 de comprimento
variável, a mesma regra do §3.2 aplica-se ao `0x83` (fora de escopo, §5).

### 3.4 Onde vive a delimitação (comportamento, não assinatura)

A política de comprimento e o hash moram no slot (`pin.rs`): é onde a
delimitação pertence, como capacidade de **leitura** do slot — comparar uma
PIN candidata contra o hash guardado sem tocar o contador, conforme o
mesmo padrão de contrato do módulo (a autorização continua no
handler)". O handler mantém a ordem de checagem, a autoridade de sessão e o
mapeamento de SW; o slot mantém a regra de comprimento, a comparação e o
consumo único da tentativa na negativa. O PIV (`piv.rs`) continua com o
seu fluxo de corpo fixo próprio e não é tocado. `pin.rs` já tem um compare
de hash público (`PinHash::verify`), mas o acesso ao `hash` interno fora do
crate hoje só é possível via `PinSlot::verify` (que decrementa) — a fatia
acrescenta a comparação de leitura e mantém o restante do `pin.rs`
inalterado.

### 3.5 Interop GnuPG — fundamento da decisão (verificado no código-fonte)

- Caminho de teclado de cartões v2 (`app-openpgp.c::do_change_pin`, ramo
  final `else`): pede o PIN antigo e o novo, ambos via `pin2hash_if_kdf`
  (no-op sem KDF-DO de PIN), **um `iso7816_verify` com o antigo primeiro** e
  depois `iso7816_change_reference_data(0x80+chvno, old, new)`. Para
  `chvno == 1` (PW1) são enviados exatamente os comprimentos digitados.
- `iso7816.c::iso7816_change_reference_data`: `buf = old‖new`
  (`memcpy(buf, oldchv, oldchvlen)`, `memcpy(buf+oldchvlen, newchv,
  newchvlen)`) com `Lc = oldchvlen + newchvlen` — sem padding, sem
  delimitador. **É esta Lc variável — 12 no shape mais comum (6+6) — que o
  handler hoje recusa.**
- O caminho de pinpad (`change_reference_data_kp`, corpo vazio) não é
  acionável (o CCID do AegisToken não declara features de pinpad) e continua
  recusado pelo formato (`Lc=0 < 12` → `0x6A80`), como antes (S10 §3.5).
- O applet não implementa KDF de PIN (KDF-DO `0xF9` — o "kdf" do
  `openpgp.rs` é o KDF do ECDH/RFC 6637), de modo que os corpos chegados
  são PINs crus: a delimitação por hash do PIN exato é consistente com o
  que o cliente envia. Se uma fatia futura implementar o KDF-DO, os corpos
  passam a carregar os dois hash de 32 bytes — o invariante da §3.1
  ("comprimento do corrente conhecido no cartão") se aplica igualmente.
- A suíte `gnupg_interop.rs` hoje não exerce `0x24` (grep) — o AC de interop
  (AC-7) valida que ela permanece verde e que a troca do PW1 com corpo no
  molde do scdaemon funciona fim a fim.

### 3.6 Resolução do gap L4 (registro da S10)

O comentário de código de
`pw1_change_still_works_without_a_session` ("the 6-byte default cannot go
through a 16-byte CHANGE body yet", `openpgp.rs:4300-4301`) fica obsoleto e
**deve** ser atualizado nesta fatia (o default de 6 passa a ser trocável pela
porta pública). O desenho do teste (instalar PW1 de 8 via `RESET RETRY` para
exercitar a troca de corpo 16 contra um slot de 8) é mantido — o
comportamento observável dele não muda.

---

## 4. Escopo

- `verify_change` (`openpgp.rs:1645`): nos modos `0x81`/`0x82`, substitui o
  filtro `len != 16` + split fixo por: filtro de intervalo de formato
  (fora de `12 ≤ Lc ≤ 254` → `0x6A80`) + delimitação por comprimento
  conhecido (varredura de leitura §3.2) + `slot.change(body[..L], body[L..])`
  no match; `persist_state()`/`0x6A84` idênticos ao piso S5. A ordem
  `P2 → formato → delimitação` fica codificada como na §3.2.
- `crates/aegis-applets/src/pin.rs`: capacidade de leitura do slot descrita
  em §3.4 (comparar candidata sem decrementar; diagnósticos unset/blocked
  idênticos aos do `verify`) + doc-comments do módulo e de `PinSlot::change`
  apontando que a delimitação por comprimento conhecido acontece no slot para
  o OpenPGP (o corpo nunca tem delimitador) e que a autorização continua no
  chamador. Nenhuma mudança de formato persistente (`PIN_STATE_VERSION`).
- `P2 = 0x83`: **nenhuma** mudança de comportamento — gate S10, corpo 16,
  SWs, persistência e sessão idênticos (I3).
- Teste de host novos (AC-1..AC-8, §6) no módulo `#[cfg(test)]` de
  `openpgp.rs`, incluindo a correção do comentário da fatia S10 (§3.6).

## 5. Não-objetivos

1. **PW3 e `0x83`** — gate de sessão S10, corpo fixo 16, SWs e persistência
   idênticos (o formato variável do §3.2 não alcança `0x83`; a
   justificativa é o §3.3, e uma eventual PW3 variável é fatia futura).
2. **`RESET RETRY COUNTER` (S4)** — corpo de 8 e rota admin inalterados
   (um unblock continua sempre resultando em PW1 de 8 octetos).
3. **Política de comprimentos do slot** — `PW_POLICY` (6, 127, 3, SHA-256)
   e os defaults de `ensure_loaded` não mudam; a divergência teórica
   "mínimo do novo PW3 é 08 na card spec vs 6 na política compartilhada" é
   irrelevante enquanto o `0x83` tiver corpo fixo (novo sempre 8) e fica
   registrada como limitação (§10).
4. **KDF-DO de PIN (`0xF9`)** — sem suporte hoje, sem suporte aqui; a
   fronteira é a mesma da fatia S6 (§10).
5. **Caminho de pinpad** (`change_reference_data_kp`, corpo vazio) —
   continua recusado pelo filtro de formato; nenhum suporte a entrada
   on-card.
6. **Máquina de sessão, flags, `select()`, pisos, `persist_state`,
   `STATE_VERSION`** — intocados.
7. **Qualquer mudança em FIDO/PIV/OATH/CTAP2** — `piv.rs`, `oath.rs`,
   `aegis-core`, roteador, firmware e HAL não são alterados. Zero `unsafe`,
   zero dependências novas, zero `std`.

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host no módulo `#[cfg(test)]` de
`crates/aegis-applets/src/openpgp.rs` (nenhum exige hardware).

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | O PW1 **default de 6 octetos** pode ser trocado pela porta pública: fresh `applet()` (nenhum `VERIFY` admin nem `RESET RETRY`), `CHANGE` 0x81 com corpo 6+6 (`123456‖654321`) → `9000`; o novo verifica (`VERIFY` 0x81 com `654321` → `9000`) e o antigo (`123456`) falha `63Cx`; contador restaurado (3) e `persist_state` aplicado — após `select()`, o novo PIN continua verificando (persistido, piso S5 intacto) | teste de host em `openpgp.rs` |
| **AC-2** | Comprimentos mistos: com PW1 default 6, `CHANGE` 0x81 com `6+8` (`123456‖88888888`) → `9000` e `VERIFY` 0x81 `88888888` → `9000`; com PW1 de 8 instalado (via `RESET RETRY`, como o teste da S10), `CHANGE` 0x81 com `8+6` (`99999999‖777777`) → `9000` e `VERIFY` 0x81 `777777` → `9000` — a delimitação segue o **hash por candidato**, não um índice fixo, e o resultado é o template Lnew = Lc − Lold da card spec | teste de host em `openpgp.rs` |
| **AC-3** | Formato fora do intervalo sem tocar o slot: `Lc < 12` (11, 0 — inclusive o `b"AAAAAAAAAAA"` do teste S10) e `Lc > 254` → `0x6A80`, **sem decremento de tentativa** (`VERIFY` vazio → `63C3` após) e sem gravação (`FlakyOpenPgpStore.save_calls` intocado); o caso `len=16` com corrente de 6 e corpo incompatível segue exatamente a semântica de "sem match" do AC-4 (não é mais rejeição de formato) | teste de host em `openpgp.rs` |
| **AC-4** | Corrente errado: corpo no intervalo com nenhum split que verifique (ex.: corrente `123456`, corpo `111111‖888888`) → `63Cx` com o contador decrementado **exatamente em uma** unidade por comando (três comandos → `63C3`→`63C2`→`63C1`; não existe dois decrementos por comando) e persist (piso sticky S5 correto); o novo hash nunca é instalado; após esgotar, `VERIFY` → `0x6983` e a troca recusa sem tocar nada | teste de host em `openpgp.rs` |
| **AC-5** | Piso S5: com store flaky (`save_fails`), uma troca válida do PW1 → `0x6A84` (nunca `9000` falso), re-`select()` → o novo PIN não sobrevive (antigo re-verifica) e o swap não fica como sucesso em memória — regra S5 intacta | teste de host em `openpgp.rs` |
| **AC-6** | PW3 sem mudança de comportamento: sem sessão, `CHANGE` 0x83 → `0x6982` antes de tocar slot/contador/store (regressão da S10 `refused_pw3_change_never_consumes_a_retry`); com sessão (`VERIFY` 0x83 → `9000`), corpo 16 `12345678‖99999999` → `9000` e `VERIFY` 0x83 com `99999999` → `9000`; com sessão e `Lc ≠ 16` — inclusive 12 — → `0x6A80` (o formato variável não se estende ao admin slot) | teste de host em `openpgp.rs` |
| **AC-7** | Suítes de interop intactas: o fluxo real do scdaemon (corpo com comprimentos exatos, ex. 12) funciona no `0x81`; `gnupg_interop.rs` (sem `0x24` hoje), `adversarial_apdu.rs` e `state_roundtrip.rs` passam sem edição; o teste `pw1_change_still_works_without_a_session` da S10 continua verde e seu comentário obsoleto é atualizado (§3.6); os dois testes de persistência S5 (AC-6 da S10) seguem verdes | gates §7.3 |
| **AC-8** | `pin.rs` documenta os contratos: a delimitação por comprimento conhecido é uma leitura do slot (não decrementa; diagnósticos de unset/blocked idênticos aos do `verify`) e a autorização continua no chamador; nenhuma mudança de encoding/persistência (sem bump em `PIN_STATE_VERSION`, testes de `decoding_rejects_tampered_state`/`encoding_round_trips`/`encoding_round_trips_an_unset_slot` intactos) | revisão do doc-comment (estático) |

## 7. Plano de teste

### 7.1 Onde ficam

No módulo `#[cfg(test)] mod tests` existente de `openpgp.rs`
(`openpgp.rs:1912`), reutilizando os helpers já estabelecidos: `applet()`
(`openpgp.rs:1947`), `frame()` (`openpgp.rs:1997`), `run()`
(`openpgp.rs:2016`), `verify_pw3()` e `FlakyOpenPgpStore`
(`openpgp.rs:1958-1995`). É o padrão da fatia S10: os helpers de corpo de
`CHANGE` passam a aceitar a `Lc` variável.

### 7.2 Como os casos são montados

- **AC-1:** fresh `applet()`; `CHANGE` 0x81 `123456654321` → `9000`;
  `VERIFY` 0x81 `654321` → `9000`; `VERIFY` 0x81 `123456` → `63Cx`;
  `select()` → re-`VERIFY` `654321` → `9000`.
- **AC-2:** com PW1 default 6, `CHANGE` 0x81 com 14 bytes
  (`123456‖88888888`) → `9000` + `VERIFY` `88888888` → `9000`; então,
  com PW1 instalado em 8 via `RESET RETRY` (helper `verify_pw3`) e
  `select()`, `CHANGE` 0x81 `99999999‖777777` (14 bytes) → `9000` +
  `VERIFY` `777777` → `9000` após `select`.
- **AC-3 / AC-4:** corpos 11/0/15/`>254` → `0x6A80` sem consumir tentativa
  (conferência de `63C3` e de `FlakyOpenPgpStore.save_calls` intocado);
  corpo válido no intervalo com corrente errado → `63Cx` com um único
  decremento por comando; repetido até `0x6983` (e a partir daí a troca
  recusa sem tocar nada).
- **AC-5:** reusar a `FlakyOpenPgpStore` do AC-6 da S10 com uma troca 6+6.
- **AC-6:** repetir literalmente os cenários da S10 (gate sem sessão; troca
  com sessão; corpo 12 com sessão → `0x6A80`).
- Nomes sugeridos (o implementador pode ajustar):
  `pw1_default_of_six_octets_is_changeable_on_the_public_path`,
  `pw1_change_follows_the_exact_lengths_of_the_command_body`,
  `pw1_change_rejects_bodies_outside_the_policy_range_without_tuning`,
  `pw1_change_consumes_one_attempt_per_mismatched_body`,
  `pw1_change_fail_closed_on_failing_store`,
  `pw3_change_body_format_is_unchanged`,
  `sticky_floor_survives_pw1_variable_length_change`.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

(Somente `aegis-applets` é tocado em código; os gates dos demais crates são
regressão e seguem verdes. A suíte atual tem 217 testes e permanece toda
verde mais os sete novos da §7.2 — AC-7 e AC-8 são verificação das suítes
existentes e do doc-comment, sem caso de teste novo além do comentário
atualizado.)

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/openpgp.rs` | `verify_change` (§1645): nos modos `0x81`/`0x82`, troca `len != 16` + split fixo por intervalo de formato + delimitação por comprimento conhecido (§3.2); testes de host AC-1..AC-8, incluindo a atualização do comentário do teste S10 (`pw1_change_still_works_without_a_session`) |
| `crates/aegis-applets/src/pin.rs` | Capacidade de leitura do slot (§3.4): comparar candidata sem decrementar, mesmos diagnósticos não-consumidores do `verify`; doc-comments do módulo e de `PinSlot::change`. Sem mudança de encoding, sem bump de `PIN_STATE_VERSION` |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | Documentação na mesma mudança (§9) |

Nada muda em `crates/aegis-core/**`, `crates/aegis-applets/src/{piv,oath,*}.rs`,
`crates/firmware-universal-rp2350/**` ou `crates/board-generic-rp2350/**` —
nenhum despacho de firmware muda, nenhum formato de estado persiste de forma
nova (o `PIN_STATE_VERSION` e o `STATE_VERSION` ficam onde estão).

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — na lista de invariantes dos applets
   (§ "PIN state is persistent and fail-closed", ~`security-model.md:137-169`),
   registrar a regra do corpo do `CHANGE REFERENCE DATA` do PW1: delimitação
   por comprimento corrente conhecido no cartão (Lnew = Lc − Lold, card spec
   §7.2.3); intervalo de formato `2·min ≤ Lc ≤ 2·max` com recusa `6A80` sem
   consumo; corrente errado → uma única tentativa (`63Cx`) com persist;
   persistência e pisos S5 inalterados; `0x83` mantém o formato 16 e o gate
   de sessão da fatia S10.
2. **`roadmap.md`** — item **OpenPGP S11** na sequência da fase/Fase 14
   após o item S10 (`roadmap.md:1241-1260`), estilo do histórico: troca do
   PW1 default de 6 agora possível pela porta pública (resolução do gap L4
   aberto pela S10), delimitação pelo hash (sem delimitador), intervalo de
   formato e `6A80` sem consumo, `63Cx` único por corpo, PW3 fixo 16 intacto,
   interop `app-openpgp.c::do_change_pin`/`iso7816.c` verificada no
   código-fonte, link desta spec.
3. **`validation.md`** — nova sub-seção no bloco "OpenPGP Card v3.4" (após a
   da fatia S10, ~`validation.md:447`) + linha **AC-028** na tabela de
   critérios (~`validation.md:653`), método: testes de host de
   `aegis-applets::openpgp`; status **Verificado em host**; hardware
   pendente. Pendência física: estender `scripts/validate_openpgp.py` com o
   caso "CHANGE PW1 a partir do default de 6 → corpo 12 → `9000` + fluxo
   `gpg --card-edit` → `passwd` → 'change PIN'" quando houver RP2350.

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Oráculo de formato muda de forma.** Corpos no intervalo
  `12..=254` (que hoje são `0x6A80` incondicional) passam a ser
  processados; corpos fora do intervalo continuam `0x6A80` sem consumo. É
  a melhoria de interop alvo; o caminho do scdaemon de teclado é o
  beneficiário. Clientes fora do ecossistema que dependessem do
  retrato "só 16 entra" não são conhecidos (a suíte de interop e as
  validações só exercitam o fluxo do scdaemon); o efeito em um cliente
  assim seria `63Cx` ao invés de `6A80` para corpos no intervalo — verificado
  nas suítes adversariais que nada mais muda.
- **R2 — Custo/tempo da varredura.** Até ~119+1 comparações SHA-256 por
  comando no caminho do slot (alcance 6..=127 limitado por Lc) — trivial
  para o RP2350 e para o CCID (rate limit do bus ainda dilui). Vazamento
  possível: posição do match = comprimento do corrente (conhecido pelo
  remetente legítimo; não é segredo). Recomendação: varrer todo o alcance
  antes de decidir, sem early-exit, para o volume de trabalho ficar
  independente do match (a implementação decide; é preferência, não AC).
- **R3 — Colisão adversarial de split.** Dois Ls candidatos diferentes
  para o mesmo corpo bateriam no mesmo hash guardado — impossibilidade
  prática de colisão do SHA-256 que o `pin.rs` já assume para toda
  comparação de hash. Se um dia se revelar relevante, a regra "primeiro
  match do menor L" determina o comportamento sem custo de protocolo
  adicional.
- **R4 — Concorrência de edição.** O loop de hardening tem outras sessões
  tocando `pin.rs`/`roadmap.md`/`validation.md`; manter os diffs pontuais e
  reconciliar no rebase.

### 10.2 Limitações

- **L1 — Sem hardware neste ciclo.** Todos os ACs são de host; a verificação
  física (extensão do `validate_openpgp.py` com a troca do default de 6 +
  fluxo `gpg --card-edit`) fica registrada em `validation.md`.
- **L2 — PW3 permanece 8-fixado.** O `0x83` continua exigindo corpo 16; a
  fundação não tem PW3 variável (default 8 + corpo fixo 16 + unblock S4
  só PW1 ⇒ PW3 é sempre 8). A divergência teórica "mínimo do novo PW3 = 08
  na card spec vs 6 na política compartilhada" é irrelevante enquanto o
  corpo do `0x83` for fixo; registrada como trabalho futuro.
- **L3 — Sem KDF de PIN.** Os corpos são PINs crus; a card spec v3.4
  (KDF-DO `0xF9`), quando implementada, exercita corpos de
  32+32 — a regra §3.1 se aplica igualmente, fatia própria.
- **L4 — `RESET RETRY` fixa PW1 em 8.** O unblock da S4 continua aceitando
  só corpo de 8; um usuário com PW1 de 6 que perder o PIN e recorrer ao
  admin recebe obrigatoriamente um PW1 de 8 octetos. Sem mudança de
  interop, mas é um limite de comprimento que a política de unblock amarra
  (S4, fora de escopo).
- **L5 — Sem segredo novo, sem material novo.** A fatia não cria chaves,
  estados persistentes novos ou bump de versão; ela reconcilia o formato do
  corpo com a card spec e com o que o scdaemon já envia.
