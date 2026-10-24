# Spec — OpenPGP: `CHANGE REFERENCE DATA` do PW3 exige sessão de admin (irmão da S4)

> **Origem:** gap recomendado pela **review adversarial** do ciclo de hardening
> (irmão do achado CRÍTICO da fatia S4, `specs/openpgp-unblock-auth.md`).
> **Risco:** ALTO — um host não autenticado com conhecimento do PW3 corrente
> (o **default de interop** `12345678` é público) troca o PIN admin e adquire a
> autoridade completa do applet sem estabelecer a sessão de administração que o
> resto da casa exige. Fatia única, fechada, em `aegis-applets`; nenhum teste
> de hardware neste ciclo (os ACs são de host; a validação física fica pendente
> em `validation.md`).

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- `crates/aegis-applets/src/openpgp.rs:1645-1662` — `verify_change`
  (INS `CHANGE_REFERENCE_DATA` = `0x24`, constante em `openpgp.rs:31`) mapeia
  `apdu.p2`: `0x81`/`0x82` → slot PW1, `0x83` → slot PW3, `P2` desconhecido →
  `INCORRECT_PARAMETERS` (`0x6A86`). O corpo é `atual(8) + novo(8)`
  (`apdu.data.len() != 16` → `WRONG_DATA`, `0x6A80`). Depois chama
  `slot.change(atual, novo)` e `persist_state()` (piso da fatia S5: save falho
  → `NOT_ENOUGH_MEMORY`, `0x6A84`).
  **Para `P2=0x83` o único fator de autorização é o PW3 corrente no corpo do
  comando.** Nada consulta `pw3_verified` — a sessão de administração
  estabelecida por `VERIFY` P2=0x83 (`verify`, `openpgp.rs:645-686`; flag
  levantado em `openpgp.rs:666`) é ignorada por este mutador.
- O padrão de autoridade da casa é o oposto, e foi sancionado pela fatia S4:
  `reset_retry` (`openpgp.rs:1664-1688`) valida `P1`/`P2` → **exige
  `pw3_verified`** (`openpgp.rs:1674-1675`, com
  `SECURITY_STATUS_NOT_SATISFIED` = `0x6982`) → só então valida o comprimento
  e toca o slot. Os demais mutadores administrativos seguem o mesmo padrão:
  `put_data` (`openpgp.rs:1037-1040`) e `generate` (`openpgp.rs:1169-1172`)
  recusam com `0x6982` sem `pw3_verified`.
- Sessão: `pw3_verified` nasce falso (`openpgp.rs:380`) e é limpo
  **exclusivamente** em `select()` (`openpgp.rs:1696-1704`). Nenhuma troca de
  PIN consome a sessão hoje — nem deve (§3.4).
- `crates/aegis-applets/src/pin.rs:214-217` — `PinSlot::change` verifica o PIN
  corrente (`self.verify(current)`, que **decrementa o contador** na falha) e
  então `set(new)`. A autoridade ainda é obrigação do chamador; o slot não
  conhece sessão.

### 1.2 Caminho de exploração

1. O atacante tem o dispositivo em mãos (CCID enumerado) e seleciona o applet
   OpenPGP pelo AID — nenhum conhecimento é preciso.
2. O estado de fábrica do applet instala PW3 como o default de interop da
   OpenPGP Card, `12345678` (`ensure_loaded`, `openpgp.rs:411-412`) — um valor
   público, exatamente como os defaults NIST do PIV (decisão de produto
   documentada em `AGENTS.md`). Em qualquer cartão cujo admin PIN não tenha
   sido trocado (estado de fábrica, provisionamento parcial), o PW3 corrente
   **não é segredo**.
3. O atacante envia `00 24 00 83 10 || 12345678 || 99999999`. O handler hoje
   executa `pw3.change(...)`: o hash do PW3 passa a ser **escolhido pelo
   atacante**, sem um único `VERIFY` PW3 bem-sucedido na sessão.
4. Com o admin PIN próprio, o atacante executa sem qualquer fricção adicional:
   `GENERATE` (substitui silenciosamente as chaves de assinatura/decifra/
   autenticação por chaves que ele controla), `PUT DATA` (fingerprints,
   atributos de algoritmo, certificado, importação do material ECDH
   `D2`) e `RESET RETRY COUNTER` (redefine o PW1). O usuário honesto,
   ao usar o cartão, está decifrando e assinando com material do atacante.

**Impacto:** tomada de autoridade admin sem estabelecer a sessão de
administração. Diferente da S4 (que precisava de zero conhecimento), aqui o
exploit exige o PW3 corrente — mas esse corrente é o default público em
qualquer estado não-personalizado, e o gate fecha a assimetria de política:
a recusa de um mutador admin não deve depender só do corpo do comando quando
toda a casa condiciona mutação à sessão. É também defesa em profundidade
futura: no dia em que a troca exigir só dados (ex.: KDF ativo, corpo
protegido de outro modo), o fator de sessão permanece.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | "PIN fail-closed e persistente; a validação de PIN é enforceada em cada handler de applet" — o modelo declara isso para o `RESET RETRY COUNTER` e generaliza a regra de autorização | `AGENTS.md`, `docs/security-model.md:132-149` (invariantes dos applets, redigidas na S4/S5) | **violada** — o mutador do PW3 está fora da regra |
| I2 | Sessão de admin como única porta de mutação referenciada: todo mutador administrativo do OpenPGP consulta `pw3_verified` (precedentes funcionais: `reset_retry`, `put_data`, `generate`) | padrão da casa estabelecido na S4 | **violada** pelo único mutador que falta |
| I3 | A recusa por falta de autoridade não modifica estado nem consome contador (a fatia S4 documentou isso como comportamento canônico: "sem alterar nenhum estado na negativa") | `validation.md:232-240`, `specs/openpgp-unblock-auth.md` §3 | **não aplicada** — hoje o corpo errado da troca desautenticada decrementa o contador do PW3 e grava |
| I4 | Interop GnuPG no domínio OpenPGP (`gnupg_interop.rs`) e as suítes adversariais S8/S9 não podem regredir | `roadmap.md` (Fase 14), `validation.md` | deve permanecer — o fluxo real do GnuPG **pre-verifica** o admin (§3.5), então o gate é interop-safe |

---

## 3. Decisão de política (documentada nesta spec)

### 3.1 Autoridade

Para `P2=0x83` (troca do **PW3**), o comando passa a exigir
**`pw3_verified == true`** no momento da chamada — a mesma autoridade que
`reset_retry`, `put_data` e `generate` já exigem. Sem sessão, a resposta é
`SECURITY_STATUS_NOT_SATISFIED` (`0x6982`) e **nenhum estado é modificado**.
O fator "PIN corrente no corpo" permanece obrigatório (`slot.change` continua
verificando o `atual` do corpo): o gate acrescenta um *segundo* fator, não
tira o primeiro. A OpenPGP Card spec (§7.2.2, formato do comando) condiciona a
execução à apresentação do PIN corrente nos dados e não define pré-requisito
de sessão — o gate é um endurecimento fail-closed do padrão da casa, e não uma
relaxação; nada na spec veda exigir mais que o mínimo.

### 3.2 PW1 (`0x81`/`0x82`) — fora do gate

A troca do **PW1** com o corrente apresentado no corpo, **sem sessão de
admin**, é o comportamento da card spec e do ecossistema: o usuário troca seu
PIN de assinatura por conhecimento do próprio PIN. É exatamente o que o
scdaemon faz para `chvno == 1` (`do_change_pin` do GnuPG só invoca
`verify_chv3` para `reset_mode` ou para cartões v1 — no caminho v2 do
PW1 não há VERIFY admin antes do CHANGE). **Não tocar** nesses modos.

### 3.3 Recusa sem sessão não consome tentativa nem persiste

O SW `0x6982` é recusa **de autoridade de sessão**, não adjudicação do PIN
corrente. A checagem acontece **antes** de `slot.change`, portanto:

- o contador do PW3 não é decrementado;
- `persist_state()` não é chamado (nenhuma gravação no store, nenhuma
  reancoragem de piso; verificável em host com `FlakyOpenPgpStore.save_calls`);
- nenhum oracle novo nasce: quem quer adivinhar o PW3 corrente continua tendo,
  no `VERIFY` 0x83, o caminho legítimo e **limitado** de tentativas — o comando
  de troca sem sessão não vira um segundo vetor de bruteforça com tentativas
  que não se esgotam.

Fundamento: é o mesmo contrato canônico da S4 ("nenhum estado é modificado"
na negativa) e a análise da review: no unblock, o comando não autorizado não
toca o contador do PW1. Coerência acima de tolerância.

### 3.4 A sessão de admin não é consumida pela troca

Decisão: `verify_change` **não limpa** `pw3_verified` — nem na troca
bem-sucedida, nem na falha do PIN corrente com sessão estabelecida (hoje o
handler só toca os flags de sessão para `VERIFY`; a troca nunca mexeu neles).
Fundamentos: (a) é o comportamento atual e a fatia não muda o que não precisa
mudar; (b) a S4 já registrou o mesmo contrato para o unblock (sessão de PW3
persistente após comando autenticado, em linha com a card spec); (c) o domínio
GnuPG encadeia operações admin em sequência (trocar admin PIN → keygen →
put fingerprints) e o scdaemon honra o cache do pw3 dentro da mesma conexão.
A única limpeza continua sendo o `select()`.

### 3.5 Interop GnuPG — fundamento da decisão (verificado no código-fonte)

O scdaemon (`scd/app-openpgp.c`, `do_change_pin`) no caminho de teclado para
v2+ cartões faz, para `chvno == 3`: pedir o **PIN admin antigo** e o novo via
pinentry e **envia primeiro `VERIFY` (0x20/0x83) com o PIN admin antigo**
(verificado no código-fonte: `iso7816_verify (app_get_slot (app), 0x80 +
chvno, buffer1, bufferlen1)` — o branch de teclado `else` após o bloco de
pinpad) e só depois `iso7816_change_reference_data (0x83, old, new)`. Ou seja:
**o domínio do GnuPG estabelece a sessão de admin antes da troca do PW3** — o gate
é interop-safe para o fluxo real. Complementos:

- **Caminho de pinpad** (`use_pinpad`): o scdaemon usa `change_reference_data_kp`
  (corpo vazio, PINs entram no leitor) sem VERIFY prévio. Esse caminho só é
  acionado se o leitor CCID declarar suporte a pinpad (`iso7816_check_pinpad`)
  e o fluxo solicitar; o AegisToken é CCID/HID sem features de pinpad e o
  handler hoje já *recusa corpo vazio* com `WRONG_DATA` (`0x6A80`) — o gate
  não muda esse comportamento pré-existente.
- O `gnupg_interop.rs` atual já segue o fluxo real: `VERIFY` 0x83 (PW3) antes
  de qualquer operação admin (`gnupg_interop.rs:353`) — o AC de interop
  revalida isso.

### 3.6 Ordem de checagem (fail-closed)

`P2` válido (mapeamento de slot; `P2` desconhecido segue `0x6A86`)
→ autoridade **só para `P2=0x83`** (`0x6982`) → comprimento (`0x6A80`).
Pedidos não autorizados nunca alcançam o slot e nunca disparam
`persist_state()`. Para `0x81`/`0x82` a ordem atual (slot → comprimento →
change) permanece intocada.

---

## 4. Escopo

- `verify_change` (`openpgp.rs:1645-1662`): para `P2=0x83`, gate de
  `pw3_verified` antes do comprimento e do `slot.change`; negativa → `0x6982`
  **sem modificar nada** (contador do PW3, hash, flags de sessão e store
  intocados; sem `persist_state()`).
- `P2=0x81`/`0x82`: nenhum gate, nenhuma mudança de comportamento (§3.2).
- Troca do PW3 autenticada: fluxo atual preservado — corpo
  `atual(8)+novo(8)`, `slot.change`, `persist_state()` no sucesso, `0x6A84`
  no save falho (piso S5). Sessão admin **mantida** após o comando (§3.4).
- `crates/aegis-applets/src/pin.rs`: doc-comment de `PinSlot::change`
  reforçado sobre onde vive a autorização (o corrente nos dados é o piso do
  slot; autoridades adicionais por sessão pertencem ao handler do applet,
  referência cruzada para o `PinSlot::unblock` e para os dois sites
  (`verify_change` 0x83, SRS P1=0x02)). Mudança de documentação, não de
  assinatura nem de comportamento.
- Dois testes existentes de `openpgp.rs` que hoje emitem `CHANGE 0x83` sem
  `VERIFY` passam a pre-verificar o admin antes do comando (são os únicos
  afetados — grep confirma que `INS_CHANGE_REFERENCE_DATA` aparece apenas
  neles; as suítes `tests/{gnupg_interop,adversarial_apdu,state_roundtrip}.rs`
  não exercitam `0x24` hoje).
- Testes de host novos (AC-1..AC-8, §6) no módulo `#[cfg(test)]` de
  `openpgp.rs` (§7).

## 5. Não-objetivos

1. **PW1 (`0x81`/`0x82`)** — a troca com o corrente no corpo sem sessão é
   comportamento da spec e do ecossistema (§3.2); nada muda nos dois modos,
   inclusive o `WRONG_DATA` (`0x6A80`) do comprimento errado.
2. **`reset_retry`** — padrão canônico da S4; inalterado.
3. **A verificação do PIN corrente no corpo (`slot.change`)** — permanece; o
   gate soma um fator, não substitui.
4. **Caminho de pinpad do scdaemon** — o `change_reference_data_kp` (corpo
   vazio) já é recusado hoje por comprimento (`0x6A80`); não é objetivo dar
   suporte a entrada on-card, nem a features CCID de pinpad.
5. **Persistência e sessões** — `persist_state()`, pisos (`pw1_floor`/
   `pw3_floor`), `select()` e `STATE_VERSION` inalterados; nenhum flag de
   sessão vira estado persistente; a limpeza da sessão continua sendo
   exclusivamente no `select()`.
6. **KDF** — nada além do gate no `kdf_hash` ou no formato do corpo (fatia S6
   já cobriu a fronteira do D2).
7. **Qualquer mudança em FIDO/PIV/OATH/CTAP2** — `piv.rs`, `oath.rs`,
   `aegis-core`, firmware e roteador não são alterados. Zero `unsafe`, zero
   dependências novas.
8. **Provisionamento do Resetting Code** — fatia futura da S4, fora daqui.

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host no módulo `#[cfg(test)]` de
`crates/aegis-applets/src/openpgp.rs` (nenhum exige hardware).

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | `CHANGE REFERENCE DATA` P2=0x83 **sem** `pw3_verified` → `0x6982`, e estado **inalterado**: o PW3 ainda verifica com o PIN original (e **não** com o `novo` dos dados), o contador do PW3 (visível no `VERIFY` vazio, `63Cx`) e a ausência de sessão permanecem como antes; **nenhuma gravação**: `FlakyOpenPgpStore.save_calls` não se move entre antes e depois do comando recusado | teste de host em `openpgp.rs` |
| **AC-2** | Verificação do **PW1** (modo `81` ou `82`) não estabelece autoridade: um `VERIFY` PW1 bem-sucedido seguido de `CHANGE` 0x83 → `0x6982` (a sessão que abre o gate é exclusivamente a do `VERIFY` 0x83) | teste de host em `openpgp.rs` |
| **AC-3** | Com **sessão de admin** (`VERIFY` 0x83 → `9000` primeiro), a troca funciona: `CHANGE` 0x83 com `atual||novo` → `0x9000`; o PIN novo verifica (`VERIFY` 0x83 com o novo → `0x9000`) e o antigo não; a **sessão persiste** após a troca — uma operação admin subsequente (`PUT DATA`) responde sem novo `VERIFY` 0x83; com sessão estabelecida e PIN corrente errado no corpo, a resposta segue o comportamento atual (`63Cx` do slot + persistência) — nenhum dos dois desfechos limpa `pw3_verified` | teste de host em `openpgp.rs` |
| **AC-4** | `select()` recomeça o ciclo: depois de um ciclo select→VERIFY→CHANGE→select, um novo `CHANGE` 0x83 sem `VERIFY` volta a `0x6982` — e volta a funcionar após um novo `VERIFY` 0x83 | teste de host em `openpgp.rs` |
| **AC-5** | PW1 sem regressão (§3.2): troca do PW1 com o corrente no corpo, **sem sessão**, funciona nos modos `81` e `82` (com PINs de 8 bytes; ver L4); comprimento errado (`data.len() != 16`) continua `WRONG_DATA` (`0x6A80`) | teste de host em `openpgp.rs` |
| **AC-6** | Piso S5 na troca autenticada: com sessão estabelecida e store flaky (`save_fails`), `CHANGE` 0x83 → `0x6A84` (nunca um `9000` falso) e, após re-`select`, o PIN novo **não** sobrevive (o antigo re-verifica); os dois testes existentes que hoje emitem `CHANGE` 0x83 sem `VERIFY` são atualizados para pre-verificar o admin e continuam verdes | teste de host em `openpgp.rs` (`change_with_failing_store_reports_the_save_error_and_never_fakes_success`, `happy_path_persists_assertions_are_unchanged_under_a_healthy_store`) |
| **AC-7** | A recusa sem sessão **não consome tentativa do PW3**: sem sessão, `CHANGE` 0x83 com corpo qualquer (inclusive `atual` errado) → `0x6982`; em seguida o `VERIFY` 0x83 vazio ainda mostra o contador cheio/corrente (`63C3` no estado limpo) e um `VERIFY` 0x83 com o PIN original continua `0x9000` — o comando recusado não foi um "verify de graça" nem uma punição do contador | teste de host em `openpgp.rs` |
| **AC-8** | Interop e suítes intactas: a sequência **VERIFY 0x83 → CHANGE 0x83** funciona fim a fim (o fluxo real do GnuPG, §3.5); `gnupg_interop.rs`, a suíte adversarial da fatia S8 (`adversarial_apdu.rs`) e o roundtrip da fatia S9 (`state_roundtrip.rs`) passam sem alterações além dos dois testes do AC-6 (prova: `cargo test -p aegis-applets` todo verde, 211+ testes) | gates §7.3 |

## 7. Plano de teste

### 7.1 Onde ficam

No módulo `#[cfg(test)] mod tests` existente de `openpgp.rs`
(`openpgp.rs:1912`), reutilizando os helpers já estabelecidos: `applet()`
(`openpgp.rs:1947`, cria o applet com `MemoryOpenPgpStore` e faz `select()`),
`frame()` (`openpgp.rs:1997`), `run()` (`openpgp.rs:2016`) e
`FlakyOpenPgpStore` (contador de saves, `openpgp.rs:1958-1995`). O padrão de
montagem é o mesmo da S4 para o caminho admin autorizado
(`reset_retry_with_pw3_sets_new_pw1_and_restores_retries`, `openpgp.rs:3383`).

### 7.2 Como os casos são montados

- **AC-1 / AC-7:** fresh `applet()` (nenhum `VERIFY`); `CHANGE` 0x83 com
  `12345678` no `atual` e algo no `novo` → `0x6982`; conferir `save_calls`
  intocado, `VERIFY` 0x83 vazio → `63C3` (contador não mudou) e
  `VERIFY` 0x83 com `12345678` → `0x9000` (hash intacto, `novo` rejeitado).
- **AC-2:** `VERIFY` 0x81 → `0x9000` (e/ou 0x82 → `0x9000`); então
  `CHANGE` 0x83 → `0x6982`.
- **AC-3:** `VERIFY` 0x83 → `0x9000`; `CHANGE` 0x83 (atual `12345678`, novo
  `99999999`) → `0x9000`; `VERIFY` 0x83 com `99999999` → `0x9000`; `PUT DATA`
  administrativo funciona sem novo `VERIFY`; e, num segundo caso, com sessão e
  `atual` errado → `63Cx` com persistência (comportamento atual).
- **AC-4:** após a troca, `applet.select()`; `CHANGE` 0x83 → `0x6982`; novo
  `VERIFY` 0x83 → `CHANGE` → `0x9000`.
- **AC-5:** o filtro de comprimento aqui é único e aplica-se aos três modos:
  `apdu.data.len() != 16` → `0x6A80` (`verify_change`), **inclusive** para o
  PW1. Montagem: instalar um PW1 de 8 bytes pela porta admin da casa
    (`VERIFY` 0x83 com o default ou o antigo → `RESET RETRY COUNTER`
  P1=0x02/P2=0x81 com `99999999`), então
  `select()` (limpa a sessão) e, **sem nenhum `VERIFY`**, `CHANGE` 0x81 com
  `99999999||77777777` → `0x9000` (e, no modo `82`, `99999999||55555555` →
  `0x9000`); um corpo com `len != 16` (ex. 15 bytes) → `0x6A80`. *(Limitação
  pré-existente registrada em L4: o PW1 default de 6 bytes não pode ser
  trocado por `0x24` hoje — o correto da spec/ecossistema para PINs de
  comprimento variável é fatia própria.)*
- **AC-6:** reutilizar os dois testes existentes adicionando `VERIFY` 0x83
  antes do `CHANGE` 0x83 e mantendo as demais asserções (store flaky →
  `0x6A84`; re-`select` → PIN novo desaparecido).
- Nomes sugeridos (o implementador pode ajustar):
  `pw3_change_requires_the_admin_session_and_leaves_the_state_untouched`,
  `pw1_verification_does_not_authorize_the_pw3_change`,
  `pw3_change_with_session_swaps_the_pin_and_keeps_the_session`,
  `select_clears_pw3_and_change_requires_it_again`,
  `pw1_change_still_works_without_a_session`,
  `refused_pw3_change_never_consumes_a_retry`.

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
| `crates/aegis-applets/src/openpgp.rs` | `verify_change` (§1645): gate de `pw3_verified` para P2=0x83 antes do comprimento, `0x6982` na negativa sem `persist_state()`; testes de host AC-1..AC-8 (novos + atualização dos dois testes do AC-6) |
| `crates/aegis-applets/src/pin.rs` | Doc-comment de `PinSlot::change` (§214): o corrente nos dados é o piso; autoridade de sessão é obrigação do chamador (referência cruzada `unblock` / `verify_change` 0x83 / `reset_retry`). Sem mudança de assinatura nem de comportamento |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | Documentação na mesma mudança (§9) |

Nada muda em `crates/aegis-core/**`, `crates/aegis-applets/src/{piv,oath,*}.rs`
(exceto o doc-comment de `pin.rs`), `crates/firmware-universal-rp2350/**` ou
`crates/board-generic-rp2350/**` — nenhum despacho de firmware muda.

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — na lista de invariantes dos applets
   (a seção redigida pelas fatias S4/S5, ~`security-model.md:132-149`),
   estender a regra de autorização: no OpenPGP, `CHANGE REFERENCE DATA` do
   **PW3** (`P2=0x83`) também exige a sessão de admin (`pw3_verified`) e
   recusa com `6982` sem tocar estado, contador ou store; a troca do **PW1**
   (`0x81`/`0x82`) mantém a autoridade do PIN corrente nos dados
   (comportamento da card spec/ecossistema).
2. **`roadmap.md`** — item **OpenPGP S10** na sequência das fatias S4..S9
   (entregue), estilo do histórico: gate de sessão no CHANGE do PW3, PW1
   intocado, recusa sem consumo de tentativa, sessão persistente, interop
   GnuPG pre-verificada (referência ao `do_change_pin` do scdaemon) e o link
   desta spec.
3. **`validation.md`** — nova sub-seção no bloco "OpenPGP Card v3.4"
   (após a da fatia S9, ~`validation.md:378`) + linha **AC-027** na tabela de
   critérios (~`validation.md:607-611`), método: testes de host de
   `aegis-applets::openpgp`; status **Verificado em host**; hardware pendente.
   Pendência física: estender `scripts/validate_openpgp.py` com o caso
   "CHANGE 0x83 sem `VERIFY` → `6982`" e conferir o fluxo real com
   `gpg --card-edit` → `passwd` → "change Admin PIN" quando houver RP2350.

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Mudança de comportamento externamente visível.** Clientes que
  enviam `CHANGE` 0x83 sem um `VERIFY` admin prévio na mesma sessão passam a
  receber `0x6982`. Os dois fluxos principais estão cobertos: (a) o scdaemon
  do GnuPG **pre-verifica** o admin no caminho de teclado (§3.5, verificado no
  código-fonte `app-openpgp.c::do_change_pin`); (b) o caminho de pinpad envia
  corpo vazio e já é recusado hoje (`0x6A80`), e o leitor CCID do AegisToken
  não declara features de pinpad. Ferramentas que não seguem esse fluxo podem
  sentir — registrado como mudança visível; validação física com
  `validate_openpgp.py`/`gpg` fica pendente (`validation.md`).
- **R2 — Dupla verificação do PIN corrente.** Com o fluxo do GnuPG, o admin
  PIN corre duas vezes: uma no `VERIFY` (cria a sessão) e outra no corpo do
  `CHANGE` (`slot.change`). Custo: uma verificação de hash extra — aceitável
  e sem oracle novo (as duas verificações são as mesmas já existentes);
  com KDF ativo o scdaemon KDF-hasheia ambos os campos (`pin2hash_if_kdf`),
  então o formato permanece consistente.
- **R3 — PW3 default provisionado.** `ensure_loaded` instala PW3 `12345678`
  (`openpgp.rs:411-412`) — valor de interop da OpenPGP Card, no mesmo espírito
  dos defaults NIST do PIV (regra do `AGENTS.md`: não marcar como leak, não
  randomizar). O gate reduz a superfície (a troca exige sessão), mas um
  atacante que conhece o default pode **se autenticar** com `VERIFY` 0x83 e
  então trocar — a raiz (default público) é decisão de produto de interop,
  fora do escopo desta fatia.
- **R4 — Concorrência de edição.** O loop de hardening tem outras sessões
  tocando `pin.rs`/`roadmap.md`/`validation.md`; manter os diffs pontuais
  (doc-comment e item novo/AC-027) e reconciliar no rebase.

### 10.2 Limitações

- **L1 — Sem hardware neste ciclo.** Todos os ACs são de host; a verificação
  física (extensão do `validate_openpgp.py` com o caso de `0x6982` sem
  sessão + fluxo `gpg --card-edit`) fica registrada em `validation.md`.
- **L2 — A autoridade do default conhecido permanece** até que a política de
  defaults mude (fora de escopo): quem conhece o PW3 de fábrica primeiro
  estabelece a sessão com `VERIFY` e depois troca à vontade. O gate é defesa
  em profundidade, não eliminação do default público.
- **L3 — Sem segredo novo, sem material novo.** A fatia só restringe uma
  instrução existente; nenhuma chave, nenhum estado persistente novo, nenhum
  bump de `STATE_VERSION`.
