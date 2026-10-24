# OpenPGP: janela de resposta da decifra > 2 KB — decisão de política (manter `0x6A84`), com o teto real de hardware registrado

> **Origem:** limitação (não-AC) registrada em §8 de
> `specs/openpgp-apdu-adversarial-tests.md`, pendência de decisão replicada em
> `roadmap.md:1210-1211` ("decisão futura sobre ampliar a janela de resposta
> fica registrada") e `docs/security-model.md:231-233`. **Risco:** BAIXO —
> nenhuma rota de pânico ou vazamento (recusado na S8); é uma **decisão de
> política/interop** sobre custo de RAM × janela decifrável, fechada aqui com
> evidência do código e do ecossistema. Fatia única, em `aegis-applets`
> (funções só de observação + um teste novo de transporte); nenhum teste de
> hardware novo.

---

## 1. Ameaça

### 1.1 Fenômeno (revalidado no código)

A decifra no modo RFC 6637 completo (o cartão decifra a mensagem sozinho,
`decipher_ecdh`, `openpgp.rs:1518-1584`) produz a mensagem inteira antes de
responder. A cadeia de buffers que limita essa resposta, na ordem em que cada
um se torna o gargalo:

| # | Buffer | Const/código | Limite | Falha observável |
|---|--------|--------------|--------|------------------|
| 1 | Plaintext do fluxo CFB (`Vec<u8, MAX_DATA>`) | `pgp_sym.rs:30,36,61` | 4096 octets | `push().ok()?` → `None` ⇒ `0x6F00` (`openpgp.rs:1572-1574`) |
| 2 | Resposta do applet `out: Vec<u8, 2048>` | `openpgp.rs:363` | 2048 | `extend_from_slice.is_err()` ⇒ `0x6A84`, **corpo vazio** (`openpgp.rs:1580-1584`; idem RSA `1483-1487`, *partial decrypt* `1613-1620`, X25519 `1638-1642`) |
| 3 | `Router<RESPONSE = DEFAULT_RESPONSE_BYTES = 2048>`, `Chainer` | `router.rs:25,68,71`; `card.rs:33,53` | 2048 | `Chainer::begin` → `0x6F00` (`apdu.rs:352-357`) — só visível se o #2 for ampliado |
| 4 | `out_buf` do task CCID do firmware `= MAX_MESSAGE_BYTES` | `firmware-universal-rp2350/src/main.rs:451`; `card.rs:246-253` | 2100 | `encode_into` → `CcidError::Overflow` — só visível se #3 crescer acima de ~2090 |

A fronteira **2048 exato → `0x9000` com os 2048 bytes / 2049 → `0x6A84` com
corpo vazio** já está congelada em host como **INFO**:
`adversarial_apdu.rs:773-808` (`response_over_two_kilobytes_is_a_documented_limitation`,
com byte-exact no OK, corpo vazio no `6A84`, material do slot intacto e
anti-serialização por janela). **O que falta hoje é a decisão**, não o teste da
fronteira do applet.

### 1.2 O que um ataque ou uma mensagem grande consegue hoje

**No transporte real (CCID) o `0x6A84` do applet é inalcançável** — a entrada
trava antes, e com comportamento pior que o SW registrado:

- `Assembler<MESSAGE = MAX_MESSAGE_BYTES = 2100>` reassembla no máximo 2100
  octets (`ccid.rs:17-23`: `HEADER_LEN = 10`, `MAX_PAYLOAD_BYTES = 2090`).
  Frame declarado maior ⇒ `feed()` → `Err(CcidError::Overflow)`
  (`ccid.rs:477-481`) ⇒ **o firmware faz `card.reset()` e descarta a demanda
  sem responder** (`main.rs:457-459`) — a sessão morre, sem SW nenhum.
- A entrada é de **comando único** (o `Apdu::parse` aceita só a moldura do
  frame; não há command chaining — qualquer `CLA ≠ 0x00` é recusado,
  `router.rs:116-118`). Teto do APDU estendido (case 4E, 7 octets de cabeçalho + 2 de `Le` estendido): `2090 - 9 = 2081` para o corpo do comando.
  - Molde do scdaemon/GnuPG (`86‖80`, ponto de 65 — TLV de 67; `gnupg_interop.rs:366-367`, `adversarial_apdu.rs:69-74`): corpo = `67 + 4` (TLV longo `82` — cipher > 255 não cabe em forma curta) + cipher ⇒ cipher ≤ **2010** ⇒ resultado ≤ cipher − 40 = **1970 octets** (a fórmula `10 + 9 + 67 + 4 + cipher ≤ 2100`, a que o AC-5 afirma — `response_window.rs::frame_len`).
  - Molde `80` só (sem ponto — RSA ou decifra parcial): cipher ≤ **2077**, mas a resposta desse molde é ≤ 440 (bloco RSA-2048…4096) ou ≤ 64 (`Z` da decifra parcial) — nunca se aproxima da janela (o **2041** antes subtraía a mobília CFB de um molde que não a tem).
- Logo, em hardware, **o teto efetivo da decifra é a entrada** (1970
  octets), abaixo da janela de 2048 do applet: a resposta gerada **sempre**
  cabe em `out` — e também no `Chainer` (2048) e no `out_buf` do firmware
  (2100), coerentemente. O `0x6A84` de `openpgp.rs:1581-1583` só se manifesta
  **fora do transporte** — na invocação direta do applet (host), que aceita
  `Apdu::parse` de moldura sem limite de CCID.

**Impacto real:** mensagens > ~2 KB **não decifram no cartão** e, pior que o
SW `0x6A84` documentado, **não recebem resposta alguma** (frame estoura o
assembler → `reset` silencioso). Nenhum octeto, nenhum fragmento e nenhum
material privado sai (corpo vazio pela construção do `Chainer::begin`/
`extend_from_slice` fechado) — o risco é de **divergência documental e de
interop**, não de exploração.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | Fail-closed: recusa é SW único, corpo vazio, sem pânico, sem gravação e sem mudança de estado | `docs/security-model.md:220-226` (contrato adversarial da S8); `openpgp.rs:1580-1584` | respeitada — a fatia **congela** por teste no nível do applet |
| I2 | Nenhuma resposta ecoa material privado, `wrapped` ou `Z` fora da rota documentada (o *partial decrypt*, PW1 modo 82) | `docs/security-model.md:134-136,224-228` | respeitada — anti-serialização da S8 (`adversarial_apdu.rs:98-108`) cobre o corpo vazio da recusa |
| I3 | Janela de resposta = contrato interop registrado; nenhuma decisão tomada em silêncio | `roadmap.md:1210-1211`, security-model 231-233 | pendente — **decidida nesta fatia** (§3) |
| I4 | Testes obrigatórios para a lógica nova/invariante de fronteira | `AGENTS.md` | o teto de **transporte** (entrada) e sua consequência (reset silencioso) não têm teste algum hoje — o applet-window tem (INFO da S8) |

---

## 3. Decisão de política (fundamentada item por item)

### 3.1 Decisão: **rota (C) — manter a janela de 2048/`0x6A84`**, registrando em doc (i) a fronteira do applet como contrato, (ii) o **teto real no transporte** (entrada, ~1970 octets + falha silenciosa de `CcidError::Overflow` + `card.reset()`), e congelando ambos por teste de host.

Não é "não-decisão": (A) é **rejeitada com números**, (B) é **rejeitada por
redundância estrutural** — e o contrato observável continua sendo fixado por
ACs (§6), com o doc atualizado para "decidido: manter", encerrando a pendência
de `roadmap.md:1210-1211` e a §8 da S8.

### 3.2 Avaliação da rota (A) — "ampliar o buffer" (REJEITADA)

Custo de RAM, quantificado no estado atual (um applet OpenPGP + um roteador
por instância: `main.rs:407,449`, `selftest.rs:127-130`):

| Buffer a ampliar | Arquivo | Hoje | Alvo p/ 4096 | Δ |
|------------------|---------|------|--------------|---|
| `out` do applet | `openpgp.rs:363` | 2048 | 4096 | **+2,0 KB** (por applet) |
| `Chainer<RESPONSE>` do roteador | `router.rs:25,68,71` | 2048 | 4096 | **+2,0 KB** (por roteador) |
| `out_buf` do firmware CCID (`MAX_MESSAGE_BYTES`) | `main.rs:451`; `card.rs:246-253` | 2100 | ~4100 | **+2,0 KB** (fora do domínio `aegis-applets`) |
| `Assembler<MESSAGE>` (entrada) — **requisito para o ganho existir** | `ccid.rs:20`; `card.rs:34,53` | 2100 | ~4200 | **+2,1 KB** |
| **Total (A) completo** | | | | **≈ +8,1 KB** |

E o ganho que esse custo compra é **vazio** dentro do escopo da fatia:

1. **Sem tocar a entrada, (A) não muda nada em hardware.** O teto de decifra
   via CCID é a entrada (§1.2: resultado ≤ 1970 < 2048). Ampliar `out` +
   `Chainer` (+4,0 KB) muda só a resposta observada **fora do transporte**
   (host, invocação direta) — nenhum usuário real do cartão ganha um byte.
2. **Com a entrada tocada** (o resize de 2100→~4200), a decifra passa e o
   resto da cadeia precisa acompanhar (`out`, `Chainer`, `out_buf`,
   `encode_data_block` via resposta de `Le` estendido — `apdu.rs:369-386`
   devolve o buffer inteiro num único frame quando `Le` grande), senão o
   frame **atravessa todos os buffers e cai em `CcidError::Overflow` do
   `out_buf`** (`card.rs:249-252`) — mesma queda silenciosa de hoje, agora
   para respostas legítimas. Ampliar `out_buf` é mudança em
   `firmware-universal-rp2350` além do despacho — fronteira do `AGENTS.md`.
3. **O teto a jusante permanece:** `MAX_DATA = 4096` (`pgp_sym.rs:30`) limita
   o fluxo a 4096 octets (resultado ≤ 4056). O caso que motivou a pendência —
   **corpo de e-mail** — tipicamente supera 4 KB: (A) **não resolve o caso
   real**; desloca a fronteira de ~2 KB para ~4 KB por 8 KB de RAM sensível
   num `no_std`/heapless da fundação.
4. **Interop de base intocada:** o modo RFC 6637 completo do cartão é opt-in —
   o host provisiona o material embrulhado por `PUT DATA D2` antes
   (`gnupg_interop.rs:358-364`; `docs/security-model.md:196-207`). O fluxo
   default do scdaemon no ECDH é o *partial decrypt* da card spec (resposta
   `Z` ≤ 64 octets, jamais na janela) —
   `docs/security-model.md:190-196`, `openpgp.rs:1595-1622`. Para mensagem >
   janela, a saída existente é decifrar no host sobre o `Z` obtido na
   decifra parcial, ou fragmentar — rota documentada, funcional, e o cliente
   que provisiona `D2` já parseou a mensagem (a chave de sessão embrulhada
   saiu dela).

### 3.3 Avaliação da rota (B) — "resposta parcial via `61xx` + GET RESPONSE" (REJEITADA — colapsa em (A))

Revalidação do pressuposto: **a maquinaria já existe no roteador**, não no
applet.

- `INS_GET_RESPONSE = 0xC0` **já é roteado** — inter-comando: `router.rs:16,
  145-148` (`chain.get_response(apdu.expected_len())`); `INS_SEND_REMAINING`
  (`0xA5`) drena o mesmo pendente (`router.rs:17-19,146`).
- O estado pendente da resposta **não precisa ser criado**: vive no
  `Chainer` do roteador — `pending: Vec<u8, RESPONSE>` + cursor
  (`apdu.rs:307-310`), alimentado por `chain.begin(response.data, le)` para
  **toda** resposta com sucesso (`router.rs:158-159`), já exercitado por
  `chains_responses_larger_than_le` (`router.rs:377-398`),
  `chainer_splits_large_responses`/`chainer_holds_back_when_le_is_not_enough_for_all_chunks`
  (`apdu.rs:538-566`) e `send_remaining_with_pending_drains_chain`
  (`router.rs:418-443`).
- **Expiração no `SELECT` já implementada**: `chain.clear()` no select
  (`router.rs:130`; testes `selecting_again_clears_pending_bytes`,
  `router.rs:463-485`) e em `reset()` ao religar/abortar CCID
  (`card.rs:180,228`). **Nada precisa ir para o estado selado**: os octets
  pendentes são resposta (plaintext da mensagem) já residente em RAM não
  selada na mesma classe de sensibilidade do próprio `out` do applet —
  manter em RAM de sessão é o desenho atual e correto.
- **Custo de continuação:** para servir respostas > 2048, o `Chainer` precisa
  materializar a resposta **inteira** (`begin` copia o
  corpo antes de fatiar, `apdu.rs:352-358`) — e o applet precisa materializá-la
  **antes** de entregar ao roteador (`openpgp.rs:1580-1584`). A RAM é
  idêntica à de (A): `out` ampliado + `pending` ampliado + `out_buf` e
  entrada para o transporte. **(B) = (A) + zero economia + nenhuma vantagem
  de estado** (o cursor e a expiração já existem).

### 3.4 Síntese da decisão

| Critério | (A) ampliar | (B) 61xx parcial | (C) manter |
|----------|-------------|------------------|------------|
| RAM no domínio (`aegis-applets`) | +4 KB e **zero efeito na decifra em hardware** sem entrada | +4 KB (idêntica) | 0 |
| RAM total p/ efeito real em hardware | ≈ +8,1 KB, cruzando firmware além do despacho | a mesma | 0 |
| Interação com `out_buf`/`Le` estendido | hazard de `Overflow` silencioso (`card.rs:249-253`) | idem | nenhuma (invariante resposta ≤ 2048 ≤ payload CCID 2090 ≤ `out_buf` 2100 mantida) |
| Interop ganho | mensagens 2–4 KB no modo opt-in `D2` | idem | nenhuma nova — o *partial decrypt* (card spec) e a decifra no host cobrem > janela |
| Teto restante | > 4 KB continua falhando (`MAX_DATA`) | idem | registro honesto: > ~2 KB é decifra parcial/host |

**(C) vence**: o custo de RAM e de fronteira de domínio não é pago pelo
funcional que produz, o teto a jusante (`MAX_DATA`) trunca o ganho no caso
real de e-mail, e a saída existente para > janela é o comportamento previsto
pela card spec (decifra parcial). O contrário — estreitar a janela ou
recusar cedo — também não proposto: os 2048/`0x6A84` de hoje são fechados e
documentados, e permanecem.

---

## 4. Escopo

- Um **único teste novo de host**
  (`crates/aegis-applets/src/openpgp/tests/response_window.rs`, módulo
  registrado por uma linha `mod response_window;` no `#[cfg(test)] mod
  tests` de `openpgp.rs`, o padrão de `gnupg_interop.rs`/`adversarial_apdu.rs`),
  com três famílias:
  1. **Fronteira do applet, byte-exact** — promoção do INFO da S8 para
     contrato executável (não duplica o caso: alimenta os dois lados com a
     fronteira 2047/2048/2049 e as asserções abaixo) — **AC-1/AC-2/AC-3**;
  2. **Teto de transporte, no pipeline real** — `Card<'_, DEFAULT_RESPONSE_BYTES,
     MAX_MESSAGE_BYTES>` (o `DefaultCard` que o firmware instancia,
     `main.rs:449`) com frame CCID real montado (`frame` de 10
     octets + APDU, como `card.rs:264-278`): o maior molde interop
     (`86‖80` + decifra total) que **cabe** (fórmula do frame: `10 + 9 + 67 + 4 + cipher = 2100` ⇒ resultado de 1970) responde `0x9000` byte-exact; o frame **um octeto além** (2101
     octets) → `CcidError::Overflow` **sem SW** — **AC-5**;
  3. **Recusa não corrompe a sessão** — após um `6A84`/overflow, o material
     do slot está intacto, o PW1 (modo 82) segue verificado, zero gravações
     (`FlakyOpenPgpStore.save_calls` intocado) e uma decifra pequena
     subseqüente funciona — **AC-4**.
- **Zero código de produção** — nenhum `.rs` de produção é tocado
  (`openpgp.rs`/`apdu.rs`/`router.rs`/`ccid.rs`/`card.rs`,
  `pgp_sym.rs`, firmware, HAL). Orçamento de impl: uma linha `mod` + um
  arquivo de testes + docs.

---

## 5. Não-objetivos

1. **Intocar a entrada (reassembly CCID)** — `Assembler`/`MAX_MESSAGE_BYTES`
   (`ccid.rs:20`, `card.rs:34`) e o `card.reset()` do
   `main.rs:457-459` não mudam: o teste do AC-5 **observa** o teto, não o
   resolve. Sem promessa de "responder como SW" (a queda silenciosa é
   comportamento do firmware fora do domínio desta fatia).
2. **Não ampliar nenhum buffer** — nem `out` (`openpgp.rs:363`), nem
   `RESPONSE` (`router.rs:25`), nem `MAX_MESSAGE_BYTES`, nem `MAX_DATA`
   (`pgp_sym.rs:30`). Decisão (C) fechada; reverter é fatia nova com a
   evidência da §3.
3. **Não tocar o protocolo**: nenhum SW novo/renomeado (`0x6A84` permanece a
   recusa), nenhuma negação no fluxo do `partial decrypt`, nenhum
   `PUT DATA`/certs (janela e DOs de certificado `MAX_CERTIFICATE = 1152` fora
   de escopo), FIDO/PIV/OATH/CCID fora, sem `unsafe`, sem dependência nova,
   sem estado selado novo/bump de `STATE_VERSION`/`PIN_STATE_VERSION`.
4. **Sem hardware neste ciclo** — todos os ACs são de host; a verificação
   física da mensagem > janela num cliente real (`validate_openpgp.py`) fica
   como pendência registrada em `validation.md`, não como AC.

## 6. Critérios de aceitação

Todos observáveis em host (`cargo test -p aegis-applets`); nenhum exige
hardware.

| AC | Critério | Esperado (verificado no código) | Observabilidade |
|----|----------|--------------------------------|-----------------|
| **AC-1** | **Fronteira exata no applet** (moldura estendida, `Apdu::parse` sem CCID): mensagem decifrável de **2048 octets** → `0x9000` com os **exatamente 2048**; de **2047** → `0x9000` com 2047; de **2049** → `0x6A84` | `0x9000`/`0x6A84` (`openpgp.rs:1580-1584`) — mesmo SW do INFO da S8, agora como contrato |
| **AC-2** | **Byte-exact + zero bytes além da janela**: no `0x9000`, o corpo é bit-a-bit a mensagem original (via cadeia KDF/key wrap/CFB+MDC, padrão `gnupg_interop.rs:288-343`); nos `0x6A84` o corpo é **vazio** (`len == 0`) — **zero bytes além da janela**: nenhum fragmento da plaintext, nem `wrapped`, nem `Z` (anti-serialização por janela reutilizando `assert_never_leaks`, `adversarial_apdu.rs:98-108`, com as fontes expandidas um byte além do OK) | corpo exato/vazio |
| **AC-3** | **Recusa sem estado**: nos `0x6A84`, `ecdh_material()` intacta (igual ao ancorado antes), `FlakyOpenPgpStore.save_calls` inalterado, flags de sessão PW1 modo 82 não mexidas e uma decifra pequena (ex. 256) subseqüente no mesmo slot → `0x9000` byte-exact | sem gravação, sem estado tocado (`adversarial_apdu.rs:806-807` como padrão) |
| **AC-4** | **Suíte de interop intacta**: `gnupg_interop.rs` (mensagens ≤ janela, decifra full e decifra parcial `Z`), `adversarial_apdu.rs` (incl. o INFO da limitação, que passa a referir esta spec) e `state_roundtrip.rs` verdes sem edição; o comentário do INFO aponta a decisão (C) | gates §7.3 (224 testes da suíte + novos) |
| **AC-5** | **Teto real de transporte (pipeline CCID completo)** sobre `DefaultCard` (2048/2100): (i) com o molde `86‖80`, o maior body decifrável que cabe no frame (fórmula do frame: `10 + 9 + 67 + 4 + cipher = 2100` ⇒ resultado de **1970 octets**) responde `0x9000` byte-exact; (ii) **um octeto a mais de frame** (total 2101) → `card.feed` → `Err(CcidError::Overflow)` — **nenhum SW, nenhum byte** de resposta; (iii) o applet **nunca** viu o comando (invariante de §1.2: a janela do applet é inalcançável via transporte) — o teste assevera que o `out` não cresceu e `save_calls` permanece no valor da provisão (o teste conta) | `CcidError::Overflow` (ccid.rs:477-481); `9000` no que cabe |

## 7. Plano de teste

### 7.1 Onde ficam

`crates/aegis-applets/src/openpgp/tests/response_window.rs` (novo), com a
linha `mod response_window;` no `#[cfg(test)] mod tests` de `openpgp.rs` (o
arquivo `crates/aegis-applets/src/openpgp.rs` agrupa os módulos de teste
em `src/openpgp/tests/` — `gnupg_interop.rs`, `adversarial_apdu.rs`,
`state_roundtrip.rs`). Helpers reutilizados:

- ECDH P-256 full-decrypt: padrão `adversarial_apdu.rs::ecdh_p256_applet`
  (:196-205) e as cadeias de `pgp_sym::encrypt_aes` (remetente) — o fluxo
  completo de `gnupg_interop.rs:288-343`;
- APDU: `frame`/`extended_frame` de `adversarial_apdu.rs:57-83`;
- **Pipeline CCID**: `crates/aegis-applets/src/card.rs` é público — o AC-5
  monta frame CCID (cabeçalho de 10 octets `PC_TO_RDR_XFR_BLOCK` + APDU,
  padrão `card.rs:264-278`) e usa `Card::feed`/`Card::poll` do `DefaultCard`
  (`Card<'_, 2048, { ccid::MAX_MESSAGE_BYTES }>` em teste); RNG de teste
  `TestRng` local.

### 7.2 Como os casos são montados

- **AC-1/AC-2/AC-3:** `ecdh_p256_applet` (material provisionado por `PUT DATA
  D2` com fingerprint), PW1 modo 82, três mensagens `{2047, 2048, 2049}`
  (`0x44` repetido), body `86‖80` + fluxo do remetente (`SESSION_KEY`
  reproduzível): assert SW + `plain.len()` + byte-equality no OK,
  corpo-vazio + `assert_never_leaks` + `save_calls` + material-intacta +
  decifra-pequena-depois nos `6A84`.
- **AC-5:** mesmo provisionamento, mas **via APDUs sobre o Card** (SELECT
  OpenPGP → VERIFY 82 → PUT DATA D2 → PSO DECIPHER); body no maior tamanho
  que cabe (o maior que a fórmula do frame permite: `10 + 9 + 67 + 4 + cipher = 2100`): resposta `0x9000` byte-exact; +1 octeto de
  frame: `feed` → `Err(CcidError::Overflow)`; as asserções de estado
  garantem que o applet não processou (v. §6).

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

(Somente `aegis-applets` em código; nenhum gate de firmware — a fatia não
toca despacho/HAL/transporte; `cargo build-fw` é regressão e segue verde.)

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/openpgp/tests/response_window.rs` | **novo** — suíte de host (AC-1..AC-5) |
| `crates/aegis-applets/src/openpgp.rs` | **somente a linha** `mod response_window;` no `#[cfg(test)] mod tests` — zero produção |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | doc na mesma mudança (§9) |

Nada em `aegis-core/**`, `firmware-universal-rp2350/**`,
`board-generic-rp2350/**`, `piv.rs`, `oath.rs`, `apdu.rs`, `router.rs`,
`ccid.rs`, `card.rs`, `pgp_sym.rs` — a decisão é "manter", não "mover"; a
cadeia de buffers fica exatamente como está.

## 9. Documentação a atualizar (na mesma mudança)

1. **`roadmap.md`** ~:1210-1211 — a pendência "decisão futura sobre ampliar a
   janela" passa a **decidida: manter** (`0x6A84`), com o sumário da §3
   (teto real em hardware = entrada, 1970 octets, falha por
   `CcidError::Overflow` + `card.reset()`; rotas (A)/(B) rejeitadas; link
   desta spec) e o item histórico da fatia (novo teste de transporte).
2. **`validation.md`** — na seção OpenPGP do bloco decifra (após
   ~:361-363, o registro da fronteira da S8): nova sub-seção "OpenPGP:
   janela de resposta da decifra — decisão (fatia S12, host)" com a tabela
   dos AC-1..AC-5 (método `aegis-applets::openpgp`; status **Verificado em
   host**) e a linha consolidada AC-029 sem hardware pendente além do já
   registrado em AC-025/AC-028.
3. **`docs/security-model.md`** ~:231-233 — substituir "the boundary is
   recorded ... for a future widening decision" pelo contrato fechado:
   decifra full-RFC 6637 no transporte real é limitada pela **entrada**
   (dado ≤ 2083 ⇒ resultado ≤ 1970 octets); frame maior →
   `CcidError::Overflow` sem SW, com `card.reset()` documentado; fora do
   transporte a janela do applet responde `0x6A84` com corpo vazio
   (2048/2049), decisão (C) — mensagem maior é decifra parcial (card spec)
   ou no host.

## 10. Riscos e limitações

### 10.1 Riscos

- **R1 — Conflito de edição**: outras sessões do loop tocam
  `openpgp.rs`/`roadmap.md`/`validation.md`; o toque em `openpgp.rs` é uma
  linha `mod` — rebase mecânico.
- **R2 - RESOLVIDO: precisão do teto do AC-5** — fórmula real `10 + 9 + 67 + 4 + cipher ≤ 2100` (case 4E: `Le` estendido de 2; TLV longo `82` de 4 — §1.2 antes liam 1974 com TLV curto e sem `Le`), teto de **1970**, afirmado por `response_window.rs::frame_len` — fórmula, não octets soltos.
- **R3 — Instabilidade de `CcidError::Overflow` como API de observação:**
  o AC-5 depende de `feed` devolver `Err` antes do applet processar
  (comportamento documentado em `ccid.rs:477-481` e exercitado em
  `assembler_refuses_messages_larger_than_its_buffer`). Refatoração do
  assembler que "corte" o frame em silêncio quebraria o AC-5
  **propositalmente** (alarme de regressão do contrato silencioso).

### 10.2 Limitações

- **L1 — Sem hardware neste ciclo.** A verificação física da mensagem >
  janela num GnuPG real (o comportamento do cliente com `reset` silencioso
  pós-frame grande) fica em `validation.md` com o hardware dos ACs pendentes
  existentes.
- **L2 — A mensagem > ~2 KB não tem decifra full no cartão, por decisão.**
  O caminho coberto é decifra parcial (`Z`, card spec, PW1 modo 82) ou
  fragmentação/host. Quem provisionar `D2` e mandar > janela recebe queda
  de sessão (frame grande) ou `0x6A84` (fora do CCID) — registrado
  honestamente, sem prometer SW que o transporte não entrega.
- **L3 — `MAX_DATA` (4096) fica trancado:** mesmo com (A) aos 4096, o
  resultado-máximo é de 4056 octets e mensagens maiores mantêm
  `0x6F00`. Ampliações maiores violam a fronteira de RAM da fundação —
  fora de qualquer fatia futura (exceto re-especificação explícita).
- **L4 — Nenhum segredo novo, nenhum estado novo, nenhuma dependência:**
  a fatia só observa e congela; `STATE_VERSION`/buffers como estão.
