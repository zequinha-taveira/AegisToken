# Spec — OpenPGP: estado gravado por `PUT DATA D2` não sobrevive à sessão (perda de chaves/PINs no reboot)

> **Origem:** achado **ALTO** da fatia de testes adversariais S8
> (`specs/openpgp-apdu-adversarial-tests.md`), teste fixador
> `d2_provisioned_state_fails_decode_across_sessions`
> (`crates/aegis-applets/src/openpgp/tests/adversarial_apdu.rs:290-352`) — é um
> **bug de produção** (revalidado no código; o teste S8 e as fatias S4..S8 estão
> na árvore, não commitados). **Risco:** ALTO — perda **permanente** de chaves
> e PINs provisionados do cartão OpenPGP no primeiro boot/reboot; nenhuma queda
> de confidencialidade (nada sai do cartão). Fatia única, fechada, de **reparo**,
> em `aegis-applets`; todos os ACs são de host.

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

A **geometria real** do slot ECDH persistido — verificada em
`crates/aegis-applets/src/openpgp.rs`:

- `EcdhMaterial::store` (`openpgp.rs:242-255`) grava no slot 1
  `slot.len = ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES = 32 + 72 = 104`
  (`openpgp.rs:254`), **fixo**, independente de `wrapped_len` (24/32/40/48) e da
  presença do fingerprint. Os 72 bytes de material RFC 6637 (constantes em
  `openpgp.rs:177,180,186`) ocupam `slot.material[32..104]`, indexados 0..71:
  `[0]` = `wrapped_len`; `[1..1+wl]` = wrapped key (alinhada à esquerda,
  zero-padded); `[49]` = `kdf_hash`; `[50]` = `kek_alg`; `[51]` = flag de
  fingerprint; `[52..72]` = fingerprint de 20 octets.
- `put_ecdh_material` (`openpgp.rs:1080-1126`) — o handler de `PUT DATA D2`
  (`openpgp.rs:1044`) — aceita o corpo e chama `material.store(...)`:
  **todo `D2` aceito persiste `len = 104`.**
- `decode_state` (`openpgp.rs:513-633`) recusa **qualquer slot não-RSA com
  `len > 48`** (`openpgp.rs:584`); a largura bruta por slot no v3 é
  `SLOT_MATERIAL_BYTES` (blob RSA-2048) e o `len` persistido é `u16`
  (`openpgp.rs:569-575,561-563`), ou seja, o formato **consegue expressar**
  104 — a recusa em 584 é o único bloqueio.
- **Quem mais grava slots de chave:** `generate` não-RSA persiste `len = 32`
  (escalar; `openpgp.rs:1200-1209`), `generate_rsa` persiste o blob RSA
  (`openpgp.rs:1225-1229`) e `put_algo` zera (`openpgp.rs:1154`) — não existe
  **nenhum outro** gravador de slot não-RSA com `len > 48`: o D2 é o único
  escritor afetado.

### 1.2 Caminho de exploração (queda no próprio dono)

1. O dono provisiona o cartão: `VERIFY` PW3 → `GENERATE 0xB8` (ECDH P-256,
   `len = 32`, persiste bem) → `PUT DATA D2` (`0x9000`) → `persist_state`
   (`openpgp.rs:1048`) — a store selada agora contém o slot com `len = 104`.
2. **Reboot** (instância nova; também vale qualquer `select()` em instância
   nova): `OpenPgp::new` zera `keys = [KeySlot::EMPTY; 3]` (`openpgp.rs:381`);
   `ensure_loaded` (`openpgp.rs:400-415`) tenta `decode_state`, que **falha**
   (104 > 48 em `openpgp.rs:584`) → re-init: PW1/PW3 assumem os defaults
   `123456`/`12345678` (`openpgp.rs:411-412`) e o fallback **salva de volta**
   (`openpgp.rs:414`) — numa instância nova os slots de chave estão vazios
   (`KeySlot::EMPTY`), então o save **apaga as chaves provisionadas da store**.
   Perda permanente de chaves + PINs customizados + contadores voltam ao máx.
3. **Em sessão o bug é mascarado**: um re-`select()` (carregamento
   programático) falha no decode mas mantém as chaves em RAM (o fallback não
   toca `self.keys`), e o re-init as salva de volta — é por isso que os
   asserts de reload existentes nunca o viram. O efeito visível in-session é
   puro soro: **a cada re-`select` o PIN persistido é sobrescrito pelos
   defaults** (integridade destruída; os contadores são salvos pelo clamp do
   piso da S5, `openpgp.rs:537-538`, e por isso não regredem).
4. Nada de confidencialidade: o bug abandona dados, nunca os revela.

**Impacto:** disponibilidade/integridade — qualquer cartão com material RFC
6637 provisionado é "formatado" nas chaves no primeiro boot; o dono perde as
chaves de decifra geradas no dispositivo (sem exportação — AGENTS.md proíbe
importação de chave privada, então não há backup) na primeira queda de energia.
**ALTO**.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | Estado gravado pelo próprio applet sobrevive à sessão (frio e re-select); o decode não rejeita o que `save_state` acabou de escrever | coerência de persistência de `openpgp.rs:400-415/449-477`; `docs/security-model.md` (persistência selada dos applets) | **violada** — o writer (`store`, `len = 104`) e o reader (`> 48`) discordam; a store só guarda estados que o próximo boot destrói |
| I2 | Fail-closed: larguras/estados desconhecidos são recusados, nunca aceitos por size-agnosticism | padrão da fábrica (`openpgp.rs:573-586`), suite S8 (AC do suite adversarial) | respeitada **para larguras desconhecidas** — o reparo não pode relaxar para "qualquer len" |
| I3 | Piso sticky do contador sobrevive a re-select e reload (fatia S5) | `openpgp.rs:537-538`, testes de `openpgp-pin-persistence.md` | respeitada no clamp, mas o PANIC adjacente (PIN substituído por default no re-select) é efeito do mesmo decode quebrado — o reparo o elimina de causa |

---

## 3. Decisões de política (documentadas nesta spec)

**1 — Domínio exato de largura no decode (nada de any-len).** A ramificação
não-RSA de `decode_state` (`openpgp.rs:576-586`) passa a aceitar `len > 48`
**somente** no seguinte domínio fechado:

- **slot de decifra** (`index == 1` no laço de chaves, `openpgp.rs:540`);
- algoritmo registrado `KEY_ALGO_UNSET` (0, que resolve para ECDH P-256 pela
  `effective_algo`, `openpgp.rs:328-338`) **ou** `KEY_ALGO_ECDH_P256`
  (`openpgp.rs:171`) — exatamente os dois algoritmos sob os quais o D2 é
  aceitável (`put_ecdh_material`, `openpgp.rs:1081`);
- `len == ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES = 104` **exatamente** — a única
  geometria que `EcdhMaterial::store` escreve.

Qualquer outra largura em qualquer slot/algoritmo continua recusada (`false`,
fail-closed, como hoje): `104` no slot 0/2, `104` em slot 1 X25519/EdDSA/RSA,
e larguras desconhecidas (103, 105…) e qualquer `len > 48` fora do domínio
acima continuam `false`.

**2 — Validação de octetos internos fica onde está (na leitura, não no
decode).** O decode **não** passa a validar `wrapped_len`/`kdf_hash`/`kek_alg`
internos: a fronteira de `EcdhMaterial::from_slot` (`openpgp.rs:213-239`) já
falha determinística em tempo de leitura, degrada ao fallback documentado da
card spec (fallback parcial, `0x9000`+Z — congelado pelo AC-4 do suite
adversarial) e não expõe segredo (o material é ciphertext+parâmetros; a chave
privada é o prefixo do slot). Recusar no **decode** por octeto interno
destruiria o estado inteiro (re-init) — pior para disponibilidade, sem ganho
de confidencialidade. O material rasgado segue invísivel como material e
inócuo como segredo.

**3 — Sem bump de `STATE_VERSION` e sem mudança de layout.** O formato de
bytes do v3 não muda: o `len` por slot já é `u16` (`openpgp.rs:561-563`) e a
laje bruta já é `SLOT_MATERIAL_BYTES` (`openpgp.rs:569`). Um estado persistido
**antes** do reparo (com a geometria de 104) é byte-idêntico ao que o reparo
escreve → **livro-in**: nenhuma migração, nenhuma versão nova, nada a
re-provisionar. v1/v2 usam laje de 48 (`openpgp.rs:569`) e não conseguem
expressar 104 — nenhuma mudança neles.

**4 — O reparo mata dois cenários, não o teste apenas.** Com o decode
coerente, o reboot recupera chaves e PINs (nada de re-init) e o re-`select`
deixa de trocar o PIN persistido pelos defaults — a máscara que Colocou o bug
em silêncio desaparece junto (fallback de `ensure_loaded` só ocorre para store
vazia/corrompida de verdade).

---

## 4. Escopo

- `crates/aegis-applets/src/openpgp.rs`:
  - `decode_state` (`openpgp.rs:513-633`): a ramificação não-RSA
    (`openpgp.rs:576-586`) aprende a geometria do slot ECDH conforme a
    **Decisão 1** (domínio fechado; exige o `index` do laço, já disponível em
    `openpgp.rs:540`). Nenhuma outra parte da função muda.
  - Teste de host novo (arquivo `tests/state_roundtrip.rs` + wiring de `mod`
    em `openpgp.rs:1906-1907`) cobrindo AC-1..AC-5 e AC-7 (§6).
- `crates/aegis-applets/src/openpgp/tests/adversarial_apdu.rs`:
  - **realizar/inverter** a asserção de
    `d2_provisioned_state_fails_decode_across_sessions`
    (`adversarial_apdu.rs:290-352`): nova sessão deve **recuperar** o slot
    provisionado (`ecdh_material().is_some()`), conforme a instrução do doc-comment
    (`adversarial_apdu.rs:299-301`); renomear o teste para o novo contrato
    (sugestão: `d2_provisioned_state_survives_across_sessions`) e atualizar o
    doc-comment; atualizar o comentário que cita o bug
    (`adversarial_apdu.rs:557-562`).
- Documentação na mesma mudança (§9).

## 5. Não-objetivos

1. **Persistência RSA, layout dos demais DOs, certificados, name/language/sex/
   url/contador** — zero mudança de bytes; o AC-8 congela a regressão.
2. **Qualquer mudança de SW/status words**: `0x9000`/`0x6A80`/`0x6A84` das
   rotas D2/decifra/persistência ficam como estão (nenhum protocolo muda).
3. **Validar `wrapped_len`/`kdf_hash`/`kek_alg` no decode** — Decisão 2 (a
   fronteira de `from_slot` mantém o papel).
4. **`PUT DATA D2` para X25519** e o formato "provisório" do D2 (alinhamento
   com o key import da card spec / GnuPG) — continuam no roadmap, fatia
   própria; o D2 segue exatamente como está.
5. **Store selada (`sealed.rs`) e `OpenPgpStore`** — nenhuma mudança de API.
6. **`ensure_loaded`** — o fallback de defaults fica como está (só é alcance
   do caminho de store vazia/corrompida); nenhuma nova lógica ali.
7. **FIDO/PIV/OATH/`aegis-core`/board/firmware** — nenhum arquivo tocado;
   `unsafe` zero, dependências zero.

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host em `aegis-applets` (nenhum exige
hardware); AC-8 é regressão estática/suíte inteira.

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | **Round-trip da sessão:** provisionamento completo (PW3 → `GENERATE 0xB8` → `D2` com corpo válido) → nova instância `OpenPgp::new(store)` + `select()`: `decode_state` carrega o estado e `ecdh_material()` retorna material **idêntico byte a byte** ao provisionado; `keys[1].len == 104`; o DO de fingerprints (`0x00C5`/`0x00C8`, derivado dos slots em `openpgp.rs:906-1022`) é idêntico ao da sessão original | teste de host em `tests/state_roundtrip.rs` |
| **AC-2** | **Identidade do estado completo pós-reboot:** além do material, nome/language/sex/url/certificado/contador de assinatura e escalar do slot (`keys[1].material[..32]`) idênticos na nova sessão | teste de host em `tests/state_roundtrip.rs` |
| **AC-3** | **Decifra RFC 6637 e2e pós-reboot:** na nova sessão, `VERIFY` PW1 modo 82 com o **PIN persistido** → `PSO DECIPHER` (`86` ponto + `80` ciphertext, helpers do suite adversarial) → `0x9000` + plaintext **idêntico**; mesmo ciclo com o re-`select()` in-session não destrói o PIN (AC-4 cobre o clobber) | teste de host em `tests/state_roundtrip.rs` |
| **AC-4** | **PINs/contadores:** PIN customizado provisionado verifica na sessão nova e após re-`select` (hoje o re-`select` o troca por `123456`); contador de tentativas é o persistido (piso da S5 intacto) | teste de host em `tests/state_roundtrip.rs` |
| **AC-5** | **Fail-closed de largura desconhecida:** blob v3 com slot ECDH `len = 105` (bem formado internamente) **ou** `len = 104` em slot 0/2 **ou** `len = 104` com algoritmo X25519/EdDSA no slot 1 → `decode_state` recusa (`false`) e o carregamento cai no re-init defaults | teste de host em `tests/state_roundtrip.rs` (montagem manual do blob, padrão `state_v1_migrates_to_p256_defaults`, `openpgp.rs:3272`) |
| **AC-6** | **Teste S8 realizado:** `d2_provisioned_state_fails_decode_across_sessions` invertido conforme o doc-comment — a nova sessão recupera o slot provisionado — renomeado e com doc-comments atualizados (`adversarial_apdu.rs:290-301,557-562`); suíte adversarial inteira verde | teste de host em `tests/adversarial_apdu.rs` |
| **AC-7** | **Livro-in (migração):** um blob v3 persistido **antes** do reparo (construído à mão com slot `len = 104`, geometria §1.1) decodifica com o reparo, sem bump de `STATE_VERSION` (continua `3`, `openpgp.rs:71`) e sem mudar `save_state`; v1/v2 (laje 48) e a largura não-RSA ≤ 48 (escalar do `GENERATE`, `len = 32`) seguem aceitos | teste de host em `tests/state_roundtrip.rs` |
| **AC-8** | **Regressão de nada mudou:** RSA (`len == RSA_BLOB_BYTES` validado em `openpgp.rs:578-583`), round-trips de estado existentes, painel de persistência da S5 (`openpgp-pin-persistence.md`) e os ACs do suite adversarial (incl. fronteira `104` lida na decifra, AC-4 do suite) — tudo verde com os gates §7.3 | `cargo test -p aegis-applets` |

## 7. Plano de teste

### 7.1 Onde ficam

- **`crates/aegis-applets/src/openpgp/tests/state_roundtrip.rs` (novo)** —
  mod tests de `openpgp.rs` já conecta subarquivos (`openpgp.rs:1906-1907`);
  adicionar `mod state_roundtrip;` ao lado de `adversarial_apdu`/
  `gnupg_interop`. Reutiliza os helpers estabelecidos (`applet()`, `frame()`,
  `run()` de `openpgp.rs:1815-1840`; `ecdh_p256_applet`/`streamed_body`/
  `point_command` de `adversarial_apdu.rs:134-194,240-288`) — nada de helper
  duplicado; se precisar de fixture de provisionamento completo, derivar de
  `ecdh_p256_applet` (que já faz PW3 → GENERATE → D2 → PW1-82).
- **`crates/aegis-applets/src/openpgp/tests/adversarial_apdu.rs`** — inversão
  do S8 (AC-6).
- Montagem dos blobs v3 de AC-5/AC-7: padrão do teste existente de migração
  (`openpgp.rs:3272`) — empurrar `version, pins, [present, len u16, algo,
  raw de SLOT_MATERIAL_BYTES]×3, DOs, contador` à mão no heapless `Vec`.

### 7.2 Como os casos são montados

- **AC-1/AC-2/AC-3/AC-6:** applet A com `MemoryOpenPgpStore` (provisiona
  exatamente como o S8 faz, `adversarial_apdu.rs:304-344`), take da store,
  applet B novo com a mesma store → `select()` → asserts de material/
  identidade; `VERIFY 0x82` (PW1) e `PSO DECIPHER` com `streamed_body`/`86`+
  `80` para o e2e (plaintext = o vetor do fixture).
- **AC-4:** provisionar PIN customizado + consumo de tentativa (contador 2),
  persistir → sessão nova → o PIN customizado verifica, contador é o
  persistido; em sequência, re-`select()` na mesma instância → PIN custom
  continua válido (a prova de que o clobber parou).
- **AC-5/AC-7:** blobs v3 à mão: (a) slot 1 `len=105`; (b) slot 0/2 `len=104`;
  (c) slot 1 `len=104` com `algo=KEY_ALGO_ECDH_X25519`; (d) slot 1 `len=104`
  com `algo` UNSET e material válido (livro-in, AC-7) → `decode_state`:
  (a)-(c) `false`; (d) `true` com material idêntico.
- **AC-8:** toda a suíte (`cargo test -p aegis-applets`) mais os testes de
  persistência existentes de `openpgp.rs` — nenhum precisa mudar.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

(Somente `aegis-applets` é tocado; os gates dos demais crates são regressão e
seguem verdes. Nenhum arquivo de firmware/HAL muda — sem `cargo build-fw`
novo, mas o `build-uf2.ps1` continua operante pela não-mudança de API.)

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/openpgp.rs` | `decode_state` (ramificação não-RSA, `openpgp.rs:576-586`) aprende o domínio da geometria ECDH (Decisão 1); wiring do novo mod de teste (`openpgp.rs:1906-1907`) |
| `crates/aegis-applets/src/openpgp/tests/state_roundtrip.rs` | **novo** — testes de host dos AC-1..AC-5, AC-7 |
| `crates/aegis-applets/src/openpgp/tests/adversarial_apdu.rs` | inversão/renome do S8 (`:290-352`), doc-comments `:290-301` e `:557-562` |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | Documentação na mesma mudança (§9) |
| `specs/openpgp-apdu-adversarial-tests.md` | nota de resolução do pin do S8 (o bug deixa de ser comportamento corrente) |

Nada é alterado em `crates/aegis-core/**`,
`crates/firmware-universal-rp2350/**`, `crates/board-generic-rp2350/**`,
`sealed.rs`, `pin.rs`, `piv.rs`, `oath.rs` — zero `unsafe`, zero dependências.

## 9. Documentação a atualizar (na mesma mudança)

1. **`roadmap.md`** — Fase 14 (OpenPGP): registrar o bug de produção do S8
   **corrigido** (decode coerente com a geometria D2, round-trip de sessão)
   e a resolução do item; manter status real.
2. **`validation.md`** — seção OpenPGP: entrada dos AC-1..AC-8, método "testes
   de host de `aegis-applets::openpgp`", status **Verificado em host**;
   registrar a pendência física: reboot real com material provisionado +
   decifra via GnuPG (`validate_openpgp.py`) em RP2350 disponível.
3. **`docs/security-model.md`** — na seção de persistência dos applets:
   registrar como comportamento garantido que **o estado escrito por um
   comando aceito sobrevive à sessão** (decode aceita exatamente a geometria
   que o writer produz; larguras desconhecidas seguem fail-closed), e que o
   material RFC 6637 provisionado é estado persistido do cartão — nada de
   segredo novo (o material é ciphertext).

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Árvore não commitada (S4..S8 in-tree):** a inversão do S8 deve virar
  **no mesmo commit lógico** do reparo (um commit = fatia de reparo); sem
  inversão pendente em commit próprio. Rebase mantendo o diff cirúrgico em
  `decode_state` (uma condição, uma ramificação).
- **R2 — Domínio de largura mal apertado:** aceitar `104` sem restringir
  slot/algos abriria buraco de fail-closed (slot de assinatura "com 104" ou
  X25519 com material fantasma). O AC-5 cobre exatamente as três faces
  erradas; a **Decisão 1** é o contrato.
- **R3 — Conflito com validação interna (Decisão 2):** um slot persistido
  com octetos internos inválidos (corrupção parcial) carrega e cai no
  fallback documentado (behavior já congelado pelo AC-4 do suite adversarial:
  `0x9000`+Z com material ausente). Colocar validação no decode destruiria o
  estado todo — pior. Postura documentada aqui; revisão adversarial deve
  conferir que o AC-4 do suite continua satisfeito (ele é: nenhuma asserção
  dele fala de decode).
- **R4 — Regressão segura para outros países de chave RSA:** o `len == 104`
  aceito é **menor** que `SLOT_MATERIAL_BYTES`, então a checagem de RSA
  (`len != rsa::RSA_BLOB_BYTES` → `false`) não é afetada; AC-8 congela.

### 10.2 Limitações

- **L1 — Sem hardware neste ciclo:** ACs exclusivamente de host; o reboot
  físico (power cycle real + GnuPG) fica registrado em `validation.md`.
- **L2 — Formato de D2 permanece "provisório"** (doc-comment de
  `put_ecdh_material`, `openpgp.rs:1067-1071`): o alinhamento com o key import
  da card spec/GnuPG é fatia de interop futura — este reparo não o muda, apenas
  faz o servidor aceitar os bytes que o próprio cliente escreve hoje.
- **L3 — Nenhum segredo novo, nenhum material novo, nenhuma API nova:** o
  byte-format persistido é idêntico; o reparo é coerência writer/reader.
