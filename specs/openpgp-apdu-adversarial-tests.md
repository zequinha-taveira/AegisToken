# OpenPGP: suíte adversarial de APDU no caminho de decifra (fatia de testes)

> **Origem:** achado **BAIXO** do `sec-audit` (loop de hardening de segurança).
> **Risco:** BAIXO — a reavaliação no código **não encontrou pânicos** no caminho de
> dados de `openpgp.rs`/`ecdh.rs`/`pgp_sym.rs` (TLV com `get(..)`, parse de APDU
> com `WRONG_LENGTH`, `heapless` com capacidade verificada, `decrypt_aes` falhando
> fechado via `push().ok()?`), mas a cobertura existente **não exercita os casos
> de fronteira**. A fatia é **semente de testes de host**: zero mudança de
> comportamento, nenhum teste de hardware novo (o pendente é o já registrado
> pelas fatias S1–S6).

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

O atacante pode, com o applet OpenPGP selecionado (AID `D27600012401...` no CCID)
e o PW1 modo 82 verificado (o default de interop `123456`, como o GnuPG faz),
enviar APDUs de fronteira nos dois comandos de dados sensíveis:

- **`PSO: DECIPHER`** (`openpgp.rs:1453-1494`, despachado por
  `INS_PSO p1=0x80 p2=0x86` em `openpgp.rs:1705`): hoje os moldes malformados
  caem nas seguintes rotas — nenhuma delas com teste dedicado:
  - TLV truncado: `tlv::Reader::next` devolve `None` no **primeiro** TLV
    malformado e a iteração para (`tlv.rs:41-48`) — `tlv::find` não entra em
    pânico e nada depois do TLV cortado é visível.
  - `86` vazio e comprimento TLV maior que o dado: `Reader` usa
    `self.rest.get(header..header + length)?` (`tlv.rs:45`) — devolve `None`
    sem pânico.
  - Caminho RSA (`openpgp.rs:1458-1463` + `rsa_cipher_block`
    `openpgp.rs:1724-1745`): cada `tlv::find` tem fallback `unwrap_or(input)`,
    então um TLV cortado **degrada para o input cru** antes de
    `rsa_cipher_block` devolver `None` (bloco de 256 bytes exato continua
    legítimo por design da card spec).
  - Caminho ECDH P-256 com material RFC 6637 (`openpgp.rs:1508-1575`):
    `external_public_key` (`openpgp.rs:262-272`) → `0x6A80` na falta de ponto;
    `point.len() != 65` → `0x6A80`; ponto fora da curva (ex.: todos-zero) →
    `from_sec1_bytes` Err → `0x6A80`; falta do `0x80` → `0x6A80`;
    MDC inválido → `0x6A80` (`openpgp.rs:1565-1569`).
  - Fallback *partial decrypt* (sem material, `openpgp.rs:1592-1612`) e
    X25519 (`openpgp.rs:1615-1633`): mesmas validações estruturais de ponto.
- **`PUT DATA D2`** (`openpgp.rs:1027-1058`, corpo em `put_ecdh_material`
  `openpgp.rs:1080-1126`, exigindo `pw3_verified`): as validações da fatia S6
  já em árvore recusam com `0x6A80` os `wrapped_len` fora do domínio de
  *key wrap* RFC 3394 (0/8/16/25/49 — cobertos por
  `d2_rejects_wrapped_len_outside_the_key_wrap_domain`, `openpgp.rs:2425-2493`),
  os hashes ≠ SHA-256 e os KEKs fora de `7..=9` (`openpgp.rs:1121-1123`).
  **Não cobertos:** os valores de `wrapped_len` **aceitos** nas quatro
  fronteiras (24/32/40/48 — só 24 e 32 têm fluxo end-to-end em `openpgp.rs:2370`
  e `openpgp.rs:2303`) e a fronteira **`value.len() < 4`** (corpo de 0/3/4
  bytes, `openpgp.rs:1084-1086`) — nenhum teste a exerce.
- **Fronteira de `EcdhMaterial::from_slot`** (`openpgp.rs:211-239`): um slot com
  `len < 32 + 72` ou com `wrapped_len` interno 0/> 48 faz
  `ecdh_material()` (`openpgp.rs:1577-1583`) devolver `None` e o comando cai no
  *partial decrypt* da card spec (§4.4.3.8) — **comportamento por design**
  (`9000` + `Z` de 32 bytes, gated por PW1 modo 82), mas não há teste algum
  desses degraus.
- **Tamanhos extremos** (`pgp_sym.rs:29,46-93` + `openpgp.rs:1570-1573`):
  `plaintext` é `Vec<u8, MAX_DATA=4096>` — acima disso o `push().ok()?` falha e
  `decrypt_aes` devolve `None` ⇒ `DECIPHER` responde um **SW único**
  `NO_PRECISE_DIAGNOSIS` (`0x6F00`), sem pânico. Acima do buffer de resposta
  `out: Vec<u8, 2048>` (`openpgp.rs:363`) o `extend_from_slice` falha ⇒
  `NOT_ENOUGH_MEMORY` (`0x6A84`) — **limitação de interop GnuPG** (mensagens
  > 2 KB), hoje sem teste e sem registro.
- **Ponto X25519 todos-zero** (`openpgp.rs:1615-1633`): qualquer 32 bytes é
  aceito como `x25519_dalek::PublicKey`; o `diffie_hellman` devolve o
  segredo todos-zero e o bloco lê `shared.to_bytes()`. Confirmado na API do
  x25519-dalek **3.0** (workspace): `SharedSecret::to_bytes`/`as_bytes` **não
  entram em pânico** — a checagem de contributividade é o método explícito
  `was_contributory()`, opt-in. Resultado:
  **`9000` + 32 bytes `0x00`**, determinístico.

### 1.2 Caminho de exploração / risco real

1. Dispositivo em mãos, applet OpenPGP enumerado, `VERIFY` PW1 modo 82.
2. APDUs malformadas (`A6` cortado, `86` vazio, comprimento TLV > dado, ponto
   off-curve, totalmente-zero em X25519, corpo D2 de 3/4 bytes).
3. Hoje: **nenhum pânico** (verificado no audit) e respostas fechadas
   (`0x6A80`/SW único) — mas **nada fixa esse contrato**: qualquer refatoração
   de `tlv.rs`, do parse de APDU ou de `openpgp.rs` que troque um `get()` por
   índice direto, ou que mude um fallback, passa silenciosamente pelos 100+
   testes atuais (todos de happy path mapeando o GnuPG). O achado é de
   **regressão invisível**, não de pânico presente.

**Impacto:** BAIXO — a fatia converte o "não achamos pânico" do audit em
**invariante observável e guardado**: cada fronteira de entrada responde o SW
determinístico documentado e nenhum dump de resposta contém material privado
(`keys[1].material`) nem o `Z` fora da rota *partial decrypt* especificada.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | Chaves privadas nunca saem do dispositivo; nenhuma resposta pode exportar material privado | `docs/security-model.md:134-136` ("Private keys never leave the device... no applet response can export them") | respeitada em código, **sem teste nas rotas adversariais** |
| I2 | O modelo ECDH é o da spec: `Z` só sai pelo *partial decrypt* (PW1 modo 82); no modo RFC 6637 o segredo nunca sai | `docs/security-model.md:165-186` | testado apenas no fluxo feliz (`openpgp.rs:2144`, `2644`) |
| I3 | Fail-closed: entrada inválida responde SW único determinístico e não muda estado, sem `save` | `docs/security-model.md:140-148`, padrão SW dos handlers | sem cobertura de fronteira no caminho de decifra |
| I4 | Testes obrigatórios para a lógica (e para a *ausência de panic* em caminho de dados) | `AGENTS.md` ("Tests mandatory for new/changed logic") | 0/6 casos do audit têm teste dedicado |

---

## 3. Leitura do contrato (checada contra o código)

Comportamento esperado validado antes de escrever esta spec — todas as rotas
de **entrada malformada** respondem `WRONG_DATA` (`0x6A80`) ou o SW único
indicado, **sem pânico**, sem gravação e sem tocar o slot:

| Entrada | Caminho | SW esperado | Fonte |
|---------|---------|-------------|-------|
| `A6` cortado (declarado > dado) | RSA / ECDH / X25519 | `0x6A80` | `tlv.rs:45`; RSA degrada ao input cru e `rsa_cipher_block` devolve `None` para moldura curta (`openpgp.rs:1459-1463`, `1724-1745`) |
| `86` vazio | RSA / ECDH / X25519 | `0x6A80` | `openpgp.rs:1461`, `1518`, `1619` |
| TLV (aninhado) com comprimento > dado | ECDH P-256 / X25519 | `0x6A80` | `tlv.rs:45`, `openpgp.rs:1515-1517`, `1593-1595`, `1616-1618` |
| Ponto P-256 todos-zero / off-curve | ECDH P-256 | `0x6A80` | `from_sec1_bytes` Err em `openpgp.rs:1527`, `1596` |
| Falta do `0x80` (cifrado) com material | ECDH P-256 | `0x6A80` | `openpgp.rs:1521-1526` |
| D2 com corpo 0/3/4 bytes | `PUT DATA D2` | `0x6A80` | `openpgp.rs:1084-1086`, `1092-1097` |
| D2 com `wrapped_len` 24/32/40/48 (hash 8, KEK 7–9, total = `base` ou `base+20`) | `PUT DATA D2` | `0x9000` | `openpgp.rs:1089-1124` |
| Slot ECDH incompleto (`len < 104` ou `wrapped_len` interno 0/49 em `from_slot`) | `DECIPHER` (fallback) | `0x9000` + `Z` (32 bytes) com PW1-82; `0x6A80` se a moldura do ponto também for inválida | `openpgp.rs:211-239`, `1508-1511`, `1592-1612` |
| Payload > `MAX_DATA` (4096) na camada CFB | ECDH P-256 (RFC 6637) | SW único `0x6F00` | `pgp_sym.rs:60-66` (`push().ok()?`) → `openpgp.rs:1562-1564` |
| Dados decifrados > buffer de resposta (2048) | qualquer decifra | `0x6A84` — **LIMITAÇÃO** | `openpgp.rs:363`, `1570-1573` |
| X25519, ponto todos-zero | `DECIPHER` | `0x9000` + 32 bytes `0x00` — **INFO/aceite** | `openpgp.rs:1616-1632`; x25519-dalek 3.0 (`was_contributory` opt-in) |

---

## 4. Escopo

- **Arquivo novo** `crates/aegis-applets/src/openpgp/tests/adversarial_apdu.rs`
  (módulo de testes de host), registrado como `mod adversarial_apdu;` dentro do
  `#[cfg(test)] mod tests` (`openpgp.rs:1901-1906`), no mesmo padrão do
  `gnupg_interop` (`openpgp.rs:1906`, helpers via `use super::*` como em
  `gnupg_interop.rs:15-16`). Único toque em `openpgp.rs` é essa linha `mod`.
- Casos cobertos (nomes sugeridos; o implementador pode ajustar):
  - `decipher_refuses_truncated_and_nested_tlv_frames` (RSA + ECDH P-256 +
    X25519: `A6` cortado, `86` vazio, comprimento > dado, ponto off-curve) —
    **AC-1**;
  - `d2_accepts_the_wrapped_len_frontiers_24_32_40_48` (com KEK 7/8/9 e com e
    sem fingerprint) — **AC-2**;
  - `d2_refuses_short_bodies_and_keeps_the_slot` (corpo 0/3/4 bytes, total
    desalinhado de `base`/`base+20`; `FlakyOpenPgpStore` prova zero `save`
    por recusa, padrão `openpgp.rs:2447-2474`) — **AC-3**;
  - `decipher_falls_back_deterministically_when_the_slot_material_is_incomplete`
    (montagem direta de `keys[1].len`/bytes às fronteiras de `from_slot`:
    `104`-1, `32`, `material[0]=0`, `material[0]=49`; fronteira exata `104`
    lê material válida) — **AC-4**;
  - `oversized_ciphertext_answers_one_status_word_without_panicking`
    (APDU estendido ~4.3 KB — `run` aceita `&[u8]`, `Apdu::parse` caso 3E,
    `apdu.rs:166-169`) — **AC-5**;
  - `adversarial_answers_never_leak_private_or_wrapped_material` (asserção de
    anti-serialização: por caso, o dump de resposta não contém nenhum sufixo
    de `keys[1].material`, nem `EcdhMaterial::wrapped`, nem `Z` — exceto o
    `Z` do fallback documentado em AC-4) — **AC-6**;
  - `x25519_zero_point_is_curve_behavior_not_an_error` (determinismo: `9000` +
    32 zeros; PW1-82 exigido antes) — **AC-7**.
- Caso adicional determinístico no mesmo teste do AC-1 (mesmo domínio
  estrutural): P-256 com material e **falta do `0x80`** → `0x6A80`
  (rotina fechada de `openpgp.rs:1521-1526`).
- **INFO (teste documentado, não AC):** mensagens decifradas > 2048 bytes com
  MDC válido → `0x6A84` com resposta vazia, e a fronteira **2048 exato →
  `9000`** / **2049 → `0x6A84`** — registra a LIMITAÇÃO de interop GnuPG
  (§8).

## 5. Não-objetivos

1. **Qualquer mudança de código de produção** — nenhum `.rs` de produção é
   tocado (`tlv.rs`, `ecdh.rs`, `pgp_sym.rs`, `apdu.rs`, handlers de
   `openpgp.rs` intocados).
2. **MDC em tempo constante** — fatia própria (`specs/openpgp-mdc-constant-time.md`
   em preparo por outra sessão). Estes testes **não** fixam timing e não
   reordenam comparações da MDC.
3. **Política de comprimento de PW** — fatia própria, fora deste escopo.
4. **Firmware/HAL** — nada em `firmware-universal-rp2350`, `board-generic-rp2350`
   ou `aegis-core` (fronteira de domínio do `AGENTS.md`).
5. **Aumentar o buffer de resposta (> 2 KB → `0x6A84`)** — LIMITAÇÃO registrada
   para decisão de fatia futura; aqui ela apenas entra no teste documentado.
6. **Recusar ponto X25519 não-contributório** (checagem via
   `was_contributory`) — decisão de produto/fatia futura; o AC-7 congela o
   aceite atual.
7. **Semântica de fallback do caminho RSA** (`unwrap_or(input)` até
   `rsa_cipher_block`; bloco cru de 256 bytes legítimo) — comportamento da
   card spec, apenas documentado pelos testes; os formatos válidos
   (cru/`00|02`/MPI) já têm cobertura (`openpgp.rs:2932-2988`).
8. **Validação em hardware adicional** — além da já pendente das fatias
   antecessoras (S1–S6); nenhuma extensão de `validate_*.py` é criada aqui.

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host (`cargo test -p aegis-applets`);
nenhum exige hardware.

| AC | Critério | SW esperado (verificado no código) | Observabilidade |
|----|----------|-------------------------------------|-----------------|
| **AC-1** | `DECIPHER` (P1=0x80, P2=0x86) com molduras malformadas — `A6` truncado, `86` vazio, TLV aninhado com comprimento > dado, ponto P-256 todos-zero, e `0x80` ausente com material — responde **`0x6A80` determinístico, resposta vazia e slot/estado intactos**, nos três caminhos (slot RSA, slot ECDH-P-256 com material RFC 6637, slot X25519); a semântica de fallback RSA (input cru → `rsa_cipher_block`) é documentada pelas entradas curtas dos vetores (molduras < 3 bytes ou inválidas como MPI) | `0x6A80` (`WRONG_DATA`) | teste de host em `adversarial_apdu.rs` |
| **AC-2** | `PUT DATA D2` (com PW3 verificado, slot ECDH P-256 com chave gerada) **aceita** os quatro `wrapped_len` de fronteira **24/32/40/48** com KDF SHA-256 (id 8) e cada KEK ∈ {7,8,9} — e com e sem fingerprint de 20 octets: `0x9000`, e o `EcdhMaterial` lido de volta (`ecdh_material()`) carrega exatamente o importado | `0x9000` | teste de host em `adversarial_apdu.rs` |
| **AC-3** | O mesmo comando **recusa** o corpo de 3 bytes e de 4 bytes (`value.len() < 4` até o desalinhamento de `base`), corpo vazio e total ≠ `base`/`base+20`: `0x6A80`, **zero `save`** no `FlakyOpenPgpStore` e material anterior intacto; os recusos de `wrapped_len` 0/8/16/25/49 permanecem garantidos pelo teste existente (`openpgp.rs:2425`) e são re-alistados como guardiões, não reimplementados | `0x6A80` | teste de host em `adversarial_apdu.rs` |
| **AC-4** | `DECIPHER` ECDH com **material de slot incompleto** (fronteira de `EcdhMaterial::from_slot`, montado diretamente nos testes: `len = 103`/`32`, ou `material[0]` = 0/49): `ecdh_material()` → `None` ⇒ **fallback determinístico** da card spec: com moldura de ponto válida `0x9000` + `Z` de 32 bytes (PW1 modo 82 verificado antes); com moldura inválida `0x6A80`; nenhuma rota entra em pânico; a fronteira exata `len == 104` lê o material válido (modo RFC 6637) | `0x9000` + 32 bytes (ou `0x6A80`) | teste de host em `adversarial_apdu.rs` |
| **AC-5** | Payload de dados > `MAX_DATA` (4096) no fluxo RFC 6637 (unwrap válido, corpo CFB ~4.3 KB sobre APDU estendido): resposta com **SW único** `0x6F00` (`NO_PRECISE_DIAGNOSIS`), corpo vazio, **sem pânico** e sem mudança de estado | `0x6F00` | teste de host em `adversarial_apdu.rs` |
| **AC-6** | **Não-vazamento (invariante):** em todos os casos dos AC-1/AC-3/AC-5 (e nas falhas do AC-4), o dump de resposta é vazio ou igual ao valor matemático documentado, e **nunca** contém material privado (`keys[1].material`), nem o `EcdhMaterial::wrapped` cru, nem `Z` — no modo RFC 6637 o `Z` não sai em nenhuma rota de erro; a asserção vive **dentro dos próprios testes** (anti-serialização do dump) | — | asserção incorporada aos testes acima |
| **AC-7** | `DECIPHER` X25519 com ponto todos-zero → **determinístico `0x9000` + 32 bytes `0x00`** (comportamento matemático da curva, RFC 7748; x25519-dalek 3.0 sem panic — `was_contributory` é opt-in). Registrado como **INFO/aceite**: o acesso segue gated por PW1 modo 82 e a recusa futura é não-objetivo (§5.6) | `0x9000` + 32 `0x00` | teste de host em `adversarial_apdu.rs` |

## 7. Plano de teste

### 7.1 Onde ficam

`crates/aegis-applets/src/openpgp/tests/adversarial_apdu.rs`, declarado em
`openpgp.rs:1906` como `mod adversarial_apdu;` ao lado de `mod gnupg_interop;`
(mesmo padrão de `gnupg_interop.rs`: `use super::*` + `use std::vec::Vec`).
Reutiliza os helpers do módulo de testes de `openpgp.rs`: `applet()`
(`openpgp.rs:1935-1939`), `frame()` (`openpgp.rs:1985-2002`),
`run()` (`openpgp.rs:2004-2014`, que aceita `&[u8]` — o que permite APDU
estendido acima da capacidade de `frame()`), `verify_pw3`/`verify_pw1_sig`,
`generate()` e `TestRng`. Provisionamento dos três caminhos segue os
padrões existentes: RSA (`openpgp.rs:2932-2988`, `pad_type2`),
ECDH P-256 RFC 6637 (`openpgp.rs:2144-2244`, cadeia KDF/key wrap/CFB+MDC via
`pgp_sym::encrypt_aes`), X25519 (`openpgp.rs:3053`).

### 7.2 Como os casos são montados

- **AC-1:** para cada slot (RSA / ECDH-P-256 com material / X25519), enviar:
  `A6 03 86 02 41` (A6 cortado), `A6 02 86 00` (86 vazio),
  `A6 FF ...` (comprimento > dado), ponto P-256 `[0x04; 65]` todos-zero e,
  no ECDH, mensagem sem `0x80`. Um vetor por caminho; assert SW + resposta
  vazia + `save_calls` inalterado.
- **AC-2/AC-3:** entrar com `VERIFY` PW3 (`12345678`), `GENERATE 0xB8`;
  para aceitos, construir `wrapped` real via `ecdh::aes_key_wrap` com
  `wrapped_len` em `24/32/40/48` e cada KEK id; para recusados, corpos de
  comprimento `0/3/4` e totais desalinhados; conferir `ecdh_material()`
  antes/depois e `store.save_calls`.
- **AC-4:** com material sana ancorada primeiro (fronteira `104` lê válida),
  mutar diretamente `applet.keys[1].len` (103, 32) e `material[0]` (0, 49) —
  visibilidade do módulo de testes; chamar `DECIPHER` com moldura do ponto
  válida (expect `0x9000` + `Z`) e inválida (expect `0x6A80`); restaurar e
  re-ler a material.
- **AC-5:** cadeia RFC 6637 completa com unwrap válido (padrão
  `openpgp.rs:2144`), corpo `0x80` de ~4.3 KB montado como array cru
  (`run(&[..., ])` — `Apdu::parse` caso 3E); expect `0x6F00` único.
- **INFO (limitação):** mesmo monte com dados de `2100`/`2049` bytes e MDC
  válido → `0x6A84` vazio; `2048` exato → `0x9000` com 2048 bytes.
- **AC-6:** em cada bloco acima, `let leak_sources = [chave_privada, wrapped, z]`;
  assegurar que nenhuma janela da resposta casa com alguma fonte — asserção
  inline, sem teste separado que precise de fixture.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

(Somente `aegis-applets` é tocado; os gates dos demais crates são regressão e
seguem verdes. Nenhum gate de firmware — fatia não toca despacho/HAL.)

## 8. Limitação registrada (não-AC): resposta > 2 KB → `0x6A84`

- O buffer de resposta do applet é `out: Vec<u8, 2048>` (`openpgp.rs:363`);
  uma mensagem decifrada com mais de 2048 octets (com MDC válido, fluxo do
  RFC 6637) responde `NOT_ENOUGH_MEMORY` (`0x6A84`) sem vazar bytes, e **2048
  exato** passa com `0x9000`.
- **Interpretação:** limitação de interop — mensagens OpenPGP > 2 KB
  (chaves de sessão AES-256 + anexos) não decifram mais no cartão com o modo
  RFC 6637; o GnuPG degrada para o *partial decrypt* ou decifra no host.
  **Registre como LIMITAÇÃO no `roadmap.md`/`validation.md`** e deixar a
  decisão (buffer maior vs. resposta parcial) para fatia futura — não é
  exploração e não é corrigida aqui.

## 9. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/openpgp/tests/adversarial_apdu.rs` | **novo** — suíte de host (testes dos AC-1..AC-7 + INFO da limitação) |
| `crates/aegis-applets/src/openpgp.rs` | **somente a linha** `mod adversarial_apdu;` dentro de `#[cfg(test)] mod tests` (`openpgp.rs:1906`), sem código de produção |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | documentação na mesma mudança (§10); zero código |

Nada em `aegis-core/**`, `firmware-universal-rp2350/**` ou
`board-generic-rp2350/**` — nenhum despacho de firmware muda; FIDO não vê
CCID; roteador CCID não muda de API.

## 10. Documentação a atualizar (na mesma mudança)

1. **`roadmap.md`** — Fatia 14 (OpenPGP), registro histórico: item **"S7 —
   suíte adversarial de APDU do caminho de decifra (semente de testes,
   entregue)"**, referência a esta spec, contagem de testes novos, e a
   **LIMITAÇÃO** de resposta > 2 KB (`0x6A84`) registrada no bloco de
   trade-offs (§8).
2. **`validation.md`** — na seção "OpenPGP Card v3.4 (Fase 14–16)"
   (~`validation.md:208`), nova sub-seção no padrão das fatias S4–S6
   ("OpenPGP: suíte adversarial de decifra (fatia S7, host)") com tabela de
   ACs (método: testes de host `aegis-applets::openpgp`; status
   **Verificado em host**; sem pendência de hardware nova) e a linha da
   tabela consolidada de ACs (~`validation.md:513-515`) com o item
   correspondente — **sem hardware pendente além do já registrado**.
3. **`docs/security-model.md`** — no item do modelo ECDH
   (`security-model.md:165-186`), declarar o contrato adversarial: entradas
   malformadas de `DECIPHER`/`PUT DATA D2` respondem SW fechado
   (`0x6A80`/`0x6F00`) sem pânico, nunca exportam material privado, o
   *partial decrypt* é a única saída de `Z` (PW1 modo 82), X25519 com ponto
   zero devolve o segredo zero da curva (aceite registrado), e respostas
   > 2048 octets respondem `0x6A84` (limitação documentada).

## 11. Riscos e limitações

- **R1 — Conflito de edição:** outras sessões do loop estão tocando
  `openpgp.rs` (fatia MDC, PIN-PW). O toque é uma única linha `mod`; manter o
  diff mínimo e reconciliar no rebase.
- **R2 — Semântica de fallback RSA:** o teste congela que `A6` cortado
  degrada ao input cru antes de `rsa_cipher_block` recusar. Se a fatia futura
  mudar essa semântica (ex.: recusar direto na TLV cortada), estes testes
  falharão **de propósito** — é o alarme de regressão desejado; ajuste
  intencional da fatia que mudar.
- **R3 — Versionamento do x25519-dalek:** o aceite do ponto todos-zero
  (`9000` + zeros, sem panic) vale para a 3.0 do workspace. Uma atualização
  do `Cargo.toml` que imponha assert de contributividade romperá o AC-7 — o
  teste documenta a decisão e o rebalance é deliberado.
- **R4 — Acoplamento a helpers privados de teste:** o AC-4 monta
  `keys[1]` diretamente; refatorações dos campos de `KeySlot` quebram o teste
  (prova de que a fronteira existe), com correção mecânica.
- **L1 — Sem hardware neste ciclo:** todos os ACs são de host; nenhuma
  pendência física nova — as pendências do `validate_openpgp.py` continuam
  as mesmas das fatias S1–S6.
- **L2 — MDC fora desta fatia:** os testes usam MDC válido/inválido
  apenas como observação de SW; disciplina de tempo constante fica para
  `specs/openpgp-mdc-constant-time.md` (não incluída).
- **L3 — Nenhum segredo novo, nenhum estado novo:** a fatia só observa; ela
  não altera protocolo, estado persistente nem tamanhos de buffer.

---

## Resolução

O bug de produção que esta fatia fixou — `PUT DATA D2` aceito persiste o slot
de decifra com `len = 104` e o `decode_state` recusava qualquer slot não-RSA
com `len > 48`, re-inicializando chaves e PINs na sessão fria — está
**resolvido** pela fatia S9 (`specs/openpgp-d2-state-roundtrip.md`). O teste
`d2_provisioned_state_fails_decode_across_sessions` foi invertido e renomeado
para `d2_provisioned_state_survives_across_sessions`, e o drift writer/reader
não é mais comportamento corrente; a cobertura do domínio fechado
{slot de decifra, `UNSET`/ECDH P-256, `len = 104`} e do fail-closed em todas as
outras larguras vive em `crates/aegis-applets/src/openpgp/tests/state_roundtrip.rs`.
