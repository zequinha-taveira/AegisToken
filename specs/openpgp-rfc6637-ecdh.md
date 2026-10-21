# Spec — OpenPGP ECDH: o segredo compartilhado não pode sair do cartão (RFC 6637)

**Origem:** achado do `sec-audit` (severidade ALTO) — o applet OpenPGP devolve o
segredo ECDH **bruto** ao host em `PSO:DECIPHER`, o que anula o papel do cartão
como única autoridade de decifra. **Escopo:** `crates/aegis-applets`
(lógica pura, testável em host) + wiring no firmware.
**Norma de referência:** RFC 6637 (ECC in OpenPGP) §7 (KDF), §8 (ECDH), §9
(encoding das chaves), §11 (OID das curvas), §13 (perfil OpenPGP); RFC 3394
(AES Key Wrap); RFC 4880 §5.1 (PKESK), §13.9 (MDC); ISO 7816-4 para o APDU.

---

## 1. Ameaça

### 1.1 Estado atual (verificado no código)

| Fato | Onde |
|---|---|
| `PSO:DECIPHER` (P-256) devolve `shared.raw_secret_bytes()` — o segredo ECDH completo | `crates/aegis-applets/src/openpgp.rs:1226-1235` |
| `PSO:DECIPHER` (X25519) devolve `shared.to_bytes()` — idem | `crates/aegis-applets/src/openpgp.rs:1201-1215` |
| O slot de decifra guarda a **chave privada** (`keys[1].material`, 32 bytes: escalar P-256 ou seed X25519) | `crates/aegis-applets/src/openpgp.rs:156`, `:1208`, `:1223` |
| O teste existente **fixa** esse comportamento como esperado: `pso_decipher_returns_the_p256_shared_secret` | `crates/aegis-applets/src/openpgp.rs:1640` |
| A documentação registra que o ECDH "não tem o KDF+AES RFC 6637 completo" e devolve o segredo bruto "para testes de transporte" | `roadmap.md` (Fase 14, "Cripto fora desta slice") |

### 1.2 O que o atacante (ou o host) consecgue

Um smartcard de decifra existe para ser a **única** autoridade que decifra: o
host entrega texto cifrado, o cartão devolve texto claro e **nunca** entrega
material que permita decifrar fora dele. O modelo atual quebra exatamente
essa propriedade:

1. **O segredo compartilhado sai do cartão.** O host que fez o ECDH aprende
   `Z` e, com ele, deriva a chave de sessão; passa a decifrar **sem** o
   cartão, e o cartão deixa de ser uma barreira. Qualquer processo com acesso
   USB (ou um host comprometido) obtém material equivalente à chave privada
   de decifra.
2. **O cartão deixa de ser a única autoridade de decifra.** O host escolhe o
   ponto efêmero `V` e recebe `Z = r·V`. Isso **não** quebra o ECDH (quem tem
   `Z` e `V` não obtém `r`), mas entrega ao host material equivalente ao da
   chave de sessão e transfere para fora do cartão a autoridade de decifra —
   que é exatamente a propriedade que o cartão de smartcard deve ter.
3. **Não há vínculo com a identidade do cartão.** Nada no fluxo associa a
   decifra ao par de chaves do slot: o host escolhe o ponto efêmero e recebe o
   segredo. Um intermediário pode pedir a decifra com um `V` próprio e obter
   um segredo que *não* corresponde ao material do cartão — o cartão deixa de
   ser o titular da chave.

O efeito líquido é o mesmo dos três casos: **o material que deveria ficar no
cartão chega ao host**.

### 1.3 Por que a RFC 6637 resolve

A RFC 6637 §8 define o modelo de decifra no cartão:

- o remetente gera um par efêmero `{v, V}`, calcula `S = v·R` e deriva
  `Z = KDF(S, Z_len, Param)`;
- `Z` é usado como **KEK** no key wrap (RFC 3394) da chave de sessão: o valor
  `m = symm_alg_ID || session key || checksum || PKCS#5 padding` é embrulhado
  em `C = AESKeyWrap(Z, m)`;
- o host envia ao cartão `MPI(V)` e `C`; o cartão calcula `S = r·V` com a
  **sua** chave privada `r`, deriva o mesmo `Z`, **desembrulha** `C` e
  decifra a mensagem.

Nesse modelo o segredo compartilhado **nunca** sai do cartão: o host conhece
apenas `V` (efêmero, público) e `C` (cifrado sob `Z`, que ele não consegue
derivar sem `r`).

## 2. Invariantes em risco

- **"Private keys never leave the device"** (`docs/security-model.md`): o
  segredo de sessão derivado da chave do cartão é material de chave.
- **"Secrets are sealed at rest"** e **"No secrets in logs or diagnostics"**:
  o segredo devolvido no corpo da resposta APDU escapa do cartão por uma
  interface de transporte.
- **"Constant-time discipline"** (`docs/security-model.md`): o caminho novo
  (KDF + key wrap) não pode introduzir comparações de variável em material
  secreto.
- **AGENTS.md — "No private-key import in applets (on-device generation
  only)"**: o material importável é **público** ou **cifrado** (a chave de
  sessão embrulhada `C` é cifrado, não é chave privada) — mas isso precisa
  estar explícito na spec, porque a importação de `C` é o que viabiliza o
  modelo do cartão.
- **AGENTS.md — nada de `unsafe` novo, `no_std`/`no_alloc` em
  `aegis-applets`, sem dependência nova sem licença `MIT OR Apache-2.0`.**

## 3. Escopo

A fatia é **dividida em duas etapas**, porque a etapa 2 depende de
provisionamento e de interop que não podem ser validados sem placa:

### 3.1 Etapa S1 (esta fatia) — primitivas e falha fechada

1. **Novo módulo `aegis-applets::ecdh`** (`crates/aegis-applets/src/ecdh.rs`),
   sem dependências novas (`sha2`, `aes`, `cbc` já estão no crate):
   - `kdf(param: &[u8], zb: &[u8], out_len: usize) -> Option<[u8; 32]>` — a
     KDF da RFC 6637 §7: **SHA-256** sobre
     `00 00 00 01 || ZB || Param` (Concatenation KDF, alternativa 1 do
     NIST SP 800-56A; `ZB` é a coordenada **x** de `S`, 32 bytes para P-256);
     extensões para >32 bytes encadeiam `00 00 00 02`… conforme a KDF.
   - `aes_key_unwrap(kek: &[u8; 16|24|32], wrapped: &[u8]) -> Option<heapless::Vec<u8, 64>>`
     — o **des**embrulho AES Key Wrap (RFC 3394) com o IV padrão
     `A6A6A6A6A6A6A6A6`: valida o *integrity check* (o último bloco XOR com
     `A6A6…`) e **rejeita** a entrada se ele não casar.
   - `param(curve_oid: &[u8], alg_id: u8, kdf_hash_id: u8, kek_alg_id: u8,
     fingerprint: &[u8; 20]) -> heapless::Vec<u8, 64>` — o `Param` da §8:
     `len(curve_oid) || curve_oid || public_key_alg_ID || 0x03 || 0x01 ||
     KDF_hash_ID || KEK_alg_ID || "Anonymous Sender    " (20) ||
     fingerprint (20)`.
   - `curve_oid_p256()` — `2A 86 48 CE 3D 03 01 07` (RFC 6637 §11).
2. **O segredo compartilhado deixa de sair do cartão.** `PSO:DECIPHER` para um
   slot ECDH **sem** material RFC 6637 provisionado responde **erro**
   (`6A81` — comando não suportado para este slot — ou `6D00`), e **não**
   devolve `Z`. O mesmo vale para a variante X25519, que **não** é coberta
   pela RFC 6637 (pertence ao draft "Curve25519" do GnuPG) e, por isso, não
   tem `Param` normado: ela também falha fechada.
3. **Nenhuma regressão** em assinatura, `READ PUBLIC`, `GENERATE`,
   `INTERNAL AUTHENTICATE` e no caminho RSA de `PSO:DECIPHER` (que continua
   devolvendo o bloco decifrado por operação privada, como manda a Yubico).

### 3.2 Etapa S2 — decifra completa no cartão (implementada; interop pendente)

- **Material no slot de decifra:** a chave privada `r` continua no dispositivo
  (gerada on-device) e passa a ser acompanhada do material RFC 6637: a chave de
  sessão **embrulhada** `C` (cifrado), o hash id da KDF e o id do algoritmo da
  KEK. O layout vive dentro do array de material que o slot já tinha (1156
  bytes), então **não há migração de formato de estado**: um slot ECDH antigo
  (material de 32 bytes) é simplesmente "não provisionado" e continua falhando
  fechado.
- **Provisionamento:** `PUT DATA` com a tag `0x00D2` (o DO de chave privada da
  chave 2) e o corpo `len || C || hash id da KDF || id da KEK`. O material
  importado é **cifrado**; a chave privada nunca é importada. O formato é
  **provisório**: ainda precisa ser alinhado ao *key import* do OpenPGP Card
  3.4, o que só pode ser conferido contra um host que fale o protocolo.
- **`PSO:DECIPHER`:** o comando traz a chave pública efêmera do remetente
  (`86`) e os dados cifrados (`80`); o cartão calcula `S = r·V`, deriva a KEK
  com a KDF da §7, desembrulha `C` (RFC 3394), confere o *checksum* da chave de
  sessão e decifra os dados com a camada simétrica do OpenPGP, verificando o
  *modification detection code*.
- **Camada simétrica (`aegis-applets::pgp_sym`):** o CFB da RFC 4880 §13.9 com
  o *resync* após o prefixo, o *quick check* da chave e a verificação do MDC
  (§5.14). Validada contra uma implementação de referência independente
  (`tests/openpgp_sym_reference.py`), que produz o mesmo texto cifrado e o
  mesmo texto claro.
- **Curve25519:** continua falhando fechado — a RFC 6637 não define os
  parâmetros de KDF para essa curva.

**O que falta para a interoperabilidade (S3):**

1. O *key import* no formato do OpenPGP Card 3.4 (e o procedimento do GnuPG
   correspondente), que é o que permite ao GnuPG importar a chave de sessão
   embrulhada no cartão.
2. A validação em hardware: `gpg -d` contra o cartão, o que exige um RP2350
   físico e um GnuPG instalado.

### 3.3 Não-objetivos

- Não implementar o AES Key Wrap **completo** (o *wrap*, não o *unwrap*) além
  do necessário para os testes: o embrulho é feito pelo remetente (GnuPG).
- Não suportar a variante X25519 do ECDH do GnuPG (draft Curve25519): ela
  falha fechada até haver uma spec própria.
- Não mexer no caminho RSA de `PSO:DECIPHER`.
- Não alterar o formato dos DOs `C1`/`C2`/`C3` nesta etapa (a migração de
  slot é da etapa S2).
- Não tocar em `aegis-core`, no firmware USB ou no `aegistoken-host`.

## 4. Tabela de decisão (normativa)

| Slot | Algoritmo | Material provisionado | Resposta de `PSO:DECIPHER` |
|---|---|---|---|
| decifra | RSA-2048 | — | bloco decifrado (inalterado) |
| decifra | ECDH P-256 | nenhum (estado atual) | **erro** `6A81` — o segredo não sai |
| decifra | ECDH P-256 | material RFC 6637 (etapa S2) | texto claro decifrado |
| decifra | ECDH X25519 | qualquer | **erro** `6A81` (sem `Param` normado) |
| assinatura | qualquer | — | inalterado |

## 5. Critérios de aceitação

- [ ] **AC-1** — `kdf` reproduz o vetor de referência do NIST SP 800-56A
      (KDF, alternativa 1) para `Param` e `ZB` conhecidos: o resultado é
      `SHA-256(00 00 00 01 || ZB || Param)`, conferido contra um valor
      calculado por uma implementação independente (referência em Python
      escrita a partir do texto da RFC 6637 §7) e embutido no teste.
- [ ] **AC-2** — `aes_key_unwrap` desembrulha os **vetores de teste da
      RFC 3394 §4** (128, 192 e 256 bits) e reproduz a chave de sessão
      original.
- [ ] **AC-3** — `aes_key_unwrap` **rejeita** (devolve `None`) um embrulho
      adulterado (integrity check errado) e um comprimento inválido; o
      desempacotamento **não** devolve parte da chave quando falha.
- [ ] **AC-4** — `param` monta exatamente o `Param` da §8: tamanho e OID da
      curva, `public_key_alg_ID`, `0x03 0x01`, hash da KDF, algoritmo da KEK,
      `"Anonymous Sender    "` e a impressão digital do destinatário.
- [ ] **AC-5** — `PSO:DECIPHER` em um slot ECDH **sem** material RFC 6637
      responde **erro** e **não** devolve o segredo compartilhado (o teste
      verifica o corpo da resposta: não contém os bytes do segredo).
- [ ] **AC-6** — O mesmo para o slot X25519.
- [ ] **AC-7** — O caminho RSA de `PSO:DECIPHER` continua devolvendo o bloco
      decifrado (regressão).
- [ ] **AC-8** — `GENERATE`, `READ PUBLIC`, `INTERNAL AUTHENTICATE` e as
      assinaturas continuam inalterados (regressão da suíte do applet).

## 6. Plano de teste

- `crates/aegis-applets/src/ecdh.rs` (novo, módulo de testes próprio):
  - AC-1: vetor de referência da KDF;
  - AC-2: os três vetores da RFC 3394 §4;
  - AC-3: adulteração do último bloco, comprimento ímpar, comprimento não
    múltiplo de 8;
  - AC-4: conferência byte a byte do `Param` com o layout da §8 (inclusive o
    comprimento: 54 bytes para P-256 com SHA-256 e AES-128).
- `crates/aegis-applets/src/openpgp.rs` (módulo de testes existente):
  - AC-5/AC-6: o teste `pso_decipher_returns_the_p256_shared_secret` é
    **substituído** por `pso_decipher_refuses_to_leak_the_shared_secret`, que
    exige status de erro e confere que o corpo **não** contém o segredo;
  - AC-7/AC-8: a suíte existente permanece verde.
- Comandos: `cargo test -p aegis-applets`, `cargo clippy -p aegis-applets
  --all-targets -- -D warnings`, `cargo fmt --all --check`.

## 7. Arquivos afetados

| Arquivo | Mudança |
|---|---|
| `crates/aegis-applets/src/ecdh.rs` (novo) | KDF (§7), AES Key Wrap (§8/RFC 3394), montagem do `Param` (§8), OID da curva (§11) + testes |
| `crates/aegis-applets/src/lib.rs` | registra o módulo `ecdh` |
| `crates/aegis-applets/src/openpgp.rs` | `PSO:DECIPHER` falha fechada para ECDH sem material RFC 6637 (P-256 e X25519); testes |
| `roadmap.md` | marca a pendência "OpenPGP KDF+AES RFC 6637" como **parcialmente** entregue (S1) e registra a etapa S2 |
| `validation.md` | matriz de host dos AC-1..AC-8 e a limitação de interop |
| `docs/security-model.md` | invariante: o segredo compartilhado do ECDH não sai do cartão |
| `docs/architecture.md`, `docs/yubico-compatibility.md` | ajuste da descrição do caminho ECDH |

## 8. Documentação

- `docs/security-model.md`: nova invariante — *"O segredo compartilhado do
  ECDH não sai do cartão: enquanto o material RFC 6637 não estiver
  provisionado, `PSO:DECIPHER` falha fechada em vez de devolver `Z`."*
- `validation.md`: tabela dos ACs com o método (testes de host) e a
  limitação explícita de que a interop com o GnuPG (`gpg -d`) depende de
  placa e da etapa S2.
- `roadmap.md` (Fase 14, "Cripto fora desta slice"): o item deixa de ser
  "não implementado" e passa a "S1 entregue (primitivas + falha fechada);
  S2 pendente (decifra completa no cartão, exige provisionamento e
  hardware)".
- `production.md`: nada muda nesta etapa (o provisionamento é da etapa S2).

## 9. Riscos e limitações

1. **Perda de funcionalidade até a etapa S2.** Depois desta fatia, a decifra
   ECDH **não funciona** — o cartão recusa. É uma regressão funcional
   deliberada: o comportamento anterior expunha o segredo, e não havia
   interop real com o GnuPG (o teste existente fixava um segredo bruto
   "para testes de transporte"). A decisão precisa de comunicação explícita
   nas notas de release.
2. **Risco de interop do `Param`.** A construção do `Param` (em especial o
   bloco `0x03 0x01` e a impressão digital) só pode ser confirmada contra o
   GnuPG em placa. Se divergir, a etapa S2 falha na interoperabilidade — e
   não há como detectar isso em host.
3. **A KDF exige SHA-256** (RFC 6637 §13: "SHA-1 MUST NOT be used with the
   ECDSA or the KDF in the ECDH method"). O `sha2` já é dependência do crate;
   `sha1` existe para o MDC do OpenPGP — cuidado para não misturar.
4. **Sem AES Key Wrap pronto em Rust `no_std`**: o desempacotamento da
   RFC 3394 é implementado no módulo (o `aes` do workspace expõe o bloco
   primitivo; o KW é uma construção de 6 blocos com XOR). O custo é ~40
   linhas e é coberto pelos vetores da RFC.
5. **A etapa S2 é a maior**: migração de estado, importação de material
   cifrado, CFB+MDC do OpenPGP e interop — precisa de hardware.
6. **Endpoint mais lento?** Não: o caminho ECDH passa a falhar antes, o que é
   mais rápido.
7. **Estado antigo**: slots ECDH já gerados continuam no cartão com a chave
   privada; na etapa S2 eles migram para o formato novo (ou são recusados
   com instrução de reprovisionar).
