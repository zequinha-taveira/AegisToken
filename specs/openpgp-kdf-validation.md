# Spec — OpenPGP: `PUT DATA D2` valida o material ECDH na fronteira (kdf_hash fail-closed)

> **Origem:** achado **MÉDIO** do `sec-audit` (loop de hardening de segurança) —
> o material do Algorithm Attributes ECDH grava `kdf_hash` sem validação,
> produzindo estado de provisionamento insustentável.
> **Risco:** MÉDIO — sem risco criptográfico direto (hash inconsistente não vaza
> segredo), mas o `PUT DATA D2` aceita estado que o cartão jamais consegue usar
> e a falha só aparece na decifra real (horas depois). Fatia única, fechada, em
> `aegis-applets`; todos os ACs são de host (a exceção é o teste de interop com
> o GnuPG, que roda quando o `gpg` existe e é pulado de forma segura quando não
> — §7.3).
>
> **Nota de revalidação:** a árvore está sendo editada por outra fatia em
> `openpgp.rs`; as referências abaixo são **por função/invariante** e o número
> de linha citado é o da leitura de hoje (pode deslocar no rebase — as funções
> são a âncora).

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- **`kdf_hash` é gravado sem validação.** `put_ecdh_material`
  (`crates/aegis-applets/src/openpgp.rs`, função `put_ecdh_material`, hoje
  ~1000-1040) valida:
  - slot de decifra coerente: `keys[1].effective_algo(1) == KEY_ALGO_ECDH_P256`
    e `present` (~1001);
  - corpo mínimo `value.len() >= 4` (~1004) — a fronteira citada pelo audit;
  - `wrapped_len` entre 1 e `ECDH_WRAPPED_MAX = 48` e comprimento total exato
    `base` ou `base + 20`, com `base = 1 + wrapped_len + 2` (~1007-1014);
  - **`kek_alg` ∈ 7..=9** ("The key encryption algorithm must be one the card
    supports", ~1035).
  Mas **`kdf_hash = value[1 + wrapped_len]` é gravado cru**, sem qualquer
  restrição de conjunto (~1030), embora o próprio módulo exporte o único valor
  com suporte: `ecdh::HASH_SHA256 = 8`
  (`crates/aegis-applets/src/ecdh.rs:27`).
- **O `kdf_hash` provisionado alimenta o KEK na decifra.** `decipher_ecdh`
  (`openpgp.rs`, função `decipher_ecdh`, ~1422-1489) monta
  `ecdh::param(CURVE_OID_P256, ALG_ECDH, material.kdf_hash, material.kek_alg,
  fingerprint)` (~1452-1458) e deriva o KEK com **`ecdh::kdf`, que codifica
  SHA-256 fixo** (`crates/aegis-applets/src/ecdh.rs`, função `kdf`,
  ~73-89; `use sha2::Sha256`, ~9). Com `kdf_hash ≠ 0x08`, o remetente derivou o
  KEK com outro hash (ex.: SHA-512) sobre parâmetros coerentes, o cartão deriva
  com SHA-256, os KEKs **nunca casam** e `ecdh::aes_key_unwrap` falha
  (`ecdh.rs:200-247`, integridade RFC 3394) → a decifra responde
  `Sw::NO_PRECISE_DIAGNOSIS` (`0x6F00`) (`openpgp.rs:1470-1471`; o valor da
  constante está em `crates/aegis-applets/src/apdu.rs:62`). Falha **fechada na
  decifra**, mas **aberta na fronteira de entrada**: o provisionamento que
  criou o estado respondeu `9000`.
- **O estado ruim persiste.** `put_data` (`openpgp.rs`, `put_data`,
  ~960-986) aceita a tag `0x00D2` com `pw3_verified` (~961), persiste via
  `save_state()` e o byte entra no slot por `EcdhMaterial::store`
  (`openpgp.rs:243-254`); `from_slot` (~210-242) o restaura a cada
  `select()`/reload — o estado ruim sobrevive a reconexão e power cycle.
- **O que já está coberto (confirmação de revalidação).** Duas partes do
  achado já são defesas existentes, não gaps: (a) `wrapped_len == 0` e
  `wrapped_len > 48` são rejeitados (~1009-1010), assim como corpo com
  comprimento ≠ `base`/`base + 20`; (b) a borda `value.len() < 4` rejeita antes
  de indexar. O que resta sem defesa é exatamente o `kdf_hash` — e a
  **estrutura** do `wrapped`: um `wrapped_len` que o `aes_key_unwrap` recusa
  (`wrapped.len() < 16 || wrapped.len() % 8 != 0` → `None`,
  `ecdh.rs:200-203`) hoje passa na D2 e estoura `0x6F00` na decifra
  (`openpgp.rs:1470-1471`) — a mesma classe de "aceitar estado que nunca
  funciona".
- **Testes atuais não cobrem a negativa.** O módulo `#[cfg(test)]` de
  `openpgp.rs` (a partir de ~1782) exerce só o caminho feliz: `import` com
  `ecdh::HASH_SHA256`/`ecdh::KEK_AES128` (`pso_decipher_unwraps_the_session_key_and_decrypts`,
  ~1990-2080; `the_fingerprint_is_an_optional_part_of_the_provisioning`,
  ~2082-2127) e o interop real com o GnuPG
  (`crates/aegis-applets/src/openpgp/tests/gnupg_interop.rs`,
  `gnupg_encrypts_and_the_card_decrypts`, D2 em ~360-364 e ~375-377). Não há
  nenhum caso com `kdf_hash ≠ 0x08`.
- **X25519 não é afetado.** `put_ecdh_material` exige o slot em P-256
  (~1001) e o `decipher_ecdh_x25519` é o *partial decrypt* da OpenPGP Card
  3.4.1 §4.4.3.8: devolve o segredo cru, sem KDF (`openpgp.rs:1528-1547`). Os
  parâmetros KDF anunciados para X25519 no export de chave pública
  (`[0x03, 0x01, 0x0A, 0x09]`, `fingerprint` de slot, `openpgp.rs:872-876`)
  são informativos do host e **não** passam pelo material D2 nos slots.

### 1.2 Caminho do provisionamento insustentável (exploração operacional)

1. O operador (ou script de provisionamento) monta um D2 com `kdf_hash = 0x0A`
   (SHA-512) — porque copiou o *Algorithm Attributes* de uma implementação que
   usa SHA-512, ou editou à mão. O corpo tem comprimento, `kek_alg = 0x09`
   válido e fingerprint opcional: o parser considera tudo certo **menos** o hash.
2. `PUT DATA D2` → **`9000`**; o byte entra no slot e persiste selado.
3. Na primeira mensagem real, o remetente deriva o KEK com SHA-512 e o cartão
   com SHA-256: `aes_key_unwrap` falha a integridade e **toda** `PSO: DECIPHER`
   responde `0x6F00`.
4. O operador descobre a falha horas/depois, com tráfego real, sem nenhum
   indício de qual provisionamento quebrou — o cartão aceitou tudo "com
   sucesso".

**Impacto:** custo operacional e confiança na API de provisionamento — a D2 é
a única fronteira de input do caminho RFC 6637 que não verifica seu domínio.
Sem vazamento (o hash errado derivar KEK errado não revela nada), sem
elevação de autoridade (o `pw3_verified` já é exigido, `openpgp.rs:961-963`).
Por isso MÉDIO e não ALTO.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | Modelo ECDH do cartão: a decifra segue RFC 6637 §7/§8 com os parâmetros provisionados; a fundação valida na fronteira o que só consegue recusar mais tarde | `docs/security-model.md:152-160` ("The card's private key never leaves it, and the ECDH model is the one the specification defines…") | **violada na fronteira** — `kdf_hash` sai do domínio implementado sem erro |
| I2 | Parsing fail-closed: input fora do conjunto suportado é recusado no comando que o recebe, não no uso | padrão do crate (kek_alg ∈ 7..=9 em `put_ecdh_material`; `parse_attrs` em `put_algo`) | **violada para `kdf_hash` e para a estrutura do `wrapped`** (≥ 24, múltiplo de 8) |
| I3 | O provisionamento é sustentável: nenhum estado aceito pode deixar o slot permanentemente incapaz de decifrar | espírito da invariante de ECDH acima + teste de interop do repositório | **violada** — D2 aceita estado cuja única saída é `0x6F00` para sempre |

---

## 3. Decisões de política (documentadas nesta spec)

**1 — `kdf_hash` único suportado: `0x08` (SHA-256). Recusar o resto com
`WRONG_DATA` (`0x6A80`).** A decisão parte da autoridade prática do
repositório:

- **O caminho de decifra do cartão é SHA-256 e só SHA-256**: `ecdh::kdf` usa
  `Sha256` fixo (`ecdh.rs:73-89`) e `decipher_ecdh` não tem ramo por hash.
- **O GnuPG usa SHA-256 com P-256** — o teste de interop
  (`gnupg_interop.rs:259`) importa a chave do GnuPG e afirma
  `key.kdf == vec![0x03, 0x01, 0x08, 0x07]` ("SHA-256 and AES-128"), e o D2
  aceito do interop grava exatamente `key.kdf[2..4] = [0x08, 0x07]`
  (`gnupg_interop.rs:360-364`).
- O slot D2 é restrito a P-256 (`put_ecdh_material:1001`); o X25519 nem usa o
  material (partial decrypt, sem KDF). Logo os KDF-DO com SHA-512 para
  Curve25519 (id `0x0A`, anunciado no export X25519) **não passam por esta
  fronteira** — validar `≠ 0x08` não fecha nenhum interop de verdade da
  fundação.

Política em código: `put_ecdh_material` acrescenta à validação de `kek_alg`
(~1035) a de `kdf_hash`: **só `ecdh::HASH_SHA256` (0x08) é aceito**; qualquer
outro byte (0x00, 0x02/SHA-1, 0x09/SHA-384, 0x0A/SHA-512, 0xFF…) marca a D2
como recusada → `put_data` responde `Sw::WRONG_DATA` (`0x6A80`), como já faz
para todo `false` de DO (`openpgp.rs:980-985`); nada é gravado nem
`save_state()` é chamado no caminho de recusa. O literal proibido não aparece
no código: a comparação é contra a constante `ecdh::HASH_SHA256`, para que a
realidade da decifra e a fronteira não diverjam.

**2 — A alternativa "KDF por id" (implementar SHA-384/512 em `ecdh::kdf`
conforme RFC 6637 §7) é rejeitada nesta fatia.** Justificativa: (a) não existe
pressão de interop — o único remetente testado (GnuPG) usa SHA-256 com P-256 e
o sufixo `!` da subkey prova o caso real; (b) o ambiente de testes do
repositório não tem vetor de referência SHA-384/512 nem remetente que os use —
implementar seria inventar suporte sem autoridade de teste; (c) o slot é
P-256-only hoje. Se uma fundação futura adicionar ECDH nos atributos com outro
hash, essa fatia implementa o `match` de hash **e** relaxa esta fronteira — as
duas coisas juntas, nunca uma só (a invariante: nada aceito que a decifra não
implemente).

**3 — Coesão do `wrapped` na mesma fronteira (mesmo AC de validação de D2, não
fatia separada).** O `aes_key_unwrap` só aceita `wrapped.len() >= 16 &&
wrapped.len() % 8 == 0` (`ecdh.rs:200-203`) — mas isso é o piso da primitiva,
não da aplicação: um `wrapped` de 16 octets desembrulha 8 octets e
`session_key_from_wrapped` (`openpgp.rs`, função `session_key_from_wrapped`,
~274-296) recusa — o estado continuaria falhando só na decifra. O piso
coerente da D2 é o menor bloco de sessão OpenPGP real: `symm_alg_ID` + chave
AES-128 (16) + checksum (2) embrulhados por RFC 3394 → **24 octets**. A D2
passa a exigir `wrapped_len` ∈ **24..=48, múltiplo de 8** (os valores reais
das chaves de sessão AES: 24/32/40; o teto de 48 fica). Corpos que hoje
passam (ex.: `wrapped_len = 10`, `wrapped_len = 25`, `wrapped_len = 16` e
`wrapped_len = 8`) passam a ser `0x6A80` na provisionação em vez de `0x6F00`
na primeira decifra. As rejeições já existentes (`0`, `> 48`, comprimento
total errado) continuam, agora garantidamente coerentes com o consumidor.

**4 — SW e ordem.** Nada muda de status word na fronteira: recusa é `0x6A80`
(idêntico ao `kek_alg` e ao comprimento hoje), a ordem de checagem dentro de
`put_ecdh_material` fica com o implementador (todos os erros são
indistinguíveis por design — não dar oráculo de parse a um provisionador
hostil). A D2 válida **idêntica ao interop** (`len || wrapped || 0x08 0x07 [||
fpr]`) continua `9000` byte a byte.

---

## 4. Escopo

- `openpgp.rs`:
  - `put_ecdh_material`: validar `kdf_hash == ecdh::HASH_SHA256` (recusar o
    resto) e a coesão do `wrapped_len` com o consumo real do material (≥ 24 —
    menor bloco de sessão OpenPGP+RFC 3394 —, múltiplo de 8, ≤
    `ECDH_WRAPPED_MAX`; os limites 0/+48/comprimento total já existem e
    ficam); recusas respondem `false` → `0x6A80` em
    `put_data`, sem gravação e sem `save_state()`.
  - doc-comment de `put_ecdh_material`: documentar o domínio aceito
    (P-256 + SHA-256/KEK AES 128-192-256) e a razão (o KDF do cartão é
    SHA-256; GnuPG usa SHA-256 com P-256 — interop de referência).
  - Testes de host AC-1..AC-6 (§6) no módulo `#[cfg(test)]` existente
    (~1782), reusando os helpers `applet()`, `run()`, `frame()`,
    `verify_pw3()`, `generate()`, `TestRng`, `append_tlv`; e a extensão do
    cenário de interop real (AC-6).
- `ecdh.rs`: **nenhuma mudança de comportamento** — `HASH_SHA256` já é `pub`
  e é a constante da fronteira; o KDF e o `aes_key_unwrap` não mudam.

## 5. Não-objetivos

1. **KDF por id (SHA-384/512) conforme RFC 6637 §7** — rejeitada nesta fatia
   (decisão 2); se um dia os atributos ECDH suportados incluírem outro hash,
   a implementação do KDF e o relaxamento da fronteira entram **na mesma**
   fatia futura.
2. **MDC em tempo constante** — fora do escopo.
3. **Política de comprimento de PW** (`CHANGE REFERENCE DATA`) — não tocada.
4. **Resetting Code (BC)** — continua fora (fato da fatia `openpgp-unblock-auth`).
5. **Persistência fail-open de `save_state()`** — fatia própria
   (`specs/openpgp-pin-persistence.md`); aqui a recusa nem chega ao save.
6. **X25519**: atributos, export, partial decrypt e o KDF-DO `0x0A 0x09`
   **não mudam** — o X25519 não passa pela D2.
7. **FIDO/PIV/OATH** — nenhum código fora de `aegis-applets::openpgp` é
   alterado; `PinSlot` não é tocado.
8. **Hardware** — nada de `cargo build-fw`; os ACs são todos de host
   (a validação física fica na pendência já registrada em `validation.md`
   para `validate_openpgp.py`).

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host no módulo `#[cfg(test)]` de
`crates/aegis-applets/src/openpgp.rs` (nenhum exige hardware); AC-6 executa o
GnuPG quando disponível e pula de forma segura quando não (§7.3).

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | **D2 válido continua aceito, byte a byte:** o mesmíssimo bloco de provisionamento usado hoje (estrutura `len \|\| wrapped \|\| 0x08 0x07` sem fingerprint, e a variante com fingerprint de 20 octets — as construídas em `pso_decipher_unwraps_the_session_key_and_decrypts` e em `the_fingerprint_is_an_optional_part_of_the_provisioning`) responde `9000` e o material lido por `applet.ecdh_material()` mantém `wrapped`, `kdf_hash == 0x08` e o fingerprint exatamente como provisionados | teste de host (regressão dos testes existentes) |
| **AC-2** | **D2 com `kdf_hash ≠ 0x08` → `0x6A80`, estado inalterado:** corpo válido exceto o hash (`ex.: 0x0A 0x09`, `0x02 0x07`, `0x00 0x07`, `0x0A 0x07`); a resposta é `WRONG_DATA`, o material anterior do slot permanece legível por `ecdh_material()` (nada foi sobrescrito) e, após `select()`, o estado recarregado é o anterior (nenhum `save_state()` no caminho de recusa) | teste de host |
| **AC-3** | **Coesão do `wrapped` na mesma fronteira:** `wrapped_len` fora do domínio de consumo real — `0` (regressão), `> 48` (regressão), não múltiplo de 8 (ex.: 25, novo) e `< 24` (ex.: 8 e 16, novos, incluiriam estado que `session_key_from_wrapped` recusaria depois) — responde `0x6A80` com o slot intacto; corpo com comprimento total ≠ `base`/`base + 20` segue `0x6A80` (regressão) | teste de host |
| **AC-4** | **Decifra e2e host-simulada continua `9000`:** o cenário de `pso_decipher_unwraps_the_session_key_and_decrypts` (remetente simulado com `ecdh::param`/`kdf`/`aes_key_wrap` + `pgp_sym::encrypt_aes`) recupera o plaintext com o D2 válido de AC-1; e o caso "sem fingerprint a decifra falha fechada" (interop sem fingerprint, `gnupg_interop.rs:369-372`) permanece `≠ Sw::OK` | teste de host (e interop) |
| **AC-5** | **Atributos NIST/P-256 não regredem:** o export de chave pública do slot DEC (`READ PUBLIC KEY` → tag `86`) mantém o KDF-DO `[0x03, 0x01, 0x08, 0x07]` e o fingerprint de slot (SHA-1 v4) inalterados; `put_algo(1, …)` aceita P-256/X25519/RSA-2048 como hoje | teste de host |
| **AC-6** | **Interop real com o GnuPG:** o teste `gnupg_encrypts_and_the_card_decrypts` roda sem mudança de asserções — o provisionamento D2 do interop (hash `0x08` + KEK `0x07`) continua `9000`, a decifra com payload GnuPG real continua `9000` e recupera a mensagem; e um D2 seguinte com hash `0x0A` é recusado com `0x6A80` sem alterar o
material válido provisionado (a decifra subsequente continua `9000`) | teste de interop (executa com `gpg`/`AEGIS_GPG` no ambiente; pula de forma segura caso contrário) |

## 7. Plano de teste

### 7.1 Onde ficam

- ACs de host (AC-1..AC-5): no módulo `#[cfg(test)] mod tests` de
  `openpgp.rs` (declarado em ~1782), ao lado dos testes de D2 existentes,
  reutilizando os helpers estabelecidos (`applet()`, `run()`, `frame()`,
  `verify_pw3()`, `generate(slot 0xB8)`, `TestRng`, `append_tlv`).
- AC-6: no arquivo de interop existente
  `crates/aegis-applets/src/openpgp/tests/gnupg_interop.rs` (o módulo é
  declarado dentro do `mod tests` de `openpgp.rs` e já é o padrão do
  repositório).

### 7.2 Como os casos são montados

- **AC-1:** replicar os dois imports do teste sem fingerprint e com
  fingerprint (hash `0x08`, KEK `0x07`), usar o `wrapped` de `aes_key_wrap`
  ou o `[0x11u8; 24]` sintético — e comparar `ecdh_material()` campo a campo.
- **AC-2:** para cada hash proibido (`0x00`, `0x02`, `0x09`, `0x0A`, `0xFF`),
  montar o import válido trocando só o byte do hash; verificar `0x6A80` +
  material anterior intacto + re-`select()` recuperando o anterior.
- **AC-3:** parametrizar sobre `wrapped_len` ∈ {0, 8, 16, 25, 49 e
  comprimento total errado}; assert de `0x6A80` + slot intacto.
- **AC-4:** asserções de regressão do teste e2e existente (o novo AC-2 não
  pode ter quebrado essas asserções); e a verificação "fail-closed sem
  fingerprint"
  movida/estendida também para o módulo de host (ela existe hoje no interop —
  manter nas duas frentes).
- **AC-5:** asserção estática do export de chave pública (o teste existente do
  KDF-DO `0x03 0x01 0x08 0x07` cobre; reexecutar).
- **AC-6:** no interop: após o D2 válido e a decifra bem-sucedida, tentar um
  D2 com `0x0A 0x09` → `0x6A80`, e reexecutar a decifra com o material
  original (provisionado de novo ou preservado) → `9000` ainda.
- Nomes sugeridos (o implementador pode ajustar):
  `d2_accepts_the_supported_kdf_hash_and_keeps_the_material`,
  `d2_rejects_unsupported_kdf_hash_without_touching_the_slot`,
  `d2_rejects_wrapped_len_outside_the_key_wrap_domain`,
  `decipher_still_unwraps_a_coherent_provisioning`,
  (interop) `gnupg_provisioning_rejects_a_foreign_kdf_hash`.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

O `cargo test -p aegis-applets` inclui o módulo de interop
(`gnupg_interop`): ele **pula de forma segura** quando o `gpg` não existe —
`gpg_path()` retorna `None` e o teste retorna cedo
(`gnupg_interop.rs:28-48`; o doc-comment do módulo documenta o skip e a
variável `AEGIS_GPG` para apontar o executável). Em CI o `gnupg` é instalado e
o AC-6 roda de verdade. Nenhum gate de firmware (nenhum arquivo de
firmware/HAL é tocado).

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/openpgp.rs` | `put_ecdh_material`: validação de `kdf_hash == ecdh::HASH_SHA256` + coesão do `wrapped_len` (domínio de `aes_key_unwrap`); doc-comment do domínio aceito; testes de host AC-1..AC-5 |
| `crates/aegis-applets/src/openpgp/tests/gnupg_interop.rs` | AC-6: D2 com hash estrangeiro recusado (`0x6A80`) sem quebrar a decifra subsequente (asserções existentes intactas) |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | Documentação na mesma mudança (§9) |

`ecdh.rs` não muda (a constante `HASH_SHA256` já é `pub e é a âncora da
fronteira). Nada é alterado em `crates/aegis-core/**`,
`crates/firmware-universal-rp2350/**` ou `crates/board-generic-rp2350/**`
(nenhum despacho de firmware; a rota CCID/roteador não muda de API).

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — na invariante ECDH dos applets
   ("The card's private key never leaves it…", ~`security-model.md:152-160`),
   declarar o domínio provisionável: `PUT DATA D2` só aceita material
   coerente com o que o cartão executa (P-256 + KDF SHA-256 + KEK AES
   128/192/256 + `wrapped` no domínio RFC 3394) e recusa o resto com `0x6A80`
   na provisionação — nada aceito pode falhar apenas na decifra.
2. **`roadmap.md`** — registrar a sub-fatia de hardening na Fase 14 (OpenPGP),
   no estilo de "OpenPGP S4" (~`roadmap.md:1119`): item **"OpenPGP S5 (ou
   numeração livre na reconciliação — ver R3) — `PUT DATA D2` fail-closed na
   fronteira (`kdf_hash`/`wrapped_len`), entregue"**, com a decisão de política
   (SHA-256 único, interop GnuPG como autoridade, referência a esta spec).
3. **`validation.md`** — na seção OpenPGP (tabela de ACs ~`validation.md:453`
   e a entrada da fatia em ~`validation.md:208`): adicionar o AC da fatia
   (método: testes de host `aegis-applets::openpgp` + interop `gnupg_interop`;
   status **Verificado em host**) e manter a pendência física existente
   (`validate_openpgp.py` em hardware, sem mudança de script neste ciclo — o
   script não provisiona D2 com hash estranho hoje; estender ao houver RP2350).

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Interop teoricamente legal, na prática ausente.** A RFC 6637 permite
  P-256 com SHA-512; um remetente assim passaria a receber `0x6A80` na
  provisionação. Nenhum implementador conhecido faz isso (o GnuPG fixa
  SHA-256 para P-256 — o teste do repositório é a autoridade prática,
  `gnupg_interop.rs:259`), e a recusa é **explícita e no momento do erro**
  (em vez de `0x6F00` silencioso após horas): o trade-off é seguro. Se surgir
  demanda real, a política é a da decisão 2 (KDF por hash + relaxamento
  juntos).
- **R2 — Concorrência de edição.** Outra fatia está tocando `openpgp.rs` e os
  docs compartilhados (`roadmap.md`/`validation.md`); manter diffs cirúrgicos
  (um bloco de validação a mais em `put_ecdh_material`, um teste a mais por
  AC, item único em cada doc) e reconciliar no rebase — as âncoras desta spec
  são funções, não linhas.
- **R3 — Numeração da sub-fatia.** As sub-fatias OpenPGP ("S4") e a fatia de
  persistência estão sendo registradas por sessões paralelas; o rótulo "S5"
  aqui proposto deve ser reconciliado no rebase (o conteúdo da decisão não
  depende do número).
- **R4 — `ECDH_WRAPPED_MAX` e o `wrapped_len as u8`.** O comprimento entra
  como um byte (`wrapped.len() as u8` nos provedores atuais); com o teto de 48
  e o piso de 16 (múltiplo de 8) nada muda para os valores reais (24/32/40/48)
  — nenhum provedor atual (`gnupg_interop`, teste e2e, GnuPG real) provê
  `wrapped` fora desse domínio.

### 10.2 Limitações

- **L1 — Sem hardware neste ciclo.** Todos os ACs são de host; o AC-6 é a
  melhor proxy de interop (GnuPG real em host) e a confirmação física fica na
  pendência de `validate_openpgp.py` já registrada.
- **L2 — O interop depende do ambiente.** Sem `gpg` no ambiente, o AC-6 pula
  de forma segura (comportamento existente do módulo); os ACs de host
  (AC-1..AC-5) cobrem a fronteira e o e2e simulado independentemente.
- **L3 — Sem segredo novo, sem material novo.** A fatia só estreita o domínio
  aceito por uma fronteira existente; o formato de estado persistente
  (`STATE_VERSION`, codificação de `EcdhMaterial`) não muda.
- **L4 — Sem oráculo de parse.** Todos os erros de D2 continuam
  indistinguíveis (`0x6A80`) — intencional, mantido.
