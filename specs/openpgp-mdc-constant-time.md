# Spec — OpenPGP: decifrador simétrico (MDC e quick-check) em tempo constante

> **Origem:** achado **BAIXO** do `sec-audit` (loop de hardening de segurança).
> **Risco:** BAIXO — canal de temporização em comparação de material derivado da
> chave de sessão, através de CCID; exploração real é marginal porque os SWs de
> erro (§1.2) já separam as categorias de falha, mas o padrão de comparação foge
> da disciplina do repositório. Fatia única, fechada, em `aegis-applets`; todos
> os ACs são de host.

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- **Quick-check com early-exit:** `crates/aegis-applets/src/pgp_sym.rs:72-74` —
  a verificação dos dois octetos repetidos do prefixo (plaintext) usa
  `plaintext[BS] != plaintext[BS - 2] || plaintext[BS + 1] != plaintext[BS - 1]`
  e retorna `None` imediatamente: o `||` de curto-circuito revela **qual dos
  dois bytes** failed, e a decisão antes de calcular o SHA-1/MDC separa
  temporalmente "quick-check ruim" de "quick-check bom + MDC ruim" dentro da
  mesma classe de resposta.
- **Verificação estrutural do pacote MDC com early-exit:**
  `pgp_sym.rs:78-81` — `plaintext[mdc_start] != MDC_TAG || plaintext[mdc_start + 1] != MDC_LENGTH`
  retorna `None` ao primeiro byte divergente (mesma classe de resposta que o
  quick-check ruim).
- **MDC com `==` de fatias:** `pgp_sym.rs:86` — `mdc == expected.as_slice()`
  usa o `PartialEq` de fatias, que sai no primeiro byte divergente: o tempo
  revela o comprimento do prefixo que casou, sobre um SHA-1 derivado da chave
  de sessão decifrada — a comparação é o alvo clássico de oráculo de
  decifração (ex.: distinguição de padding-MDC de mensagens abertas).
- **Padrão de referência do repositório, ignorado aqui:**
  `crates/aegis-applets/src/pin.rs:147-156` — `constant_time_eq(a, b)` sem
  early-exit, fechada com `core::hint::black_box(diff) == 0`; usada por
  `PinHash::verify` (`pin.rs:115-118`) e por `PartialEq for PinHash`
  (`pin.rs:132-136`). A disciplina existe no crate — o decifrador simétrico
  simplesmente não a segue.

### 1.2 Caminho de exploração (e onde ele estanca)

1. O atacante tem o dispositivo em CCID e envia `PSO: DECIPHER` com um ECDH
   público **de sua escolha** — o cartão deriva a chave de sessão por
   RFC 6637 (`openpgp.rs:1530-1561`) e decifra o corpo fornecido
   (`openpgp.rs:1562`).
2. Medindo o tempo de resposta **dentro de uma mesma classe de SW**, o
   atacante distingui: (a) qual dos octetos do quick-check falhou; (b) quantos
   bytes do MDC casaram antes do primeiro mismatch (até 20 passos em vez de
   1 decisão).
3. **Fator atenuante confirmado no código:** os dois caminhos já respondem
   com SWs **diferentes** no nível do protocolo — quick-check/estrutura ruim
   → `None` → `Sw::NO_PRECISE_DIAGNOSIS` (`0x6F00`, `openpgp.rs:1562-1564` e
   `apdu.rs:62`); MDC ruim → `Some(mdc_verified = false)` →
   `Sw::WRONG_DATA` (`0x6A80`, `openpgp.rs:1565-1569` e `apdu.rs:32`). Ou
   seja: o atacante não aprende nada por temporização que o SW não diga
   **entre** categorias — o ganho real do canal é a granularidade *dentro* de
   cada categoria (prefixo do MDC, byte falho do quick-check). Por isso o
   achado é **BAIXO**: enemigo marginal, de alto custo e baixa utilidade
   contra a chave de sessão efêmera que o próprio atacante encadeou.
4. Mesmo baixo, é disciplina de projeto: o comparador de PIN e o comparador
   HMAC do OATH (`docs/security-model.md:95` — "the HMAC comparison stays
   constant time") seguem o padrão; o MDC é o único material derivado de
   segredo comparado fora dele.

**Impacto:** nenhum contexto de quebra direto; a correção fecha uma
inconsistência de disciplina (uniformidade de código crítico) e elimina a
superfície residual antes que qualquer mudança futura (ex.: modo AES-OCB ou
SW unificado) transforme o ruído temporização em fuga.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | Comparações de material dependente de chave seguem a disciplina constante-tempo do repositório (`constant_time_eq` + `black_box`) | `pin.rs:147-156` como padrão; `docs/security-model.md:95` (HMAC do OATH é constante-tempo) | **violada** no decifrador simétrico — `==` de fatia e `\|\|` de curto-circuito sobre dados derivados da chave |
| I2 | O decifrador simétrico recusa quick-check ruim e MDC ruim fail-closed, sem mudança de comportamento observável | RFC 4880 §5.14/§13.9, comentários de `pgp_sym.rs:44-45`, teste `a_wrong_key_fails_the_quick_check` (`pgp_sym.rs:212-217`) | preservada — a fatia **não** muda SWs, nomes de API ou resultados |

---

## 3. Decisões de política (documentadas nesta spec)

**1 — Reuso, não duplicação.** `constant_time_eq` é privada hoje
(`pin.rs:147`); a fatia a promove a **`pub(crate)`** e `pgp_sym` importa
`crate::pin::constant_time_eq`. Nenhuma dependência nova, nenhuma cópia do
corpo: uma palavra de visibilidade + doc-note de que o helper é o comparador
do crate inteiro. Se no rebase `pin.rs` estiver em disputa, a alternativa
mínima aceita é mover o helper para um módulo utilitário existente do crate —
não criar cópia em `pgp_sym.rs`.

**2 — Todas as verificações são decididas ao fim, em uma única ramificação
por categoria.** O quick-check, o tag/length do pacote MDC e o compare do
SHA-1 são calculados **condicionalmente a nada** (SHA-1 e MDC rodam também
quando o quick-check falha — hoje eles nem começam): o acumulador `diff` em
estilo `constant_time_eq` absorve os quatro bytes (quick-check ×2, tag ×2)
e o resultado booleano do compare de 20 bytes; uma única decisão no fim
escolhe `None` (quick-check/tag/quick) ou `Some(Decrypted)` com
`mdc_verified` do `constant_time_eq`. Isso torna uniforme o tempo *dentro* da
classe `0x6F00` e da classe `0x6A80`, o que é o objetivo real do achado
(§1.2). O custo de sempre calcular o SHA-1 sobre ≤ 4096 bytes é irrelevante:
já é o custo dominante de qualquer mensagem decifrável.

**3 — Nada muda de SW, de resultado ou de API.** `decrypt_aes` continua
retornando `Option<Decrypted>` com `mdc_verified`; o quick-check ruim **continua
`None`** (`0x6F00` no chamador) e o MDC ruim **continua** `Some` com flag falso
(`0x6A80`). A diferença de SW entre categorias é mantida deliberadamente:
é o comportamento atual, documentado e interoperável com GnuPG — unificá-la
seria mudança de protocolo e é não-objetivo.

**4 — Comprimentos públicos não entram no regime.** Os early-returns sobre
comprimento de entrada (`pgp_sym.rs:47-52`) dependem do tamanho do
ciphertext, que é entrada pública do atacante (e do comprimento da chave de
sessão, validado por igualdade exata antes de qualquer material): não
carregam segredo e ficam como estão.

---

## 4. Escopo

- `crates/aegis-applets/src/pgp_sym.rs`:
  - `decrypt_aes`: quick-check (`pgp_sym.rs:72-74`), tag/length do MDC
    (`pgp_sym.rs:78-81`) e compare do hash (`pgp_sym.rs:82-86`) reimplementados
    com a disciplina de acumulador constante-tempo, decisões no fim (decisão 2);
    o MDC de 20 bytes usa `constant_time_eq(&expected, mdc)` com `black_box` no
    resultado;
  - nenhum comentário novo de auditoria precisa de API nova — a assinatura de
    `decrypt_aes` e de `Decrypted` não muda;
  - testes de host no módulo `#[cfg(test)]` existente (`pgp_sym.rs:151`,
    vetores de interop GnuPG em `pgp_sym.rs:155-192`).
- `crates/aegis-applets/src/pin.rs`: `constant_time_eq` (`pin.rs:147-156`)
  ganha visibilidade `pub(crate)` (documentando o rol) — nenhuma mudança de
  comportamento.
- `crates/aegis-applets/src/openpgp.rs`: **apenas testes** — o caminho de
  `PSO: DECIPHER` (`openpgp.rs:1562-1569`) é exercitado com SWs exatos nos
  casos de quick-check ruim, MDC corrupto e caminho feliz (o módulo de testes
  do `openpgp.rs` já tem estrutura `applet()`/`frame()`/`run()` e vetores de
  handshake ECDH — sem nova API de teste).

## 5. Não-objetivos

1. **Testes adversariais de APDU extra (novo INS/modes, fuzz de command
   stream)** — fatia própria.
2. **Política de comprimento de PW** — fatia própria.
3. **Validação de `kdf_hash` no D2** — já entregue na fatia OpenPGP S6
   (`roadmap.md:1154-1157`).
4. **Unificar os SWs de erro das categorias** (`0x6F00` → `0x6A80` ou
   vice-versa) — mudança observável de protocolo, prohibida nesta fatia (§3
   decisão 3).
5. **Medição quantitativa de tempo em host ou em hardware** — o timing não
   é deterministicamente testável em host: a fatia registra a verificação
   constante-tempo como **revisão de código estática + disciplina** (AC-5),
   como o repositório já faz para o HMAC do OATH.
6. **Modo de criptografia da strutura (AES-OCB, RFC 4880 §5.16)** — futuro
   formato de mensagem, fora do ciclo.
7. **Firmware, FIDO, PIV, OATH, core** — nenhum arquivo desses domínios é
   tocado; `board-generic-rp2350` e `firmware-universal-rp2350` não mudam
   (nenhum despacho de firmware muda — `pgp_sym` é `no_std` de domínio,
   teste em host).

## 6. Critérios de aceitação

Todos os ACs são de host, no módulo `#[cfg(test)]` de `pgp_sym.rs` (ACs de
comportamento da função) e do `openpgp.rs` (ACs de SW do chamador); AC-5 é
revisão estática. Nenhum exige hardware.

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | **Quick-check ruim recusado com o mesmo resultado:** para uma chave de sessão trocada em **qualquer byte** (0, índice do meio, 31 — para as três larguras 16/24/32) e para cada um dos **dois** octetos do check alterados um a um, `decrypt_aes` devolve `None` — nenhum caso passa e nenhum resultado muda de classe | teste de host em `pgp_sym.rs` (amplia `a_wrong_key_fails_the_quick_check`, `pgp_sym.rs:212-217`) |
| **AC-2** | **MDC corrupto recusado com o mesmo resultado:** acumular bit 1 em **cada um dos 20 bytes** do pacote MDC (um teste paramétrico por byte) devolve `Some` com `mdc_verified == false`, e os 20 bytes do `data` decifrado permanecem **idênticos** ao valor base — nenhuma leitura de dado parcial antes da decisão mudou | teste de host em `pgp_sym.rs` (amplia `a_tampered_ciphertext_fails_the_modification_code`, `pgp_sym.rs:219-226`) |
| **AC-3** | **Tag/length do pacote MDC corrupto → mesmo resultado:** alterar o tag (`0xD3`), o length (`0x14`) ou ambos → `None`, com o quick-check íntegro (hoje esse caminho é confundido com quick-check ruim — após a fatia continua `None`, mas exercitado com quick-check válido) | teste de host em `pgp_sym.rs` |
| **AC-4** | **Caminho feliz e interop inalterados:** o vetor real do GnuPG continua decifrando com `mdc_verified == true` e o `encrypt` reproduz o ciphertext octeto a octeto (`pgp_sym.rs:194-210` — regressão de nada mudou), e o teste de interop GnuPG real (skip seguro quando ausente) continua passando | teste de host em `pgp_sym.rs` (vetor GnuPG) |
| **AC-5** | **Disciplina constante-tempo verificada estaticamente:** nenhuma comparação `==` entre fatias de material derivado da chave de sessão (quick-check bytes, tag bytes, hash MDC) e nenhum `\|\|` de curto-circuito em decisões sobre esses material; o único comparador de fatias é `constant_time_eq` (`pin.rs:147-156`, agora `pub(crate)`) fechado com `black_box`; decisões filtradas no fim, após o acumulador completo | revisão de código estática (grep dos padrões proibidos no `pgp_sym.rs` sobre material derivado do session key) |
| **AC-6** | **SWs do chamador inalterados:** via caminho APDU (`PSO: DECIPHER`), quick-check ruim → `0x6F00` (`NO_PRECISE_DIAGNOSIS`); MDC corrupto → `0x6A80` (`WRONG_DATA`); caminho feliz → `0x9000` e resposta com o literal. Nenhuma mudança de SW em nenhum desses caminhos | teste de host em `openpgp.rs` (regride SWs exatos sobre o fluxo de ECDH existente) |

## 7. Plano de teste

### 7.1 Onde ficam

- **Unidade/funcional:** módulo `#[cfg(test)] mod tests` de
  `crates/aegis-applets/src/pgp_sym.rs` (`pgp_sym.rs:151`), com os vetores
  GnuPG existentes (`KEY`, `CIPHERTEXT`, `PLAINTEXT` — `pgp_sym.rs:163-192`)
  e helpers mínimos de mutação (paramétrico por byte, laço/`#[test]` por
  caso).
- **Integração APDU:** o módulo `#[cfg(test)]` de `openpgp.rs` (helpers
  `applet()`/`frame()`/`run()`), estendendo o teste existente de fluxo
  `PSO: DECIPHER` (o mesmo fluxo que já exercita
  `pgp_sym::decrypt_aes`): assert nos SWs exatos de AC-6.

### 7.2 Como os casos são montados

- **AC-1:** `let mut key = KEY; key[i] ^= bit;` para `i` em
  {0, 15, testado com KEY de 32} × 3 larguras de chave (o vetor é 256; são
  adicionados vetores sintéticos de 128/192 por meio do `encrypt_aes` local —
  o mesmo envia/decifra já usado em `pgp_sym.rs:205-210`); a variante por
  octeto do quick-check (primeiro vs segundo) é derivada do
  `PLAINTEXT`/`CIPHERTEXT`: construir o plaintext sintético com os oito bytes
  repetidos "quebrando" cada posição do repeat, cifra com `encrypt_aes` e
  decifra com `decrypt_aes`.
- **AC-2/AC-3:** `let mut ct = CIPHERTEXT; ct[last - k] ^= 1;` com `k` em
  0..20 (MDC) e no tag/length; a dificuldade está em assegurar que o
  quick-check **não** muda nos ACs de MDC (os bytes do MDC não afetam os
  oito primeiros octetos — já está garantido pelos índices da cauda).
- **AC-4:** sem alteração — os testes existentes
  (`decrypts_a_message_encrypted_by_gnupg`,
  `encrypts_to_the_gnupg_ciphertext`) rodam como regressão;
  `cargo test -p aegis-applets` também executa o teste de interop GnuPG real
  do crate quando `gpg` está presente (skip seguro quando não está).
- **AC-5:** passo de revisão (não é teste): liberar `grep -n "==\|\|\|"`
  limitado ao `pgp_sym.rs` e constatar que nenhum hit compara material
  derivado do session key antes do acumulador; conferir no diff que
  `constant_time_eq` é o único comparador de fatia usado.
- Nomes sugeridos (implementador pode ajustar):
  `wrong_quick_check_byte_is_rejected_for_every_position`,
  `every_mdc_byte_flip_still_fails_the_verification_with_unchanged_data`,
  `corrupted_mdc_tag_or_length_is_rejected`,
  `gnupg_vector_still_decrypts` (regressão), e no `openpgp.rs`:
  `decipher_reports_pro_sw_for_quick_check_mdc_and_success`.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

(Somente `aegis-applets` é tocado em código; os gates dos demais crates são
regressão e seguem verdes. Nenhum firmware/HAL é tocado — não há
`cargo build-fw` nesta fatia.)

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/pgp_sym.rs` | `decrypt_aes`: quick-check, tag/length do MDC e compare do hash em acumulador constante-tempo com decisão ao fim; testes de host AC-1..AC-4 |
| `crates/aegis-applets/src/pin.rs` | `constant_time_eq` (`pin.rs:147-156`): `fn` → `pub(crate) fn`, doc-note do rol de comparador do crate. Nenhuma mudança de comportamento |
| `crates/aegis-applets/src/openpgp.rs` | Apenas testes: assert nos SWs exatos de `PSO: DECIPHER` (AC-6) no módulo de testes existente |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | Documentação na mesma mudança (§9) |

Nada é alterado em `crates/aegis-core/**`, `crates/board-generic-rp2350/**`
ou `crates/firmware-universal-rp2350/**` — o decifrador é domínio puro
(`no_std`/`no_alloc` via `heapless`), host-testável, sem HAL e sem despacho
de firmware.

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — na invariante de applets (seção "Applet
   security invariants", `security-model.md:130`), **uma linha** registrando
   que o decifrador simétrico OpenPGP (RFC 4880 §13.9 — quick-check e MDC)
   usa comparação constante-tempo, mesma disciplina do `constant_time_eq`
   do PIN (`pin.rs:147-156`) e do HMAC do OATH (`security-model.md:95`);
   nota de residual: as categorias de falha continuam distinguíveis por SW
   (`0x6F00` vs `0x6A80`) por interoperabilidade — documento como
   comportamento, não como gap.
2. **`roadmap.md`** — Fase 14 (OpenPGP, `roadmap.md:1043`): registrar a
   sub-fatia de hardening ("MDC/quick-check simétrico em tempo constante,
   achado BAIXO do `sec-audit`, spec `specs/openpgp-mdc-constant-time.md`)
   nos mesmos estilos das sub-fatias S6/boa prática existentes
   (`roadmap.md:1121-1157`); manter a linha de status "Concluída".
3. **`validation.md`** — seção "OpenPGP Card v3.4": adicionar os ACs da
   fatia (método: testes de host de `aegis-applets::pgp_sym` + SWs no
   `openpgp`; status **Verificado em host**; nenhuma pendência de hardware —
   o timing não é medido em host nem em hardware neste ciclo, a disciplina
   é estática; se um estudo de temporização em hardware for desejado
   futuramente, fica registrado como não-objetivo, não como pendência).

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Otimizador derrotando o acumulador no `black_box`.** O LLVM pode
  constatar que `diff|byte ^ byte` é equivalente a uma comparação e pular
  dentro (branch-free) — `core::hint::black_box` no acumulador final
  (`pin.rs:155`) é o mitigador padrão e **não** garantia absoluta: a
  disciplina é revisão manual, não prova (mesmo nível do PIN hoje).
- **R2 — Concorrência de edição.** O loop de hardening tem outras sessões
  tocando `pin.rs`, `openpgp.rs` e os três docs; a mudança em `pin.rs` é
  **uma palavra** (visibilidade) — manter o diff cirúrgico e reconciliar no
  rebase; se houver conflito na visibilidade, avaliar mover o helper no
  rebase (§3 decisão 1, alternativa mínima).
- **R3 — Falso confiança na granularidade intra-classe.** Com a fatia, o
  tempo dentro de cada classe de SW é uniforme na função, mas o chamador
  (`openpgp.rs:1562-1569`) decide `0x6F00`/`0x6A80`/`0x9000` **após** o
  retorno — não é sigilo: os SWs são públicos e já eram distinções de
  protocolo antes da fatia (§1.2 item 3). A fatia não tenta esconder
  categorias de protocolo, apenas para de enriquecer com temporização.

### 10.2 Limitações

- **L1 — Timing não é testável deterministicamente em host.** O AC de
  constante-tempo é verificação estática (AC-5) + disciplina do helper
  testado do `pin.rs`; nenhum benchmark de timing entra no gate (não é
  rodorigo determinístico e daria flange).
- **L2 — Canal fraco reconhecido.** A exploração real é de utilidade baixa:
  a chave de sessão é efêmera, derivada por ECDH com chave pública do
  atacante, e os SWs de categoria já distinguem o que o atacante via por
  temporização (§1.2). A fatia é uniformidade de código crítico, fechando a
  superfície residual.
- **L3 — Sem segredo novo, sem material novo, sem estado.** A fatia não
  adiciona APIs, estado persistente ou dependência; o diff esperado é o
  corpo de um único função + uma visibilidade.
