# Spec — `numberOfCredentials` conforme a CTAP 2.1 e lista de candidatos sem truncamento silencioso

**Origem:** achado do `sec-audit` (itens ALTO "numberOfCredentials sempre 1 /
emitido onde a CTAP 2.1 proíbe" e BAIXO "truncamento silencioso da lista de
candidatos"). **Escopo:** `crates/aegis-core` (lógica pura, testável em host) +
wiring no firmware.

---

## 1. Ameaça

A resposta de `authenticatorGetAssertion` carrega o membro CBOR 5
(`numberOfCredentials`), que informa à plataforma **quantas** credenciais
correspondem à requisição. A plataforma usa esse número para decidir se deve
enumerar as demais (`authenticatorGetNextAssertion`) e para presented
as opções de conta ao usuário.

Dois defeitos na implementação atual:

1. **Contagem errada no caminho do firmware.** `sign_assertion`
   (`crates/aegis-core/src/authenticator.rs:648`) fixa
   `number_of_credentials: 1`, e o firmware usa `sign_assertion` diretamente
   (`crates/firmware-universal-rp2350/src/main.rs`, caminho de
   `authenticatorGetAssertion`). O valor real só é preenchido em
   `get_assertion` (`authenticator.rs:568`), que **o firmware não usa**. Efeito:
   a plataforma recebe sempre `1` e nunca enumera as demais credenciais — a
   função de enumeração entregue fica morta no dispositivo, e o usuário não vê
   as outras contas do RP.
2. **Membro emitido onde a CTAP 2.1 proíbe.** A CTAP 2.1 determina que
   `numberOfCredentials` **não** pode estar presente: (a) quando a requisição
   trouxe `allowList`; (b) quando o valor seria 1; (c) em respostas de
   `authenticatorGetNextAssertion`. O codificador (`authenticator.rs:333-351`)
   escreve a chave 5 **sempre**, e `sign_assertion` (usada tanto pela primeira
   asserção quanto pela continuação) produz `1`. Uma plataforma que obedeça a
   norma pode interpretar a presença do membro como "há mais de uma credencial"
   e entrar num laço de enumeração que devolve `NoCredentials` — ou, no caso
   da allowList, concluir que a credencial é ambígua.

3. **Truncamento silencioso (BAIXO).** `assertion_candidates`
   (`authenticator.rs:592` e `:608`) descarta o resultado de `push` com
   `let _ = ...`. Hoje o store e o vetor de candidatos têm a mesma capacidade
   (`MAX_CREDENTIALS = 8`), então o estouro é inalcançável; mas, quando a
   capacidade do store crescer, a lista será truncada **em silêncio** e a
   contagem subnotificada — o mesmo defeito do item 1, agora silencioso.

## 2. Invariantes em risco

- **Contagem fiel** (`docs/security-model.md`, seção FIDO): a plataforma decide
  a enumeração pelo número informado; um número errado altera o fluxo de
  autenticação do usuário.
- **Conformidade CTAP 2.1**: os membros opcionais só são emitidos quando a
  norma permite.
- **Falha explícita** (`AGENTS.md`): nada de descartar resultado silencioso;
  toda falha tem status observável.

## 3. Escopo

1. `GetAssertionResponse.number_of_credentials` passa a `Option<u32>`; o
   codificador escreve a chave 5 **apenas** quando o membro está presente.
2. Novo helper no núcleo com a regra da CTAP 2.1:
   - sem `allowList` e contagem `> 1` → `Some(count)`;
   - com `allowList` → `None`;
   - contagem `<= 1` → `None`;
   - resposta de continuação (`getNextAssertion`) → `None`.
3. `get_assertion` e o caminho do firmware aplicam o helper. `sign_assertion`
   deixa o membro ausente (é usada na primeira asserção do firmware e na
   continuação).
4. `assertion_candidates` passa a devolver `Result` e responde
   `Ctap2Status::LimitExceeded` quando a lista estoura o limite — em vez de
   descartar a credencial em silêncio.

## 4. Não-objetivos

- Não alterar o formato do `authenticatorData`, a assinatura, o fluxo de
  `clientPIN` nem o estado de asserção pendente por canal.
- Não implementar `authenticatorGetNextAssertion` no host CLI.
- Não mexer em `makeCredential` (`excludeList` já é respeitado).
- Não tocar no `numberOfCredentials` de outras respostas (não existe outro).

## 5. Critérios de aceitação

- [ ] **AC-1** — Sem `allowList` e com 2 credenciais correspondentes, a resposta
      de `getAssertion` **contém** `numberOfCredentials = 2`.
- [ ] **AC-2** — Com `allowList` (mesmo com 2 correspondências), a resposta
      **não** contém a chave 5.
- [ ] **AC-3** — Com uma única credencial, a resposta **não** contém a chave 5.
- [ ] **AC-4** — A resposta de `authenticatorGetNextAssertion` **não** contém a
      chave 5.
- [ ] **AC-5** — O caminho do firmware (`authenticatorGetAssertion`) informa a
      contagem real (2) e a omite quando a norma exige (allowList, ou 1
      credencial).
- [ ] **AC-6** — A lista de candidatos que estoura o limite devolve
      `LimitExceeded` (0x15) em vez de truncar em silêncio.
- [ ] **AC-7** — Nenhuma outra resposta muda de forma; a regressão de
      `getAssertion` (assinatura verificável, `authData` com UP/UV) permanece
      verde.

## 6. Plano de teste

- `crates/aegis-core/src/authenticator.rs` (módulo de testes):
  - AC-1..AC-4: decodificar o CBOR da resposta e verificar a presença/ausência
    da chave 5 e o valor;
  - AC-5: o wiring do firmware é verificado por `cargo clippy-fw` e
    `cargo build-fw-release` (o caminho do firmware é binário, sem harness de
    host); a regra em si é coberta por AC-1..AC-4 no núcleo;
  - AC-6: um store de teste que devolve mais credenciais que o limite
    (`CredentialStore::list` devolve `&[Credential]`) → `LimitExceeded`;
  - AC-7: os testes existentes de `get_assertion` continuam verdes.
- Comandos: `cargo test -p aegis-core`, `cargo clippy -p aegis-core
  --all-targets -- -D warnings`, `cargo clippy-fw`, `cargo build-fw-release`.

## 7. Arquivos afetados

| Arquivo | Mudança |
|---|---|
| `crates/aegis-core/src/authenticator.rs` | `Option<u32>` no membro, codificador condicional, helper da regra CTAP 2.1, `assertion_candidates` com `Result`, testes |
| `crates/firmware-universal-rp2350/src/main.rs` | aplica o helper no caminho de `getAssertion` e propaga o `LimitExceeded` |

## 8. Documentação

- `docs/security-model.md`: invariante "a contagem de credenciais segue a CTAP
  2.1 e nunca é truncada em silêncio".
- `validation.md`: matriz de host dos AC-1..AC-7 e a limitação de hardware.
- `roadmap.md`: registrar a correção na fase 7.

## 9. Riscos e limitações

- Plataformas que esperam a chave 5 sempre presente passam a receber a
  resposta sem o membro — é o comportamento exigido pela CTAP 2.1, e a
  plataforma trata a ausência como "uma credencial".
- O caminho do firmware não tem harness de host: a parte de wiring é coberta
  por build/clippy no alvo, e a validação em dispositivo (enumerate com duas
  contas) fica pendente de hardware.
