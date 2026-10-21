# Spec — Escopo do `pinUvAuthToken` (permissão por operação + vínculo por RP)

> **SUPERADA.** Esta especificação foi escrita durante a implementação e
> diverge da que foi implementada: ela prevê que um token sem vínculo de RP
> sirva qualquer RP e que o token legado (de `getPinToken`) autorize
> credential management. A versão aprovada e implementada é
> [`specs/ctap2-token-scope.md`](ctap2-token-scope.md) (fatia 7g do
> `roadmap.md`), que adota a nota de §6.5.5.7 da CTAP2.1 (o token sem
> *permissions RP ID* é vinculado no primeiro uso) e exige a permissão `cm`
> explícita para credential management. O arquivo fica como registro do
> caminho de análise; **não** usar como referência de implementação.

**Origem:** achado do `sec-audit` (severidade ALTO) — o token `pinUvAuthToken` não é
escopado: a prova de UV não está vinculada nem à operação nem ao *relying party*.
**Escopo:** `crates/aegis-core` (núcleo testável em host) + wiring em
`crates/firmware-universal-rp2350`.
**Norma de referência:** CTAP 2.1 (WebAuthn/FIDO CTAP 2.1), seções de
`pinUvAuthToken`, `authenticatorMakeCredential`, `authenticatorGetAssertion` e
`authenticatorCredentialManagement`.

---

## 1. Contexto e ameaça

### 1.1 Estado atual (verificado no código)

| Fato | Onde |
|---|---|
| `ClientPin::verify_pin_uv_auth_param` valida **apenas** o HMAC do `clientDataHash` contra o token ativo; nenhum bit de permissão e nenhum `pin_uv_auth_rp_id` é consultado | `crates/aegis-core/src/pin.rs:422` |
| `ClientPin::allows_credential_management` testa **apenas** o bit `cm` (ou o flag `legacy_token`); o RP vinculado é ignorado | `crates/aegis-core/src/pin.rs:440` |
| `pin_uv_auth_rp_id` é gravado na emissão do token e **nunca** comparado | `crates/aegis-core/src/pin.rs:610` |
| `check_user_verification` aceita qualquer `pinUvAuthParam` cujo HMAC valide e devolve `uv = true`; é usado por `makeCredential` e por `getAssertion` sem diferenciar a operação | `crates/firmware-universal-rp2350/src/main.rs:954`, `main.rs:825`, `main.rs:843` |
| `enumerateRPsBegin` exige apenas `cm` (mais o HMAC), sem exigir ausência de RP vinculado | `crates/firmware-universal-rp2350/src/main.rs:1000` |
| `deleteCredential` exige apenas `cm` (mais o HMAC), sem comparar o RP da credencial com o RP vinculado ao token | `crates/firmware-universal-rp2350/src/main.rs:1071` |

### 1.2 O que o atacante consecgue hoje

**Pré-condições:**

1. Acesso USB local ao token (qualquer processo no mesmo host, ou uma aplicação
   maliciosa com permissão de falar CTAPHID).
2. Obtenção de um `pinUvAuthToken` **por um caminho mais privilegiado** que o
   atacante não deveria ter: por exemplo, um token emitido apenas com a
   permissão `mc`, ou emitido com `rpId = a.example` (vinculado a um RP em que
   o atacante tem legitimidade), e depois **reutilizado** fora do escopo.
3. Nenhuma precondição exige interação física adicional: basta o HMAC válido
   sobre o `clientDataHash` da requisição.

**Consequência:**

- **Escopo por operação quebrado.** Um token emitido com **apenas** `mc` (ou
  apenas `cm`) é aceito em `getAssertion`. O atacante apresenta o token como
  `pinUvAuthParam` de um `getAssertion`/`makeCredential` e o autenticador
  responde `uv = true`: a flag `UV` (`FLAG_UV`, `crates/aegis-core/src/authenticator.rs:518`)
  é gravada no `authenticatorData` e a asserção sai marcada como
  *user-verified*, embora nenhuma prova de PIN/UV tenha sido exigida para essa
  operação específica.
- **Escopo por RP quebrado.** Um token vinculado a `a.example` é aceito em
  requisições de `b.example`. A prova de UV é transportada entre *relying
  parties* sem limite: um token obtido legitimamente para `a.example` (por
  exemplo, por um app de banco que roda no mesmo host) passa a valer como
  prova de UV para `b.example`.
- **Credential management sem escopo de RP.** `deleteCredential` apaga uma
  credencial de qualquer RP usando um token vinculado a um RP diferente;
  `enumerateRPsBegin` lista **todos** os RPs do dispositivo com um token que
  deveria estar restrito a um único RP. Um token `cm` vinculado a `a.example`
  vaza a lista completa de RPs e permite apagar credenciais de terceiros.

**Por que a prova de UV precisa estar escopada:** o valor do token é
justamente *provar* que o usuário foi verificado **para esta operação** e
**para este relying party**. Sem escopo, o token degrada-se a um simples
"prova de que alguém digitou o PIN uma vez" reutilizável em qualquer contexto —
a propriedade `uv` da asserção deixa de significar o que a WebAuthn presume.
O próprio CTAP 2.1 exige: *"Verify that the pinUvAuthToken has the `mc`/`ga`
permission"* e *"If the permissions RPID does not match the `rp.id` in this
request → `CTAP2_ERR_PIN_AUTH_INVALID`"*.

---

## 2. Invariantes em risco

### De `docs/security-model.md`

- **"PIN state is persistent and fail-closed"** (`docs/security-model.md:32`):
  o token é estado PIN/UV vivo; um token que autoriza operações que não
  deveria autorizar é uma falha aberta (fail-open) no caminho PIN.
- **"Transport paths stay isolated"** (`docs/security-model.md:41`): o caminho
  FIDO deve permanecer independente; o escopo do token é parte da fronteira
  *lógica* do caminho FIDO (o token não pode atravessar contextos de RP).
- **"No secrets in logs or diagnostics"** (`docs/security-model.md:45`):
  o token é material secreto; ampliá-lo para operações/RPs não autorizados é
  ampliação de exposição, ainda que sem log.
- **Constante-tempo** (`docs/security-model.md:48`): as decisões de escopo não
  podem introduzir comparações de string timing-variáveis sobre o RP (o RP
  não é secreto; a comparação do HMAC continua constant-time).

> Observação: `docs/security-model.md` documenta hoje apenas invariantes de
> *applets*; não há seção de invariantes FIDO/PIN-UV. A correção deve incluir
> essa seção (ver §8).

### De `AGENTS.md`

- **"FIDO path independent of Management/Keyboard/CCID"** — não pode ser
  quebrado por wiring novo; a lógica de escopo fica em `aegis-core`.
- **"Recovery denies FIDO/CCID/credentials"** — o escopo do token não pode criar
  caminho de recuperação paralelo.
- **"Keep `aegis-core`/`aegis-applets` free of HAL/executor deps"** — a
  verificação de escopo é lógica pura, testável em host.
- **"Tests mandatory for new/changed logic"** — cada comportamento exigido
  abaixo vira um teste de host observável.
- **"No new `unsafe` without justification"**, **"sem dependência nova"**,
  **"legibilidade primeiro"**.
- **"Always validate after any code change"** — os gates de `fmt`, `clippy -D
  warnings` e `test` dos crates tocados são parte da entrega.

---

## 3. Escopo

### 3.1 Escopo por operação (permissão exigida)

O token ativo carrega `pin_uv_auth_permissions` (`pin.rs:394`) e o flag
`legacy_token` (`pin.rs:398`). A verificação usada por `makeCredential` e
`getAssertion` passa a exigir, além do HMAC válido:

| Operação | Permissão exigida | `legacy_token` (de `getPinToken`) |
|---|---|---|
| `authenticatorMakeCredential` | `mc` (`PERMISSION_MC`, `pin.rs:106`) | tratado como `mc` (o legado concede `mc|ga`, `pin.rs:122`) |
| `authenticatorGetAssertion` | `ga` (`PERMISSION_GA`, `pin.rs:108`) | tratado como `ga` |

Um token sem a permissão exigida **não** produz `uv = false`: a requisição
falha (§3.4).

### 3.2 Escopo por RP (`permissions RP ID`)

`pin_uv_auth_rp_id` (`pin.rs:396`) passa a ser consultado:

- **Token sem RP vinculado** (`rp_id` ausente na emissão — `pin.rs:610` recebe
  `None`): serve **qualquer** RP. É o caso do token legado e o caso de
  `getPinUvAuthTokenUsingPinWithPermissions` emitido sem `rpId`.
- **Token com RP vinculado** (`rp_id = R`): serve **apenas** requisições cujo
  `rp.id` seja exatamente `R` (comparação de string exata e case-sensitive).
  Qualquer outra requisição é recusada (§3.4).

`makeCredential` e `getAssertion` devem comparar o `rp.id` da requisição
(`MakeCredentialRequest.rp_id`, `crates/aegis-core/src/ctap2.rs:386`;
`GetAssertionRequest.rp_id`, `ctap2.rs:408`) com o RP vinculado.

### 3.3 Credential management (`cm`)

O bit `cm` (`PERMISSION_CM`, `pin.rs:110`) continua sendo requisito de
autenticação, com a semântica já existente em `allows_credential_management`
(`pin.rs:440`): token presente **e** (`legacy_token` **ou** bit `cm`). Por cima
dela, o escopo por RP passa a valer:

| Subcomando | Regra adicional |
|---|---|
| `getCredsMetadata` (`authenticator.rs:666`) | **inalterado**: não exige token hoje; nenhuma mudança de escopo nesta slice |
| `enumerateRPsBegin` (`authenticator.rs:668`, `main.rs:1000`) | exige token com capacidade `cm` **e** **sem** RP vinculado. Token com RP vinculado é recusado — a enumeração de RPs é, por natureza, global e não pode ser restringida a um RP |
| `enumerateCredentialsBegin` (`authenticator.rs:672`, `main.rs:1033`) | exige capacidade `cm`; se o token tem RP vinculado `R`, o `rpIdHash` pedido deve ser `SHA-256(R)` (`authenticator::rp_id_hash`, `authenticator.rs:944`); caso contrário é recusado |
| `deleteCredential` (`authenticator.rs:677`, `main.rs:1071`) | exige capacidade `cm`; se o token tem RP vinculado `R`, a credencial alvo (`CredentialStore::get`, `authenticator.rs:148`) deve pertencer a `R`; credencial de outro RP é recusada **e preservada** |
| `enumerateRPsGetNextRP` / `enumerateCredentialsGetNextCredential` | continuam sem autenticação própria: são continuações de um `Begin` já autenticado e escopado (`main.rs:1024`, `main.rs:1059`) |

### 3.4 Resposta quando o token não tem a permissão / o RP exigidos

**Definido explicitamente nesta spec (não fica em aberto):**

- Token ausente, HMAC inválido, permissão exigida ausente ou RP vinculado
  diferente do `rp.id` da requisição → **`CTAP2_ERR_PIN_AUTH_INVALID` (`0x33`,
  `Ctap2Status::PinAuthInvalid`, `crates/aegis-core/src/ctap2.rs:111`)**.
  É o status exigido pelo CTAP 2.1 para a divergência de *permissions RP ID*
  e é o status já usado hoje para `pinUvAuthParam` inválido
  (`main.rs:966`).
- **A operação é abortada antes de qualquer efeito**: nenhuma credencial é
  criada, nenhuma asserção é assinada, nenhuma credencial é removida, e a flag
  `UV` **não** é gravada no `authenticatorData`. O handler não pode responder
  `uv = false` como se a prova de UV tivesse sido apenas "omitida": com PIN
  configurado, a ausência de prova é `PinRequired` (`0x36`), e um token
  presente porém mal escopado é um erro de autenticação, não uma ausência
  (`main.rs:971`).
- `Ctap2Status::UnauthorizedPermission` (`0x40`, `ctap2.rs:133`) permanece
  reservado ao caminho de **emissão** do token (permissão não suportada em
  `getPinUvAuthTokenUsingPinWithPermissions`, `pin.rs:639`) e **não** é
  reutilizado para o caminho de uso.

### 3.5 Tabela de decisão (normativa)

| Token ativo | Operação | RP da requisição | Resultado |
|---|---|---|---|
| legado (`getPinToken`) | `makeCredential` | qualquer | `uv = true` |
| legado (`getPinToken`) | `getAssertion` | qualquer | `uv = true` |
| legado (`getPinToken`) | credential management | qualquer | permitido (ver §9, desvio documentado) |
| com `permissions`, sem `rpId` | `makeCredential` | qualquer | `uv = true` |
| com `permissions`, sem `rpId` | `getAssertion` | qualquer | `uv = true` |
| com `permissions`, sem `rpId` | credential management | qualquer | permitido |
| com `rpId = a.test` | `makeCredential` | `a.test` | `uv = true` |
| com `rpId = a.test` | `makeCredential` | `b.test` | `PinAuthInvalid` |
| com `rpId = a.test` | `getAssertion` | `a.test` | `uv = true` |
| com `rpId = a.test` | `getAssertion` | `b.test` | `PinAuthInvalid` |
| só `mc` | `getAssertion` | qualquer | `PinAuthInvalid` |
| só `ga` | `makeCredential` | qualquer | `PinAuthInvalid` |
| só `cm` | `makeCredential` / `getAssertion` | qualquer | `PinAuthInvalid` |
| `cm`, sem `rpId` | `enumerateRPsBegin` | — | permitido |
| `cm`, com `rpId = a.test` | `enumerateRPsBegin` | — | `PinAuthInvalid` |
| `cm`, com `rpId = a.test` | `enumerateCredentialsBegin` (`rpIdHash` de `b.test`) | — | `PinAuthInvalid` |
| `cm`, com `rpId = a.test` | `deleteCredential` (credencial de `a.test`) | — | permitido |
| `cm`, com `rpId = a.test` | `deleteCredential` (credencial de `b.test`) | — | `PinAuthInvalid`, credencial preservada |

### 3.6 Onde a decisão mora (comportamento exigido, sem inventar API)

A **decisão** precisa ser testável em host, portanto mora em `aegis-core`; o
firmware apenas fornece os dados da requisição (RP, id da credencial,
`rpIdHash`).

- `crates/aegis-core/src/pin.rs` — o `ClientPin` passa a expor o estado de
  escopo do token ativo e a verificação escopada:
  - o bit de permissão exigido para a operação;
  - o RP vinculado (`pin_uv_auth_rp_id`), quando houver;
  - a equivalência legado → `mc|ga` (mantendo `legacy_token`);
  - a comparação do RP vinculado com o `rp.id` da requisição.
  - `verify_pin_uv_auth_param` (`pin.rs:422`) **deve continuar existindo com a
    semântica atual** (verificação pura do HMAC) porque ele é a primitiva de
    baixo nível usada em outros pontos; o teste existente
    `set_pin_then_get_token_round_trips` (`pin.rs:909`) depende desse
    comportamento. O **escopo** entra por uma verificação nova, distinta, que
    combina HMAC + permissão + RP.
  - `allows_credential_management` (`pin.rs:440`) **deve continuar existindo**
    com a semântica atual (capacidade `cm`), pelo mesmo motivo (teste existente
    `token_permissions_follow_the_requested_subcommand`, `pin.rs:1304`); o
    escopo por RP é uma camada adicional.
- `crates/aegis-core/src/authenticator.rs` — a parte que depende do **store**
  (credencial → RP) fica aqui, onde já mora `CredentialStore`, `rp_id_hash`
  (`authenticator.rs:944`) e `delete_credential` (`authenticator.rs:1025`):
  - decisão de escopo de `deleteCredential` (RP da credencial vs. RP vinculado);
  - decisão de escopo de `enumerateCredentialsBegin` (`rpIdHash` pedido vs.
    RP vinculado).
- `crates/firmware-universal-rp2350/src/main.rs` — apenas *wiring*: repassar o
  `rp.id` da requisição e a permissão exigida ao núcleo, e tratar o status
  devolvido. Nenhuma decisão de segurança nova nasce no firmware.

> Nota de compatibilidade de tipos: o RP vinculado é um
> `FixedString<MAX_RP_ID_LEN>` com `MAX_RP_ID_LEN = 253` (`pin.rs:125`), enquanto
> o `rp.id` da requisição é um `FixedString<64>` (`ctap2.rs:386`, `ctap2.rs:408`).
> A comparação é por string exata; um RP vinculado com mais de 64 caracteres
> nunca casa com uma requisição — comportamento seguro (fail-closed), registrado
> em §9.

---

## 4. Não-objetivos

- `changePIN` (`crates/aegis-core/src/pin.rs:657`) — já existe e não é tocado.
- **Não** alterar a contagem de tentativas (retries) nem a política de bloqueio
  de PIN.
- **Não** alterar o protocolo PIN/UV (versão 1): formato do `pinUvAuthToken`,
  ECDH P-256, AES-256-CBC, HMAC-SHA-256 e truncamento de 16/32 bytes ficam como
  estão.
- **Não** introduzir PIN/UV bio (`getPinUvAuthTokenUsingUvWithPermissions`,
  `pin.rs:98`) nem permissões `be`/`lbw`/`acfg` (`pin.rs:111`–`pin.rs:116`).
- **Não** exigir autenticação em `getCredsMetadata` (comportamento atual
  mantido).
- **Não** adicionar autenticação própria a `enumerateRPsGetNextRP` /
  `enumerateCredentialsGetNextCredential` (continuam condicionados ao `Begin`).
- **Não** mexer no formato do token, no layout persistido do store selado nem
  em `SealedCredentialStore`.
- **Não** mudar o caminho de assinatura (`authenticator::sign_assertion`,
  `authenticator.rs:622`) nem o `authData`: a flag `UV` passa a ser gravada
  apenas quando a prova escopada é válida — o que já é verdade, só passa a ser
  garantido antes.
- **Não** introduzir `unsafe`, dependência nova, `alloc` ou dependência de HAL
  em `aegis-core`.

---

## 5. Critérios de aceitação

Cada AC é observável em teste de host no crate `aegis-core` (exceto o AC-9,
que é *wiring* de firmware).

- [ ] **AC-1 — escopo por operação:** um token com **apenas** `mc` é recusado
      em `getAssertion` (`PinAuthInvalid`) e um token com **apenas** `ga` é
      recusado em `makeCredential` (`PinAuthInvalid`). Recíproco: `mc` não
      autoriza `getAssertion` e `ga` não autoriza `makeCredential`.
- [ ] **AC-2 — escopo por RP (requisição FIDO):** um token vinculado a
      `a.test` é recusado (`PinAuthInvalid`) em requisição de `b.test`, tanto
      em `makeCredential` quanto em `getAssertion`; e aceito em `a.test`.
- [ ] **AC-3 — token sem RP vinculado:** um token emitido por
      `getPinUvAuthTokenUsingPinWithPermissions` **sem** `rpId` é aceito em
      qualquer RP (`a.test` e `b.test`), em `makeCredential` e `getAssertion`.
- [ ] **AC-4 — compatibilidade do token legado:** o token de `getPinToken`
      continua aceito em `makeCredential` e `getAssertion`, para qualquer RP
      (não tem RP vinculado) — o fluxo CTAP2.0 existente não quebra.
- [ ] **AC-5 — `enumerateRPsBegin`:** com um token que **tem** RP vinculado
      (`a.test`), o subcomando é recusado (`PinAuthInvalid`); com token `cm`
      **sem** RP vinculado, é aceito.
- [ ] **AC-6 — `deleteCredential` escopado:** com token vinculado a `a.test`,
      apagar uma credencial de `b.test` é recusado (`PinAuthInvalid`) **e a
      credencial continua no store**; apagar uma credencial de `a.test` é
      permitido.
- [ ] **AC-7 — `enumerateCredentialsBegin` escopado:** com token vinculado a
      `a.test`, pedir `rpIdHash` de `b.test` é recusado (`PinAuthInvalid`); pedir
      o `rpIdHash` de `a.test` é aceito.
- [ ] **AC-8 — permissões suportadas preservadas:** `SUPPORTED_PERMISSIONS`
      (`mc|ga|cm`, `pin.rs:119`) continua válido na emissão
      (`getPinUvAuthTokenUsingPinWithPermissions` aceita, sem
      `UnauthorizedPermission`); `permissions = 0` continua
      `InvalidParameter`; permissões fora de `SUPPORTED_PERMISSIONS` continuam
      `UnauthorizedPermission`; o `getPinToken` legado continua recusando
      `permissions`/`rpId` (`InvalidParameter`).
- [ ] **AC-9 — wiring de firmware:** `check_user_verification`
      (`main.rs:954`) distingue a permissão exigida por operação (`mc` em
      `main.rs:825`, `ga` em `main.rs:843`) e compara o RP vinculado com o
      `rp.id` da requisição; `handle_credential_management` (`main.rs:986`)
      aplica as regras de §3.3 em `enumerateRPsBegin` (`main.rs:1000`),
      `enumerateCredentialsBegin` (`main.rs:1033`) e `deleteCredential`
      (`main.rs:1071`). Verificado por build do firmware no alvo + `clippy -D
      warnings`; validação em hardware fica para a fase de validação (§9).

---

## 6. Plano de teste

### 6.1 Onde

Testes de host em `crates/aegis-core/src/pin.rs` (módulo `#[cfg(test)] mod
tests`, a partir de `pin.rs:749`), para a parte de token/permissão/RP; e em
`crates/aegis-core/src/authenticator.rs` (módulo de testes a partir de
`authenticator.rs:1035`) para a parte que depende do store (credencial → RP).
Nenhum teste novo exige HAL: o `MemoryCredentialStore` já existe
(`authenticator.rs:167`).

### 6.2 Como montar o token (reaproveitando o que já existe)

O arquivo já tem as ferramentas necessárias:

- `TestRng` (`pin.rs:753`) e `Platform` (`pin.rs:792`) — o lado plataforma;
- `set_pin_from_plaintext` (`pin.rs:818`) — provisiona o PIN;
- o bloco de `setPIN` + `getPINToken` do teste `set_pin_then_get_token_round_trips`
  (`pin.rs:852`) — decifra o token emitido (`pin.rs:901`) e calcula o
  `pinUvAuthParam` (`hmac_sha256(&token, &message)`, `pin.rs:908`);
- `token_permissions_follow_the_requested_subcommand` (`pin.rs:1273`) — o
  padrão para emitir tokens com permissões diferentes
  (`SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS`, `permissions: Some(...)`,
  `rp_id: Some(...)`);
- `token_requests_validate_the_permissions` (`pin.rs:1340`) — o padrão para as
  asserções de emissão.

Para emitir tokens com permissão/RP específicos, o teste repete o bloco de
`get_pin_token` do teste existente, trocando `sub_command` por
`SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS` e preenchendo `permissions` e
`rp_id` (`FixedString::<MAX_RP_ID_LEN>::new("a.test")`). O `pin_uv_auth_rp_id`
é gravado em `pin.rs:610` — nenhuma alteração de formato é necessária.

### 6.3 Casos de teste e AC cobertos

| Teste (nome sugerido) | AC | O que prova |
|---|---|---|
| `token_with_mc_permission_is_refused_on_get_assertion` | AC-1 | token só `mc` → `getAssertion` recusado |
| `token_with_ga_permission_is_refused_on_make_credential` | AC-1 | token só `ga` → `makeCredential` recusado |
| `token_bound_to_rp_is_refused_for_another_rp` | AC-2 | token `a.test` → `b.test` recusado; `a.test` aceito |
| `token_without_rp_binding_serves_any_rp` | AC-3 | token sem `rpId` → qualquer RP aceito |
| `legacy_token_is_accepted_by_make_credential_and_get_assertion` | AC-4 | compatibilidade CTAP2.0 |
| `enumerate_rps_requires_a_token_without_rp_binding` | AC-5 | token vinculado → recusado; sem vínculo → aceito |
| `delete_credential_is_restricted_to_the_bound_rp` | AC-6 | credencial de outro RP recusada **e preservada** |
| `enumerate_credentials_is_restricted_to_the_bound_rp` | AC-7 | `rpIdHash` de outro RP recusado |
| `supported_permissions_are_still_accepted` | AC-8 | `SUPPORTED_PERMISSIONS` aceito; zero → `InvalidParameter`; não suportadas → `UnauthorizedPermission`; legado rejeita `permissions`/`rpId` |

Complementares (não são ACs próprios, mas protegem contra regressão):
`legacy_token_still_allows_credential_management` (preserva o teste existente
`token_permissions_follow_the_requested_subcommand`, `pin.rs:1304`),
`change_pin_invalidates_token_scopes` (o `changePIN` limpa
`pin_uv_auth_token`/`permissions`/`rp_id` em `pin.rs:741`–`pin.rs:744`).

### 6.4 Comandos de gate que provam cada AC

```powershell
# AC-1..AC-8 (comportamento, crate aegis-core)
cargo test -p aegis-core pin::tests
cargo test -p aegis-core authenticator::tests

# AC-8 (emissão de token com permissões)
cargo test -p aegis-core token_permissions
cargo test -p aegis-core token_requests_validate_the_permissions

# Gates do crate tocado (obrigatórios antes de considerar concluído)
cargo fmt --all --check
cargo clippy -p aegis-core --all-targets -- -D warnings
cargo test -p aegis-core

# AC-9 (wiring de firmware): build no alvo + clippy no alvo
cargo clippy-fw
cargo build-fw-release
```

Evidência a reportar: saída de `cargo test -p aegis-core` com o número de
testes (baseline: 228 testes em `aegis-core` conforme `roadmap.md:511`) e o
número de testes novos desta slice; `clippy` limpo em host e no alvo.

---

## 7. Arquivos afetados

| Arquivo | Motivo da mudança |
|---|---|
| `crates/aegis-core/src/pin.rs` | Fonte da verdade do estado do token. Adicionar a verificação escopada (permissão por operação + RP vinculado) ao lado de `verify_pin_uv_auth_param` (`pin.rs:422`) e `allows_credential_management` (`pin.rs:440`); expor o RP vinculado e as permissões do token ativo; manter `pin_uv_auth_rp_id` (`pin.rs:396`, gravado em `pin.rs:610`) como fonte do vínculo. Testes de host no módulo `tests`. |
| `crates/aegis-core/src/authenticator.rs` | Parte da decisão que depende do store: escopo de `deleteCredential` (RP da credencial vs. RP vinculado) e de `enumerateCredentialsBegin` (`rpIdHash` vs. RP vinculado), ao lado de `delete_credential` (`authenticator.rs:1025`), `list_credentials` (`authenticator.rs:979`) e `rp_id_hash` (`authenticator.rs:944`). Testes de host no módulo de testes. |
| `crates/firmware-universal-rp2350/src/main.rs` | Wiring: `check_user_verification` (`main.rs:954`) passa a receber a permissão exigida e o `rp.id` da requisição, com call sites em `main.rs:825` (`mc`) e `main.rs:843` (`ga`); `handle_credential_management` (`main.rs:986`) aplica as regras de §3.3 em `main.rs:1000`, `main.rs:1033` e `main.rs:1071`. |
| `roadmap.md` | Fase 7 (fatia 7e/7f) — registrar a correção de segurança e o novo comportamento; ver §8. |
| `validation.md` | Matriz de AC e evidência de host; ver §8. |
| `docs/security-model.md` | Nova seção de invariantes FIDO/PIN-UV (escopo de token); ver §8. |
| `README.md` / `CONTEXT.md` | Se o comportamento observável mudar de forma relevante para o usuário (ex.: erro `PinAuthInvalid` em requisição com token de outro RP), registrar em uma linha. Opcional, mas recomendado. |

Nenhum outro crate é tocado. `aegis-applets`, `aegistoken-host` e
`board-generic-rp2350` não são afetados (isolamento do caminho FIDO).

---

## 8. Documentação

1. **`roadmap.md`** — na Fase 7 (fatias 7e/7f), acrescentar a correção:
   *"Correção de segurança: o `pinUvAuthToken` passa a ser escopado — a
   permissão exigida por operação (`mc`/`ga`) é verificada e o *permissions RP
   ID* é comparado com o `rp.id` da requisição; `enumerateRPsBegin` exige token
   sem RP vinculado e `deleteCredential`/`enumerateCredentialsBegin` ficam
   restritos ao RP vinculado"*. Registrar o número de testes de host novos e
   marcar o item de roadmap correspondente como concluído na **mesma** mudança.
2. **`validation.md`** — acrescentar uma linha na matriz de AC ou uma seção
   "evidência de host" com: método (testes de host em `aegis-core`), o que é
   coberto (AC-1..AC-8) e a limitação explícita de que a validação em hardware
   (fluxo com token de permissão/RP errada via `scripts/validate_fido.py`)
   depende de dispositivo físico. Registrar a mudança de comportamento
   observável (novo `PinAuthInvalid` em cenários antes aceitos).
3. **`docs/security-model.md`** — criar a seção ausente de invariantes
   FIDO/PIN-UV, com os itens:
   - *"O `pinUvAuthToken` é escopado: a prova de UV vale apenas para a
     operação autorizada e para o RP vinculado; token sem vínculo serve
     qualquer RP."*
   - *"Permissões ausentes ou RP divergente resultam em `PinAuthInvalid`; a
     operação é abortada antes de qualquer efeito e a flag `UV` não é
     gravada."*
   - *"O caminho FIDO permanece independente de Management, teclado e CCID;
     a verificação de escopo é lógica pura em `aegis-core`, sem HAL."*
4. **`CONTEXT.md`** — a linha de "known gaps" que hoje diz que *"Credential
   management (`enumerateRPs`/`enumerateCredentials`/`deleteCredential`) and
   `changePIN` require a PIN/UV token with the `cm` permission"* passa a
   mencionar que o token também é escopado por operação e por RP.

---

## 9. Riscos e limitações

1. **Clientes CTAP2.0 legados.** O token de `getPinToken` permanece aceito em
   `makeCredential`/`getAssertion` (AC-4) e continua **sem** vínculo de RP, para
   não quebrar clientes que não pedem permissões. Consequência: a proteção de
   escopo por RP só existe para tokens emitidos por
   `getPinUvAuthTokenUsingPinWithPermissions` com `rpId` — o cliente legado
   continua gerando token "universal". Isso é o comportamento do CTAP 2.1
   (o token legado é o único modo de compatibilidade), mas deve constar da
   documentação de segurança.
2. **Desvio CTAP2.1 no caminho legado de credential management.** Hoje
   `allows_credential_management` aceita o token legado (`pin.rs:442`) e
   existe teste cobrindo isso (`pin.rs:1304`). O CTAP 2.1 estrito exigiria
   `cm` explícito. **Decisão desta spec: manter o comportamento atual** (o PIN
   já foi provado) e registrá-lo como desvio documentado em
   `docs/security-model.md`; mudá-lo é uma slice própria, com impacto de
   compatibilidade, e não é objetivo aqui.
3. **Ausência de hardware para validação em dispositivo.** Não há RP2350
   físico disponível no ciclo atual: os ACs são cobertos por testes de host;
   o wiring (AC-9) é coberto por build + `clippy` no alvo
   (`cargo clippy-fw`, `cargo build-fw-release`) e a validação de ponta a ponta
   (token com permissão/RP errada contra o firmware flashed) fica pendente
   para a fase de validação em hardware. `scripts/validate_fido.py` é o
   candidato natural para exercitar o novo comportamento em dispositivo.
4. **Interação com `authenticatorGetNextAssertion` (implementação paralela).**
   `getNextAssertion` (`main.rs:882`) reusa o estado de UV já decidido no
   `getAssertion` (`AssertionState.uv`, `main.rs:870`) e **não** revalida o
   token. Consequência: o escopo é decidido **uma vez**, no `getAssertion` que
   iniciou a sequência — que é o comportamento correto do CTAP 2.1 (a
   sequência é uma continuação do mesmo comando). Esta spec **não** altera
   `getNextAssertion` nem `AssertionState`; se a implementação paralela mexer em
   `main.rs:870`/`main.rs:882`, a coordenação é: **a decisão de escopo fica
   exclusivamente em `check_user_verification` + núcleo**; `getNextAssertion`
   continua consumindo o `uv` já decidido. Nenhuma mudança de layout de
   `AssertionState` é exigida por esta slice.
5. **`FixedString<64>` vs. `MAX_RP_ID_LEN = 253`.** Um RP vinculado com mais de
   64 caracteres nunca casa com o `rp.id` de uma requisição (que é
   `FixedString<64>`, `ctap2.rs:386`): fail-closed, sem risco, mas registrado
   como assimetria a observar caso o limite de 64 bytes seja ampliado.
6. **Escopo por operação em `makeCredential`/`getAssertion` continua binário.**
   O token não distingue "criar credencial" de "criar credencial *com UV*":
   `mc` cobre ambos. A CTAP 2.1 não faz essa distinção também.
7. **Interação com a opção `uv` do cliente.** Quando o cliente pede `uv = true`
   e não envia `pinUvAuthParam`, o caminho atual responde `PinRequired`
   (`main.rs:971`). Essa semântica **não muda**; a spec só endurece o caminho
   em que o `pinUvAuthParam` é presente.
8. **Risco de compatibilidade de plataforma.** Some WebAuthn clients pedem
   `getPinUvAuthTokenUsingPinWithPermissions` com `permissions = mc|ga` e
   `rpId` do RP corrente — compatíveis. Clientes que pedem `cm` **com** `rpId`
   pasan a receber `PinAuthInvalid` em `enumerateRPsBegin` (AC-5): é o
   comportamento exigido pelo CTAP 2.1, mas pode falhar em clientes que
   pedem `cm` com `rpId` e depois enumeram RPs. Mudança de comportamento deve
   ser comunicada em `validation.md` e `README.md`.
9. **Sem cobertura em `aegis-applets`/`aegistoken-host`.** Nada a fazer: o
   escopo é exclusivo do caminho FIDO, e os applets não compartilham o estado
   do token.

---

## 10. Itens deliberadamente adiados (fora desta fatia)

Uma segunda especificação de token (`specs/ctap2-token-scope.md`, escrita em
paralelo por outra sessão do loop) é **mais estrita** que esta e exige alguns
comportamentos que aqui são não-objetivos explícitos (§4 e §9.2). Para não
duplicar trabalho nem misturar escopos, os itens abaixo ficam registrados como
fatias futuras, a serem executadas pelo loop com spec e gates próprios:

| Item | Origem | Por que fica para depois |
|---|---|---|
| Token legado (`getPinToken`) deixa de autorizar credential management | §9.2 (desvio CTAP 2.1) | mudança de comportamento com impacto de compatibilidade; precisa de slice e matriz de validação próprias |
| Redução das permissões do token após a presença do usuário | spec paralela | não é exigido pelo CTAP 2.1 nesta altura |
| `authenticatorReset` invalida o token e o escopo | spec paralela | `authenticatorReset` ainda não é aplicado no firmware (Fase 7 pendente) |
| `getCredsMetadata` passa a exigir autenticação | spec paralela | comportamento atual mantido aqui (§4) |
| Vinculação de RP no primeiro uso do token | spec paralela | o vínculo continua sendo o emitido no token |
| `scripts/validate_fido.py` exercita os casos negativos em hardware | §9.3 | exige dispositivo físico; validador atual só usa o token legado |

A decisão do orquestrador foi: **implementar esta spec como fatia fechada e
auditável** (9 ACs, testes de host + wiring de firmware) e tratar a spec
paralela como fonte de itens para as próximas fatias do loop.

**Atualização:** a fatia **7g** (implementada a partir de
`specs/ctap2-token-scope.md`) entregou os itens acima com uma política **mais
estrita** que a desta spec: o token legado deixou de autorizar credential
management, o primeiro uso vincula o token ao RP, uma operação com presença
bem-sucedida descarta as permissões do token, `authenticatorReset` o invalida e
`getCredsMetadata` passa a exigir token com `cm`. O código de `aegis-core`
reflete hoje a política da 7g; esta spec permanece no histórico como o
registro do escopo mínimo originalmente implementado, e as diferenças
deliberadas estão descritas em `validation.md` (Fase 7g) e em
`docs/security-model.md`.
