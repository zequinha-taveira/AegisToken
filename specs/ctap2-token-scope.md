# Spec — Escopo e ciclo de vida do `pinUvAuthToken` (CTAP2.1)

**Origem:** roadmap.md, fatia 7e — "Limitações registradas" (roadmap.md:481-487) e validation.md, seção "Limitações conhecidas" (validation.md:524) · **Risco:** ALTO

Referência normativa: **CTAP 2.1 — Client to Authenticator Protocol**, FIDO Alliance, *Proposed Standard, June 15, 2021* (`fido-v2.1-ps-20210615`). Todas as citações textuais abaixo são dessa versão.

## Ameaça

O `pinUvAuthToken` é a credencial que a plataforma apresenta para provar PIN/UV. Hoje o
firmware trata o token como um segredo opaco: ele é verificado por HMAC
(`ClientPin::verify_pin_uv_auth_param`, `crates/aegis-core/src/pin.rs:422-431`) e nada
mais. O *permissions RP ID* emitido com o token (`ClientPin::pin_uv_auth_rp_id`,
`crates/aegis-core/src/pin.rs:396`, gravado em `get_pin_token`,
`crates/aegis-core/src/pin.rs:610`) **nunca é lido** — nenhuma verificação o consulta.

Consequências no estado atual:

1. **Um token emitido para um RP vale para qualquer RP.** As permissões `mc`/`ga` são
   *por RP* na CTAP2.1: o token tem que carregar o `permissions RP ID` do RP da operação.
   Hoje `makeCredential`/`getAssertion` aceitam um token válido de qualquer RP, e o
   `permissions RP ID` emitido é apenas decorativo.
2. **Um token `mc|ga` (ou legado) também pode gerir credenciais de qualquer RP.**
   `ClientPin::allows_credential_management` (`crates/aegis-core/src/pin.rs:440-443`)
   só olha o bit `cm` (e a herança do `getPinToken`), sem escopo de RP. O despacho do
   firmware (`handle_credential_management`,
   `crates/firmware-universal-rp2350/src/main.rs:1002-1107`) chama
   `verify_credential_management_param` (`crates/aegis-core/src/pin.rs:450-452`) sem
   qualquer informação de RP: um token com `cm` emitido para `banco.example` pode
   enumerar e **apagar** credenciais de `outro.example`.
3. **O token não perde permissões após uma operação com User Presence.** A CTAP2.1
   determina a redução do conjunto de permissões; hoje o token mantém `cm` (e `mc`/`ga`)
   depois de `makeCredential`/`getAssertion`, que exigem presença. Um token vazado ou
   reutilizado continua autorizando credential management indefinidamente.

Exploração: uma plataforma maliciosa (ou malware com acesso USB) obtém **um** token com
`cm` — ou o token legado de `getPinToken` — e passa a enumerar/apagar credenciais de
todas as RPs do dispositivo, ou reutiliza um token para operar em nome de uma RP que
nunca o solicitou. O impacto é integridade e confidencialidade de credenciais
(`deleteCredential`, `enumerateCredentials` devolvem `user id` e chave pública).

## Invariantes em risco

- **Autorização por operação, não apenas por posse do segredo.** Um `pinUvAuthToken`
  deve autorizar apenas as operações para as quais a permissão foi concedida e apenas
  para o RP ao qual está vinculado (`docs/security-model.md`, seção "Applet security
  invariants" — o mesmo princípio de escopo vale para o caminho FIDO).
- **Princípio de privilégio mínimo.** O token concede o mínimo necessário: `mc`, `ga` e
  `cm` são permissões distintas (`crates/aegis-core/src/pin.rs:106-110`), e cada uma
  tem escopo próprio.
- **Isolamento de caminhos.** O caminho FIDO permanece independente de Management/CCID
  (AGENTS.md, "Rules"); esta fatia não toca nessas rotas.
- **Segredos selados em repouso.** O estado do token vive em RAM (`FidoSession.client_pin`,
  `crates/firmware-universal-rp2350/src/main.rs:609-616`); o banco de credenciais segue
  selado em AES-256-GCM sob a chave de OTP
  (`crates/aegis-core/src/credential_store.rs:43-77`) — esta fatia não altera o formato
  do store.

## Escopo

1. **Vínculo do token ao RP (`permissions RP ID`).** O `permissions RP ID` passa a ser
   lido e comparado. Referência CTAP2.1:
   - §6.5.5.7 (tabela de permissões): `mc` → coluna RP ID **"Required"**; `ga` → **"Required"**; `cm` → **"Optional"**, com a nota "The rpId parameter is optional, if it is present, the pinUvAuthToken can only be used for Credential Management operations on Credentials associated with that RP ID."
   - §6.1.2 (`makeCredential`): "Verify that the pinUvAuthToken has the `mc` permission, if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID." e "If the pinUvAuthToken has a permissions RP ID associated: If the permissions RP ID does not match the rp.id in this request, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID."
   - §6.2.2 (`getAssertion`): "Verify that the pinUvAuthToken has the `ga` permission, if not, return CTAP2_ERR_PIN_AUTH_INVALID." e "If the permissions RP ID does not match the rpId in this request, return CTAP2_ERR_PIN_AUTH_INVALID."
2. **Token com `mc`/`ga` emitido sem `rpId`:** §6.5.5.7.2 lista `rpId` como
   "Required for some permissions, optional for others" (a tabela de
   permissões marca `mc`/`ga` como "Required" e `cm` como "Optional"), mas os
   procedimentos do autenticador **não** tratam a ausência de `rpId` como
   erro; a nota de §6.5.5.7 diz: "if default permissions are used, it is
   possible that the permissions RP ID is not set even though it is required
   for some of the permissions. It will be set on first use of the
   pinUvAuthToken with an RP ID (for mc and ga only)". A fatia adota essa
   regra: token com `mc`/`ga` e **sem** `rpId` é aceito e o RP do primeiro uso
   passa a ser o `permissions RP ID` do token.
3. **Escopo de `cm` no credential management.** §6.8.2 (`getCredsMetadata`) e §6.8.3
   (`enumerateRPs`): "The authenticator verifies that the pinUvAuthToken has the `cm`
   permission and no associated permissions RP ID. If not, return CTAP2_ERR_PIN_AUTH_INVALID."
   §6.8.4 (`enumerateCredentials`): "The authenticator verifies that the pinUvAuthToken has
   the `cm` permission and that the pinUvAuthToken does not have an permissions RP ID
   associated or that the pinUvAuthToken permissions RP ID matches the RP ID of this
   request. If not, return CTAP2_ERR_PIN_AUTH_INVALID."
   §6.8.5 (`deleteCredential`): "... or that the pinUvAuthToken permissions RP ID matches the
   RP ID of the credential. If not, return CTAP2_ERR_PIN_AUTH_INVALID."
4. **Redução das permissões após operação com User Presence.** §6.5.5.7: "When a
   pinUvAuthToken is used with an operation that tests user presence, it is updated to
   remove all permissions except lbw. If lbw was not originally requested then the
   pinUvAuthToken becomes permission-less and cannot be used for future operations.
   However, the platform can fetch a fresh pinUvAuthToken in order to perform any future
   operations." Como `lbw` não é suportado (`SUPPORTED_PERMISSIONS`,
   `crates/aegis-core/src/pin.rs:119`), o token fica **sem permissões**.
5. **Regra única para o token legado.** §6.5.5.7 (nota): "if default permissions are used,
   it is possible that the permissions RP ID is not set even though it is required for some
   of the permissions. It will be set on first use of the pinUvAuthToken with an RP ID (for
   mc and ga only)."
6. **Ciclo de vida do token:** `changePIN` já invalida o token
   (`crates/aegis-core/src/pin.rs:740-744`) e passa a continuar invalidando **permissões e
   `permissions RP ID`**; `authenticatorReset` passa a invalidar o token ativo (hoje o
   `authenticatorReset` limpa o store e o estado de PIN — `authenticator::reset`,
   `crates/aegis-core/src/authenticator.rs:653-663` — mas o token em RAM sobrevive).
7. **`getCredsMetadata` passa a exigir token** (hoje o despacho responde sem qualquer
   autenticação — `crates/firmware-universal-rp2350/src/main.rs:1013-1015`), conforme
   §6.8.2.

### Regra única para o token legado (`getPinToken`, subcomando 0x05)

**Escolha: o token legado concede apenas `mc|ga` (0x03) e nunca autoriza credential
management.**

Justificativa:

- §6.8.2/§6.8.3/§6.8.4/§6.8.5 exigem explicitamente a permissão `cm`; um token emitido
  por `getPinToken` (0x05) não tem como ter `cm`, porque o subcomando é *superseded* e
  rejeita os parâmetros `permissions`/`rpId` (`crates/aegis-core/src/pin.rs:626-631`).
- O comando `authenticatorCredentialManagement` (0x0A) **não existe no CTAP2.0**; ele
  foi introduzido no CTAP2.1. O dispositivo anuncia `FIDO_2_0` (não `FIDO_2_1`) e não
  implementa o `credentialMgmtPreview` (0x41) do CTAP2.0 — logo, não há interop real a
  preservar ao tratar o token legado comoporting de `cm`.
- O caminho legado permanece útil para `mc`/`ga`: o `permissions RP ID` é vinculado no
  primeiro uso (nota de §6.5.5.7 citada acima), exatamente como a especificação prevê.

Consequência prática: `getPinToken` (0x05) seguido de credential management responde
`CTAP2_ERR_PIN_AUTH_INVALID` (0x33). O caminho oficial é
`getPinUvAuthTokenUsingPinWithPermissions` (0x09) com a permissão `cm`.

## Não-objetivos

- `updateUserInformation` (0x07) e `largeBlobKey` (0x0B) continuam **fora** (não
  implementados; ver roadmap.md:483-485).
- O firmware continua **não anunciando `FIDO_2_1`**: nenhuma opção nova de `getInfo`,
  nenhum `bioEnroll`, `largeBlobs`, `authenticatorConfig` ou `authenticatorSelection`.
- `getPinUvAuthTokenUsingUvWithPermissions` (0x06) continua fora (não há UV embutida);
  `SUB_GET_UV_TOKEN_WITH_PERMISSIONS` permanece declarado mas não implementado
  (`crates/aegis-core/src/pin.rs:97-98`).
- **Sem expiração por temporizador**: o `usage timer` / `max usage time period`
  (§6.5.2.1) não é implementado — o token vive enquanto a sessão CTAPHID viver.
- **Sem PIN/UV auth protocol 2** (continua apenas v1, `crates/aegis-core/src/pin.rs:103`).
- Nenhuma mudança de layout/criptografia no `SealedCredentialStore`
  (`crates/aegis-core/src/credential_store.rs`): o `permissions RP ID` do token é estado
  de RAM, não do store selado.
- RSA-3072/PSS permanecem fora de escopo (`docs/security-model.md:47-56`).
- Nenhuma mudança na CLI de host (`crates/aegistoken-host`) nem no Management HID.

## Critérios de aceitação

- [ ] **AC1:** `getPinUvAuthTokenUsingPinWithPermissions` (0x09) com `permissions`
  contendo `mc` **ou** `ga` e **sem** `rpId` (chave 0x0A) é **aceito**: o token
  sai sem `permissions RP ID` e o RP do primeiro uso passa a ser vinculado
  (nota de §6.5.5.7). As rejeições que continuam valendo: `permissions = 0` →
  `CTAP1_ERR_INVALID_PARAMETER` (0x02); permissão não suportada (`be`, `lbw`,
  `acfg`) → `CTAP2_ERR_UNAUTHORIZED_PERMISSION` (0x40).
- [ ] **AC2:** 0x09 com `permissions = cm` e **sem** `rpId` emite token com a
  permissão `cm` e **sem** `permissions RP ID` associado; nesse caso
  `getCredsMetadata` (0x01) e `enumerateRPsBegin` (0x02) — que exigem `cm` **e**
  ausência de `permissions RP ID` (§6.8.2/§6.8.3) — são aceitos. 0x09 com
  `permissions = cm` e **com** `rpId` emite token com `cm` e com o `rpId`
  associado; nesse caso os mesmos subcomandos são recusados (ver AC9).
- [ ] **AC3:** `getPinToken` (0x05) emite token com `mc|ga` (0x03) e **sem**
  `permissions RP ID`; esse token **não** autoriza credential management em nenhuma
  hipótese (ver AC8).
- [ ] **AC4:** `makeCredential` com `pinUvAuthParam` válido, mas token **sem** a
  permissão `mc` (ex.: token só com `cm` ou `ga`), é rejeitado com
  `CTAP2_ERR_PIN_AUTH_INVALID` (0x33) — hoje é aceito.
- [ ] **AC5:** `getAssertion` com `pinUvAuthParam` válido, mas token **sem** a permissão
  `ga`, é rejeitado com 0x33.
- [ ] **AC6:** `makeCredential`/`getAssertion` com token cujo `permissions RP ID` é
  **diferente** do `rp.id`/`rpId` da requisição são rejeitados com 0x33 (nenhum RP
  cruzado).
- [ ] **AC7:** `makeCredential`/`getAssertion` com token **sem** `permissions RP ID`
  associado (token legado, AC3) vincula o `rp.id`/`rpId` da primeira operação como
  `permissions RP ID` do token; uma segunda operação para **outro** RP com o mesmo token
  é rejeitada com 0x33.
- [ ] **AC8:** Todo subcomando de credential management (`getCredsMetadata` 0x01,
  `enumerateRPsBegin` 0x02, `enumerateCredentialsBegin` 0x04, `deleteCredential` 0x06)
  exige token com a permissão `cm`: token sem `cm` — **inclusive o token legado** — é
  rejeitado com 0x33; ausência de `pinUvAuthParam` responde
  `CTAP2_ERR_PUAT_REQUIRED` (0x36).
- [ ] **AC9:** `getCredsMetadata` (0x01) e `enumerateRPsBegin` (0x02) com token que **tem**
  `permissions RP ID` associado são rejeitados com 0x33 (esses subcomandos listam todos
  os RPs e não podem ser escopados).
- [ ] **AC10:** `enumerateCredentialsBegin` (0x04) com token que **tem** `permissions RP ID`
  associado é aceito **somente** se o `rpIDHash` da requisição
  (`CredentialManagementRequest::rp_id_hash`,
  `crates/aegis-core/src/authenticator.rs:687`) for o SHA-256 do `permissions RP ID` do
  token (via `authenticator::rp_id_hash`, `crates/aegis-core/src/authenticator.rs:944`);
  caso contrário → 0x33.
- [ ] **AC11:** `deleteCredential` (0x06) com token que **tem** `permissions RP ID`
  associado é aceito **somente** se a credencial alvo (`CredentialManagementRequest::credential_id`,
  `crates/aegis-core/src/authenticator.rs:685`) pertencer ao mesmo RP (o RP vem do store,
  `Credential::rp_id`, `crates/aegis-core/src/authenticator.rs:53`); caso contrário → 0x33
  e **nenhuma** credencial é removida.
- [ ] **AC12:** Após uma `makeCredential` ou `getAssertion` **bem-sucedida** que testou
  User Presence usando o token, o token fica **sem permissões** (`mc`, `ga` e `cm`
  removidos; `lbw` nunca foi concedido) e o `permissions RP ID` deixa de valer. Qualquer
  uso posterior do mesmo token (em `makeCredential`, `getAssertion` ou credential
  management) é rejeitado com 0x33.
- [ ] **AC13:** A redução de permissões (AC12) ocorre **somente** quando a operação que
  testou presença conclui com sucesso e **usou** o token; uma operação que termina em
  erro (`NoCredentials`, `CredentialExcluded`, `UpRequired`) ou que não usa
  `pinUvAuthParam` mantém as permissões do token intactas.
- [ ] **AC14:** `changePIN` bem-sucedido continua invalidando o token: o token anterior
  é rejeitado com 0x33 e nenhum `permissions RP ID` permanece associado
  (regressão de `crates/aegis-core/src/pin.rs:740-744`).
- [ ] **AC15:** `authenticatorReset` invalida o token ativo: após o reset, o token
  anterior é rejeitado com 0x33 (hoje sobrevive em RAM, porque `FidoSession.client_pin`
  — `crates/firmware-universal-rp2350/src/main.rs:609-616` — não é limpo no caminho de
  reset).

## Plano de teste

Todos os AC são verificáveis em host, no crate `aegis-core` (`no_std`/`no_alloc`,
testável), sem HAL:

- `crates/aegis-core/src/pin.rs` (módulo `tests`, a partir de
  `crates/aegis-core/src/pin.rs:749`): estado do token, emissão e escopo.
  - AC1/AC2/AC3: emissão com/sem `rpId`, com `mc`, `ga`, `cm`; rejeição de `mc`/`ga` sem
    `rpId`.
  - AC12/AC13/AC14/AC15: redução de permissões após operação com UP, manutenção em
    operação com erro, invalidação por `changePIN` e por reset.
- `crates/aegis-core/src/authenticator.rs` (módulo `tests`, a partir de
  `crates/aegis-core/src/authenticator.rs:1035`) + `crates/aegis-core/src/pin.rs`:
  autorização por operação e por escopo de RP (AC4–AC11), combinando `ClientPin` com
  `MemoryCredentialStore` (`crates/aegis-core/src/authenticator.rs:167`) para resolver o
  RP da credencial alvo no `deleteCredential`.
- Testes existentes que **precisam** ser atualizados (a mudança é intencional):
  `token_permissions_follow_the_requested_subcommand`
  (`crates/aegis-core/src/pin.rs:1273`) — hoje afirma que o token legado autoriza
  credential management; e `token_requests_validate_the_permissions`
  (`crates/aegis-core/src/pin.rs:1340`) — deve ganhar o caso `mc`/`ga` sem `rpId`.
- **Gates:**
  ```powershell
  cargo fmt --all --check
  cargo clippy -p aegis-core --all-targets -- -D warnings
  cargo test -p aegis-core
  cargo build-fw        # o despacho do firmware muda
  cargo clippy-fw
  ```
- **Gate de hardware (procedimento, pendente de dispositivo físico):**
  `python scripts/validate_fido.py --pin <PIN>` — o validador já cobre
  `getPinUvAuthTokenUsingPinWithPermissions` com `cm` e a enumeração
  (`scripts/validate_fido.py:196-227`); deve ser estendido com os casos negativos
  (token com `cm` + `rpId` → `enumerateRPs` recusado; token `mc` usado em `getAssertion`
  de outro RP → 0x33).

## Arquivos afetados

- `crates/aegis-core/src/pin.rs`: estado do token (`pin_uv_auth_permissions`,
  `pin_uv_auth_rp_id`, `legacy_token`, `crates/aegis-core/src/pin.rs:390-399`),
  validação da emissão (`requested_permissions`, `crates/aegis-core/src/pin.rs:624-645`),
  verificação do `pinUvAuthParam` com permissão + RP
  (`verify_pin_uv_auth_param`, `crates/aegis-core/src/pin.rs:422-431`), autorização de
  credential management (`allows_credential_management` /
  `verify_credential_management_param`, `crates/aegis-core/src/pin.rs:440-452`) e a
  redução de permissões após User Presence. Toda a decisão de autorização fica **em
  `aegis-core`**; o firmware só despacha.
- `crates/firmware-universal-rp2350/src/main.rs`: despacho —
  `check_user_verification` (`crates/firmware-universal-rp2350/src/main.rs:963-988`) passa a
  informar a permissão exigida (`mc`/`ga`) e o RP da requisição; `handle_credential_management`
  (`crates/firmware-universal-rp2350/src/main.rs:1002-1107`) passa a informar o RP
  efetivo (`rpIDHash` do pedido ou RP da credencial alvo) e a exigir `cm`; o caminho de
  `authenticatorReset` passa a limpar o token da `FidoSession`
  (`crates/firmware-universal-rp2350/src/main.rs:609-616`).
- `crates/aegis-core/src/authenticator.rs`: sem mudança de API obrigatória — a resolução do
  RP da credencial reutiliza `CredentialStore::get`
  (`crates/aegis-core/src/authenticator.rs:148`), `Credential::rp_id`
  (`crates/aegis-core/src/authenticator.rs:53`) e `rp_id_hash`
  (`crates/aegis-core/src/authenticator.rs:944`).
- `crates/aegis-core/src/credential_store.rs`: **sem alteração** (o estado do token não é
  persistido; o banco continua selado em AES-256-GCM).
- `scripts/validate_fido.py`: extensão opcional dos casos negativos (gate de hardware).

## Documentação

- `roadmap.md`: atualizar a fatia 7e, "Limitações registradas" (roadmap.md:481-487) —
  a nota "O par RP/credencial da plataforma é verificado pela permissão `cm` e, para
  tokens com `rpId` associado, apenas o escopo do RP é considerado" deixa de ser
  limitação e passa a ser comportamento verificado.
- `validation.md`: registrar a evidência (testes de host novos + gate
  `validate_fido.py` em hardware, quando houver dispositivo) na seção das fases 7e
  (validation.md:430) e em "Limitações conhecidas" (validation.md:524).
- `docs/security-model.md`: acrescentar o invariante "o `pinUvAuthToken` autoriza apenas
  as permissões concedidas e apenas o RP vinculado" na seção de invariantes.
- `README.md`: apenas se a descrição do fluxo `clientPIN` mudar (hoje não detalha
  permissões).

## Riscos e limitações

- **Interoperabilidade CTAP2.0.** Remover a herança de `cm` para o token legado quebra
  plataformas que usem `getPinToken` (0x05) antes de credential management. O comando de
  credential management (0x0A) é CTAP2.1 e o dispositivo anuncia `FIDO_2_0`, então o
  risco é prático baixo — mas é a mudança de comportamento mais visível desta fatia.
- **Sem expiração por tempo.** O `usage timer` (§6.5.2.1) continua não implementado: um
  token emitido permanece válido enquanto a sessão CTAPHID viver, desde que não seja
  usado numa operação com presença. A mitigação é o vínculo de RP e a redução de
  permissões.
- **Divergência de semântica em operação com falha.** A CTAP2.1 não diz se a redução de
  permissões (AC12) também ocorre quando a operação com presença falha. Optou-se por
  só reduzir em caso de sucesso (AC13), para não punir retentativas legítimas da
  plataforma (ex.: `excludeList`). Autenticadores que reduzem em qualquer caso são
  mais restritivos — este é um ponto de divergência que deve ser documentado.
- **`rpId` ausente em token com `mc`/`ga`.** A tabela de permissões (§6.5.5.7)
  marca o `rpId` como obrigatório para `mc`/`ga` — obrigação da plataforma —, mas
  os procedimentos do autenticador não tratam a ausência como erro e a nota de
  §6.5.5.7 manda vincular o RP no primeiro uso. A fatia segue a nota (vincula no
  primeiro uso) em vez de recusar a emissão: recusar quebraria plataformas que
  pedem `mc`/`ga` sem `rpId` (por exemplo `python-fido2` com
  `get_pin_token(pin, permissions=MAKE_CREDENTIAL)`).
- **`getCredsMetadata` passa a exigir autenticação.** O despacho atual não exige nada
  (contagem de credenciais residentes era informação sem autenticação). Clientes que não
  enviam `pinUvAuthParam` para 0x01 passam a receber 0x36 — o `python-fido2` sempre
  envia; outros clientes precisam ser verificados.
- **Ordem entre verificação e operação.** A verificação de permissão/RP deve ocorrer
  **antes** de esperar User Presence, para não gastar a presença do usuário em uma
  requisição que será rejeitada (o despacho atual já verifica UV antes de
  `wait_presence_notifying`, `crates/firmware-universal-rp2350/src/main.rs:824-838`).
- **Estado do token em RAM.** O token vive no `FidoSession`; um `CTAPHID_INIT`/reabertura
  de sessão ou um power cycle zera o estado — comportamento aceito (o estado do token
  não é persistido por definição).
- **Risco residual de descrição de credencial.** `enumerateCredentials` devolve `user id`
  e chave pública das credenciais do RP autorizado; com a permissão `cm` + `rpId` o
  escopo é o RP, o que é o comportamento exigido pela CTAP2.1 (§6.8.4).
