# Spec — OATH leitura fail-closed: store ilegível fecha o applet (`6F00`, `SELECT` retenta)

> **Origem:** achado do `sec-audit` (loop de hardening de segurança) e follow-up
> explícito **não-objetivo 1** da fatia irmã `specs/oath-reset-fail-closed.md`
> ("`load_state` tratando erro de leitura como estado vazio — informacional
> adjacente, fatia própria"), também registrado como pendência da Fase 13 em
> `roadmap.md` e como resíduo **L4** daquela spec. Achado informacional na
> triagem, mas **fail-open real**: o efeito é permissivo, então a direção é
> fail-closed. HEAD de referência: `ae17160`.
> **Risco:** MÉDIO — a leitura da store selada não distingue "vazio" de
> "ilegível"; qualquer erro de integridade/IO é convertido em "sem estado" e o
> applet passa a atender com `auth_key` vazio, o que **desliga o access code em
> silêncio** e deixa um `PUT` sobrescrever o blob que não foi lido. O gatilho é
> físico (`docs/security-model.md`, "Hardware trust boundary": flash doente e
> tamper estão fora do modelo de ameaça vivo) e não há caminho remoto, por isso
> MÉDIO e não ALTO/CRÍTICO — mas a garantia quebrada é a do access code, o
> invariante mais forte do applet, e o custo de correção é baixo. Fatia única,
> fechada, em `aegis-applets`; todos os ACs são de host (a indução de falha de
> flash em hardware não é exercida neste ciclo — pendência em `validation.md`).

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

- **O contrato de leitura não tem lado de falha.** `trait OathStore` declara
  `fn load(&mut self, out: &mut [u8]) -> Option<usize>` (`oath.rs`) sem dizer o
  que `None` significa. `MemoryOathStore::load` devolve `None` quando não há
  estado **e** quando o buffer é pequeno; `SealedOathStore::load` é
  `self.inner.load(out).ok()?` (`sealed.rs`), isto é, **colapsa
  `Err(CoreError::StorageError)` em `None`** exatamente como um registro em
  branco. O `SealedBlob::load` já distingue os dois casos: `Ok(None)` quando não
  existe nenhum registro de commit (região virgem ou tombstone de `clear`) e
  `Err` quando há commit mas nenhuma geração completa é reassemblável (shard
  corrompido, não decifrável, nonce fora do domínio, falha de IO em
  `SecretStorage::read_slot`). A distinção existe e é **descartada** no
  adaptador.
- **`load_state` marca "carregado" mesmo quando não carregou nada.**
  `Oath::load_state` (`oath.rs`) faz `self.loaded = true;` **antes** de tentar
  ler; em `None` retorna sem tocar em `credentials`/`auth_key`. O applet segue
  atendendo com o estado que estiver na RAM — no primeiro `SELECT` após o boot,
  o estado de `Oath::new` (`credentials` vazio, `auth_key` vazio,
  `authenticated = false`), que é indistinguível de "usuário sem access code".
- **O resultado do decoder também é descartado.** Ainda em `load_state`,
  `let _ = self.decode_state(&encoded[..len]);`. Um blob **legível mas
  inválido** (versão desconhecida, contagem fora do domínio, corpo truncado)
  retorna `false` e o applet continua aberto com o que o decoder já tiver
  escrito — e `decode_state` limpa `credentials` e `auth_key` **antes** de
  parsear, então o resultado de uma falha parcial é um prefixo de credenciais
  com `auth_key` vazio. O fail-open não é só de IO: é de integridade também.
- **`auth_key` vazio é o lado permissivo.** `Oath::require_auth` devolve `Ok`
  quando `self.auth_key.is_empty() || self.authenticated`. Com a leitura
  falhando, `LIST`, `CALCULATE`, `CALCULATE ALL`, `PUT`, `DELETE` e `SET CODE`
  passam sem autenticação; `VALIDATE` responde `Sw::AUTH_NOT_ENABLED` (`6984`)
  em vez de recusar, o que o host lê como "não há access code configurado".
- **`PUT` sobrescreve o blob não lido.** `Oath::put` → `require_auth` (libera) →
  altera a RAM → `save_state`, que serializa `credentials` + `auth_key`
  (`auth_present = !auth_key.is_empty()`). O blob anterior — com as credenciais
  e o access code reais — é substituído por um blob sem access code. A falha de
  leitura vira **remoção silenciosa e não autenticada da autoridade**, além de
  destruição das credenciais que estavam persistidas.
- **O `SELECT` seguinte é o único ponto de nova tentativa, e ele também mente.**
  `Applet::select`/`select_with_rng` zeram `loaded` e chamam `load_state`; em
  falha, `select_response` responde `9000` com o FCI e — se a RAM ainda tiver um
  `auth_key` de uma seleção anterior — emite `TAG_CHALLENGE`/`0x7B` de um
  challenge que não é o persistido. Qualquer pilha PC/SC reseleciona o AID por
  operação, então "power cycle" aqui é um `SELECT`.
- **O PIV falha fechado na condição análoga; o OpenPGP tem outro modelo.**
  `Piv::select_response` chama `load_state()` e, em `false`, responde
  `Sw::NO_PRECISE_DIAGNOSIS` (`6F00`) **no próprio `SELECT`**. O OpenPGP não
  fecha: `OpenPgp::ensure_loaded`, em leitura/decodificação falha, **reprovisiona
  os defaults** (PW1 `123456`, PW3 `12345678`, piso da sessão) e grava, e o
  `select` responde `9000`. Esse modelo não transfere para o OATH: o default do
  OpenPGP é **restritivo** (PINs de interop existem e são exigidos), enquanto o
  "vazio" do OATH **não tem access code** — e o OATH não tem credencial de
  fábrica para reprovisionar; o conteúdo é segredo do usuário. Copiar o
  comportamento do OpenPGP aqui seria fabricar exatamente o estado permissivo.
- **Nenhum teste cobre a falha.** A suíte OATH usa `MemoryOathStore` (nunca
  falha) e, desde a fatia do `RESET`, `FailingOathStore` — que já tem
  `set_clear_fails`, `set_save_fails` e contadores `clears()`/`saves()`/
  `loads()`, mas **não tem falha de `load`** (o `load` só conta e delega).
  A persistência provada em `list_delete_and_state_persist`,
  `access_code_validate_round_trips` e
  `failed_reset_leaves_the_persisted_state_reachable_from_a_reload` sempre passa
  por uma leitura saudável.

### 1.2 Caminho de exploração

1. O dono tem credenciais OATH e um access code configurado no blob selado.
2. O flash falha na leitura (desgaste, bit rot dentro de um shard, commit antigo
   não decifrável, IO) ou o blob fica ilegível por tamper físico.
3. O host abre o applet: `SELECT` → `load_state` → `None`/`decode_state` `false`
   → `loaded = true`, RAM vazia, `9000`.
4. `LIST` responde `9000` vazio, `VALIDATE` responde `6984`, e o access code
   simplesmente não existe mais do ponto de vista do protocolo — **sem nenhuma
   resposta de erro**.
5. Um `PUT` (do dono, de um script de provisionamento ou de qualquer processo
   PC/SC local) grava por cima do blob ilegível: as credenciais antigas e o
   access code são destruídos e o applet passa a servir o estado novo, sem
   autoridade nenhuma.
6. Variante mais barata: com a RAM vazia e o blob intacto, o atacante nem
   precisa de `PUT` para calcular — `CALCULATE` responde `9000` para qualquer
   credencial **que ele mesmo inserir**, e o access code do dono fica
   permanentemente desligado no blob que ele sobrescreveu.

**Impacto:** quebra simultânea de três cláusulas do `docs/security-model.md`:
*"PIN state is persistent and fail-closed"* (o access code deixa de ser
exigido), *"The state an accepted command writes survives the session"*
(grava-se por cima de um estado que não foi lido) e *"Secrets are sealed at
rest"* na sua consequência operacional (o blob selado é descartado sem
diagnóstico). A gravidade é limitada por: o gatilho é físico e está fora do
modelo de ameaça vivo; não há caminho remoto (PC/SC local); não há exportação de
segredo nesta fatia; e a falha só ocorre num dispositivo cujo armazenamento já
está degradado. Mas o efeito é **permissivo e silencioso**, é a mesma classe de
defeito já corrigida em `piv-pin-persistence`, `openpgp-pin-persistence` e
`oath-reset-fail-closed`, e a correção é local. Por isso **MÉDIO**.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | Nenhum comando opera sobre estado que o applet não leu; o access code não pode ser desligado por uma leitura que falhou | `docs/security-model.md` ("Applet security invariants", cláusula *PIN state is persistent and fail-closed*) | **violada** — `load_state` trata falha como "sem estado" e `require_auth` libera com `auth_key` vazio |
| I2 | "The state an accepted command writes survives the session" — não se confirma escrita sobre um estado que não foi lido | `docs/security-model.md` (mesma seção) | **violada** — `put`/`delete`/`set_code` gravam a partir de uma RAM que não reflete a store |
| I3 | Store selada é fail-closed: corrupção ou IO recusado nunca é lido como conteúdo | `sealed.rs` (`SealedBlob::load` devolve `Err` para corrupção), `specs/oath-reset-fail-closed.md` §10 L4 | **violada no adaptador** — `SealedOathStore::load` colapsa `Err` em `None` |
| I4 | A resposta de `SELECT` descreve o estado que o applet realmente tem (o bloco de access code só aparece quando há access code) | `oath.rs` (`fn select_response`) | **violada** — o FCI pode anunciar um challenge que não foi lido |
| I5 | Recuperação não destrutiva é preferível a apagar estado recuperável | `docs/security-model.md`, fatia `oath-reset-fail-closed` (o `RESET` só apaga depois de persistir) | respeitada; **preservada** (o `RESET` continua sendo a saída, com o custo documentado na decisão 3 de §3 e em §10 R3) |

---

## 3. Decisões de política (documentadas nesta spec)

**1 — SW da recusa: `Sw::NO_PRECISE_DIAGNOSIS` (`0x6F00`).** A condição é
"não consegui ler o estado", não "a store recusou a gravação":

- `0x6A84` (`Sw::NOT_ENOUGH_MEMORY`) é, neste crate, o SW do **contrato de
  escrita** — `put`, `delete`, `calculate_index`, `set_code`, `validate`,
  `reset` e, nas fatias irmãs, os mutadores de PIN do PIV/OpenPGP. Reutilizá-lo
  aqui faria o host inferir que uma escrita foi tentada e recusada (e que
  retentar o mesmo comando faz sentido), quando nada foi escrito.
- `0x6F00` é o "erro técnico interno" do ISO 7816-4, já usado pelo applet para
  falha interna (`calculate_all` sem HMAC válido) e é **exatamente** o que o PIV
  responde na mesma condição (`Piv::select_response` → `load_state()` `false`).
  Consistência entre applets e zero colisão com o contrato de escrita.
- `0x6982`/`0x6984` insinuariam problema de autenticação (e `6984` é hoje a
  resposta de `VALIDATE` sem access code: a pior mensagem possível para esta
  falha); `0x6A82`/`0x6A88` sugeririam arquivo/referência inexistente; `0x6581`
  é armazenamento físico e já se confundiria com gravação.

**2 — Uma única fronteira de recusa: o applet fica "fechado" e o despacho
recusa tudo, menos `RESET`.** Novo campo volátil em `Oath<S>` (nome à escolha,
aqui `closed`), escrito por `load_state` (única autoridade sobre aberto/fechado)
e por `reset` (decisão 3). Mecanismo exato, sem duplicar checagem em 8 handlers:

1. `Oath::load_state` passa a devolver/registrar o resultado e é o **único**
   lugar que decide aberto/fechado. Estados: `store.load` → `None` ⇒ fechado;
   `Some(0)` ⇒ store em branco (estado vazio legítimo) ⇒ aberto; `Some(len)` com
   `decode_state` `false` ⇒ fechado; `Some(len)` decodificado ⇒ aberto.
   Em "fechado" a RAM é normalizada para o estado de boot
   (`credentials`/`auth_key` vazios, `authenticated = false`,
   `auth_challenge = DEFAULT_CHALLENGE`, `auth_algorithm = SHA1`,
   `pending = None`) — determinismo, não autoridade: quem recusa é a flag.
2. `Oath::process` recebe **uma** guarda antes do `match`: se a state nunca foi
   lida nesta seleção (applet não selecionado pelo roteador), lê; em seguida, se
   fechado e `apdu.ins != INS_RESET`, responde `6F00`. Nenhum handler ganha
   checagem própria.
3. `Oath::confirm_presence` (segunda porta de entrada, fora de `process`) tem a
   mesma guarda: fechado ⇒ `6F00`, nunca `calculate_index`.
4. `Oath::deny_presence` não precisa de guarda: só descarta `pending` e responde
   `6982`, não revela nem serve estado.

Consequências assumidas (documentadas em §9 e testadas):

- **`SELECT` continua respondendo `9000` com o FCI** (versão + `DEVICE_ID`) em
  vez de falhar como o PIV. Fundamento: o `RESET` é o caminho de recuperação
  (decisão 3) e as ferramentas reais (`ykman oath`, Yubico Authenticator)
  abortam no `SELECT`; um `SELECT` que falha tornaria a recuperação impossível
  pela ferramenta padrão. O bloco de access code (`TAG_CHALLENGE`/`0x7B`) **não**
  é emitido enquanto fechado, para não anunciar um challenge que o applet não
  pode validar.
- **Instrução desconhecida com o applet fechado responde `6F00`, não `6D00`**:
  a disponibilidade do estado precede a recusa de instrução. `INS_RESET` fica
  fora da guarda inteira, então `P1`/`P2` fora do par canônico continuam
  respondendo `6D00` (parâmetro é validado antes de estado) e sem tocar a store.

**3 — `RESET` permanece permitido com o store ilegível: exceção fail-open
deliberada.** É o único comando que atravessa a guarda.

*Por quê:* sem ele, um dispositivo com a região de OATH ilegível fica com o
applet morto até reflash/recovery, sem nenhuma saída no protocolo. O `RESET`
YKOATH (`P1=0xDE, P2=0xAD`) é **destrutivo e nada revela** (apaga, nunca lê) e
já é não autenticado por protocolo desde sempre — a fatia irmã documentou isso
como característica aceita, não como gap. Permitir o `RESET` não dá ao atacante
nada que ele já não tenha (ele pode igualmente apagar chamando o comando), e dá
ao dono um caminho de volta.

*Limites da exceção, todos testados:* o resultado do `RESET` continua
fail-closed (`clear` recusado ⇒ `6A84`, applet **permanece** fechado); o erase
não confirma nada sobre a leitura; e, no sucesso, o applet fica aberto **com o
estado que o próprio erase provou** (vazio, igual ao que um reload devolveria) —
a próxima leitura ainda é dona do destino (decisão 4): um `SELECT` seguinte que
falhe volta a fechar.

*Custo aceito:* um `RESET` executado durante uma falha **transiente** apaga
credenciais que um `SELECT` seguinte teria recuperado. Mitigação de projeto e de
documentação (não de protocolo): cada `SELECT` já retenta a leitura, então a
recomendação registrada em `validation.md`/`roadmap.md` é **reselecionar antes
de resetar**; `ykman oath reset` não é automático.

**4 — Recuperação: cada `SELECT` é uma nova tentativa; nada é "sticky".**
`Applet::select`/`select_with_rng` continuam zerando `loaded` antes de
`load_state`; a flag `closed` é **volátil** e é reavaliada a cada leitura, não
persistida em lugar nenhum:

- leitura volta a funcionar + `SELECT` ⇒ applet **reabre** com o estado
  persistido (credenciais e access code de volta, challenge novo);
- leitura falha de novo ⇒ continua fechado, sem degradação acumulada;
- depois de um `RESET` bem-sucedido o applet fica **aberto com o estado que o
  erase confirmou** (vazio) e `loaded` continua verdadeiro — o erase commitado é
  a prova do estado, e responder `6F00` imediatamente depois de um `9000` seria
  incoerente; o `SELECT` seguinte relê a store e, se a leitura falhar, fecha
  outra vez;
- **não** há nova tentativa por comando enquanto fechado: a guarda responde
  `6F00` sem tocar a store (provado por contadores), para não transformar o applet
  fechado num martelo de flash.

**5 — Contrato de `OathStore::load`: `None` é falha, `Some(0)` é vazio.** É o
mínimo para fechar o buraco sem mudar assinatura, sem `Result` e sem método
novo (a fatia irmã deixou "mudar `OathStore`/`SealedOathStore` para `Result`"
como não-objetivo, e continua sendo):

- `trait OathStore` ganha a documentação do contrato: `Some(len)` = estado
  presente; `Some(0)` = nenhum estado (região virgem/tombstone); `None` =
  leitura falhou (IO/corrupção/indecifrável) e o applet **deve** falhar fechado.
  Quem não souber distinguir devolve `None` (default fail-closed).
- `MemoryOathStore::load`: `Some(0)` quando `len == 0`; `None` só quando o
  buffer é insuficiente (erro de chamador = falha de leitura).
- `SealedOathStore::load`: `Err(_) → None`; `Ok(None) → Some(0)`;
  `Ok(Some(n)) → Some(n)` — a distinção que o `SealedBlob::load` já produz e que
  hoje é jogada fora. `SealedBlob`/`SealedCell`/`SecretStorage` **não** mudam.
- A semântica de "vazio" continua sendo servida normalmente (dispositivo de
  fábrica, `clear` lógico que grava commit de `total = 0`): o mapeamento é exato
  porque `SealedBlob::load` só devolve `Ok(None)` quando **não existe** registro
  de commit, e mapeia inconsistência de tamanho para `Err`.

**6 — Nada de novo no formato, nas dependências ou no build.** Nenhum estado
persistente novo (a flag é volátil de sessão), sem bump de `STATE_VERSION`, sem
migração, sem mudança em `save_state`/`decode_state`, sem dependência, sem
`unsafe`, sem `std`/alocação (a leitura continua usando o buffer
`[u8; STATE_BYTES]` na pilha). Nenhum default OATH (`DEFAULT_CHALLENGE`,
`DEVICE_ID`, políticas de touch, comprimentos) muda. A superfície de protocolo
muda **só** nos SWs de recusa; `9000`, `6D00`, `6982`, `6984`, `6985`, `6A80`,
`6A84` seguem com o mesmo significado quando o applet está aberto.

**Tabela de comportamento por caminho**

| Caminho | Hoje | Depois |
|---|---|---|
| `SELECT`, leitura ok | `9000` + FCI (com bloco de access code se houver) | idêntico |
| `SELECT`, store em branco (`Some(0)`) | (colapsado em "sem estado") | `9000` + FCI, **aberto**, estado vazio — igual a hoje |
| `SELECT`, leitura falha | `9000` + FCI, applet aberto com RAM vazia/parcial (pode anunciar challenge velho) | `9000` + FCI **sem** bloco de access code, applet **fechado** |
| `LIST`/`CALCULATE`/`CALCULATE ALL`, fechado | `9000` sobre estado vazio ou parcial | **`6F00`**, 0 escritas, 0 leituras |
| `PUT`/`DELETE`/`SET CODE`, fechado | `9000` e grava o blob sem access code | **`6F00`**, 0 `save`, 0 `clear`, blob intacto |
| `VALIDATE`, fechado | `6984` (ou `6982`) | **`6F00`**; nunca libera |
| `CALCULATE` de credencial com toque, fechado | `6FF0` (`PRESENCE_REQUIRED`) sobre estado não lido | **`6F00`**; nenhum toque é pedido |
| `RESET` `DE AD`, fechado, `clear` ok | `9000` (apaga um estado que a RAM dizia vazio) | `9000`; store apagada; applet aberto com o estado vazio que o erase confirmou (o `SELECT` seguinte relê) |
| `RESET` `DE AD`, fechado, `clear` falha | `6A84` | `6A84`; **continua fechado** |
| `RESET` `P1`/`P2` fora do par, fechado | `6D00` | `6D00`, 0 `clear` |
| INS desconhecido, fechado | `6D00` | **`6F00`** (decisão 2) |
| INS desconhecido, aberto | `6D00` | `6D00` |

---

## 4. Escopo

- `crates/aegis-applets/src/oath.rs`:
  - `trait OathStore::load`: documentar o contrato (`Some(0)` = vazio, `None` =
    falha) sem mudar assinatura.
  - `MemoryOathStore::load`: devolver `Some(0)` para store vazia.
  - `Oath<S>`: novo campo volátil de "fechado" (nome à escolha, aqui `closed`),
    inicializado aberto e decidido exclusivamente pela leitura; a guarda do
    `process` lê antes de atender, de modo que um applet nunca selecionado não
    atende com estado não lido.
  - `Oath::load_state`: distinguir `None` (fechar), `Some(0)` (abrir vazio) e
    `Some(len)` + `decode_state` (abrir/fechar); normalizar a RAM no fechamento;
    registrar o resultado na flag.
  - `Oath::process`: guarda única (ler se `loaded == false`; fechar ⇒ `6F00`
    exceto `INS_RESET`), preservando o `match` e a ordem de parâmetros atual.
  - `Oath::confirm_presence`: mesma guarda.
  - `Oath::select_response`: só emitir `TAG_CHALLENGE`/`0x7B` com o applet
    aberto e `auth_key` não vazio; quando fechado, `authenticated = false`
    explícito (não derivado de `auth_key` vazio).
  - `Oath::reset`: no sucesso, limpar a RAM e deixar o applet **aberto com o
    estado vazio que o erase confirmou** (o `SELECT` seguinte relê e pode
    fechar); no `6A84`, continuar fechado. Nada mais do handler muda.
  - Testes de host: `FailingOathStore` ganha falha de `load` (flag +
    `set_load_fails`) mantendo os contadores; os helpers já são genéricos sobre
    `S: OathStore` desde a fatia do `RESET`.
- `crates/aegis-applets/src/sealed.rs`:
  - `impl OathStore for SealedOathStore::load`: `Err → None`, `Ok(None) →
    Some(0)`, `Ok(Some(n)) → Some(n)`, com comentário do contrato; teste de host
    da distinção (virgem/`clear`/shard corrompido).
- Documentação (§9) na mesma mudança.

## 5. Não-objetivos

1. **Bounds e ciclo de vida de `pending`** (`confirm_presence` indexa
   `credentials[pending.index]` sem checar; `delete` não limpa `pending`) —
   informacional adjacente, fatia própria. Aqui só se garante que um applet
   fechado nunca chega a `calculate_index`.
2. **Fallback do firmware para `MemoryOathStore` quando `SealedOathStore::open`
   falha** (`main.rs`): é a mesma família de degradação (o applet passa a servir
   um estado vazio e mutável), mas é política de firmware/HAL e merece fatia
   própria; registrado como follow-up em `roadmap.md` (§10 L2).
3. **Robustez do `SealedBlob`/`SealedCell`** (por exemplo, um slot de commit
   antigo que passe no CRC mas não abra no GCM derruba o load inteiro, e
   `fresh_gen` também falha, podendo impedir o `RESET`): a atomicidade e a
   política de gerações ficam como estão; esta fatia só **respeita** o `Err`.
4. **Mudar `OathStore::load` para `Result`/tipo de erro novo**, ou revisar a
   serialização (`save_state`/`decode_state`): API e formato intocados.
5. **Mudar o `SELECT` para falhar com `6F00` (modelo do PIV)** ou introduzir
   qualquer TLV/estado novo que anuncie "applet fechado": mudaria o protocolo
   YKOATH e quebraria a recuperação pela ferramenta padrão.
6. **Persistir o estado de "fechado"**, criar marcador de degradação, contador
   ou flag no blob: nada persistido muda.
7. **PIV, OpenPGP, FIDO, `aegis-core`, firmware, HAL, `aegistoken-host`,
   `scripts/`** — nenhum arquivo tocado; nenhum despacho alterado (a assinatura
   do trait não muda, então o firmware compila sem edição).
8. **OTP/flash, partições, layout do `SealedBlob`, chave de selagem** —
   intocados.
9. **Novos SWs** além do uso de `6F00` como recusa: `9000`, `6D00`, `6982`,
   `6984`, `6985`, `6A80`, `6A84` preservados no applet aberto.
10. **Dependências novas, `unsafe` ou `std`** no crate: não.

## 6. Critérios de aceitação

Todos os ACs são observáveis em teste de host no módulo `#[cfg(test)]` de
`crates/aegis-applets/src/oath.rs` (e um caso em `sealed.rs`), com
`MemoryOathStore` (caminho feliz/vazio) e `FailingOathStore` (falha de `load`);
nenhum exige hardware. A exceção é o AC-8 (doc/regressão estática).

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | **Recusa total enquanto fechado, `SELECT` ainda seleciona:** com `load` falhando, `select()` responde `9000` com `TAG_VERSION`/`TAG_NAME` e **sem** `TAG_CHALLENGE`/`0x7B`; `LIST`, `CALCULATE` (TOTP e com toque), `CALCULATE ALL`, `PUT`, `DELETE`, `SET CODE` (vazio e com chave) e `VALIDATE` respondem **`6F00`** — nunca `9000`, nunca `6FF0`/`6982`/`6984`; um `VALIDATE` com resposta HMAC correta sobre o challenge da store **não** libera (o `LIST` seguinte continua `6F00`, não `9000`) | teste de host em `oath.rs` |
| **AC-2** | **Nenhuma escrita, nenhuma sobrescrita:** com o applet fechado, `PUT`/`DELETE`/`SET CODE` respondem `6F00` com `saves() == 0` e `clears() == 0`; o blob persistido é **byte-idêntico** ao snapshot tirado antes da falha (comparação via `store_mut().load(&mut buf)` depois de a falha ser desligada) — prova de que o `PUT` não gravou o estado vazio por cima | teste de host em `oath.rs` |
| **AC-3** | **`RESET` é a exceção e continua fail-closed:** fechado → `DE AD` → `clear` chamado **uma vez** → `9000`, com a RAM vazia e o applet aberto sobre o estado vazio que o erase confirmou (`LIST` `9000` vazio e `SET CODE` aceito, mesmo com a leitura ainda falhando — o erase é a prova do estado; o `SELECT` seguinte relê); variante `clear` falhando → `6A84`, `clears() == 1`, `LIST` continua `6F00` (não reabre) e nenhuma leitura extra acontece; variante `DE 00`/`00 AD` → `6D00` com `clears() == 0` | teste de host em `oath.rs` |
| **AC-4** | **Falha transiente não perde nada:** applet aberto com credencial TOTP + access code; snapshot do blob e do código; falha de `load` ligada → `select()` sem bloco de access code e `LIST` `6F00`; falha desligada → `select()` responde `9000` com `TAG_CHALLENGE`, `LIST` volta a `6982`, `VALIDATE` com HMAC correto libera, a credencial antiga lista e `CALCULATE` devolve **o mesmo código** de antes, e o blob continua byte-idêntico ao snapshot; cada `SELECT` faz exatamente **1** `load` e os comandos recusados **0** | teste de host em `oath.rs` |
| **AC-5** | **Falha repetida não acumula e não vaza RAM:** três `SELECT` consecutivos com `load` falhando → `6F00` em todos os comandos de estado e `loads() == 3`; nenhum caminho entra em pânico; `VALIDATE` e `LIST` respondem `6F00` (não `6984`/`6982`) depois de uma sessão anterior em que havia access code e credencial — a RAM normalizada não autentica nem serve | teste de host em `oath.rs` |
| **AC-6** | **Falha de integridade também fecha, e não é sticky:** grave um corpo cru inválido pela própria store (`store_mut().save(&[..])`, ex. versão desconhecida ou corpo truncado) → `select()` → `LIST` `6F00`; regrave o corpo válido (o snapshot) → `select()` → `9000` com a credencial de volta, sem nenhuma escrita feita durante o período fechado | teste de host em `oath.rs` |
| **AC-7** | **Store vazia continua aberta (sem brick) e o caminho feliz é o de hoje:** `MemoryOathStore` nova → `select()` `9000`, `LIST` `9000` vazio, `PUT` `9000`; `SealedOathStore` vira `Some(0)` no `load` virgem e após `clear()`, e `None` quando um shard de dados está corrompido (teste em `sealed.rs`); `reset_removes_credentials_and_authentication`, `list_delete_and_state_persist`, `access_code_validate_round_trips` e `touch_required_calculation_uses_card_presence_flow` passam **sem edição**; suíte de `aegis-applets` sem regressão (245 hoje + os casos novos) | testes de host em `oath.rs`/`sealed.rs` + `cargo test -p aegis-applets` |
| **AC-8** | **Documento de contrato atualizado na mesma mudança:** `docs/security-model.md` ganha a cláusula de leitura fail-closed do OATH (contrato `None`/`Some(0)`, flag volátil, `6F00`, `SELECT` com FCI e sem bloco de access code, retentativa por `SELECT`, `RESET` como exceção deliberada); `roadmap.md` registra a sub-fatia na Fase 13 e atualiza as pendências; `validation.md` ganha a subseção OATH com a tabela de ACs, a linha **AC-032** e a pendência física | revisão estática |

## 7. Plano de teste

### 7.1 Onde ficam

No módulo `#[cfg(test)] mod tests` já existente em
`crates/aegis-applets/src/oath.rs`, reutilizando `applet()`, `applet_with()`,
`frame()`, `run()`, `put_data()`, `calculate_data()`, `code()`, `TestRng`,
`set_access_code()`, `validate_access_code()` e a constante `RFC_SECRET`. Nada
de infraestrutura nova além de um flag na wrapper:

- `FailingOathStore` já existe (fatia do `RESET`) com `inner:
  MemoryOathStore`, `clear_fails`, `save_fails`, contadores `clears()`/
  `saves()`/`loads()`, `reset_calls()` e `Default`. Ganha `load_fails` +
  `set_load_fails(bool)`: quando ligado, `load` conta e devolve `None` sem
  delegar (falha de leitura); desligado, delega. Ela **não** é código de
  produção (fica em `#[cfg(test)]`).
- Os helpers `run`/`set_access_code`/`validate_access_code`/`applet_with` já são
  genéricos sobre `S: OathStore`; nenhuma genericização nova é necessária.
- Para o AC-6 não é preciso hook novo: `OathStore::save` aceita bytes
  arbitrários, então o próprio `store_mut().save(&corpo_invalido)` instala o blob
  quebrado (zerar `reset_calls()` depois, porque o `save` conta).
- Em `sealed.rs`, os helpers `TestFlash`, `test_key()`, `SealedOathStore::open`
  e a corrupção direta de bytes (`mem.borrow_mut()[...] ^= 0xFF`) já são usados
  pelos testes de persistência/torn-save; o teste novo só precisa reabrir a
  store e chamar `load`.

### 7.2 Como os casos são montados

- **AC-1:** `applet_with(FailingOathStore)` com credencial TOTP + access code
  configurado por `set_access_code` (lembrar: `SET CODE` termina com
  `authenticated = true`; chamar `select()` antes de ligar a falha para voltar
  ao estado não autenticado e ter um `auth_challenge` conhecido). Ligar
  `set_load_fails(true)`, `select()` e conferir o FCI; rodar a tabela de INS e
  afirmar `6F00` em todas, com `saves()/clears()` zerados. Variante: `VALIDATE`
  correto → `6F00` e `LIST` ainda `6F00`.
- **AC-2:** snapshot do blob (`store_mut().load`) com o applet aberto; ligar a
  falha; `select()`; `PUT` de outra credencial, `DELETE`, `SET CODE` vazio →
  `6F00`; afirmar contadores zerados; desligar a falha e reler o blob → igual ao
  snapshot (comparar os `len` bytes).
- **AC-3:** fechado como no AC-1; `RESET` `DE AD` → `9000`, `clears() == 1`,
  `LIST` `9000` vazio e `SET CODE` aceito ainda com a falha de leitura ligada
  (o erase commitado é a prova do estado); depois, com a falha desligada,
  `select()` → `LIST` `9000` (relê e continua aberto). Variante
  `set_clear_fails(true)` → `6A84`, `clears() == 1`, `loads()` não cresce e
  `LIST` `6F00` (fechado). Variante `P1=0xDE,P2=0x00` e `P1=0x00,P2=0xAD` →
  `6D00`, `clears() == 0`. Repetir o caminho feliz com `MemoryOathStore`.
- **AC-4:** estado saudável (credencial TOTP com `RFC_SECRET`, access code,
  código esperado `287082` para moving factor `1`), snapshots de blob e código;
  falha ligada; `select()` → sem `TAG_CHALLENGE`; falha desligada; `select()` →
  com `TAG_CHALLENGE`; `validate_access_code` → `OK`; `LIST` e `CALCULATE`
  iguais aos snapshots; blob igual.
- **AC-5:** fechado; três `select()`; `LIST`/`VALIDATE` → `6F00`; contador de
  `loads()` igual ao número de seleções (nenhum comando relê);
  `confirm_presence` → `6F00` (mesma guarda da decisão 2 — nunca `6985` nem
  `calculate_index`).
- **AC-6:** applet aberto com credencial; snapshot; `store_mut().save(&[0xFF; 8])`
  (ou corpo truncado) + `select()` → `6F00`; `store_mut().save(&snapshot)` +
  `select()` → `LIST` `9000` com a credencial.
- **AC-7 (sealed):** store selada virgem → `load` == `Some(0)`; `save(estado)` →
  `Some(len)`; `clear()` → `Some(0)`; applet novo sobre a mesma store depois de
  corromper um byte de um shard de dados (o CRC falha ⇒ o slot é ignorado e a
  geração não é reassemblável) → `load` == `None`.
- Nomes sugeridos (o implementador pode ajustar):
  `failed_load_closes_the_applet_and_never_confirms_state_commands`,
  `closed_applet_never_writes_or_overwrites_the_blob`,
  `reset_stays_available_and_fail_closed_while_the_read_fails`,
  `a_good_reselect_reopens_and_preserves_credentials_and_access_code`,
  `repeated_failed_loads_stay_closed_without_leaking_ram`,
  `undecodable_blob_closes_and_reopens_with_a_valid_one`,
  `blank_store_still_serves_an_empty_applet`,
  `sealed_oath_load_distinguishes_blank_from_corrupt`.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

Suíte atual de `aegis-applets`: **245** testes (medido na fatia do `RESET`
fail-closed). A contagem final deve ser registrada em
`roadmap.md`/`validation.md` na mesma mudança. Somente `aegis-applets` é tocado
em código; `cargo build-fw` não é exigido (nenhum arquivo de firmware/HAL muda e
a assinatura do trait não muda).

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `crates/aegis-applets/src/oath.rs` | contrato de `OathStore::load` documentado e `MemoryOathStore::load` (`Some(0)` para vazio); campo volátil de "fechado"; `load_state` decidindo aberto/fechado (IO, vazio e decodificação) e normalizando a RAM; guarda única em `process` (+ `INS_RESET` isento) e em `confirm_presence`; `select_response` sem bloco de access code quando fechado; `reset` abrindo o applet sobre o estado vazio que o erase confirmou; testes AC-1..AC-7 e `set_load_fails` na wrapper |
| `crates/aegis-applets/src/sealed.rs` | `SealedOathStore::load`: `Err → None`, `Ok(None) → Some(0)`, `Ok(Some(n)) → Some(n)`; teste da distinção vazio/corrompido |
| `roadmap.md`, `validation.md`, `docs/security-model.md` | Documentação na mesma mudança (§9) |

Nada é alterado em `crates/aegis-core/**`,
`crates/firmware-universal-rp2350/**`, `crates/board-generic-rp2350/**`,
`crates/aegistoken-host/**` ou `scripts/**`; nenhum despacho de firmware muda e
`SealedBlob`/`SealedCell`/`SecretStorage` ficam como estão.

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — em "Applet security invariants", logo depois do
   parágrafo do OATH sobre o `RESET` fail-closed, acrescentar a cláusula de
   **leitura** fail-closed: `OathStore::load` distingue `Some(0)` (store em
   branco, estado vazio legítimo) de `None` (IO/corrupção/indecifrável); qualquer
   `None` ou recusa do decoder fecha o applet, que responde `6F00` a **todo**
   comando de estado (`LIST`, `CALCULATE`, `CALCULATE ALL`, `PUT`, `DELETE`,
   `SET CODE`, `VALIDATE`, `confirm_presence`) e normaliza a RAM para o estado de
   boot — o motivo é que o "vazio" do OATH é o lado **permissivo**
   (`require_auth` libera sem access code), ao contrário do default restritivo do
   OpenPGP e do `6F00` no `SELECT` do PIV. Registrar como decisões aceitas, não
   como gaps: (a) o `SELECT` continua respondendo o FCI (`9000`, sem bloco de
   access code) para que a recuperação seja alcançável pela ferramenta padrão;
   (b) `RESET` (`DE AD`) é a **exceção necessária** — apaga sem revelar, seu
   resultado segue fail-closed (`6A84`) e, quando o erase persiste, o applet
   segue aberto apenas com o estado vazio que o próprio erase confirmou (o
   `SELECT` seguinte relê e pode fechar); (c)
   cada `SELECT` é uma nova tentativa e a recusa é volátil (não persistida);
   (d) instrução desconhecida com o applet fechado responde `6F00` porque a
   disponibilidade do estado precede a recusa de instrução. Mencionar que o
   gatilho (flash doente) está fora do modelo de ameaça vivo e que esta é uma
   mudança de robustez na direção restritiva.
2. **`roadmap.md`** — Fase 13 (OATH), seção **Entregue**: acrescentar a
   sub-fatia de leitura fail-closed (`None` vs `Some(0)` no contrato da store,
   applet fechado, `6F00`, `SELECT` retentando, `RESET` como exceção) com a
   contagem de testes novos e o total da suíte. Na seção **Pendências**: remover
   o follow-up "leitura da store tratada como estado vazio no `load_state`"
   (entregue aqui), manter `AC-018 em hardware` e os bounds de `pending`, e
   registrar dois follow-ups novos explicitamente fora de escopo: o fallback do
   firmware para `MemoryOathStore` quando `SealedOathStore::open` falha e a
   robustez do `SealedBlob` quando um slot de commit antigo não abre.
3. **`validation.md`** — na seção "OATH / TOTP / HOTP (Fase 13)", depois da
   subseção do `RESET`, adicionar "Leitura fail-closed (fatia
   `specs/oath-load-fail-closed.md`)" com a tabela de ACs (método: testes de host
   de `aegis-applets::oath`/`sealed`; status **Verificado em host**) e a
   pendência física: a falha de leitura não é induzida em hardware
   (`validate_oath.py` não simula flash doente), ficando pendente o caso "store
   ilegível → todo comando `6F00`, `RESET` recuperando" em dispositivo real;
   registrar também a recomendação operacional "reselecionar antes de resetar"
   (o `RESET` apaga credenciais que uma nova leitura poderia recuperar). Na
   tabela de critérios, acrescentar a linha **AC-032** com o resumo da fatia e
   ajustar o texto de status do **AC-018** para incluir "leitura fail-closed".

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Mudança de contrato num trait público do workspace.** `OathStore` é
  público e os únicos implementadores estão no repositório (`MemoryOathStore`,
  `SealedOathStore`, a wrapper de teste), mas quem implementar `load` devolvendo
  `None` para "vazio" passa a ser recusado. A direção é fail-closed e o contrato
  fica documentado no trait; é a troca que fecha o buraco sem `Result` nem método
  novo.
- **R2 — `SELECT` + FCI enquanto fechado pode parecer inconsistente.** Um host
  que só olhe o `SELECT` vê um cartão saudável e vê `6F00` em tudo depois. É
  intencional (decisão 2) e o teste de AC-1 fixa o contrato; `ykman` mostrará
  erro de cartão em cada comando, não um cartão ausente.
- **R3 — `RESET` ainda apaga com a leitura falhando.** É a exceção deliberada
  (decisão 3): sob falha transiente, um `RESET` do usuário destrói credenciais
  recuperáveis. Mitigado por documentação e por a retentativa acontecer em cada
  `SELECT`; não há como distinguir transiente de permanente sem inventar estado
  persistido (fora de escopo, decisão 6).
- **R4 — `SealedBlob::load` é rígido com slots antigos.** Um slot de commit
  antigo que passe no CRC mas não abra no GCM derruba o load inteiro (e
  `fresh_gen` também falha, podendo recusar o `RESET` com `6A84`). O applet fica
  fechado — correto — mas sem recuperação pelo protocolo até
  reflash/recovery/update. Não é regressão desta fatia (o `Err` já existia), e
  endurecer o `SealedBlob` é fatia própria (não-objetivo 3).
- **R5 — Concorrência de edição.** `oath.rs` é grande e as fatias irmãs mexeram
  em `roadmap.md`/`validation.md`; manter o diff cirúrgico (o handler, a guarda e
  o módulo de testes) e reconciliar no rebase. AC-7 é a rede de regressão.

### 10.2 Limitações

- **L1 — Sem hardware neste ciclo.** ACs exclusivamente de host; nenhum
  `cargo build-fw` (nada de firmware/HAL é tocado). A indução de falha de leitura
  em flash real fica pendente em `validation.md`.
- **L2 — O fallback do firmware continua permissivo.** Se `SealedOathStore::open`
  falhar (célula de commit ilegível sob a chave), `main.rs` registra o aviso e
  cai para `MemoryOathStore`: o applet serve um estado vazio, sem access code,
  mutável e não persistente. Não há segredo legível nesse caminho (o blob não
  abre), mas a autoridade também não é exigida — o efeito prático é
  disponibilidade + um applet vazio, e essa decisão é de firmware/HAL
  (não-objetivo 2, follow-up registrado).
- **L3 — Uma região fisicamente zerada é indistinguível de aparelho novo.** Se
  todos os registros de commit forem apagados fisicamente, a store é "em branco"
  (`Some(0)`) e o applet abre vazio, como um dispositivo de fábrica. Sem um
  marcador fora de banda (que seria estado persistido novo, decisão 6) não há
  como diferenciar; a garantia desta fatia cobre leitura que **falha** e blob
  **ilegível**, não um wipe total.
- **L4 — A recusa é por seleção, não persistente.** Um boot novo (ou um
  `SELECT` seguinte) tenta ler outra vez: se o meio físico se recuperou, o applet
  reabre com o estado antigo; se não, fecha de novo. Não existe "modo
  degradado" memorizado nem telemetria — o host só vê o `6F00`.
- **L5 — Não há como restaurar o access code sem apagar.** Fechado, o applet não
  consegue distinguir "não há access code" de "não consegui ler o access code",
  então `SET CODE` é recusado como todo o resto; a ordem de recuperação é
  `RESET` → `SET CODE` → `PUT`. É consequência direta da decisão 2 e está
  documentada.
- **L6 — Sem segredo novo e sem estado novo.** A fatia não adiciona estado
  persistente, não muda a serialização (`save_state`/`decode_state`) nem cria SWs
  além do uso de `6F00` como recusa.
