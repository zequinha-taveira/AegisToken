# Spec — Segredos fora do argv no ferramental de host

> **Origem:** achado do `sec-audit` (loop de hardening de segurança), risco
> **BAIXO** (local, mas real): `scripts/set_pin.py` aceita `--pin`/`--old-pin` e
> `aegistoken-host piv-set-mgmt-key` aceita a chave nova como positional, além de
> `--key`/`--old-key`. Segredos em `argv` são visíveis na lista de processos
> (`ps`, `/proc/<pid>/cmdline`, Gerenciador de Tarefas, WMI) e no histórico do
> shell. HEAD de referência: **`5ef978f`**.
> **Risco:** BAIXO no modelo de ameaça local — exige acesso local de mesmo
> usuário (ou root/administrador) e o token ainda precisa estar acessível para o
> segredo ser usado —, com escalada condicional para **ALTO** em hosts
> compartilhados, CI e estações multiusuário: a chave de gestão do PIV é a
> autoridade administrativa do applet e o PIN do clientPIN libera UV e credential
> management. A exposição é trivial (`ps`/histórico), o custo da correção é
> local e a quebra interna é pequena: as únicas chamadas com segredo em `argv`
> no repositório estão na documentação, não em scripts/runbooks.

---

## 1. Ameaça

### 1.1 Estado atual (confirmado no código)

#### `scripts/set_pin.py`

- O parsing é manual, em `parse_args(argv)`: não usa `argparse`. `--pin` e
  `--old-pin` consomem o **próximo token** e o devolvem como `str`; não há
  validação de forma, comprimento ou eco controlado.
- `main()` só chama `getpass.getpass` quando o valor correspondente é `None`.
  Ou seja, o caminho **default** (sem flags) já é o seguro; o caminho
  "explícito" (`--pin`, `--old-pin`) é justamente o inseguro.
- Opções desconhecidas e flags sem valor são **silenciosamente ignoradas**; não
  existe `--help`/`-h` explícito. O texto de ajuda é o docstring do módulo, que
  mostra exemplos com `--pin 123456` e `--old-pin 123456`.
- `--retries` ignora qualquer valor de PIN fornecido.
- `python-fido2` é importado no topo do módulo; sem o pacote o script sai com
  código 2 **antes** de parsear qualquer argumento. Isso impede testar o parser
  sem a dependência opcional.
- Erros de `client_pin.*` são impressos como `[FAIL] {exc}` (texto de exceção de
  terceiro), sem scrubbing do valor sensível.
- Não há teste de `set_pin.py` em `tests/`; os testes existentes são de
  `pcsc_transport` e dos vetores OpenPGP.

#### `crates/aegistoken-host/src/cli.rs`

- `struct Cli` guarda `key: Option<String>` e `old_key: Option<String>` — o
  segredo vive em `String` vinda de `std::env::args()`.
- `parse()` reconhece `--key` e `--old-key` como opções **globais**, com valor
  inline (`--key=...`) ou no token seguinte, sem validar contra o comando.
- `run()` trata o **primeiro positional** de `piv-set-mgmt-key` como
  `<NEW_KEY_HEX>` e passa `cli.old_key` adiante. `piv-import-cert` também usa
  `cli.key` como chave de gestão.
- `print_help()` documenta `--key <HEX>`, `--old-key <HEX>` e
  `piv-set-mgmt-key <NEW_KEY_HEX>`.
- **Não existe helper de prompt, detecção de TTY nem leitura de stdin** em
  `cli.rs`/`main.rs`. Diferente da premissa do achado para o script Python, o CLI
  Rust **não tem caminho default seguro**: `piv-set-mgmt-key` sempre exigiu o
  segredo em `argv`.
- `main.rs` imprime `error: {message}` em `stderr`; a mensagem não é sanitizada
  além do que cada chamador constrói. `main.rs` tem `#![forbid(unsafe_code)]`,
  então um prompt sem eco não pode ser implementado com `termios`/WinAPI local
  sem dependência ou sem `unsafe`.
- `cli.rs` **não tem** `#[cfg(test)]`. A suíte compilada do crate tem **15**
  testes hoje: 5 em `framing.rs`, 6 em `card.rs` e 4 em `piv_cmd.rs`.
- `oath_cmd.rs` existe e tem 15 testes, mas **não é declarado em `main.rs`**;
  portanto não é compilado nem executado por `cargo test -p aegistoken-host`.
  É outro item (fora desta fatia) e não deve ser tocado aqui.

#### `piv_cmd.rs` / `card.rs`

- `piv_set_mgmt_key(new_key_hex, old_key_hex, alg_arg, reader_filter)` começa
  parseando a chave nova com `card::parse_hex`; a antiga também. Os erros de
  comprimento/alg falam apenas de `len()` (seguro), mas `card::parse_hex`
  devolve `invalid hex byte '<dois caracteres>': ...`, isto é, **ecoa dois
  caracteres do segredo**.
- `piv_import_cert(slot_arg, cert_path, mgmt_key_hex, reader_filter)` usa o
  mesmo `card::parse_hex` para `--key`; o mesmo eco de dois caracteres vale ali.
- `--alg` é ecoado em erro (`unknown algorithm '{a}'`), mas não é segredo.
- Não há escrita de arquivo temporário, arquivo de configuração nem log de
  chave; a persistência do segredo no host é apenas `argv`/histórico.

#### `--help` e uso

- O help do CLI lista os flags de segredo e o positional de chave.
- O docstring de `set_pin.py` contém PINs literais de exemplo.
- O help é a principal "documentação executável" que ensina o caminho inseguro.

### 1.2 Caminho de exploração

1. O administrador provisiona o token em uma estação compartilhada, CI ou
   workstation e usa o caminho "não interativo" documentado:
   `python scripts/set_pin.py --set --pin <PIN>` ou
   `aegistoken-host piv-set-mgmt-key <NEW_KEY_HEX> --old-key <OLD_KEY_HEX>`.
2. Enquanto o processo vive, qualquer processo de mesmo usuário (ou root/admin)
   lê `argv` por `ps`, `/proc/<pid>/cmdline`, Gerenciador de Tarefas ou WMI. Num
   runner de CI, a linha de comando costuma ir para o log da tarefa.
3. Depois que o processo termina, o segredo continua no histórico do shell
   (`~/.bash_history`, histórico do PowerShell) e possivelmente em logs de
   terminal/CI. Um atacante local que não estava olhando no momento ainda o
   obtém.
4. Com o PIN do clientPIN, o atacante obtém token de UV/credential management;
   com a chave de gestão do PIV, exerce a autoridade administrativa do applet
   (trocar PIN/PUK, importar certificado, trocar a própria management key). O
   token precisa estar acessível para o uso, mas a chave costuma ser reutilizada
   no próximo provisionamento.
5. **Rejeitar `argv` não apaga o valor já digitado.** O caminho de remediação
   também é operacional: se um segredo foi usado por `argv`, ele deve ser
   rotacionado e o histórico limpo. O ferramental não tem como fazer isso pelo
   usuário.

**Impacto:** exposição local, não remota. O caminho Python default já era
seguro; o CLI Rust não era. A direção da correção é restritiva (recusar o
caminho inseguro), e o custo de compatibilidade é baixo porque não há chamada
em script/runbook do repositório — só exemplos de documentação.

---

## 2. Invariantes em risco

| # | Invariante | Origem | Estado hoje |
|---|-----------|--------|-------------|
| I1 | "Secrets are never exported or logged" — um segredo não pode sair pelo `argv`, que é um log do sistema operacional | `docs/security-model.md`, abertura | **violada** por `--pin`, `--old-pin`, `--key`, `--old-key` e pelo positional de `piv-set-mgmt-key` |
| I2 | "No secrets in logs or diagnostics" — o mesmo princípio vale para o ferramental de host | `docs/security-model.md`, invariantes de applet | **violada na prática**: histórico do shell e lista de processos são logs |
| I3 | Nunca registrar/comitar segredos (PINs, chaves) | `AGENTS.md`, regras | **violada** pelo caminho que ensina e aceita o segredo em `argv` |
| I4 | O caminho default de uma operação com segredo é o seguro; o caminho de automação é explícito e igualmente seguro | esta fatia | **parcialmente violada**: Python tem `getpass` default; o CLI Rust só tem o caminho inseguro |
| I5 | Mensagens de erro, usage, `Debug` e logs nunca revelam o valor do segredo; entradas inválidas reportam apenas a forma | `AGENTS.md` ("never log secrets"), `docs/security-model.md` | **violada** por `card::parse_hex` (dois caracteres) e pelo erro de opção desconhecida do CLI (eco do argumento inteiro, inclusive `--key=valor`) |
| I6 | O ferramental de host não cria cópia persistente do segredo (arquivo temporário, config, env) | `docs/security-model.md` ("Secrets are sealed at rest") e esta fatia | **respeitada** hoje; precisa continuar respeitada (sem `--key-file`, sem env) |

---

## 3. Decisões de política (documentadas nesta spec)

**1 — `argv` é recusado de forma dura; não há opt-in nem depreciação.** O
segredo **nunca** é aceito por `argv`. Fundamento:

- **Opt-in (`--insecure-key-argv`) não resolve:** quem tem um script antigo
  adiciona o flag e mantém exatamente a exposição; o flag vira documentação
  permanente do caminho inseguro.
- **Depreciação com warning não resolve:** o valor continua visível durante
  toda a janela de depreciação e o próprio warning normaliza o uso. Não há como
  medir quando é seguro remover.
- **Rejeição é testável e ensina a alternativa:** o erro aponta
  `--key-stdin`/`--old-key-stdin`/prompt e `--pin-stdin`/prompt. Um script antigo
  falha alto, em vez de vazar em silêncio.
- **A quebra é pequena dentro do repositório:** nenhum script ou runbook chama
  `set_pin.py` com `--pin`; as ocorrências são `validation.md` (exemplos) e o
  docstring. `piv-set-mgmt-key <NEW_KEY_HEX>` aparece em
  `docs/plano-desenvolvimento.md` e no histórico do `roadmap.md`; nenhum
  script o invoca. O custo externo é migrar para stdin/prompt, documentado na
  mesma mudança.
- **Rejeitar não desfaz o vazamento já ocorrido:** a documentação deve dizer
  que um segredo usado por `argv` precisa ser rotacionado (e o histórico
  limpo). Isso é limitação operacional, não motivo para manter o caminho.

**2 — Automação por stdin; não por env nem por arquivo.** Os canais seguros são:

- **Prompt interativo** (sem eco) quando há TTY e nenhum flag de stdin.
- **stdin** (`--pin-stdin`, `--old-pin-stdin`, `--key-stdin`,
  `--old-key-stdin`) para automação, alimentado por pipe/secret manager.

Fundamento para não usar env: o ambiente de um processo é legível por processos
do mesmo usuário (`/proc/<pid>/environ` no Linux; debugger/administrador no
Windows), é herdado por filhos e costuma ser capturado por CI/crash reporting.
Stdin é um canal do processo, não um estado global herdado. Fundamento para não
usar arquivo: `--key-file`/`--pin-file` criaria uma cópia persistente do segredo
no host, contrariando a política de segredo selado em repouso; o pipe de um
secret manager entrega o valor sem arquivo intermediário.

**3 — Prompt sem eco exige uma dependência pequena e host-only:
`rpassword`.** O crate tem `#![forbid(unsafe_code)]` em `main.rs` e não há API
de terminal no `std` que desligue o eco. As alternativas são:

- prompt com eco (`std::io::stdin().read_line`) — vaza para scrollback/log de
  terminal;
- `unsafe`/FFI de `termios`/WinAPI — proibido pelo `forbid(unsafe_code)` e
  contrário à regra de não introduzir `unsafe`;
- `rpassword` 7.5.x, licença **Apache-2.0** (compatível com a política
  permissiva do repositório, que aceita MIT ou Apache-2.0), dependência apenas
  de `crates/aegistoken-host`, sem impacto em `aegis-core`/`aegis-applets`.

Decisão: adicionar `rpassword` ao workspace e ao crate de host. Se a política
de dependências rejeitar a adição, o fallback é **não ter prompt no CLI Rust** e
exigir `--key-stdin`/`--old-key-stdin` (pior ergonomia, mesma segurança); não se
volta a `argv`.

**4 — Prompt e stdin são canais mutuamente exclusivos e conscientes do TTY.**
Para não transformar um pipe esquecido em prompt pendurado, nem um terminal em
leitura de segredo com eco:

- **Nenhum flag de stdin + TTY:** prompt interativo (sem eco).
- **Nenhum flag de stdin + sem TTY:** erro com código de uso, apontando o flag
  de stdin; não lê stdin, não abre dispositivo, não pendura.
- **Flag de stdin + sem TTY:** lê o número de linhas documentado.
- **Flag de stdin + TTY:** erro "use o prompt ou redirecione a entrada"; um
  `--key-stdin` digitado no terminal teria eco e anularia o benefício.

**5 — `scripts/set_pin.py` mantém `getpass` como default e ganha stdin
explícito.**

- `--pin` e `--old-pin` (nas formas `--pin VALOR` e `--pin=VALOR`) são
  **recusados** com código 2 e mensagem que não ecoa o valor, apontando
  `--pin-stdin`/`--old-pin-stdin` e o prompt.
- `--pin-stdin` e `--old-pin-stdin` leem uma linha cada de stdin; o modo stdin
  é **tudo ou nada**: em `--change`, os dois flags são obrigatórios; em
  `--set`, só `--pin-stdin`; `--retries` não aceita flag de segredo. Nada de
  misturar prompt com stdin na mesma execução.
- Ordem no modo stdin de `--change`: **PIN atual primeiro, PIN novo depois**
  (a mesma ordem do prompt atual).
- O default sem flags continua `getpass` (PIN atual, depois novo em
  `--change`), mas com checagem de TTY: sem TTY e sem flags, erro 2 em vez de
  prompt/eco.
- `--help`/`-h` passa a existir, imprime usage sem PIN literal e sai 0. O help
  é processado antes do uso de qualquer segredo: se vier acompanhado de um flag
  de segredo, apenas imprime o help, sem ler nem ecoar o valor.
- Opções desconhecidas passam a ser erro (não mais ignoradas); o erro mostra
  apenas o nome da opção, nunca o valor inline.
- O import de `fido2` é adiado para depois do parse/help, para que o parser seja
  testável em host sem a dependência opcional e para que erros de uso não
  dependam dela.

**6 — `aegistoken-host piv-set-mgmt-key` não aceita secreto em `argv` e não
aceita positional nenhum.**

- A chave nova é obrigatória e vem de `--key-stdin` (pipe) ou do prompt (TTY).
- A chave antiga é opcional: `--old-key-stdin` (pipe, lida **depois** da nova)
  ou prompt (TTY, vazio = chave padrão NIST). Sem `--old-key-stdin` no modo
  stdin, usa a `DEFAULT_MGMT_KEY` (comportamento atual preservado). Linha vazia
  em `--old-key-stdin` é erro; para a chave padrão, omita o flag.
- `--old-key-stdin` sem `--key-stdin` é erro: não há como ler a antiga e
  promptar a nova na mesma execução.
- **Qualquer positional de `piv-set-mgmt-key` é rejeitado**, inclusive o antigo
  `<NEW_KEY_HEX>`. A seleção de leitor vai para `--reader <SUBSTR>`, porque
  reutilizar o primeiro positional como filtro de leitor faria
  `connect_card` ecoar o segredo em `no reader matching '<segredo>' found`
  (`card.rs`). `--reader` é específico deste comando; em outro comando é erro
  de uso.
- `piv-import-cert` mantém o comportamento sem `--key`: usa a
  `DEFAULT_MGMT_KEY` (chave pública de interop). `--key` é recusado; uma chave
  diferente da padrão vem de `--key-stdin` (uma linha, pipe). Não há prompt
  nesse comando para não transformar uma importação não interativa em
  interativa.
- `--alg` continua válido para a chave nova; a inferência por comprimento
  (16→AES-128, 24→TDES, 32→AES-256) continua a mesma, e o erro de
  comprimento/alg reporta apenas números.

**7 — Erros, usage, `Debug` e logs nunca ecoam o segredo.**

- Erros de forma reportam só a forma: "esperado 32 caracteres hex (16 bytes);
  recebido 12" ou "esperado hexadecimal". O parser de segredo **não** reutiliza
  `card::parse_hex`, que ecoa dois caracteres do valor.
- Opção desconhecida reporta apenas o nome (`--key`), nunca o token inteiro
  (`--key=valor`).
- Nenhum tipo que carrega material secreto deriva `Debug` que imprima bytes;
  `Cli` continua sem `Debug`.
- No Python, exceções de chamadas que receberam segredo passam por um
  `redact_secrets(texto, segredos)` antes de ir para `stderr`; o teste usa um
  valor sentinela. Se a exceção não puder ser sanitizada com segurança, o
  código imprime apenas a classe/status CTAP.
- Nada de `println!`/`eprintln!` com chave/PIN; nada de arquivo temporário,
  config ou env. O único estado do segredo é o buffer de aquisição, descartado
  depois do uso.

**8 — Fronteiras: só host.** Nenhuma mudança de protocolo Management HID, CCID,
PIV ou CTAP2; nenhum arquivo de firmware, HAL, `aegis-core` ou
`aegis-applets`. O crate de host continua com `#![forbid(unsafe_code)]`; a
exceção de dependência é `rpassword` (decisão 3). `oath_cmd.rs` e
`scripts/validate_fido.py --pin` são explicitamente **fora** (não-objetivos 1 e
2).

**Tabela de comportamento por caminho**

| Caminho | Hoje | Depois |
|---|---|---|
| `set_pin.py --set --pin V` | aceita e usa `V` do `argv` | **erro 2**, sem eco, aponta `--pin-stdin`/prompt |
| `set_pin.py --change --old-pin A --pin B` | aceita `A`/`B` do `argv` | **erro 2**, sem eco, aponta os flags de stdin/prompt |
| `set_pin.py --set` (TTY) | `getpass` | idêntico |
| `set_pin.py --set` (sem TTY) | `getpass` pode ler/ecoar ou pendurar | **erro 2** com instrução de stdin |
| `set_pin.py --set --pin-stdin` (pipe, sem TTY) | não existe | lê uma linha e usa |
| `set_pin.py --change --old-pin-stdin --pin-stdin` (pipe) | não existe | lê atual, depois novo |
| `set_pin.py --help --pin V` | ignora o help e tenta usar `V` | help 0, sem eco de `V` |
| `piv-set-mgmt-key K` | usa `K` do positional | **erro**, sem eco, aponta `--key-stdin`/prompt |
| `piv-set-mgmt-key --key K` / `--key=K` | usa `K` | **erro**, sem eco |
| `piv-set-mgmt-key --old-key K` | usa `K` | **erro**, sem eco |
| `piv-set-mgmt-key --key-stdin` (pipe) | não existe | lê a chave nova; antiga = padrão NIST |
| `piv-set-mgmt-key --key-stdin --old-key-stdin` (pipe) | não existe | lê nova, depois antiga |
| `piv-set-mgmt-key` (TTY, sem flags) | erro por falta do positional | prompt novo (2×) + antigo (vazio = padrão) |
| `piv-set-mgmt-key` (sem TTY, sem flags) | erro por falta do positional | erro com instrução de stdin |
| `piv-import-cert ... --key K` | usa `K` | **erro**, sem eco |
| `piv-import-cert ...` (sem chave) | `DEFAULT_MGMT_KEY` | idêntico |
| `piv-import-cert ... --key-stdin` (pipe) | não existe | lê uma linha e usa |
| chave hex inválida | ecoa 2 caracteres | erro de forma, sem valor |
| opção desconhecida `--x=V` | ecoa `--x=V` | ecoa apenas `--x` |

---

## 4. Escopo

- `scripts/set_pin.py`:
  - `parse_args`: recusar `--pin`/`--old-pin` (com e sem `=`), aceitar
    `--pin-stdin`/`--old-pin-stdin`, `--help`, erro de opção desconhecida sem
    eco; devolver fontes, não valores.
  - `main`: selecionar prompt (`getpass`) ou stdin conforme TTY e flags; ordem
    atual→novo; erro de uso com código 2; import de `fido2` adiado; scrubbing de
    exceções.
  - Docstring/uso sem PIN literal.
- `crates/aegistoken-host/src/cli.rs`:
  - `Cli`: remover `key`/`old_key` como `String`; guardar fontes de segredo
    (`stdin`/`prompt`) e `reader` para `piv-set-mgmt-key`.
  - `parse`: recusar `--key`/`--old-key` (inclusive `=`), aceitar
    `--key-stdin`/`--old-key-stdin`/`--reader`, recusar positional de
    `piv-set-mgmt-key`; erro de opção desconhecida só com o nome.
  - `run`: resolver a chave antes de chamar `piv_cmd`; rejeitar positional;
    usar `--reader`; não abrir dispositivo se a aquisição falhar.
  - `print_help`: remover os flags/positional de segredo; documentar prompt,
    stdin, `--reader` e que `argv` é recusado.
  - `#[cfg(test)] mod tests` novo, com testes de parsing e de aquisição
    injetada (sem TTY, sem hardware).
- `crates/aegistoken-host/src/secret.rs` (novo módulo privado, declarado em
  `main.rs`):
  - leitura de uma linha de um `Read` injetável (remove `\r\n`, rejeita vazio);
  - parser hex de segredo com erros **só de forma** (sem reutilizar
    `card::parse_hex`);
  - prompt fino sobre `rpassword` (não chamado nos testes de unidade).
- `crates/aegistoken-host/src/piv_cmd.rs`:
  - `piv_set_mgmt_key`: receber a chave nova/antiga já resolvida (bytes), não a
    string de `argv`; manter a inferência de alg e as validações de
    comprimento; erros só com números.
  - `piv_import_cert`: receber o material da chave de gestão já resolvido
    (bytes), em vez da string de `argv`; sem `--key`; sem mudança de APDU.
- `crates/aegistoken-host/src/main.rs`: declarar `mod secret;`; nenhuma mudança
  de `forbid(unsafe_code)`.
- `Cargo.toml` (workspace) e `crates/aegistoken-host/Cargo.toml`: adicionar
  `rpassword` (host-only).
- `tests/test_set_pin_args.py` (novo): testes do parser/leitura/redação do
  script Python.

## 5. Não-objetivos

1. **`scripts/validate_fido.py --pin`.** É o mesmo padrão (PIN em `argv`), mas
   é um harness de validação com outros chamadores e outra matriz de testes;
   fica registrado como follow-up no `roadmap.md`, não nesta fatia.
2. **`crates/aegistoken-host/src/oath_cmd.rs`.** Existe e tem 15 testes, mas
   **não está declarado em `main.rs`** (não compila). Se for ligado ao CLI,
   precisa da mesma política para o segredo do `otpauth://`; é outro item.
3. **Cofre de segredos, keyring do SO, env vars, `--key-file`/`--pin-file`.**
   A decisão é stdin/prompt; nenhuma cópia persistente nova.
4. **`unsafe`/FFI para prompt.** Proibido pelo `forbid(unsafe_code)`; a
   dependência `rpassword` é a alternativa.
5. **Mudanças de protocolo, firmware, HAL, `aegis-core`/`aegis-applets`,
   Management HID, CCID, PIV/CTAP2, rollback floor do update de firmware.**
   Nada além do parsing/entrada de segredo e documentação.
6. **Rotacionar automaticamente segredos que já vazaram, limpar histórico do
   shell ou reescrever `argv` do processo.** Fora do alcance da ferramenta; a
   documentação orienta a rotação/limpeza.
7. **Zeroização de memória/`mlock`/proteção contra dump de processo.** O
   objetivo é tirar o segredo do `argv`; a memória do processo continua fora
   do escopo (limitação registrada).
8. **Mudar a `DEFAULT_MGMT_KEY`, a inferência de algoritmo ou o comportamento
   do `piv-import-cert` sem chave.** A chave padrão NIST e o default da
   importação continuam iguais.
9. **Depreciação, opt-in (`--insecure-key-argv`) ou warning em vez de erro.**
   A política é rejeitar (decisão 1).
10. **Novas dependências além de `rpassword`.** Não há necessidade de
    `clap`, `dialoguer`, `secrecy`/`zeroize` para esta fatia.
11. **Validação em hardware.** Todos os ACs são de host; não há APDU novo, não
    há `cargo build-fw` e não há pendência física.

## 6. Critérios de aceitação

Todos os ACs são observáveis em host, sem token e sem `python-fido2`
(quando aplicável). AC-1..AC-5 são testes de unidade/integração de parsing e de
aquisição; AC-6 é documentação/estática; AC-7 são os gates.

| AC | Critério | Observabilidade |
|----|----------|-----------------|
| **AC-1** | **CLI Rust recusa todo segredo em `argv`:** `piv-set-mgmt-key <SENTINEL_HEX>`, `piv-set-mgmt-key --key <SENTINEL>`, `--old-key <SENTINEL>`, `--key=<SENTINEL>` e `--old-key=<SENTINEL>` retornam erro de parsing (`run` devolve `Err`, exit != 0), **sem** ecoar o sentinela em `stdout`/`stderr`, e a mensagem contém `--key-stdin`/`--old-key-stdin`/prompt. `piv-import-cert 9A cert.pem --key <SENTINEL>` idem. Nenhum caminho abre USB/PC-SC antes do erro | `#[cfg(test)]` de `cli.rs` chamando `parse`/`run` com `Vec<String>`; teste de ausência do sentinela |
| **AC-2** | **stdin é o caminho de automação, sem TTY e sem hardware:** `piv-set-mgmt-key --key-stdin` lê uma linha de um `Read` injetado (`Cursor`/`&[u8]`), remove `\r\n`, e entrega exatamente os bytes do sentinela; `--old-key-stdin` lê a linha seguinte (nova primeiro, antiga depois); sem `--old-key-stdin`, a antiga é `DEFAULT_MGMT_KEY`; `--old-key-stdin` sem `--key-stdin` é erro; linha vazia e hex inválido/tamanho errado falham com mensagem de forma (sem valor); `piv-import-cert --key-stdin` é aceito na camada de aquisição/parse e resolve a mesma chave | Testes de `secret.rs` e `cli.rs` com leitor fake; sem TTY, sem placa |
| **AC-3** | **Prompt só com TTY e sem mistura de canais:** sem flags de stdin e TTY=true, a fonte é prompt (novo duas vezes, antigo uma vez; vazio = NIST default); sem flags e TTY=false → erro de uso apontando `--key-stdin`, sem ler stdin e sem pendurar; flag de stdin com TTY=true → erro "use o prompt ou redirecione"; `--old-key-stdin` com TTY=true e sem `--key-stdin` → erro. No `set_pin.py`, o `getpass` atual é preservado; no CLI Rust o prompt é novo. A decisão de fonte é injetável (`is_terminal`/leitor) e testada; o prompt real (sem eco) é verificado manualmente em terminal | Testes de unidade com `is_terminal` falso/verdadeiro; smoke manual documentado em `validation.md` |
| **AC-4** | **`set_pin.py` recusa `--pin`/`--old-pin` e funciona por stdin/prompt:** `--pin V`, `--old-pin V`, `--pin=V` e `--old-pin=V` saem com código 2, sem eco de `V`, apontando `--pin-stdin`/`--old-pin-stdin`/prompt; `--help` sai 0 e não mostra PIN literal; `--set --pin-stdin` lê uma linha; `--change --old-pin-stdin --pin-stdin` lê atual e depois novo; modo stdin incompleto é erro (não prompta); `--retries` com flag de segredo é erro; sem flags e sem TTY → erro 2 (não pendura nem ecoa); sem flags e com TTY → `getpass` (default preservado); o import de `fido2` é adiado e o parse/erro funciona sem o pacote | `tests/test_set_pin_args.py` (unittest, sem `fido2`) + subprocesso `--help`/`--pin`; `python -m py_compile` |
| **AC-5** | **Nenhuma mensagem de erro/usage/`Debug`/log emite o segredo:** um sentinela (PIN e chave hex) nunca aparece em `stdout`/`stderr` nos caminhos de AC-1..AC-4; erros de hex/tamanho reportam apenas a forma; opção desconhecida `--x=SENTINELA` reporta só `--x`; `card::parse_hex` não é usado para segredo; nenhum tipo que carrega segredo deriva `Debug` imprimível; nenhum arquivo temporário/config é criado; no Python, uma exceção sintética contendo o sentinela é redigida por `redact_secrets` | Testes com valor sentinela e `assert!(!saida.contains(SENTINELA))`; revisão estática de `#[derive(Debug)]`/`println!` |
| **AC-6** | **Documentação de usuário atualizada na mesma mudança:** `README.md` (validação/CLI), `validation.md` (scripts de host, PIN, ferramenta Rust, linha **AC-034**, limitações), `docs/plano-desenvolvimento.md` (sintaxe de `piv-set-mgmt-key`/`piv-import-cert`), `roadmap.md` (Fase 18 entregue + follow-ups), `docs/security-model.md` (seção de host tooling), `production.md` (chave de gestão por prompt/stdin) e `docs/pesquisa-bibliotecas.md` (`rpassword`, Apache-2.0). Nenhum exemplo novo desta fatia usa segredo em `argv`; os exemplos antigos de `set_pin.py` e do CLI são substituídos. `validate_fido.py --pin` é preservado nesta fatia e registrado como follow-up (não é "exemplo novo") | Revisão estática/grep; `--help` do CLI e do script conferidos |
| **AC-7** | **Sem regressão e gates verdes:** `cargo fmt --all --check`; `cargo clippy -p aegistoken-host --all-targets -- -D warnings`; `cargo test -p aegistoken-host` (15 testes compilados hoje + os novos; contagem exata registrada em `roadmap.md`/`validation.md`); `python -m py_compile scripts/set_pin.py`; `python tests/test_set_pin_args.py`; `cargo build-fw` **não** é exigido (nenhum arquivo de firmware/HAL muda). `oath_cmd.rs` continua fora da compilação, como hoje | Comandos de gate abaixo |

## 7. Plano de teste

### 7.1 Onde ficam

- **`crates/aegistoken-host/src/cli.rs`** — novo `#[cfg(test)] mod tests` (o
  arquivo não tem testes hoje). Acessa `parse`, `Cli` e os helpers privados do
  módulo; não abre dispositivo.
- **`crates/aegistoken-host/src/secret.rs`** — novo módulo com
  `#[cfg(test)] mod tests` para leitura de linha e parser hex de segredo. Usa
  `std::io::Cursor`/`&[u8]`; nenhum TTY e nenhuma placa.
- **`crates/aegistoken-host/src/piv_cmd.rs`** — o módulo `tests` existente
  ganha, se necessário, um caso para a resolução de chave padrão/bytes; os
  testes de APDU continuam os mesmos (não há hardware).
- **`tests/test_set_pin_args.py`** — `unittest` puro (sem `pytest`), com
  `sys.path` para `scripts/`; importa `set_pin` sem `fido2` (import adiado) e
  usa `io.StringIO`/`subprocess` para os casos de help/erro. É executável com
  `python tests/test_set_pin_args.py`.

Nada de infraestrutura nova de hardware; nenhum teste precisa de `rpassword`
real (o prompt é uma função fina, e a decisão de fonte é testada com
`is_terminal` injetado). Os nomes de helpers usados em §7.2 são ilustrativos;
o contrato é o comportamento descrito nos ACs, não a assinatura.

### 7.2 Como os casos são montados

- **AC-1:** `parse(vec!["piv-set-mgmt-key", SENTINEL])` → `Err` cuja mensagem
  não contém `SENTINEL` e contém `--key-stdin`; idem para `--key`, `--old-key`,
  `--key=SENTINEL`, `--old-key=SENTINEL`; `piv-import-cert` com `--key` idem.
  Um teste de `run` confirma que o erro de parsing vence a abertura do
  dispositivo (não há mensagem de "no reader"/USB).
- **AC-2:** `secret::read_secret_line(&mut Cursor::new(b"SENTINEL\r\n"))` →
  `b"SENTINEL"`; linha vazia → `Err`; `secret::parse_secret_hex("SENTINEL", 32)`
  → erro sem `SENTINEL`; `parse_secret_hex` de 32 hex válidos → bytes;
  `--key-stdin --old-key-stdin` com `"NOVA\nANTIGA\n"` → nova/antiga na ordem;
  `--key-stdin` sem antiga → `DEFAULT_MGMT_KEY`; `--old-key-stdin` sozinho →
  erro. O leitor é injetado; nenhum `std::io::stdin` real.
- **AC-3:** helper de decisão `(flags, is_terminal) -> Source`:
  `(nenhum, true) -> Prompt`, `(nenhum, false) -> Err`, `(stdin, true) -> Err`,
  `(old_stdin sem key_stdin, true) -> Err`; o prompt real não é chamado no
  teste. Smoke manual: rodar `aegistoken-host piv-set-mgmt-key` em um terminal e
  confirmar que a chave não aparece na tela; documentar em `validation.md`.
- **AC-4:** `set_pin.parse_args(["--pin", SENTINEL])` → erro de uso sem
  `SENTINEL`; idem `--old-pin`, `--pin=SENTINEL`; `parse_args(["--help"])` →
  help/0; `parse_args(["--set", "--pin-stdin"])` → fonte stdin;
  `parse_args(["--change", "--pin-stdin"])` → erro de modo incompleto;
  `read_secret_line(StringIO("SENTINEL\n"))` → `SENTINEL`;
  `--change --old-pin-stdin --pin-stdin` com `"ATUAL\nNOVO\n"` → atual/novo;
  `redact_secrets("falha: SENTINEL", [SENTINEL])` não contém `SENTINEL`;
  subprocesso `python scripts/set_pin.py --help` sai 0 e não mostra `--pin `;
  subprocesso `--pin SENTINEL` sai 2 e não ecoa.
- **AC-5:** sentinela distinto para PIN (`S3NT1N3L-PIN`) e chave
  (`DEADBEEF...`); capturar `stdout`/`stderr` de cada caminho e afirmar
  ausência. Revisão estática: `rg 'println!|eprintln!|Debug'` nos tipos de
  segredo; confirmar que `card::parse_hex` não é chamado nos caminhos de chave.
- **AC-6:** grep pelos comandos antigos em `README.md`, `validation.md`,
  `docs/plano-desenvolvimento.md`, `production.md`, `roadmap.md` e
  `docs/security-model.md`; nenhum exemplo novo com `--pin VALOR`,
  `--key VALOR` ou `<NEW_KEY_HEX>`.
- **AC-7:** rodar os gates; se a contagem divergir, atualizar a evidência na
  mesma mudança.

Nomes sugeridos (o implementador pode ajustar):
`cli_rejects_argv_secrets_without_echoing_them`,
`stdin_key_source_reads_new_then_old_without_tty`,
`prompt_is_selected_only_for_a_tty`,
`set_pin_rejects_argv_pins_and_reads_stdin`,
`secret_errors_report_shape_not_value`,
`secret_material_is_not_debug_printed`,
`set_pin_help_has_no_literal_pin`.

### 7.3 Comandos de gate

```powershell
cargo fmt --all --check
cargo clippy -p aegistoken-host --all-targets -- -D warnings
cargo test -p aegistoken-host
python -m py_compile scripts/set_pin.py
python tests/test_set_pin_args.py
```

Suíte atual de `aegistoken-host`: **15** testes compilados (5 `framing`, 6
`card`, 4 `piv_cmd`). Os 15 testes de `oath_cmd.rs` **não** entram porque o
módulo não é declarado em `main.rs`; isso é registrado, não corrigido aqui.
`cargo build-fw` não é exigido: nenhum arquivo de firmware/HAL muda e nenhuma
assinatura pública do domínio é tocada. Se o workspace recusar `rpassword`,
o fallback da decisão 3 remove o prompt do CLI e mantém apenas stdin; os ACs de
stdin/erro continuam válidos, o AC-3 muda para "sem prompt" e deve ser
registrado na mesma mudança.

---

## 8. Arquivos afetados

| Arquivo | Motivo |
|---------|--------|
| `scripts/set_pin.py` | parser sem `--pin`/`--old-pin`; `--pin-stdin`/`--old-pin-stdin`; `--help`; TTY; import adiado; scrub de exceção; docstring sem PIN literal |
| `crates/aegistoken-host/src/cli.rs` | remoção de `key`/`old_key` como `String`; recusa de `argv` e positional; `--key-stdin`/`--old-key-stdin`/`--reader`; help seguro; testes de unidade |
| `crates/aegistoken-host/src/secret.rs` (novo) | leitura de linha, parser hex de segredo com erro só de forma, wrapper de prompt |
| `crates/aegistoken-host/src/piv_cmd.rs` | `piv_set_mgmt_key`/`piv_import_cert` recebem bytes resolvidos; erros sem valor; sem mudança de APDU |
| `crates/aegistoken-host/src/main.rs` | `mod secret;`; `forbid(unsafe_code)` mantido |
| `Cargo.toml`, `crates/aegistoken-host/Cargo.toml` | `rpassword` (Apache-2.0, host-only) |
| `tests/test_set_pin_args.py` (novo) | testes de parsing/leitura/redação do script Python |
| `README.md`, `validation.md`, `roadmap.md`, `docs/security-model.md`, `docs/plano-desenvolvimento.md`, `production.md`, `docs/pesquisa-bibliotecas.md` | documentação na mesma mudança (§9) |

Nada é alterado em `crates/aegis-core/**`, `crates/aegis-applets/**`,
`crates/firmware-universal-rp2350/**`, `crates/board-generic-rp2350/**`,
`crates/aegistoken-host/src/oath_cmd.rs` ou nos protocolos Management HID/CCID.
Nenhum despacho de firmware muda.

## 9. Documentação a atualizar (na mesma mudança)

1. **`docs/security-model.md`** — nova seção curta **Host tooling** (depois de
   "Backup scope", antes dos invariantes de FIDO), registrando como decisão
   aceita: (a) PINs, chaves de gestão do PIV e segredos de credencial **nunca**
   são aceitos em `argv`; (b) o caminho interativo é prompt sem eco e o de
   automação é stdin (`--pin-stdin`, `--old-pin-stdin`, `--key-stdin`,
   `--old-key-stdin`); (c) env, arquivo e opt-in inseguro não são oferecidos;
   (d) erros/usage/`Debug`/logs reportam apenas a forma, nunca o valor; (e) o
   ferramental não cria cópia persistente do segredo; (f) a política é do host
   e não altera o protocolo do dispositivo; (g) um segredo que já passou por
   `argv` deve ser rotacionado, porque a rejeição não apaga o histórico.
2. **`roadmap.md`** — Fase 18 (**Ferramental de host**), seção **Entregue**:
   acrescentar a sub-fatia "segredos fora do argv" (recusa de `--pin`/
   `--old-pin`/`--key`/`--old-key`/positional, stdin e prompt, help seguro,
   `rpassword`, testes de host) e a contagem de testes do crate. Na seção
   **Pendências**, registrar dois follow-ups: `scripts/validate_fido.py --pin`
   (mesma classe, harness de validação) e `oath_cmd.rs` (não declarado em
   `main.rs`; ao ligá-lo, aplicar a mesma política ao segredo do `otpauth://`).
   Não criar pendência física.
3. **`validation.md`** — (a) em **Scripts de host**, trocar os exemplos
   `set_pin.py --pin`/`--old-pin` por prompt e `--pin-stdin`/`--old-pin-stdin`;
   (b) em **PIN (clientPIN)**, atualizar o bloco "não-interativo" com o fluxo
   seguro e a nota de que `argv` é recusado; (c) em **Ferramenta de host em
   Rust (libusb)**, documentar `piv-set-mgmt-key --key-stdin [--old-key-stdin]
   [--reader SUBSTR]`, `piv-import-cert --key-stdin` e o comportamento do
   prompt/TTY; (d) na **Matriz de critérios**, acrescentar a linha **AC-034**
   com o resumo desta fatia (método: testes de host de
   `aegistoken-host::cli`/`secret` e `tests/test_set_pin_args.py`; status
   **Verificado em host**); (e) em **Limitações conhecidas**, registrar que
   `argv` já exposto não é apagado pela rejeição (rotacionar/limpar histórico)
   e que `validate_fido.py --pin`/`oath_cmd.rs` ficam como follow-up.
4. **`README.md`** — na seção de validação/CLI, uma nota curta: segredos são
   pedidos por prompt ou stdin, nunca por `argv`; `set_pin.py` sem flags
   prompta; automação usa `--pin-stdin`. Não adicionar exemplo com PIN literal.
5. **`docs/plano-desenvolvimento.md`** — atualizar a sintaxe de
   `piv-set-mgmt-key` (sem `<NEW_KEY_HEX>`; `--key-stdin`/`--old-key-stdin`/
   `--reader`) e a de `piv-import-cert` (`--key-stdin` em vez de `--key`),
   mantendo a descrição de algoritmos.
6. **`production.md`** — na linha da management key do PIV, apontar que a troca
   usa prompt/stdin e que a chave padrão NIST é pública; não mostrar comando
   com segredo em `argv`.
7. **`docs/pesquisa-bibliotecas.md`** — registrar `rpassword` 7.5.x
   (`Apache-2.0`, host-only) como dependência adotada para prompt sem eco,
   justificando a exceção à preferência por `MIT OR Apache-2.0` (a política
   aceita Apache-2.0) e o motivo de não usar `unsafe`/FFI.

## 10. Riscos e limitações

### 10.1 Riscos de implementação

- **R1 — Quebra de scripts externos.** `set_pin.py --pin` e
  `piv-set-mgmt-key <HEX>` deixam de funcionar. Dentro do repositório não há
  chamador em script/runbook (só documentação), mas usuários externos podem ter
  automação. Mitigação: erro alto e claro, exemplos de migração para stdin na
  mesma mudança, e nenhuma janela de depreciação que mantenha o vazamento.
- **R2 — O valor já foi exposto antes do erro.** Quando o usuário digita
  `--key SEGREDO`, o processo já nasceu com o segredo em `argv`; a rejeição
  impede o uso e o eco, não o vazamento ocorrido. A documentação precisa dizer
  para rotacionar o segredo e limpar o histórico; o teste não pode provar isso.
- **R3 — Dependência `rpassword`.** É uma dependência nova (Apache-2.0,
  host-only, ~21 KiB), com dependências transitivas de plataforma. Se a
  política de licenças/dependências a recusar, o fallback é stdin-only (sem
  prompt) — pior ergonomia, mesma segurança. Não se volta a `argv`.
- **R4 — stdin não é automaticamente secreto.** `echo SEGREDO | tool` coloca o
  segredo no histórico do shell e, dependendo do shell, na linha de comando do
  processo pai; `printf`/variável de ambiente têm o mesmo problema. Os
  documentos devem recomendar prompt ou um secret manager que escreva no pipe
  (`secret-tool`, `Get-Credential`), não `echo`. O ferramental não consegue
  distinguir a origem do pipe.
- **R5 — Scrub de exceção no Python é best-effort.** `redact_secrets` substitui
  as representações exatas dos segredos fornecidos; uma exceção que transforme
  o valor (hex, base64, truncamento) pode escapar. Mitigação: não interpolar o
  segredo em mensagens próprias e, para chamadas sensíveis, preferir
  classe/status CTAP a `str(exc)`; o teste sentinela cobre o caso comum.
- **R6 — `piv-set-mgmt-key` perde a ergonomia do leitor positional.** A
  seleção de leitor passa a `--reader <SUBSTR>` para que um segredo antigo não
  seja interpretado como filtro e ecoado por `connect_card`. Scripts que
  passavam o leitor como segundo positional também quebram; a documentação
  mostra a nova forma.
- **R7 — `oath_cmd.rs` não está no build.** A revalidação mostra que seus 15
  testes não rodam; não é regressão desta fatia, mas significa que a política
  de segredo não está aplicada ao OATH do CLI. Fica como follow-up explícito;
  não "consertar" o módulo aqui para não misturar duas mudanças.

### 10.2 Limitações

- **L1 — Sem hardware neste ciclo.** Todos os ACs são de host; não há APDU novo,
  não há `cargo build-fw` e não há pendência física. O prompt real sem eco é
  verificado manualmente em terminal; a decisão de fonte é testada por injeção.
- **L2 — O segredo continua na memória do processo.** A fatia tira o segredo do
  `argv`, não implementa `mlock`, zeroização garantida ou proteção contra dump.
  A memória do host continua no modelo de ameaça local.
- **L3 — O histórico do shell é do usuário.** A ferramenta não limpa
  `~/.bash_history`, histórico do PowerShell ou logs de CI; só evita criar novas
  entradas com o valor. A orientação de rotação/limpeza é documental.
- **L4 — `set_pin.py` depende de `getpass` para o prompt.** O comportamento do
  `getpass` varia por plataforma (aviso quando não há TTY); a checagem explícita
  de TTY antes do prompt transforma o caso não interativo em erro 2, mas o
  prompt em si continua sendo o do `getpass` (sem confirmação do novo PIN, como
  hoje).
- **L5 — A política não cobre `validate_fido.py` nem `oath_cmd.rs`.** Ambos são
  follow-ups registrados; até lá, o PIN do validador e o segredo do OATH (se o
  módulo for ligado) ainda podem ser passados em `argv`. A documentação desta
  fatia não deve apresentá-los como seguros.
- **L6 — Sem estado novo, sem segredo novo, sem protocolo novo.** A fatia não
  persiste nada, não muda o blob, não cria SW/APDU e não altera defaults de
  PIV/FIDO/OATH.
