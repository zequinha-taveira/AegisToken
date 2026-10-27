# Spec — PIN fora do argv no validador FIDO

> **Origem:** follow-up da fatia `specs/host-secrets-not-in-argv.md` (AC-034) e
> item da fila em `roadmap.md`. `scripts/validate_fido.py` ainda aceita
> `--pin <PIN>` em `argv`: a linha de comando é visível para outros processos
> locais (`ps`, `/proc/<pid>/cmdline`, Gerenciador de Tarefas, WMI) e fica no
> histórico do shell. HEAD de referência: **`93f2854`**.
> **Risco:** MÉDIO no modelo local. O PIN do clientPIN libera UV, credential
> management e `changePIN`; quem o obtém pode girar o PIN e tomar a credencial.
> A exposição é trivial e a correção é local, com a mesma disciplina já
> aplicada a `set_pin.py` e ao `aegistoken-host`. O validador roda em hardware,
> então a mudança precisa manter o modo presença-apenas (sem PIN) intacto.

---

## 1. Estado atual (confirmado no código)

- `scripts/validate_fido.py` importa `python-fido2` no topo e chama `sys.exit(2)`
  se a dependência faltar; por isso o módulo não é importável num host sem
  `fido2` (o CI instala apenas `pytest` e `cryptography`).
- `parse_args(argv)` varre `argv` e devolve o valor seguinte a `--pin` como
  `str | None`. Não há `--pin-stdin`, `--pin-prompt`, rejeição de
  `--pin=VALUE` nem de `-pin=VALUE`.
- `main()` usa `sys.argv[1:]` e não recebe `argv` injetável.
- Não há prompt oculto: o PIN só entra por `--pin`.
- `record()` imprime o detalhe da falha; não há redação de segredo. Em
  `check_change_pin`, a falha de restauração imprime o PIN temporário completo.
- `--help` não é tratado: o script não tem `USAGE` nem caminho de ajuda.
- O modo sem `--pin` é presença-apenas e **deve continuar sendo o padrão**.

---

## 2. Decisões

1. **Canais explícitos e sem valor em `argv`:**
   - `--pin-stdin`: lê uma linha do stdin (pipe; recusa TTY);
   - `--pin-prompt`: lê por prompt oculto (`getpass`; exige TTY);
   - sem nenhum dos dois: presença-apenas, como hoje.
2. **`--pin` e `--old-pin` são recusados** em `--opt valor`, `--opt=valor` e
   no typo de um dash (`-pin=valor`), sem ecoar o valor. A mensagem aponta
   `--pin-stdin`/`--pin-prompt`. O validador só precisa do PIN atual (o
   `changePIN` gira e restaura sozinho), então `--old-pin` não é aceito.
3. **Flags mutuamente exclusivas.** `--pin-stdin` + `--pin-prompt` é erro de
   uso; `--pin-stdin` com TTY e `--pin-prompt` sem TTY são erros, nunca
   fallback silencioso.
4. **`--help` vence qualquer flag de segredo** e não lê nem ecoa o valor.
5. **Import guardado:** o `import fido2` deixa de derrubar o módulo no import;
   `main()` devolve 2 com a mensagem de dependência. Isso torna o parser
   testável no CI sem `fido2` e mantém o comportamento de execução.
6. **Redação:** o PIN adquirido entra em `SECRETS` e `record()` redige todo
   detalhe antes de imprimir. A falha de restauração do `changePIN` não imprime
   mais o PIN temporário; informa a regra (último dígito trocado para 0/1) para
   o usuário reconstruir o valor a partir do PIN que ele conhece.

---

## 3. Invariantes

- I1: o PIN nunca aparece em `argv`, `stdout`, `stderr` ou log.
- I2: o canal é stdin (pipe) ou prompt oculto; TTY e pipe não se misturam.
- I3: erro de uso descreve a forma (flag, canal, linha vazia), nunca o valor.
- I4: sem flags, o validador continua presença-apenas (nenhuma leitura de PIN).
- I5: a ausência de `python-fido2` continua retornando código 2 em execução.
- I6: os checks FIDO/CTAP e o firmware não mudam.

---

## 4. Critérios de aceitação

| AC | Critério | Verificação |
|----|----------|-------------|
| AC-1 | `--pin`/`--old-pin` são recusados nas formas `--opt valor`, `--opt=valor` e `-opt=valor`, sem ecoar o valor | testes de `parse_args` com sentinela |
| AC-2 | `--pin-stdin` lê uma linha (sem line ending), recusa TTY, rejeita linha vazia/stdin fechado; `--pin-prompt` exige TTY e usa `getpass`; as duas flags juntas erram | testes de `_acquire_pin` com `StringIO`/TTY falso |
| AC-3 | Sem flags, `parse_args` devolve `(False, False)` e `_acquire_pin` devolve `None`; `--help` sai 0 sem ecoar `--pin V` | testes de `parse_args`/`main`/subprocesso |
| AC-4 | O módulo importa sem `fido2`; `main()` sem a dependência retorna 2; `--help` funciona sem a dependência | teste de import + subprocesso |
| AC-5 | `record()` redige o PIN adquirido; a mensagem de falha do `changePIN` não imprime o temporário | teste de `redact`/`record` com sentinela + revisão |
| AC-6 | Docs atualizados (`validation.md`, `roadmap.md`, docstring/`USAGE`); `pytest tests -q` verde | comandos executados |

---

## 5. Plano de teste

- `tests/test_validate_fido_args.py`:
  - `parse_args`: defaults, `--pin-stdin`, `--pin-prompt`, exclusão mútua,
    `--pin`/`--old-pin`/typo de um dash sem eco, opção desconhecida sem eco,
    positional sem eco, `--help` ignorado pelo parser.
  - `_acquire_pin`: linha via `StringIO`, CRLF, vazio/fechado, TTY recusado com
    `--pin-stdin`, `--pin-prompt` sem TTY, `getpass` mockado em TTY.
  - `redact`/`record`: sentinela não aparece no `RESULTS`/stdout.
  - `main`: `--help --pin V` → 0 sem eco; `--pin=V` → 2 sem eco; sem `fido2`
    → 2 (dependência) sem ler o PIN.
  - Subprocesso: `--help --pin V` e `--pin=V` (exit/streams reais).
- Regressão: `python -m pytest tests -q` (inclui os 20 de `set_pin` e os
  demais).

## 6. Não-objetivos

- Não alterar os checks FIDO/CTAP, o firmware, `validate_oath.py` nem o
  `aegistoken-host`.
- Não adicionar `--old-pin` (o `changePIN` do validador gira e restaura).
- Não instalar `python-fido2` no CI; o parser é testado sem a dependência.
