# Spec — OATH no CLI de host (wiring) e URI fora do argv

> **Origem:** follow-up da fatia `specs/host-secrets-not-in-argv.md` (AC-034) e
> item da fila em `roadmap.md` (Fase 18). `crates/aegistoken-host/src/oath_cmd.rs`
> existe com 14 testes, mas **não é declarado em `main.rs`**: não é compilado,
> não roda e não aparece no `--help`. A interface documentada
> (`oath list|code|add|delete|reset`) não existe no binário.
> **Risco:** MÉDIO no modelo local. O comando `oath add <uri>` colocaria o
> segredo compartilhado TOTP/HOTP (parâmetro `secret=` da URI) em `argv`,
> visível a outros processos do mesmo usuário e no histórico do shell — a mesma
> classe de exposição já corrigida para PIV/PIN. O parser também ecoa a URI
> inteira em erro de esquema e um caractere do segredo em Base32 inválido.
> HEAD de referência: **`b5a757a`**.

---

## 1. Estado atual (confirmado no código)

- `main.rs` declara `card`, `cli`, `framing`, `piv_cmd`, `secret`, `transport`;
  **não** declara `oath_cmd`. Os 14 testes do módulo nunca são executados.
- `oath_cmd.rs` implementa `oath_list`, `oath_code`, `oath_add`, `oath_delete`,
  `oath_reset` sobre PC/SC e o protocolo YKOATH (LIST/CALCULATE/PUT/DELETE/RESET).
- `oath_add(uri, reader)` recebe a URI como `&str`: se chamado do CLI, o segredo
  viria de `argv`.
- `parse_otpauth_uri`:
  - erro de esquema: `"URI must start with 'otpauth://': {uri}"` → ecoa a URI
    inteira (segredo incluído);
  - `base32_value`: `"invalid Base32 character: '{ch}'"` → ecoa um caractere do
    segredo;
  - demais erros (`type`, `algorithm`, `digits`, `period`, `counter`) não são
    segredo.
- `OtpAuthCredential` deriva `Debug`, imprimindo `secret: Vec<u8>` se algum
  chamador usar `{:?}` — viola a invariante de não expor segredo em `Debug`.
- `cli.rs` não conhece OATH; `--reader` hoje só é válido para
  `piv-set-mgmt-key`.
- `secret.rs` já oferece `read_line`, `parse_hex`, `prompt` e `stdin_is_tty`;
  a política de canais (pipe/TTY) está estabelecida.

---

## 2. Decisões

1. **Declarar o módulo e expor os subcomandos** `oath list|code|add|delete|reset`,
   como já documentado em `docs/plano-desenvolvimento.md` e `docs/MILESTONES.md`.
   O primeiro positional é o subcomando; os demais são `NAME` quando aplicável.
2. **A URI do `oath add` nunca vem de `argv`.** Canais:
   - `--uri-stdin`: lê uma linha do stdin (pipe; recusa TTY);
   - sem flag: prompt oculto (`rpassword`) quando stdin é TTY;
   - sem TTY e sem flag: erro de uso (não pendura, não ecoa).
   Qualquer positional em `oath add` é recusado **sem ecoar o valor** (pode ser
   uma URI com segredo).
3. **Leitor por `--reader <SUBSTR>` em todos os subcomandos OATH.** Evita a
   ambiguidade de positional (que poderia tratar uma URI como leitor e ecoá-la
   em “no reader matching …”).
4. **Parser sem eco:** remover a URI e o caractere ofensivo das mensagens de
   erro; reportar apenas a classe do problema.
5. **Sem `Debug` imprimível** em `OtpAuthCredential` (remover o derive; manter
   `Clone` só se usado).
6. **Opções globais validadas por comando:** `--uri-stdin` só com `oath add`;
   `--reader` com `oath` e `piv-set-mgmt-key`; as demais combinações erram sem
   ecoar valores.

---

## 3. Invariantes

- I1: nenhum segredo OATH (URI com `secret=`, base32 decodificado) aparece em
  `argv`, `stdout`, `stderr`, `Debug` ou log.
- I2: a URI só entra por stdin (pipe) ou prompt oculto; TTY e pipe não se
  misturam na mesma execução.
- I3: erro de parse descreve a forma (esquema ausente, Base32 inválido, dígitos
  fora de 6..=8), nunca o valor.
- I4: o caminho FIDO/CCID do firmware não muda; o applet OATH não é tocado.
- I5: a suíte do crate volta a compilar e executar os testes do módulo.

---

## 4. Critérios de aceitação

| AC | Critério | Verificação |
|----|----------|-------------|
| AC-1 | `oath_cmd` é declarado em `main.rs`; os testes existentes do módulo rodam em `cargo test -p aegistoken-host` | contagem antes/depois no relatório |
| AC-2 | `oath add` recusa positional (incluindo URI) sem ecoar o valor; `--uri-stdin` lê uma linha de um leitor injetado e recusa TTY; sem flag e sem TTY erra; com TTY usa prompt oculto | testes de `cli.rs` com `Cursor`/TTY falso |
| AC-3 | `parse_otpauth_uri` não ecoa a URI nem caracteres do segredo em erro de esquema/Base32; `OtpAuthCredential` não deriva `Debug` | testes com sentinela + revisão estática |
| AC-4 | `oath list|code|add|delete|reset` despacham para o módulo; `--reader` é aceito em `oath` e recusado fora; `--uri-stdin` só em `oath add` | testes de `parse`/`run` + `--help` |
| AC-5 | Documentação atualizada: `README.md`, `validation.md`, `roadmap.md`, `docs/plano-desenvolvimento.md`, `docs/security-model.md` (host tooling) e help do CLI | grep/revisão |
| AC-6 | Gates verdes: `fmt`, `clippy -p aegistoken-host --all-targets -- -D warnings`, `cargo test -p aegistoken-host`, e o hook completo (`clippy` nos 4 crates) | comandos executados |

---

## 5. Plano de teste

- `oath_cmd.rs`: sentinela de URI (`otpauth://totp/x?secret=SENTINEL`) e de
  caractere Base32; asserção de ausência do sentinela na mensagem.
- `cli.rs`: `parse` de `--uri-stdin`, `--reader`; `acquire_otpauth_uri` com
  `Cursor` (pipe) e TTY falso; recusa de positional em `oath add` sem eco;
  `reject_misplaced_options` para `--uri-stdin`/`--reader`.
- `run(["oath", ...])` para subcomando desconhecido sem eco do valor.
- Regressão: `cargo test -p aegistoken-host` (33 atuais + 14 do módulo + novos).

## 6. Não-objetivos

- Não alterar o applet OATH, o protocolo YKOATH, `validate_oath.py` nem o
  firmware.
- Não implementar `oath add` por arquivo (`@FILE`); stdin/prompt bastam.
- Não migrar `validate_fido.py --pin` nesta fatia (follow-up separado).
