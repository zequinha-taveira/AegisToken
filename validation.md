# Validação de hardware — AegisToken Universal RP2350 Firmware

Documento da Fase 10: como validar os critérios de aceitação (AC-001..AC-015)
do MVP em hardware RP2350A (e depois RP2350B).

> **Estado atual:** um dispositivo AegisToken no perfil genérico (VID `0x1209`,
> PID `0x0001`) foi validado em hardware. A interface **Management HID** passou
> **12/12** checks e a interface **FIDO HID** passou **13/13**, incluindo
> `authenticatorGetInfo`, `authenticatorMakeCredential` e
> `authenticatorGetAssertion` com User Presence (BOOTSEL) e `clientPIN`. Restam
> apenas os itens dependentes do bootrom/OTP de produção (AC-010, AC-014,
> AC-015) e o ciclo físico de energia (AC-008).
>
> Firmwares construídos para uma placa de terceiros (`AEGIS_BOARD=<perfil>`)
> enumeram com o `VID:PID` da placa (ex.: Waveshare RP2350-Zero `0x2E8A:0x10B0`)
> e reportam o fabricante da placa em `GET_DEVICE_INFO`; a validação Management
> deve então usar `aegistoken-host --vid 0x2E8A --pid 0x10B0`. A matriz de
> critérios abaixo foi executada no perfil genérico (`0x1209:0x0001`, id próprio
> no pid.codes). A identidade USB YubiKey que `ykman` / Yubico Authenticator
> podem reconhecer é um build opt-in (`AEGIS_BOARD=yubikey5-lab`, `1050:0407`),
> só para laboratório autorizado — não distribuir. Esse PID sozinho **não**
> comprova suporte funcional ao OTP comercial da Yubico.
>
> Fase 17: os applets (PIV, OATH, OpenPGP ECC + RSA-2048) estão completos em
> firmware com 147 testes de host; o autoteste on-target cobre roteamento por
> AID (`applet-select`); a validação PC/SC e de interop (AC-016..AC-021)
> aguarda dispositivo físico, com procedimentos e scripts prontos.

## Ferramentas

- `probe-rs` — flash e RTT (`probe-rs run --chip RP2350`).
- `picotool` — conversão de UF2 e `picotool info` (valida imagem RP2350).
- `python-fido2` — validação FIDO2/U2F (`scripts/validate_fido.py`).
- `hidapi` + `cbor2` — validação do Management HID (`scripts/validate_management.py`).
- `pcsc_transport` (embutido, MIT OR Apache-2.0, ou `pyscard` como fallback) — validação CCID/ISO 7816 dos applets (`scripts/validate_ccid.py`).
- `aegistoken-host` — CLI de host em Rust sobre **libusb** para o Management HID,
  sem WinUSB/Zadig (ver abaixo).
- Autoteste on-target no boot (log via defmt/RTT).

## Build e flash

```powershell
# Firmware normal (autoteste não destrutivo no boot)
& scripts/build-uf2.ps1

# Firmware com o teste destrutivo de storage selado
cargo build -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf --features selftest

# Flash + RTT
probe-rs run --chip RP2350 target/thumbv8m.main-none-eabihf/release/firmware-universal-rp2350
```

O autoteste registra `self-test <nome>: PASS|FAIL` para capacidades, HID, TRNG,
codificação `getInfo`, resposta do Management HID e leitura de BOOTSEL; com
`--features selftest` inclui um round-trip do store selado em flash.

## Scripts de host

```powershell
python scripts/validate_management.py   # Management HID (AC-003..AC-009)
python scripts/validate_fido.py         # FIDO2/U2F (AC-002, AC-011, AC-013)
python scripts/validate_fido.py --pin 123456   # + changePIN e credential management
python scripts/validate_ccid.py         # CCID (AC-016)
python scripts/validate_piv.py          # PIV (AC-017/AC-021)
python scripts/validate_oath.py         # OATH/TOTP/HOTP (AC-018)
python scripts/validate_openpgp.py      # OpenPGP Card P-256/Ed25519/X25519/RSA-2048 (AC-019/AC-021)
python scripts/set_pin.py               # define/altera o PIN do clientPIN
```

## Compatibilidade Yubico Authenticator / `ykman`

A compatibilidade com as ferramentas Yubico é verificada por protocolo, em
três caminhos independentes:

| Caminho | Interface | Ferramentas | Critérios |
|---|---|---|---|
| FIDO2/U2F | FIDO HID | `ykman fido`, navegador/WebAuthn | AC-002, AC-011, AC-013 |
| OATH | CCID/YKOATH | Yubico Authenticator, `ykman oath` | AC-016, AC-018, YUB-003..YUB-007 |
| PIV | CCID/PIV | `ykman piv`, `yubico-piv-tool`, OpenSC | AC-016, AC-017, YUB-008..YUB-010 |
| OTP Lab | HID vendor-defined `0xFF51` | Cliente próprio com report interrupt de 64 B | LAB-OTP-001/002; **não** `ykman otp` |

O teste deve registrar versão do firmware, versão da ferramenta, sistema
operacional e reader PC/SC. A identidade USB padrão permanece `0x1209:0x0001`;
um perfil que imite VID/PID de Yubico é exclusivamente de laboratório e não é
evidência suficiente de compatibilidade nem pode ser distribuído.

Procedimento mínimo, em hardware físico:

```powershell
ykman fido info
ykman oath accounts list
ykman oath accounts code <nome>
ykman piv info
python scripts/validate_oath.py
python scripts/validate_piv.py
```

Alguns comandos de `ykman` são extensões específicas de modelos YubiKey e
podem responder como não suportados. Isso não invalida a compatibilidade dos
protocolos FIDO, YKOATH e PIV implementados; registre tais casos como
limitações de extensão no relatório de validação.

### Perfil OTP+FIDO+CCID somente de laboratório

```powershell
& scripts/build-uf2.ps1 -Board universal -BoardProfile yubikey5-lab
```

Identidade esperada: `1050:0407`, `YubiKey 5 Series OTP+FIDO+CCID`.
Interfaces esperadas: FIDO HID (`0xF1D0`), Management HID (`0xFF00`),
**OTP Lab HID** (`0xFF51`, interrupt IN/OUT de 64 B, polling de 10 ms) e CCID
(`0x0B`). O perfil genérico continua com **duas HID + CCID**, sem OTP Lab.
No Linux, confira `lsusb -v -d 1050:0407` e `lsusb -t`; no Windows, confira os
`MI_00`–`MI_03` do dispositivo USB composto. Observe que enumeração/descritores
**ainda exigem hardware físico**, não são validados só pelo build cruzado.

O protocolo mínimo, cabeçalho e status constam em
[docs/yubico-compatibility.md](docs/yubico-compatibility.md) e no módulo
`aegis-core::otp_lab`. Para um teste interrupt HID em hardware, selecione a
interface pela usage page `0xFF51` (não por PID apenas); envie 64 bytes
`A5 01 02 00 00 00 00 01 00 00` seguidos de 54 zeros. INFO deve responder
no mesmo canal com status `00`, length `0F` e ASCII `AEGIS-OTP-LAB/1`. Para
PING, troque o comando para `01`, defina length `01` e byte 10=`42`; a resposta
deve ecoar `42`. Framing inválido deve ser descartado. Cada chamada tem timeout:
um frame malformado **não** tem resposta. A validação determinística de parser,
encoder, limites e erros roda com `cargo test -p aegis-core otp_lab`.

**Não** testar `ykman otp` como se estivesse implementado: não há programação
de slots, Yubico OTP AES, challenge-response nem emissão de teclado. O applet
YKOATH (OATH/TOTP/HOTP) usa **CCID**, não esse HID. `ykman`/Authenticator
podem rejeitar comandos OTP no perfil lab; registrar separadamente de FIDO,
OATH e PIV, sem inferir compatibilidade pelo VID/PID.

## CCID / applets ISO 7816 (Fase 11)

O dispositivo compõe a interface **CCID** (classe USB `0x0B`), que
expõe os applets PIV, OpenPGP e OATH via PC/SC. O roteamento por AID, o
enquadramento APDU/CCID e o framework de PIN vivem em `aegis-applets`
(testáveis em host); o firmware apenas transporta bytes entre os endpoints bulk
e o roteador.

- **Windows** — a interface é reivindicada automaticamente pelo driver inbox
  `usbccid.sys`; confirme em **Gerenciador de Dispositivos → Leitores de cartão
  inteligente**. Não é preciso WinUSB/Zadig.
- **Linux** — instale `pcscd` e `ccid`; `opensc-tool -l` deve listar o leitor.

Enquanto os applets reais não chegam (fases 12-14), cada AID registra um
*placeholder*: `SELECT` responde `9000` e qualquer outra instrução responde
`6D00`.

```powershell
python scripts/validate_ccid.py
# em um host com outros leitores, selecione o correto:
python scripts/validate_ccid.py --reader Aegis
```

Critérios verificados: enumeração PC/SC, ATR `3B 00`, `SELECT` de PIV/OpenPGP/
OATH (`9000`), AID desconhecido (`6A82`), instrução não suportada (`6D00`),
CLAss proprietária (`6E00`), `GET RESPONSE` sem pendência (`6985`) e comando
sem seleção prévia (`6985`).

## PIV (Fase 12)

O applet PIV responde às ferramentas padrão (`pivy`, OpenSC, `yubico-piv-tool`)
com os defaults de fábrica: PIN `123456`, PUK `12345678` e management key 3DES
`0102030405060708` repetida três vezes. O PIN/PUK são exigidos com padding
`0xFF` até 8 bytes; os contadores de tentativa (`63Cx` → `6983`) são
persistidos a cada verificação.

```powershell
python scripts/validate_piv.py
python scripts/validate_piv.py --reader Aegis   # em hosts com outros leitores
```

Critérios verificados: `SELECT` PIV, `GET DATA` do CCC/CHUID, objeto
desconhecido (`6A82`), `PUT DATA` sem autenticação de administrador (`6982`),
verificação do PIN (retries `63Cx` e sucesso `9000`), autenticação **mútua** do
management key (3DES: o cartão devolve `7C { 80 E(nonce) }`, o host decifra e
devolve o nonce em `80`, e o cartão responde `7C { 82 E(challenge) }`),
`GENERATE ASYMMETRIC KEY PAIR` P-256 (`7F49 { 86 ponto }`) e assinatura via
`GENERAL AUTHENTICATE` com verificação externa em `cryptography`.

O teste com `pivy --admin --genkey` e com `pkcs11-tool` (OpenSC) usa os mesmos
comandos; a touch policy padrão é `never` (o `AB` do `GENERATE` pode exigir
presença, respondida pelo botão BOOTSEL).

> **Persistência no firmware:** com a chave raiz provisionada, PIN/PUK e
> contadores usam `SealedPivStore` (AES-256-GCM na região de applets) e
> sobrevivem a power cycle; sem a chave, o firmware usa `MemoryPivStore`.

## OATH / TOTP / HOTP (Fase 13)

O applet OATH usa o protocolo YKOATH sobre a mesma interface CCID. Os segredos
ficam no estado interno e nunca são retornados por `LIST`, `CALCULATE ALL` ou
respostas de erro. O host fornece o moving factor em oito bytes big-endian:
`timestamp / period` para TOTP ou o contador interno para HOTP.

```powershell
python scripts/validate_oath.py
python scripts/validate_oath.py --reader Aegis
```

O script grava uma credencial TOTP temporária com o vetor RFC 6238, executa
`LIST`, calcula o código para moving factor `1` (esperado `94287082`) e remove
a credencial. Os testes de host cobrem também RFC 4226, SHA-256/SHA-512,
access code, persistência serializada e touch-required.

## OpenPGP Card v3.4 (Fase 14–16)

O applet OpenPGP usa o AID v3.4 e implementa PW1/PW3, retry counters, os DOs
principais (`6E`, `C1`-`C5`, `C4`, `C7`–`C9`, `DE`, `7A/93`), key generation
P-256/Ed25519/X25519/RSA-2048 (algoritmo por slot via `PUT DATA C1`–`C3`),
ECDSA/EdDSA e RSA (`PSO:COMPUTE DIGITAL SIGNATURE` com bloco EM ou
`DigestInfo`) para assinatura, `INTERNAL AUTHENTICATE` cru e ECDH P-256 /
X25519 ou RSA cru em `PSO:DECIPHER`. Assinaturas ECDSA saem em `r||s` bruto,
como o GnuPG espera.

```powershell
python scripts/validate_openpgp.py
python scripts/validate_openpgp.py --reader Aegis
```

O script verifica `SELECT`, C1/C4, PW3, geração de chave, PW1, assinatura e
verificação externa com `cryptography`, além dos fluxos Ed25519 (atributos,
keygen, assinatura 64 bytes), X25519 (acordo com chave efêmera) e RSA-2048
(AC-021: atributos `01 0800 0020`, keygen, assinatura `DigestInfo` verificada
por OpenSSL, decifra com bloco cru, fingerprint `C7`). KDF OpenPGP completo,
certificados completos e `gpg --card-edit` ficam para validação posterior.
Curvas fora de escopo: brainpoolP512r1 / X448 / Ed448 (sem aritmética `no_std`
madura em Rust); brainpoolP256r1 e P384r1 seguem suportados.

### OpenPGP: `RESET RETRY COUNTER` exige PW3 (fatia S4, host)

O `RESET RETRY COUNTER` (`00 2C …`) deixou de ser um caminho público: com
`P1=0x02`/`P2=0x81` ele exige o PIN admin já verificado na sessão
(`pw3_verified`) e responde `6982` sem alterar nenhum estado na negativa; o
caminho do Resetting Code (`P1=0x00`) responde `6A81` enquanto o BC não é
provisionado; `P1` ou `P2` desconhecidos respondem `6A86`. O desbloqueio
autenticado restaura os retries do PW1 para o máximo da política, nunca mexe
no PW3 e não consome a sessão de PW3.

| AC | Critério | Teste de host (`aegis-applets::openpgp`) | Status |
|----|----------|------------------------------------------|--------|
| AC-1 | SRS (P1=02, P2=81) sem PW3 → `6982`, estado inalterado (hash, contador e sessão PW1 intactos) | `reset_retry_requires_pw3_and_leaves_state_untouched` | **Verificado em host** |
| AC-2 | Com PW3 verificado: PW1 novo verifica, contador restaurado (`63C3`) e PW3 intacto | `reset_retry_with_pw3_sets_new_pw1_and_restores_retries` | **Verificado em host** |
| AC-3 | O comando não encerra a sessão de PW3 (`PUT DATA` segue OK sem novo `VERIFY`) | `reset_retry_does_not_end_the_pw3_session` | **Verificado em host** |
| AC-4 | P2 desconhecido → `6A86`, estado inalterado | `reset_retry_rejects_unknown_p2` | **Verificado em host** |
| AC-5 | Caminho do Resetting Code (P1=00) → `6A81`, estado inalterado | `reset_retry_rejects_the_resetting_code_path` | **Verificado em host** |
| AC-6 | `select()` limpa a sessão: novo SRS sem PW3 volta a `6982` | `select_clears_pw3_and_reset_retry_requires_it_again` | **Verificado em host** |
| AC-7 | PW1 bloqueado continua bloqueado até o unblock autenticado | `blocked_pw1_stays_blocked_until_authenticated_unblock` | **Verificado em host** |
| AC-8 | Contato do `unblock` documentado (autorização é do chamador) | doc-comment de `PinSlot::unblock` (`pin.rs`) | **Verificado** (revisão estática) |

**Limitação (gate de hardware pendente):** sem RP2350 físico nesta sessão, a
validação física do `0x2C` fica registrada: estender
`scripts/validate_openpgp.py` com o caso "RST RETRY COUNTER sem PW3 →
`6982`" (o script hoje não exerce `0x2C`) e conferir o fluxo com `gpg`
(`gpg --change-pin` / unblock) quando houver dispositivo.

### OpenPGP: persistência de PIN fail-closed (fatia S5, host)

Os mutadores de PIN do OpenPGP (`VERIFY` com tentativa consumida,
`CHANGE REFERENCE DATA`, `RESET RETRY COUNTER` autenticado e `PUT DATA`
aceito) propagam a falha de gravação do estado selado com **`6A84`** em vez de
confirmar a mutação (`9000`/`63Cx`): o estado em RAM fica restritivo e um
**piso sticky por slot** (volátil de sessão, sobrevive a `select()`) comanda um
clamp `min(restaurado, piso)` em todo reload, então re-selecionar nunca
ressuscita tentativas; um persist bem-sucedido reancora o piso. `VERIFY`
bem-sucedido emite um save a menos (nada persistível muda). Write-ahead por
tentativa ficou deliberadamente de fora (desgaste de flash); o resíduo entre
power cycles — o estado persistido governa até o próximo persist ok — está
documentado em `docs/security-model.md` como modelo de degradação, não como
gap.

| AC | Critério | Teste de host (`aegis-applets::openpgp`) | Status |
|----|----------|------------------------------------------|--------|
| AC-1 | `VERIFY` que consome tentativa com store em falha → `6A84` (nunca `63Cx`); contador em RAM decrementado (`63C2`) e bloqueio `6983` quando esgota | `verify_failure_with_failing_store_reports_the_save_error` | **Verificado em host** |
| AC-2 | Piso sticky entre re-seleções: `select()` não restaura o contador (`63C2`); com store íntegra o re-select mantém o comportamento atual | `sticky_floor_survives_reselect` (+ `happy_path_persists_assertions_are_unchanged_under_a_healthy_store`) | **Verificado em host** |
| AC-3 | `CHANGE REFERENCE DATA` com save falhando → `6A84` (nunca `9000`); PIN novo verifica in-session; após `select()` o PIN antigo volta a verificar | `change_with_failing_store_reports_the_save_error_and_never_fakes_success` | **Verificado em host** |
| AC-4 | `RESET RETRY COUNTER` (P1=02, P2=81, `pw3_verified`) com save falhando → `6A84`; após `select()` o PW1 retorna ao estado persistido (bloqueado → `6983`); unblock definitivo só sob persistência ok | `unblock_with_failing_store_keeps_the_persisted_blocked_state` | **Verificado em host** |
| AC-5 | `PUT DATA` aceito com save falhando → `6A84` e DO antigo após `select()`; rejeitado (`WRONG_DATA`) não emite save | `put_data_with_failing_store_reports_the_save_error` | **Verificado em host** |
| AC-6 | Clamp no carregamento: `min(Y, X)` para PW1 e PW3; store íntegra sem efeito | `reload_never_climbs_above_the_session_floor` | **Verificado em host** |
| AC-7 | Caminho feliz inalterado (persistência de verify errado/change/unblock/put_data; `VERIFY` bem-sucedido não chama `save`; defaults de `ensure_loaded` sobrevivem a store falhando) | `happy_path_persists_assertions_are_unchanged_under_a_healthy_store`, `successful_verify_does_not_call_save`, `provisioning_defaults_survive_a_failing_store` | **Verificado em host** |
| AC-8 | Contrato em `pin.rs` (persistência é do handler, resultado propagado) e trade-off registrado em `docs/security-model.md` (piso intra-sessão; power cycle pelo persistido; write-ahead rejeitado) | doc-comment do módulo `pin.rs` + `docs/security-model.md` | **Verificado** (revisão estática) |

**Limitação (gate de hardware pendente):** a falha de gravação não é induzida
em hardware neste ciclo — nenhum procedimento do `validate_openpgp.py`
simula flash doente. Fica pendente o caso "mutação de PIN com gravação
negada → `6A84`" (e conferir que o GnuPG trata o status como erro do cartão,
não como PIN errado), para quando houver método de indução ou RP2350 físico
(`memory_error` por flash desgastado não é reprodutível em script). O resíduo
documentado entre power cycles com store indisponível é aceito (AC-8).

### OpenPGP: `PUT DATA D2` valida o material ECDH na fronteira (fatia S6, host)

O `PUT DATA D2` (material RFC 6637 do slot de decifra) aceitava estado que a
decifra jamais consumiria: `kdf_hash` gravava cru enquanto a decifra deriva o
KEK com SHA-256 fixo, e `wrapped_len` admitia blocos abaixo do menor bloco de
sessão real (o `aes_key_unwrap`/`session_key_from_wrapped` recusariam depois).
A fronteira agora é fail-closed — o mesmo corpo coerente com o que o cartão
executa (P-256, já exigido pelos atributos) permanece:

| AC | Critério | Teste de host (`aegis-applets::openpgp`) | Status |
|----|----------|------------------------------------------|--------|
| AC-1 | D2 válido (`0x08 0x07`, com e sem fingerprint de 20 octets) → `9000` byte a byte; o material provisionado mantém `wrapped`, `kdf_hash`, `kek_alg` e fingerprint | `d2_accepts_the_supported_kdf_hash_and_keeps_the_material` | **Verificado em host** |
| AC-2 | `kdf_hash ≠ 0x08` (0x00, 0x02, 0x09, 0x0A, 0xFF) → `6A80`, slot intacto, sem save e o reload recupera o material anterior | `d2_rejects_unsupported_kdf_hash_without_touching_the_slot` | **Verificado em host** |
| AC-3 | `wrapped_len` fora do domínio de `aes_key_unwrap` + `session_key_from_wrapped` (0, 8, 16, 25, 49; comprimento total errado) → `6A80`, slot intacto | `d2_rejects_wrapped_len_outside_the_key_wrap_domain` | **Verificado em host** |
| AC-4 | Decifra e2e host-simulada continua `9000` (teste e2e existente); sem fingerprint provisionado a decifra falha fechada | `pso_decipher_unwraps_the_session_key_and_decrypts` + `decipher_fails_closed_without_the_provisioned_fingerprint` | **Verificado em host** |
| AC-5 | Export NIST P-256 não regrediu: `READ PUBLIC KEY` → tag `86` estável, fingerprint v4 do slot cobre o KDF-DO `0x03 0x01 0x08 0x07` (DEC em C5) e `put_algo(1)` inalterado | `the_decryption_slot_exports_the_nist_kdf_parameters` (+ `put_data_c1_accepts_ed25519_rsa_and_rejects_others`) | **Verificado em host** |
| AC-6 | Interop real com o GnuPG: provisionamento do interop segue `9000`, decifra do payload GnuPG continua `9000` e um D2 com hash `0x0A` é recusado (`6A80`) sem alterar o material — a decifra seguinte é idêntica | `gnupg_encrypts_and_the_card_decrypts` (extensão) | **Verificado em host** (com `gpg` disponível; pula de forma segura sem ele) |

**Limitação (gate de hardware pendente):** o `validate_openpgp.py` não
provisiona D2 com hash estranho hoje; estender o script com o caso negativo
("D2 com `0x0A 0x09` → `6A80` e provisioning válido subsequente → `9000`")
quando houver RP2350 físico.

### OpenPGP: decifrador simétrico em tempo constante (fatia S7, host)

O decifrador do `PSO: DECIPHER` comparava material derivado da chave de
sessão com early-exit: `||` de curto-circuito no quick-check e no tag/length
do pacote MDC (revelando qual octeto falhou) e `==` de fatias no SHA-1 do MDC
(revelando quantos bytes casaram, o alvo clássico de oráculo de decifração).
As três verificações agora são absorvidas por um acumulador constante-tempo
(a disciplina do `constant_time_eq` do `pin.rs`, promovido a `pub(crate)`) e
decididas uma única vez no fim, por categoria — o SHA-1 roda também nos
caminhos que terminam em `None`. Nada muda de SW, resultado ou API.

| AC | Critério | Teste de host (`aegis-applets`) | Status |
|----|----------|---------------------------------|--------|
| AC-1 | Quick-check ruim recusado com o mesmo resultado: chave de sessão trocada em {0, meio, último} para as larguras 16/24/32 e cada um dos dois octetos do check quebrado um a um → `None` | `wrong_quick_check_byte_is_rejected_for_every_position` (`pgp_sym`) | **Verificado em host** |
| AC-2 | MDC corrupto recusado com o mesmo resultado: flip em cada um dos 20 bytes do pacote MDC → `Some` com `mdc_verified == false` e `data` idêntico ao baseline | `every_mdc_byte_flip_still_fails_the_verification_with_unchanged_data` (`pgp_sym`) | **Verificado em host** |
| AC-3 | Tag (0xD3), length (0x14) ou ambos corrompidos com quick-check íntegro → `None` | `corrupted_mdc_tag_or_length_is_rejected` (`pgp_sym`) | **Verificado em host** |
| AC-4 | Caminho feliz e interop inalterados: o vetor do GnuPG decifra com `mdc_verified == true` e o `encrypt` reproduz o ciphertext octeto a octeto; interop real com `gpg` (skip seguro) | `decrypts_a_message_encrypted_by_gnupg`, `encrypts_to_the_gnupg_ciphertext` (`pgp_sym`) + `gnupg_encrypts_and_the_card_decrypts` | **Verificado em host** |
| AC-5 | Disciplina constante-tempo verificada estaticamente: nenhum `==` de fatias nem `\|\|` de curto-circuito sobre material derivado da chave em `pgp_sym.rs`; o único comparador de fatias é `constant_time_eq` (`pin.rs`, agora `pub(crate)`), com `black_box`, e as decisões ficam após o acumulador completo | revisão de código estática | **Verificado** (revisão estática) |
| AC-6 | SWs do chamador inalterados via fluxo APDU `PSO: DECIPHER`: quick-check ruim → `6F00`, MDC corrupto → `6A80`, feliz → `9000` com o literal | `decipher_reports_pro_sw_for_quick_check_mdc_and_success` (`openpgp`) | **Verificado em host** |

Sem pendência de hardware: o timing não é medido em host nem em hardware
neste ciclo — a comparação constante-tempo é disciplina estática (a mesma
registrada para o HMAC do OATH); um estudo de temporização em hardware, se
desejado no futuro, é não-objetivo, não uma pendência.

### OpenPGP: suíte adversarial de APDU do caminho de decifra (fatia S8, host)

Suite de acusações sobre as rotas de dados do decifrador: todo frame
malformado de `PSO: DECIPHER` e todo corpo fora de domínio de `PUT DATA D2`
responde um único SW fechado, com corpo vazio, sem pânico, sem gravação e
sem mudança de estado — e nenhuma resposta ecoa material privado, a chave
de sessão embrulhada ou um segredo compartilhado fora da rota documentada
(verificação por janela em cada recusa). Referente a
`specs/openpgp-apdu-adversarial-tests.md`.

| AC | Critério | Teste de host (`aegis-applets::openpgp`) | Status |
|----|----------|------------------------------------------|--------|
| AC-1 | Frames estruturalmente malformados de DECIPHER (`A6` truncado, `86` vazio, comprimento estendido além do dado, `86` nu longo demais) → um SW fechado determinístico com corpo vazio, nas três famílias de slot (RSA, ECDH P-256, X25519), estado intacto | `decipher_refuses_truncated_and_nested_tlv_frames` | **Verificado em host** |
| AC-2 | As quatro fronteiras de `wrapped_len` do domínio de key wrap (24/32/40/48) com cada KEK id (7/8/9) e com e sem fingerprint do remetente importam e round-tripam byte a byte | `d2_accepts_the_wrapped_len_frontiers_24_32_40_48` | **Verificado em host** |
| AC-3 | Corpos abaixo do mínimo parseável e totais fora da base declarada → `6A80` zero gravações, slot ancorado intacto (a fronteira de `wrapped_len` permanece coberta pela fatia S6; só a fronteira 24 é reafirmada) | `d2_refuses_short_bodies_and_keeps_the_slot` | **Verificado em host** |
| AC-4 | Material RFC 6637 abaixo/fora da fronteira de leitura (`len` 103, 32; `wrapped_len` 0/49 com `len` 104) → decifra parcial determinística da especificação do cartão (`9000` + Z de 32 bytes), portão PW1 `82` antes; a fronteira exata (104, `wrapped_len` válido) relê o material e o modo RFC 6637 volta | `decipher_falls_back_deterministically_when_the_slot_material_is_incomplete` | **Verificado em host** |
| AC-5 | Corpo além do `MAX_DATA` interno (4096): decifra de ~4,3 KB via APDU estendido → um único SW fechado (`6F00`) sem pânico, corpo vazio, sem fragmento de texto claro | `oversized_ciphertext_answers_one_status_word_without_panicking` | **Verificado em host** |
| AC-6 | Anti-serialização por janela: nenhuma resposta de recusa reproduz a chave privada do slot, a chave de sessão embrulhada ou um segredo compartilhado fora da rota documentada (o `Z` da decifra parcial é a rota documentada) | verificação embutida em cada recusa dos testes acima (`assert_never_leaks`) | **Verificado em host** |
| AC-7 | Ponto zero X25519 é comportamento da curva, não erro: resposta determinística `9000` + 32 zeros, portão PW1 `82` antes; recusar pontos não contributivos é não-objetivo | `x25519_zero_point_is_curve_behavior_not_an_error` | **Verificado em host** |

Limitação registrada (INFO, não critério de aceitação): mensagens de exatamente
2048 bytes ainda cabem no buffer de resposta; um byte a mais responde `6A84`
com corpo vazio. A fronteira 2048/2049 é gravada por
`response_over_two_kilobytes_is_a_documented_limitation` e segue para decisão
futura no `roadmap.md` — a suíte a registra, não a corrige.

Achado do ciclo (bug de produção, fix for a fatia própria): um `PUT DATA D2`
aceito persiste o slot de decifra com `len = 104` (32 bytes de escalar +
72 bytes de material RFC 6637), mas o `decode_state` recusa qualquer slot
não-RSA com `len > 48`: numa sessão nova (boot de um cartão recém-provisionado)
a releitura falha de forma fechada e o applet reseta para os padrões, perdendo
chaves e PINs. Recarregas na mesma sessão mascaram o defeito — o decode falha
depois das chaves em RAM, que sobrevivem, e a re-inicialização salva-as de
volta. Fixado deliberadamente por
`d2_provisioned_state_survives_across_sessions` (assert invertido) que o
reparo da fatia S9 realizou — a resolução completa está na seção abaixo.

### OpenPGP: o estado gravado por `PUT DATA D2` sobrevive à sessão (fatia S9, host)

Bug de produção acusado pela fatia S8: o `decode_state` recusava qualquer
slot não-RSA com `len > 48`, mas um `PUT DATA D2` aceito persiste o slot de
decifra com `len = 104` (32 octets de escalar + 72 octets de material RFC
6637, geometria fixa de `EcdhMaterial::store`) — o primeiro boot de um cartão
provisionado re-inicializava o card no boot frio e, a cada re-`select`,
sobrescrevia o PIN persistido com os padrões. O reparo é coerência
writer/reader: o decode aceita o domínio fechado {slot de decifra,
algoritmo UNSET/ECDH P-256, `len = 104`} e continua fail-closed em qualquer
outra largura/slot/algoritmo; nenhuma palavra do protocolo muda, nada de
bump de `STATE_VERSION` (o blob v3 escrito antes do reparo é byte-idêntico e
decodifica — livro-in). A validação dos octets internos segue onde estava:
na leitura (`EcdhMaterial::from_slot`), com o fallback parcial documentado
da card spec para material rasgado — recusar no decode destruiria todo o estado.
Referente a `specs/openpgp-d2-state-roundtrip.md`.

| AC | Critério | Teste de host (`aegis-applets::openpgp`) | Status |
|----|----------|------------------------------------------|--------|
| AC-1 | Round-trip da sessão: provisionamento PW3 → `GENERATE 0xB8` → `D2` → boot frio (`OpenPgp::new` + `select`): `decode_state` carrega, `ecdh_material()` byte a byte, `keys[1].len == 104`, DO de fingerprints `0x00C5` idêntico | `d2_provisioned_state_round_trips_to_a_cold_session` | **Verificado em host** |
| AC-2 | Identidade do estado completo pós-reboot: name/language/sex/url/certificado, escalar do slot (`keys[1].material[..32]`) e contador de assinatura idênticos | `d2_provisioned_state_round_trips_to_a_cold_session` | **Verificado em host** |
| AC-3 | Decifra RFC 6637 fim a fim pós-reboot: `VERIFY` PW1 mod 82 com o PIN persistido → `PSO DECIPHER` (`86` + `80`) → `9000` com o plaintext idêntico; o mesmo ciclo sobrevive ao re-`select` | `decipher_after_reboot_returns_the_plaintext_with_the_persisted_pin` | **Verificado em host** |
| AC-4 | PINs/contadores: PIN customizado provisionado verifica na sessão nova e após re-`select` (sem clobber); contador é o persistido (retries 2 recarregados, piso da S5 intacto) | `custom_pin_and_persisted_counter_survive_cold_boot_and_re_select` | **Verificado em host** |
| AC-5 | Fail-closed: `len = 103`/`105` bem formados internamente, `len = 104` no slot 0/2, `len = 104` com X25519/EdDSA (e a largura RSA com algoritmo ECDH) → `decode_state` recusa e o boot cai no re-init dos padrões | `unknown_widths_and_slots_still_fail_closed` | **Verificado em host** |
| AC-6 | Teste S8 realizado: `d2_provisioned_state_fails_decode_across_sessions` invertido e renomeado para `d2_provisioned_state_survives_across_sessions`, doc-comments atualizados; suíte adversarial inteira verde | `adversarial_apdu::d2_provisioned_state_survives_across_sessions` | **Verificado em host** |
| AC-7 | Livro-in: blob v3 construído à mão com slot `len = 104` (algoritmo UNSET) decodifica, sem bump de `STATE_VERSION` (continua 3) e sem mudar `save_state`; o re-save decodifica de novo; o escalar do `GENERATE` (`len` 32) segue aceito no mesmo teste; v1/v2 (laje 48) cobertos por `state_v1_migrates_to_p256_defaults`/`state_v2_migrates_to_v3` | `pre_repair_blob_decodes_book_in_and_resaves_without_a_version_bump` | **Verificado em host** |
| AC-8 | Regressão de nada mudou: RSA (`len == RSA_BLOB_BYTES`, validação de chave privada no decode), round-trips de estado existentes, painel da S5 e os ACs do suite S8 (incl. fallback parcial) — toda a suíte verde | `cargo test -p aegis-applets` (211 testes) | **Verificado em host** |

Pendência física: reprodução real — power cycle com material provisionado +
decifra via GnuPG (`validate_openpgp.py`) em RP2350 disponível; os ACs acima
são todos de host.

### OpenPGP: `CHANGE REFERENCE DATA` do PW3 exige a sessão de admin (fatia S10, host)

Irmã da fatia S4 (unblock): o `verify_change` mapeava `P2=0x83` para o slot
PW3 com o PIN corrente no corpo como **único** fator de autorização — o
default de interop `12345678` é público, então qualquer cartão
não-personalizado podia trocar o PIN admin (e adquirir `GENERATE`/`PUT
DATA`/`RESET RETRY`) sem estabelecer a sessão que a casa exige nos demais
mutadores. O comando agora consulta `pw3_verified`, como `reset_retry`,
`put_data` e `generate`: sem sessão responde `6982` **antes** de tocar o
slot — sem decrementar o contador do PW3, sem alterar hash ou flags e sem
chamar `persist_state()` (recusa por falta de sessão não é adjudicação de
PIN). Com sessão, o fluxo é o de sempre: corpo `atual(8)+novo(8)`,
`slot.change` (dupla verificação não é oracle), `persist_state()` com o piso
da S5 (`6A84` na falha de gravação) e a **sessão mantida** após o comando —
a única limpeza segue sendo o `select()`. O **PW1** (`0x81`/`0x82`) fica
intocado: troca com o corrente no corpo sem sessão é o comportamento da card
spec (o scdaemon só pre-verifica o admin para `chvno == 3` — verificado em
`app-openpgp.c::do_change_pin`). Referente a
`specs/openpgp-pw3-change-authority.md`.

| AC | Critério | Teste de host (`aegis-applets::openpgp`) | Status |
|----|----------|------------------------------------------|--------|
| AC-1 | `CHANGE` 0x83 sem sessão → `6982`; hash/contador/sessão intactos e **nenhuma gravação** (`save_calls` não se move) | `pw3_change_requires_the_admin_session_and_leaves_the_state_untouched` | **Verificado em host** |
| AC-2 | `VERIFY` PW1 (mod 81 e 82, `9000`) não estabelece autoridade: `CHANGE` 0x83 → `6982` | `pw1_verification_does_not_authorize_the_pw3_change` | **Verificado em host** |
| AC-3 | Com sessão: `CHANGE` 0x83 → `9000`; `PUT DATA` responde sem novo `VERIFY` (sessão mantida); corrente errado com sessão segue o contrato do slot (`63Cx` persistido) e a sessão sobrevive | `pw3_change_with_session_swaps_the_pin_and_keeps_the_session` | **Verificado em host** |
| AC-4 | `select()` recomeça o ciclo: `CHANGE` 0x83 → `6982` até um novo `VERIFY` 0x83 reabrir a sessão | `select_clears_pw3_and_change_requires_it_again` | **Verificado em host** |
| AC-5 | PW1 sem regressão: troca sem sessão nos modos 81/82 com PIN de 8 bytes → `9000`; corpo fora do intervalo de formato → `6A80` nos três modos | `pw1_change_still_works_without_a_session` | **Verificado em host** |
| AC-6 | Piso S5: `CHANGE` 0x83 autenticado com store flaky → `6A84` (nunca `9000` falso) e o PIN novo não sobrevive ao re-`select`; os dois testes S5 existentes passam a pre-verificar o admin e seguem verdes | `change_with_failing_store_reports_the_save_error_and_never_fakes_success`, `happy_path_persists_assertions_are_unchanged_under_a_healthy_store` | **Verificado em host** |
| AC-7 | A recusa sem sessão não consome tentativa do PW3 nem vira verify de graça: contador cheio no `VERIFY` vazio e o original ainda `9000` | `refused_pw3_change_never_consumes_a_retry` | **Verificado em host** |
| AC-8 | Interop GnuPG (`VERIFY` 0x83 → `CHANGE` 0x83) e suítes S8/S9 sem regressão: suíte toda verde | `cargo test -p aegis-applets` (217 testes) | **Verificado em host** |

Limitação registrada (L4): ~~o PW1 default de 6 octetos (`123456`) não pode
ser trocado via `0x24` hoje~~ — **resolvida pela fatia S11** (sub-seção a
seguir): o default de fábrica agora é trocável pela porta pública. O AC-5
da S10 segue usando o PW1 de 8 bytes instalado pela porta admin da casa
(`RESET RETRY COUNTER`) para exercitar o corpo fixo 16 contra um slot de 8.

Pendência física: estender `scripts/validate_openpgp.py` com o caso
"`CHANGE` 0x83 sem `VERIFY` → `6982`" e conferir o fluxo real
`gpg --card-edit` → `passwd` → "change Admin PIN" em RP2350 disponível.

### OpenPGP: troca do PW1 default com corpo de comprimento variável (fatia S11, host)

Fecha o gap L4 da S10: o caminho real do scdaemon
(`app-openpgp.c::do_change_pin` + `iso7816.c::iso7816_change_reference_data`,
verificados no código-fonte) monta o corpo de `CHANGE REFERENCE DATA` como a
**concatenação exata** `atual‖novo`, sem delimitador e sem padding, com
`Lc = oldlen + newlen` — com o default de fábrica, `Lc = 12`, que o filtro
antigo (`len != 16`) recusava: o PW1 de fábrica era imutável pela porta
pública. O `verify_change` agora aplica a regra da card spec §7.2.3
("the length of the existing password is known in the card", `Lnew =
Lc − Lold`): intervalo de formato `2·min ≤ Lc ≤ 2·max` (`12 ≤ Lc ≤ 254`;
fora disso → `6A80` **antes de qualquer interação com o slot** — nenhuma
tentativa consumida, nenhum save) e **delimitação pelo hash armazenado** —
nova capacidade read-only `PinSlot::resolve_change` (`pin.rs`) escaneia os
candidatos `L` da janela de política sem consumir tentativa; o match alimenta
o `slot.change` de sempre (que restaura o contador e persiste sob o piso S5:
`6A84` na falha de gravação) e a negativa consome **exatamente uma tentativa**
(`63Cx` com persist) — o mesmo preço que o corpo fixo 16 já cobrava por
corrente errado, sem ampliar o orçamento de bruteforça. Slot esgotado →
`6983` sem tocar nada. O formato persistente não muda (sem bump de
`PIN_STATE_VERSION`); `0x83` intocado (gate S10 + corpo fixo 16).

| AC | Critério | Teste de host (`aegis-applets::openpgp`) | Status |
|----|----------|------------------------------------------|--------|
| AC-1 | Fresh `applet()`, sem `VERIFY` admin nem `RESET RETRY`: `CHANGE` 0x81 corpo 6+6 → `9000`; `VERIFY` 0x81 com o novo → `9000`, com o antigo → `63Cx`; contador restaurado (vazio → `63C3`) e persistido (após `select()`, o novo re-verifica) | `pw1_default_of_six_octets_is_changeable_on_the_public_path` | **Verificado em host** |
| AC-2 | Comprimentos mistos: com PW1 de 6, `6+8` → `9000` + novo `9000`; com PW1 de 8 instalado via `RESET RETRY`, `8+6` → `9000` + novo `9000` — a delimitação segue o hash por candidato (`Lnew = Lc − Lold`), não um índice fixo | `pw1_change_follows_the_exact_lengths_of_the_command_body` | **Verificado em host** |
| AC-3 | formato fora do intervalo (0, 11, 255 octetos) → `6A80` sem decremento (vazio → `63C3` depois) e sem gravação (`save_calls` intocado); corpo de 16 com corrente de 6 e corpo incompatível → semântica de sem-match do AC-4 (não mais rejeição de formato) | `pw1_change_rejects_bodies_outside_the_policy_range_without_tuning` | **Verificado em host** |
| AC-4 | corrente errado (corpo no intervalo, nenhum split bate: 12, 14 e 15 octetos) → `63Cx` com **um único** decremento por comando (`63C2`→`63C1`→`63C0`) e persist; o hash novo nunca é instalado; esgotado → `6983` sem tocar nada | `pw1_change_consumes_one_attempt_per_mismatched_body` | **Verificado em host** |
| AC-5 | Piso S5: troca válida 6+6 com store flaky → `6A84` (nunca `9000` falso); re-`select` → o novo não sobrevive e o antigo re-verifica | `pw1_change_fail_closed_on_failing_store` | **Verificado em host** |
| AC-6 | PW3 intocado: sem sessão `0x83` (corpo de 12) → `6982` antes de tocar slot/contador/store; com sessão, corpo 16 → `9000` + novo `9000`; com sessão e `Lc≠16` (inclusive 12) → `6A80` sem consumo | `pw3_change_body_format_is_unchanged` | **Verificado em host** |
| AC-7 | Suítes intactas: `gnupg_interop.rs` (sem `0x24`), `adversarial_apdu.rs` e `state_roundtrip.rs` sem edição; os dois testes de persistência S5 verdes; `pw1_change_still_works_without_a_session` continua verde com o comentário obsoleto atualizado (o corpo de 11 octetos mantém a recusa de formato do teste) | `cargo test -p aegis-applets` (224 testes) | **Verificado em host** |
| AC-8 | Contratos documentados em `pin.rs`: delimitação por comprimento conhecido como **leitura** do slot (não decrementa; diagnósticos de unset/blocked idênticos aos do `verify`); autorização no chamador; sem mudança de encoding (`PIN_STATE_VERSION` intacto, testes de encoding existentes verdes) | doc-comments de `pin.rs` (revisão estática) | **Verificado** |

Nota de resolução da spec: a spec da fatia lista o corpo de 15 octetos do
teste da S10 entre os "recusados como hoje" (`6A80`); com a janela
normativa `12 ≤ Lc ≤ 254` ele entra no escaneamento e, sem split que bate
com o corrente, responde `63Cx` (um consumo), como qualquer corpo
in-definido no intervalo — a recusa de formato fica para `Lc < 12` ou
`> 254`. O teste da S10 usa um corpo de 11 octetos para manter a recusa
sem consumo, e o caso de 15 octetos com corrente errado está coberto pelo
AC-4. Contradição interna da spec registrada aqui para o review.

Pendência física: estender `scripts/validate_openpgp.py` com o caso
"troca do PW1 default de 6 → corpo 12 → `9000`" e o fluxo
`gpg --card-edit` → `passwd` → "change PIN" em RP2350 disponível.

## SSH / Git signing (Fase 15, AC-020)

`validate_fido.py` cobre `makeCredential`/`getAssertion` Ed25519 (`alg -8`,
assinatura de 64 bytes) além dos fluxos ES256. Com hardware, o fluxo completo
é `ssh-keygen -t ed25519-sk` (residente ou não), `ssh-agent` e assinatura Git
via `gpg.format ssh` — ver o guia em `docs/ssh-git.md`. O dispositivo é
presença-apenas (BOOTSEL): a opção `verify-required` do OpenSSH não se aplica.

## Ferramenta de host em Rust (libusb)

O crate `crates/aegistoken-host` fala com o Management HID via **libusb**
(crate `rusb`, com a libusb compilada junto), sem depender de WinUSB/Zadig:

- **Windows** — usa o backend HID do libusb sobre o driver HID inbox
  (`hidusb`), então a interface de gestão é acessível sem trocar driver.
- **Linux** — o libusb desanexa o `usbhid` da interface; permissões via
  `scripts/99-aegistoken.rules`.
- **macOS** — acesso direto.

```powershell
cargo run -p aegistoken-host -- list          # enumera dispositivos/interfaces
cargo run -p aegistoken-host -- info          # GET_DEVICE_INFO
cargo run -p aegistoken-host -- capabilities  # GET_CAPABILITIES
cargo run -p aegistoken-host -- config        # GET_CONFIGURATION
cargo run -p aegistoken-host -- validate      # AC-003..AC-009 (Management HID)
```

Opções globais: `--vid`/`--pid` (padrão `0x1209:0x0001`), `--interface N`
(dispensa a descoberta pelo nome da interface) e `--timeout MS`. O comando
`validate` roda a mesma bateria do `validate_management.py` e retorna código de
saída diferente de zero em caso de falha.

> **Sem WinUSB:** o `aegistoken-host` não instala nem usa driver WinUSB. No
> Windows o libusb usa o **backend HID** (`hid.dll` + `CreateFile`/`ReadFile`
> sobre o driver HID inbox); o nome `windows_winusb.c` no libusb é apenas o
> arquivo que contém os dois sub-APIs. Sem Zadig, sem pnputil, sem remapear
> driver para a interface de gestão. O `validate` no Windows adiciona um check
> `Windows driverless access (libusb HID backend, no WinUSB)`, que falha se o
> backend HID do libusb não estiver disponível (caso em que um driver
> WinUSB/libusbK seria necessário).

## PIN (clientPIN)

O firmware implementa o CTAP2 clientPIN v1 (`getKeyAgreement`, `setPIN`,
`getPinToken`, `getPinUvAuthTokenUsingPinWithPermissions`, `getPINRetries`) e
anuncia `clientPin: true` e `pinProtocols: [1]` em `getInfo`, com presença
UP-only (BOOTSEL). Uma credencial residente (passkey) exige verificação do
usuário, então o Windows/Chrome pede para **criar o PIN** no primeiro uso —
basta digitar um PIN (≥4 caracteres) no diálogo "Segurança do Windows".

`makeCredential`/`getAssertion` com `options.uv = true` são aceitos quando o
`pinUvAuthParam` acompanha a requisição e confere com o token emitido pelo
`getPinToken`/`getPinUvAuthTokenUsingPinWithPermissions` (HMAC-SHA-256 sobre o
`clientDataHash`); nesse caso a flag UV é marcada no `authData`. Sem o
`pinUvAuthParam` válido, uma requisição UV é rejeitada com `PIN_AUTH_INVALID`
(0x33) em vez de travar o diálogo do Windows.

Para depurar falhas do cliente Windows sem acesso à interface FIDO, o firmware
guarda o último comando/status CTAP2 e os expõe pela Management HID
(`GET_LAST_FIDO_STATUS = 0x14`). Após reproduzir o erro, rode:

```powershell
python scripts/validate_management.py
```

e veja a linha `last FIDO command=0x.. status=0x.. (nome)`.

Para criar/alterar o PIN diretamente (após liberar a interface FIDO):

```powershell
python scripts/set_pin.py            # define o PIN (interativo)
python scripts/set_pin.py --change   # troca o PIN (interativo)
python scripts/set_pin.py --retries  # tentativas restantes
# não-interativo:
python scripts/set_pin.py --set --pin 123456
python scripts/set_pin.py --change --old-pin 123456 --pin 654321
```

## Acesso cross-platform ao USB

O perfil padrão expõe **FIDO HID** e **Management HID** (mais CCID); o perfil
`yubikey5-lab` acrescenta **OTP Lab HID**, sem suporte a comandos comerciais.
A forma de acesso varia por sistema operacional:

| SO | FIDO/Management (HID) |
|----|-----------------------|
| Linux | `hidraw` (regras udev em `scripts/99-aegistoken.rules`) |
| macOS | funciona direto (IOKit/hidapi) |
| Windows | driver `fidohid` bloqueia o FIDO; remapear MI_00 (Opção B) |

- **Linux** — instale as regras udev para acesso sem root:
  ```bash
  sudo cp scripts/99-aegistoken.rules /etc/udev/rules.d/
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```

Os scripts imprimem `[PASS]/[FAIL]` por AC e retornam código de saída diferente
de zero em caso de falha. O script FIDO2 pede para pressionar o BOOTSEL quando
User Presence é necessário.

## Windows: liberar a interface FIDO para validação

Por padrão o Windows associa a interface FIDO (MI_00, usage page `0xF1D0`) ao
driver `fidohid.inf`, que a mantém aberta com exclusividade e impede
`hidapi`/`python-fido2` (erro `ACCESS_DENIED`). Para validar
`makeCredential`/`getAssertion`, escolha uma das opções.

### Opção A — WebAuthn no navegador (recomendada, sem alterar drivers)

1. Abra <https://webauthn.io> (ou <https://demo.yubico.com/webauthn-technical/>).
2. Registre uma credencial; quando solicitado, pressione **BOOTSEL** (User
   Presence).
3. Autentique novamente com a credencial, pressionando **BOOTSEL**.

Isso exercita AC-011 (makeCredential/getAssertion) pela pilha FIDO do próprio
Windows, sem mexer em drivers.

### Opção B — Remapear o driver para HID genérico (habilita `validate_fido.py`)

1. `Win+X` → **Gerenciador de Dispositivos** (`devmgmt.msc`).
2. Em **Dispositivos de Interface Humana**, localize **HID-compliant fido**
   (Instance ID `HID\VID_1209&PID_0001&MI_00\...`). Dica: **Exibir → Dispositivos
   por conexão** e expanda o **USB Composite Device** `VID_1209&PID_0001`.
3. Botão direito → **Atualizar driver** → **Procurar drivers no computador**.
4. **Deixe-me escolher em uma lista de drivers disponíveis no computador**.
5. Desmarque **Mostrar hardware compatível**.
6. Fabricante **Microsoft** → modelo **USB Input Device** (driver `hidusb.inf`).
   Se essa entrada não aparecer, escolha **USB Device** — o rótulo varia conforme
   a versão do Windows; ambos vinculam `hidusb.sys`.
7. Avançar/confirmar. O dispositivo vira **Dispositivo de Entrada USB** / **USB
   Device**.
8. Confirme que ficou acessível:
   ```powershell
   python -c "from fido2.hid import CtapHidDevice; print(list(CtapHidDevice.list_devices()))"
   ```
9. Rode a validação:
   ```powershell
   python scripts/validate_fido.py
   ```
   Pressione **BOOTSEL** quando o script pedir.

Para reverter ao `fidohid.inf`:

1. **Gerenciador de Dispositivos** → localize o dispositivo remapeado
   (`USB\VID_1209&PID_0001&MI_00`).
2. Botão direito → **Atualizar driver → Pesquisar drivers automaticamente**.
3. Se o Windows informar que os melhores drivers já estão instalados:
   **Desinstalar dispositivo** (não marque "excluir o driver"; `fidohid.inf` é
   inbox) e **reconecte** o dispositivo. Na reenumeração o Windows reassocia
   `fidohid.inf` por casar `HID_DEVICE_UP:F1D0_U:0001`.
4. Alternativa por linha de comando (PowerShell como administrador):
   ```powershell
   pnputil /scan-devices
   ```
   após remover/reconectar o dispositivo.

Verificação da volta ao driver original:

```powershell
Get-PnpDeviceProperty -InstanceId "HID\VID_1209&PID_0001&MI_00\8&4C66895&0&0000" `
  -KeyName DEVPKEY_Device_DriverInfPath | Select-Object -ExpandProperty Data
# esperado: fidohid.inf
```

> Se o Windows reaplicar `fidohid.inf` a cada reconexão, use a Opção A
> (WebAuthn) ou um host Linux/macOS (Opção C).

### Opção C — Linux/macOS

Rode `scripts/validate_fido.py` em um host onde a interface FIDO esteja
acessível via `hidraw`.

## Matriz de critérios de aceitação

| AC | Critério | Método | Status |
|----|----------|--------|--------|
| AC-001 | Inicializar em RP2350A | `GET_CAPABILITIES` (gpio=30) + boot | **Verificado** |
| AC-002 | Enumerar FIDO HID | `validate_fido.py` + PnP `UP:F1D0` | **Verificado** |
| AC-003 | Enumerar Management HID | `validate_management.py` | **Verificado** |
| AC-004 | Responder `GET_DEVICE_INFO` | `validate_management.py` | **Verificado** |
| AC-005 | Responder `GET_CAPABILITIES` | `validate_management.py` | **Verificado** |
| AC-006 | Configuração válida via Management HID | `validate_management.py` (SET+COMMIT) | **Verificado** |
| AC-007 | Rejeitar configuração incompatível | `validate_management.py` (status 4 e 6) | **Verificado** |
| AC-008 | Persistir configuração após power cycle | `ConfigStorage` (testes) + ciclo físico | Parcial (COMMIT grava em flash; ciclo físico pendente) |
| AC-009 | Descoberta sem seleção manual | `validate_management.py` | **Verificado** |
| AC-010 | BOOTSEL no boot → Recovery | Bootrom (BOOTSEL → bootloader USB) + gating por plano de boot (`aegis-core::state::BootPlan`) | Bootrom pendente; gating entregue (host/estático, ver abaixo) |
| AC-011 | BOOTSEL em `FIDO_WAIT_PRESENCE` → presença | `validate_fido.py` makeCredential/getAssertion | **Verificado** |
| AC-012 | BOOTSEL em outros estados ≠ aprovação | Testes de host (`ContextualPresence`) | Coberto por teste de host |
| AC-013 | Material privado nunca exportado | Ausência de API de exportação + testes | **Verificado** / revisão |
| AC-014 | Firmware inválido não executa | Secure boot do bootrom (secp256k1 + OTP) | Pendente (produção) |
| AC-015 | Rollback não autorizado não executa | `update` (testes) + rollback do bootrom | Lógica OK; OTP pendente |
| AC-016 | CCID enumera e roteia por AID | `validate_ccid.py` + `opensc-tool -l` + selftest `applet-select` | Transporte e roteamento OK em host/tests e no autoteste on-target; PC/SC em hardware pendente |
| AC-017 | PIV: PIN, chaves P-256/P-384 e assinatura | `validate_piv.py` + `pivy`/OpenSC | Applet OK em testes de host; hardware pendente; persistência selada entregue |
| AC-018 | OATH: HOTP/TOTP e CCID | `validate_oath.py` + RFC 4226/6238 | Applet OK em testes de host; hardware pendente; persistência selada entregue |
| AC-019 | OpenPGP Card: PW1/PW3, ECC e assinatura | `validate_openpgp.py` + GnuPG/OpenSC | Slices P-256/Ed25519/X25519 OK em testes de host; hardware pendente; persistência selada entregue |
| AC-020 | SSH/Git (`ed25519-sk`) + OpenPGP Ed25519/X25519 | `validate_fido.py` + `validate_openpgp.py` + OpenSSH | Firmware pronto em testes de host; hardware pendente |
| AC-021 | RSA-2048 (PIV/OpenPGP): keygen, assinatura, decifra | `validate_piv.py` + `validate_openpgp.py` + OpenSSL/GnuPG/`pkcs11-tool` | Firmware pronto em testes de host (147 `aegis-applets`); hardware pendente; RSA-3072/PSS fora de escopo |
| AC-022 | OpenPGP: `RESET RETRY COUNTER` exige PW3 verificado (unblock fail-closed; BC → `6A81`) | Testes de host `aegis-applets::openpgp` (fatia S4) + `validate_openpgp.py` | **Verificado em host** (7 testes novos); `validate_openpgp.py` em hardware pendente |
| AC-023 | OpenPGP: persistência de PIN fail-closed (mutadores de PIN → `6A84` em falha de gravação; piso sticky intra-sessão) | Testes de host `aegis-applets::openpgp` (fatia S5) + `docs/security-model.md` | **Verificado em host** (10 testes novos); indução de falha de flash em hardware pendente |
| AC-024 | OpenPGP: `PUT DATA D2` fail-closed na fronteira (`kdf_hash` só SHA-256; `wrapped_len` no domínio de *key wrap* RFC 3394; recusa → `6A80` sem gravar) | Testes de host `aegis-applets::openpgp` (fatia S6) + interop `gnupg_interop` | **Verificado em host** (5 testes novos + extensão do interop); `validate_openpgp.py` em hardware pendente |
| AC-025 | OpenPGP: frames malformados de DECIPHER e corpos D2 fora de domínio → SW fechado único, corpo vazio, sem pânico/gravar/eco de material; fronteiras 24/32/40/48 aceitas; fallback parcial documentado; limite de resposta 2048 registrado; ponto zero X25519 = comportamento da curva | Testes de host `aegis-applets::openpgp` (fatia S8) | **Verificado em host** (8 testes novos); sem pendência de hardware |
| AC-026 | OpenPGP: o estado gravado por um comando aceito sobrevive à sessão — `decode_state` aceita exatamente a geometria que o writer produz (slot de decifra, UNSET/ECDH P-256, `len` 104), larguras desconhecidas fail-closed, sem bump de versão (livro-in do blob v3) | Testes de host `aegis-applets::openpgp` (fatia S9, `state_roundtrip`) | **Verificado em host** (5 testes novos + inversão do teste S8); power cycle físico + GnuPG em hardware pendente |
| AC-027 | OpenPGP: `CHANGE REFERENCE DATA` do PW3 (`P2=0x83`) exige a sessão de admin (`6982` sem tocar estado, contador ou store); o PW1 (`0x81`/`0x82`) mantém a autoridade do corrente no corpo; sessão mantida pela troca | Testes de host `aegis-applets::openpgp` (fatia S10) | **Verificado em host** (6 testes novos + 2 S5 atualizados); extensão do `validate_openpgp.py` + interop `gpg` físicos pendentes |
| AC-028 | OpenPGP: `CHANGE REFERENCE DATA` do PW1 aceita o corpo variável `atual‖novo` da card spec (`12 ≤ Lc ≤ 254`; fora → `6A80` sem tocar slot/contador/store; delimitação pelo hash armazenado — varredura read-only `PinSlot::resolve_change`; corrente errado → exatamente **uma** tentativa `63Cx` com persist; piso S5 com `6A84` na falha de gravação; `0x83` mantém corpo fixo 16 + gate da S10; sem bump de `PIN_STATE_VERSION`) | Testes de host `aegis-applets::openpgp` (fatia S11) | **Verificado em host** (7 testes novos + comentário do teste S10 atualizado); `validate_openpgp.py` + interop `gpg --card-edit` físicos pendentes |

### Fases 7e — credential management e `changePIN` (host; hardware pendente)

Cobertos por 225 testes de host em `aegis-core` (14 novos) e pelo validador
`scripts/validate_fido.py --pin <PIN>`, que exercita em hardware:

- `getPinUvAuthTokenUsingPinWithPermissions` com a permissão `cm`;
- `changePIN` (rotação de ida e volta);
- `enumerateRPs` e `enumerateCredentials` sobre uma credencial residente.

O status de hardware permanece pendente (sem RP2350 físico nesta sessão).

### Fase 7g — escopo e ciclo de vida do `pinUvAuthToken` (host; hardware pendente)

Cobertos por 258 testes de host em `aegis-core` (16 novos nesta fatia: 13 em
`pin.rs` e 3 em `authenticator.rs`; 6 testes antigos de escopo foram
substituídos pelos novos). A especificação da
fatia é `specs/ctap2-token-scope.md` (AC1..AC15).

| AC | Critério | Teste de host | Status |
|----|----------|---------------|--------|
| AC-1 | Emissão com `mc`/`ga` sem `rpId` aceita; `permissions = 0` → 0x02 e permissão não suportada → 0x40 | `token_requests_validate_the_permissions` | **Verificado** |
| AC-2 | Token `cm` sem `rpId` fica sem vínculo e opera o dispositivo inteiro | `cm_token_without_rp_id_drives_the_whole_device` | **Verificado** |
| AC-3 | Token legado concede `mc|ga` e nunca autoriza credential management | `legacy_token_is_accepted_by_make_credential_and_get_assertion`, `token_permissions_follow_the_requested_subcommand` | **Verificado** |
| AC-4 | `makeCredential` exige a permissão `mc` (0x33) | `make_credential_requires_the_mc_permission` | **Verificado** |
| AC-5 | `getAssertion` exige a permissão `ga` (0x33) | `get_assertion_requires_the_ga_permission` | **Verificado** |
| AC-6 | Token de outro RP é recusado (0x33) | `token_bound_to_another_rp_is_refused` | **Verificado** |
| AC-7 | Primeiro uso vincula o token ao RP; outro RP é recusado | `first_use_binds_the_token_to_the_relying_party` | **Verificado** |
| AC-8 | Credential management exige `cm` (0x33); sem `pinUvAuthParam` → 0x36 | `credential_management_requires_the_cm_permission` | **Verificado** |
| AC-9 | Escopo global exige token sem vínculo de RP (0x33) | `device_scope_requires_a_token_without_rp_binding` | **Verificado** |
| AC-10 | `enumerateCredentialsBegin` restrito ao `rpIDHash` do RP vinculado | `enumerate_credentials_is_restricted_to_the_bound_rp` | **Verificado** |
| AC-11 | `deleteCredential` restrito ao RP da credencial (lido do store); credencial preservada | `delete_credential_is_restricted_to_the_bound_rp` | **Verificado** |
| AC-12 | Operação com presença bem-sucedida esvazia as permissões do token | `user_presence_operation_drops_the_token_permissions` (auxiliar em `aegis-core`) | **Verificado** no auxiliar; *wiring* do firmware verificado só por build/inspeção |
| AC-13 | Operação com erro (ou sem token) mantém as permissões | `failed_operation_keeps_the_token_permissions` (auxiliar em `aegis-core`) | **Verificado** no auxiliar; *wiring* do firmware verificado só por build/inspeção |
| AC-14 | `changePIN` invalida o token (0x33) | `change_pin_invalidates_the_token` | **Verificado** |
| AC-15 | `authenticatorReset` invalida o token (0x33) | `reset_invalidates_the_pin_uv_auth_token` | **Verificado** |
| AC-W | Wiring de firmware (escopo por operação, por RP e ciclo de vida) | `cargo clippy-fw` + `cargo build-fw` | **Verificado** (build/alvo) |

Método: testes de host em `aegis-core` (`pin::tests` e `authenticator::tests`).
A decisão de autorização mora em `aegis-core::pin::ClientPin::authorize`
(HMAC + permissão + escopo de RP, com `Result<bool, Ctap2Status>`); o firmware
apenas despacha e informa o contexto (permissão exigida, RP da requisição,
RP efetivo da credencial). Sem HAL, executor ou dependência de storage.

**Limitação (gate de hardware pendente):** a validação de ponta a ponta em
dispositivo físico continua **pendente** — não há RP2350 físico nesta sessão.
`scripts/validate_fido.py --pin <PIN>` é o candidato natural: o validador foi
estendido com os casos negativos desta fatia (token legado em credential
management → 0x33; token `cm` com `rpId` → `enumerateRPsBegin` recusado;
token `mc` vinculado a `example.com` em `getAssertion` de outro RP → 0x33) e
passou a buscar um **token novo por operação** — o token é consumido por uma
operação com User Presence bem-sucedida (§6.5.5.7), então reutilizá-lo
falharia com 0x33. O script não foi executado (sem dispositivo).

**Mudanças de comportamento observável:** o token de `getPinToken` (0x05)
passa a ser recusado em credential management (0x33); `getCredsMetadata`
(0x01) passa a exigir token com `cm` (sem `pinUvAuthParam` → 0x36); o token
usado numa operação com User Presence bem-sucedida perde as permissões
(0x33 no uso seguinte); `authenticatorReset` invalida o token ativo.

### Fase 7h — Recovery/Locked não servem FIDO/CCID (host; hardware pendente)

Cobertos por 258 testes de host em `aegis-core` (10 novos nesta fatia: 8 em
`aegis-core::state`, 1 em `recovery.rs` e 1 em `management_protocol.rs`) e por
`cargo clippy-fw` + `cargo build-fw-release` (verificação estática do wiring):

| AC | Critério | Teste de host / verificação | Status |
|----|----------|----------------------------|--------|
| AC-1 | `Active` habilita FIDO, CCID, Management e HID OTP | `boot_plan_active_enables_fido_ccid_management` | **Verificado** |
| AC-2 | `Recovery` nega FIDO/CCID e mantém Management | `boot_plan_recovery_denies_fido_ccid_keeps_management` | **Verificado** |
| AC-3 | `Locked` nega FIDO/CCID e mantém Management | `boot_plan_locked_denies_fido_ccid_keeps_management` | **Verificado** |
| AC-4 | FIDO e CCID não divergem; FIDO nunca habilitado onde `fido_allowed` nega | `boot_plan_fido_and_ccid_never_diverge`, `boot_plan_never_enables_fido_where_fido_allowed_denies` | **Verificado** |
| AC-5 | Falha fechada nos estados que não são destino de boot | `boot_plan_is_fail_closed_for_non_destination_states` | **Verificado** |
| AC-6 | O destino de boot é sucessor legal de `Boot` | `boot_destination_is_always_a_legal_successor_of_boot` | **Verificado** |
| AC-7 | Stores selados só são abertos quando o caminho está habilitado | `boot_plan_denies_sealed_stores_outside_active` + `cargo clippy-fw` (pontos de abertura condicionados ao plano) | **Verificado** (host/estático) |
| AC-8 | Management HID não é afetado pelo gating | Suíte de `aegis-core::management_protocol` (`GET_STATUS`, `GET_DIAGNOSTICS`) + flags do plano | **Verificado** |
| AC-9 | Boot com BOOTSEL não inicia `fido_task`/`ccid_task`; mantém `housekeeping`/`otp_task`; loga destino e plano | `cargo clippy-fw` + `cargo build-fw-release` + log de boot | **Verificado** (estático) |
| AC-10 | FIDO/CCID enumeram mas não respondem; Management responde | Procedimento físico abaixo | Pendente (hardware) |
| AC-11 | `GET_DIAGNOSTICS` expõe o destino do boot e os caminhos servidos | `diagnostics_report_shows_the_boot_plan`, `diagnostics_report_shows_the_denied_paths_in_recovery` | **Verificado** |
| AC-12 | A leitura do BOOTSEL no boot exige nível estável (3 amostras) | `cargo clippy-fw` + `cargo build-fw` (rotina `read_bootsel_stable`) | **Verificado** (estático) |

Método: a decisão é lógica pura no núcleo (`aegis-core::state::BootPlan`),
sem HAL, executor ou storage; o firmware apenas lê o plano e obedece.

**Diagnóstico de um dispositivo silenciado:** `GET_DIAGNOSTICS` (0x0A) passa a
reportar `boot_destination` (0x08), `fido_enabled` (0x09) e `ccid_enabled`
(0x0A), para que um dispositivo mudo pelo plano seja distinguível de um
dispositivo quebrado.

**Leitura do BOOTSEL:** o destino do boot é decidido por 3 amostras do pad
(1 ms de intervalo). Uma leitura instável é tratada como "solto" e registrada
em log: um falso positivo colocaria o dispositivo em `Recovery` e o deixaria
mudo, o que é pior do que perder um boot de recuperação.

**Procedimento físico (AC-10, pendente de RP2350 físico):**

1. Flash do firmware: `& scripts/build-uf2.ps1`.
2. **Manter BOOTSEL pressionado durante o power cycle.**
3. Esperar a enumeração e registrar que as interfaces FIDO (usage page
   `0xF1D0`) e CCID enumeram.
4. `python scripts/validate_fido.py` → **deve falhar/timeout** (sem resposta).
5. `python scripts/validate_ccid.py` (ou `opensc-tool -l` + seleção de AID) →
   **deve falhar/timeout**.
6. `python scripts/validate_management.py` → `GET_STATUS` e `GET_DIAGNOSTICS`
   **devem responder**.
7. Power cycle **sem** BOOTSEL → `validate_fido.py` volta a passar.

**Limitação:** as interfaces FIDO/CCID **continuam enumerando**; a supressão da
enumeração USB é não-objetivo desta fatia (efeito observável: enumerado e
mudo). A saída do Recovery é o **power cycle sem BOOTSEL mantido** (o destino
volta a ser `Active`) ou um firmware update assinado seguido de reboot — o
caminho de update permanece disponível em Recovery.

**Selftest destrutivo:** `crates/firmware-universal-rp2350/src/selftest.rs`
abre um `SealedCredentialStore` **na área de scratch** (`0x0016_0000`, região de
staging), não na região do store de credenciais (`0x136000`), e apenas sob a
feature `selftest` (fora das imagens padrão de `scripts/build-uf2.ps1`). Ele
não é via de leitura de credenciais em Recovery.

### Estado de asserção pendente é restrito ao canal CTAPHID (host)

A continuação de `authenticatorGetNextAssertion` fica em
`aegis-core::assertion` (lógica pura, testável em host): o estado é criado
apenas para uma requisição que produziu assinatura e é indexado pelo **canal
CTAPHID** que a iniciou. Uma segunda aplicação no mesmo host recebe
`NoCredentials` — sem id de credencial, sem user handle e sem a assinatura de
um `clientDataHash` que não enviou.

| Verificação | Resultado |
|-------------|-----------|
| `cargo test -p aegis-core assertion` | 4 testes aprovados |
| Canal diferente tenta continuar | `None` (o dono da asserção ainda consegue continuar) |
| Credenciais servidas em ordem | primeira, segunda; depois `None` |
| Contexto preservado (`rp_id`, `clientDataHash`, `uv`) | verificado |

**Limitação:** a validação em hardware (dois canais CTAPHID contra o firmware
flashado) permanece pendente — não há RP2350 físico nesta sessão.

### OpenPGP ECDH: o segredo compartilhado não sai do cartão (RFC 6637, etapa S1)

O applet OpenPGP **não devolve mais** o segredo ECDH ao host: `PSO:DECIPHER`
passa a falhar fechada (`6A81`) para slots ECDH sem material RFC 6637
provisionado. As primitivas (KDF da RFC 6637 §7, AES Key Wrap da RFC 3394 e o
bloco de parâmetros do §8) estão em `aegis-applets::ecdh`. Spec:
`specs/openpgp-rfc6637-ecdh.md`.

| AC | Verificação | Resultado |
|----|-------------|-----------|
| AC-1 | KDF reproduz o vetor de referência (`SHA-256(00 00 00 01 \|\| ZB \|\| Param)`) | **Verificado** (`the_kdf_matches_the_reference_value`) |
| AC-2 | Desembrulho reproduz os quatro vetores da RFC 3394 §4 (KEK de 128/192/256 bits, dados de 128 e 192 bits) | **Verificado** (`unwraps_the_rfc3394_vectors`) |
| AC-3 | Embrulho adulterado e comprimento inválido são recusados, sem devolver parte da chave | **Verificado** (`rejects_a_tampered_wrapping`, `rejects_invalid_lengths`) |
| AC-4 | `Param` do §8 com o layout exato (tamanho 54 para P-256) | **Verificado** (`the_parameters_follow_the_rfc_layout`) |
| AC-5 | `PSO:DECIPHER` em slot ECDH P-256 responde erro e **não** devolve o segredo | **Verificado** (`pso_decipher_refuses_to_leak_the_shared_secret`) |
| AC-6 | O mesmo para o slot X25519 (sem `Param` normado na RFC 6637) | **Verificado** (`x25519_decipher_fails_closed_without_rfc6637_material`) |
| AC-7 | O caminho RSA de `PSO:DECIPHER` continua devolvendo o bloco decifrado | **Verificado** (suíte do applet verde) |
| AC-8 | `GENERATE`, `READ PUBLIC`, `INTERNAL AUTHENTICATE` e as assinaturas inalterados | **Verificado** (suíte do applet verde) |

**Mudança de comportamento observável:** a decifra ECDH deixa de funcionar
até a etapa S2 (material provisionado, desembrulho da chave de sessão e decifra
do texto no cartão). É uma regressão funcional deliberada: o comportamento
anterior expunha o segredo compartilhado ao host, o que anulava o cartão como
autoridade de decifra.

**Limitação:** o `Param` da §8 (bloco `0x03 0x01` e impressão digital do
destinatário) só pode ser confirmado contra o GnuPG em placa; a etapa S2
depende de hardware e de provisionamento.

### OpenPGP ECDH: decifra no cartão e interop com o GnuPG (RFC 6637, S1-S3)

**Correção de premissa:** a OpenPGP Card 3.4.1 §4.4.3.8 define o ECDH do
`PSO:DECIPHER` como um ***partial decrypt*** — o cartão calcula o segredo
compartilhado e o **devolve**, porque a chave efêmera da mensagem foi escolhida
pelo *remetente* e o host não consegue calculá-la. O que o cartão protege é a
chave privada, que nunca sai; a liberação do segredo derivado é condicionada à
verificação de PW1 no modo 82. O cartão **mantém** esse comportamento (para a
interoperabilidade com o GnuPG) e **acrescenta** o modo em que decifra sozinho
(RFC 6637 §8), ativado quando o host provisiona a chave de sessão embrulhada.

**Interop real:** o teste `gnupg_encrypts_and_the_card_decrypts` cria uma home
temporária do GnuPG, deixa o **GnuPG** gerar a chave ECDH P-256 no formato do
cartão, extrai a chave privada do *export* (S2K sem proteção) e a injeta no slot
de decifra do applet (só no teste: o applet não importa chave privada). O GnuPG
cifra uma mensagem de verdade para essa chave e o applet a decifra pelo caminho
APDU real (`PUT DATA 0xD2` + `PSO:DECIPHER`), com PW1/PW3 verificados. O lado do
remetente é 100% GnuPG (KDF, *key wrap*, MFX).

| AC | Verificação | Resultado |
|----|-------------|-----------|
| AC-1 | A KDF da §7 reproduz o vetor de referência e o `Param` tem o layout da §8 (54 bytes para P-256) | **Verificado** (`the_kdf_matches_the_reference_value`, `the_parameters_follow_the_rfc_layout`) |
| AC-2 | O *key wrap* da RFC 3394 reproduz os quatro vetores da RFC, nos dois sentidos | **Verificado** (`unwraps_the_rfc3394_vectors`, `wraps_to_the_rfc3394_vectors`) |
| AC-3 | A camada simétrica reproduz uma mensagem **real do GnuPG** nos dois sentidos, com *quick check* e MDC | **Verificado** (`decrypts_a_message_encrypted_by_gnupg`, `encrypts_to_the_gnupg_ciphertext`, `a_wrong_key_fails_the_quick_check`, `a_tampered_ciphertext_fails_the_modification_code`) |
| AC-4 | Com material provisionado, o cartão decifra uma mensagem real: o teste faz o papel do remetente (chave efêmera, segredo compartilhado, chave de sessão embrulhada, mensagem cifrada) e o cartão devolve o texto claro | **Verificado** (`pso_decipher_unwraps_the_session_key_and_decrypts`) |
| AC-5 | Sem material provisionado, o cartão devolve o segredo compartilhado (*partial decrypt* da especificação), com PW1 modo 82 exigido | **Verificado** (`pso_decipher_returns_the_shared_secret_per_the_card_spec`) |
| AC-6 | O mesmo para X25519, com a simetria DH conferida | **Verificado** (`x25519_decipher_returns_the_shared_secret`) |
| AC-7 | O caminho RSA de `PSO:DECIPHER` e o resto da suíte do applet seguem verdes | **Verificado** (172 testes) |
| AC-8 | **Interop fim a fim com o GnuPG**: a mensagem que o GnuPG cifra para a chave do cartão é decifrada pelo `PSO:DECIPHER` do applet, e o GnuPG decifra a mesma mensagem com a própria chave | **Verificado** (`gnupg_interop::gnupg_encrypts_and_the_card_decrypts`) |
| AC-9 | O fingerprint do destinatário que o remetente usou na KDF chega pelo provisionamento e o cartão o usa em vez do que calcula (sem relógio, `ctime = 0`); sem ele, se o fingerprint próprio não casar, a decifra falha fechada | **Verificado** (o próprio teste de interop, mais `pso_decipher_unwraps_the_session_key_and_decrypts` e `the_fingerprint_is_an_optional_part_of_the_provisioning`) |
| AC-10 | `GENERATE`/`READ PUBLIC KEY` devolvem o ponto EC sob a tag `86` da OpenPGP Card 3.4.1 §4.4.3.10, nunca `81` | **Verificado** (`ec_public_key_response_uses_the_spec_tag`) |

**Três divergências reais que a interop achou (e o que ficou):**

1. O ponto EC saía sob a tag `81` (que é o módulo RSA) em vez de `86`: corrigido
   em `public_key_response` e em `scripts/validate_openpgp.py`.
2. O fingerprint da RFC 4880 §12.2 cobre o **tempo de criação** da chave; o
   cartão não tem relógio e calcula fingerprints com `ctime = 0`, então a KDF da
   §8 não fechava com a do remetente. O provisionamento `PUT DATA 0xD2` passou a
   aceitar os 20 octetos do fingerprint do destinatário (opcionais; sem eles o
   cartão cai no fingerprint que calcula).
3. A camada simétrica tratava os dois octetos de *quick check* como um ponto de
   ressincronização do CFB. O GnuPG mantém a cadeia **contínua** com IV zero
   (RFC 4880 §13.9): os octetos repetidos fazem parte do fluxo. Com a
   ressincronização errada o MDC da mensagem real nunca fechava.

**Limitação (hardware):** o formato do provisionamento da chave de sessão
embrulhada continua **provisório** (`PUT DATA 0xD2`); o *key import* da OpenPGP
Card 3.4 importa a **chave privada**, o que contraria a regra do projeto de não
importar chave privada — daí o caminho próprio. A validação `gpg -d` contra o
cartão físico segue pendente (não há RP2350 nem leitor PC/SC nesta sessão); o
que está verificado é a cadeia completa em software contra o GnuPG real.

### Contagem de credenciais conforme a CTAP 2.1 (host)

O membro `numberOfCredentials` (chave CBOR 5) segue as regras da CTAP 2.1:
presente apenas quando mais de uma credencial correspondeu e a requisição **não**
trouxe `allowList`; ausente com `allowList`, com uma única credencial e nas
respostas de `authenticatorGetNextAssertion`. A lista de candidatos deixou de
ser truncada em silêncio: um store com mais credenciais que o limite responde
`LimitExceeded` (0x15). Spec: `specs/ctap2-number-of-credentials.md`.

| AC | Verificação | Resultado |
|----|-------------|-----------|
| AC-1 | Sem `allowList` e 2 credenciais → membro presente com o valor 2 | **Verificado** (`number_of_credentials_follows_the_ctap21_rules`, `the_count_member_is_absent_when_the_rules_forbid_it`) |
| AC-2 | Com `allowList` e 2 correspondências → membro ausente | **Verificado** |
| AC-3 | Com 1 credencial → membro ausente | **Verificado** |
| AC-4 | Resposta de continuação → membro ausente | **Verificado** |
| AC-5 | Caminho do firmware informa a contagem real e a omite quando a norma exige | `cargo clippy-fw` + `cargo build-fw-release` (build/alvo) |
| AC-6 | Estouro do limite → `LimitExceeded`, sem truncamento | **Verificado** (`a_candidate_list_over_the_limit_is_not_truncated_silently`) |
| AC-7 | Regressão de `getAssertion` (assinatura, `authData` com UP/UV) | **Verificado** (suíte de `aegis-core` verde) |

**Limitação:** a validação em hardware (enumeração com duas contas do mesmo RP
contra o firmware flashado) permanece pendente — não há RP2350 físico nesta
sessão.

### Gate de release: a chave de update de desenvolvimento nunca é distribuída (host)
Verificado por testes de host em `crates/aegis-build-support` e por execução
real do build (a spec é `specs/release-requires-vendor-key.md`):

| Verificação | Resultado |
|-------------|-----------|
| `cargo test -p aegis-build-support` | 12 testes aprovados |
| `AEGIS_RELEASE=1` sem `AEGIS_UPDATE_VENDOR_PUBKEY` | build **falha** (`AEGIS_RELEASE=1 requires a production firmware-update vendor key …`) |
| `AEGIS_RELEASE=1` com chave de produção válida | build **passa**, sem o aviso de chave DEV |
| `AEGIS_RELEASE=1` com o hex da chave DEV explícito | build **falha** (a chave DEV é detectada por bytes) |
| `AEGIS_RELEASE=true` (valor inválido) | build **falha** (`AEGIS_RELEASE must be '1' …`) |
| Chave com sinal (`+a`) ou caractere não-hex | **falha** (`must be hexadecimal …`) — o parsing estrito rejeita o que `from_str_radix` aceitaria |
| Sem `AEGIS_RELEASE` e sem chave | build **passa** com o aviso de chave DEV (comportamento de desenvolvimento) |
| `& scripts/build-uf2.ps1 -Release` sem a chave | **falha antes** de compilar |
| `& scripts/build-uf2.ps1 -Release` com chave malformada ou com a chave DEV | **falha antes** de compilar (mesma política do `build.rs`, via `vendor-key-check`) |
| `& scripts/build-uf2.ps1 -Release` com chave válida | compila, gera o UF2 e restaura `AEGIS_RELEASE` no shell |
| Job de release do CI | tags versionadas compilam com `-Release`; nightlies seguem em modo de desenvolvimento |

**Limitação:** o gate é opt-in por variável de ambiente/`-Release`; builds de
terceiros que não o usem continuam embutindo a chave de desenvolvimento com
aviso. O aviso no boot permanece como defesa para imagens já gravadas.

### Rodada de gate em hardware (roteiro único)

Sequência para executar o gate completo em um RP2350 físico. Tudo o que a
rodada produz deve ser anexado a `validation.md` (evidência) e ao commit da
fatia correspondente.

**Pré-requisitos**

| Item | Necessário para |
|------|-----------------|
| `python-fido2` (`pip install fido2`) | `validate_fido.py` (FIDO2/U2F, clientPIN, credential management) |
| `cbor2`, `hidapi` | `validate_management.py` (Management HID) |
| `pcsc_transport`/`pyscard` **ou** `pcscd`+`usbccid` | `validate_ccid.py`, `validate_piv.py`, `validate_oath.py`, `validate_openpgp.py` |
| Interface FIDO liberada do driver `fidohid` do Windows | `validate_fido.py` (ver "Windows: liberar a interface FIDO") |
| `probe-rs` (flash e RTT) | `flash` + log de boot |
| `AEGIS_UPDATE_VENDOR_PUBKEY` exportada | build com chave de update de produção |

**1. Build e flash da imagem de release**

```powershell
& scripts/build-uf2.ps1 -Release
probe-rs run --chip RP2350 target/thumbv8m.main-none-eabihf/release/firmware-universal-rp2350
```

O log de boot (RTT) deve mostrar o destino `active` e o plano com
`fido=true ccid=true management=true`. Uma imagem com a chave de
desenvolvimento é recusada por `-Release`.

**2. Management HID (AC-003..AC-009)**

```powershell
python scripts/validate_management.py
```

Além dos 12 checks já automatizados, registrar o `GET_DIAGNOSTICS`:
`boot_destination` deve ser `active` e `fido_enabled`/`ccid_enabled` devem
ser `true` (chaves CBOR 0x08/0x09/0x0A).

**3. FIDO2/U2F, clientPIN e credential management (AC-002/011/013, 7e/7g)**

```powershell
python scripts/validate_fido.py                 # sem PIN: fluxo só com presença
python scripts/validate_fido.py --pin 123456    # com PIN: exige a prova do PIN
```

Com `--pin`, o script exercita: `getPinToken`/`getPinUvAuthTokenWithPermissions`,
`changePIN` (ida e volta), `enumerateRPs`/`enumerateCredentials` sobre uma
credencial residente e os **casos negativos** do escopo do token (token legado
em credential management → 0x33; token `cm` com `rpId` → `enumerateRPsBegin`
recusado; token `mc` de um RP em `getAssertion` de outro RP → 0x33).

**4. CCID e applets (AC-016..AC-021)**

```powershell
python scripts/validate_ccid.py
python scripts/validate_piv.py
python scripts/validate_oath.py
python scripts/validate_openpgp.py
```

**5. Procedimento 7h — Recovery/Locked negam FIDO/CCID (AC-10)**

1. Flash do firmware e **manter BOOTSEL pressionado durante o power cycle**.
2. Registrar que as interfaces FIDO (usage page `0xF1D0`) e CCID **enumeram**.
3. `python scripts/validate_fido.py` → **deve falhar/timeout** (sem resposta).
4. `python scripts/validate_ccid.py` → **deve falhar/timeout**.
5. `python scripts/validate_management.py` → `GET_STATUS` e `GET_DIAGNOSTICS`
   **respondem**, com `boot_destination = recovery` e `fido_enabled`/
   `ccid_enabled` = `false`.
6. Power cycle **sem** BOOTSEL → `validate_fido.py` volta a passar.

**6. Evidência**

Anexar a saída dos scripts, o log de boot e a captura da USB (enumerate +
`GET_DIAGNOSTICS`) às seções "Evidência — …" desta matriz e marcar as linhas
correspondentes como **Verificado** (hoje estão "host; hardware pendente").

### Evidência — Management HID (12/12)

```
[PASS] AC-003 Management HID enumeration
[PASS] AC-004 GET_DEVICE_INFO        (AegisToken FIDO2 USB Authenticator, família RP2350, 0.1.0)
[PASS] AC-005 GET_CAPABILITIES
[PASS] AC-009 automatic discovery    (gpio_count=30)
[PASS] capabilities advertise both HID interfaces
[PASS] AC-006a GET_CONFIGURATION
[PASS] AC-006 valid configuration applied (set=0 commit=0)
[PASS] AC-007 reject out-of-range GPIO (status=4)
[PASS] AC-007 reject bad USB identity  (status=6)
[PASS] GET_LIFECYCLE / GET_STATUS / GET_DIAGNOSTICS
```

### Evidência — FIDO (13/13)

```
[PASS] AC-002 FIDO HID enumeration (accessible)
[PASS] CTAPHID cap CBOR / NMSG (U2F)
[PASS] U2F VERSION — U2F_V2
[PASS] getInfo: ['FIDO_2_0', 'U2F_V2'], up, clientPin, pinUvAuthProtocols [1]
[PASS] AC-011 makeCredential (UP) — fmt=packed
[PASS] AC-011 getAssertion (UP) — sig=71B
[PASS] clientPIN getPINRetries — retries=8
[PASS] AC-013 no credential export API
```

### Evidência — applets/RSA em host (147 `aegis-applets`, 193 `aegis-core`)

```
[PASS] rsa textbook n=3233 round trip (Montgomery end-to-end)
[PASS] rsa keygen e*d=1 mod phi, n 2048-bit, CRT == full private op
[PASS] rsa EMSA-PKCS1-v1_5 + DigestInfo encode/verify, blinding determinism
[PASS] piv GENERATE RSA-2048 -> 7F49{81 n, 82 010001}; raw SIGN inverts via public_op
[PASS] piv RSA PIN-once gate, touch always/confirm/deny, reopen persistence
[PASS] openpgp C1-C3 RSA attrs (5/6-byte forms), GENERATE/READ PUBLIC 7F49{81,82}
[PASS] openpgp PSO:CDS DigestInfo + raw-EM sign, AUT raw challenge, DECIPHER (bare/00|02/MPI)
[PASS] openpgp RSA fingerprint vs pacote RFC 4880 reconstruído; estado v2->v3
```

### AC-021 em hardware (procedimento, pendente de dispositivo)

Com o dispositivo conectado e a interface CCID ativa (`opensc-tool -l`):

```powershell
python scripts/validate_piv.py       # AC-021: GENERATE 9A + SIGN + s^e mod n
python scripts/validate_openpgp.py   # AC-021: attrs + GENERATE + sign (OpenSSL) + decipher + C7
```

Interop complementar (regressão ECC preservada):

```powershell
pivy --admin --genkey --slot 9A --alg RSA2048   # PIV via pivy
pkcs11-tool --module opensc-pkcs11.dll --test  # PIV via OpenSC
gpg --card-edit  # key-attr rsa2048 -> generate -> sign/decrypt
```

Suposições de interop registradas em código e confirmadas só com hardware:
`PSO:DECIPHER` devolve o bloco cru de 256 B (o GnuPG remove o padding
PKCS#1); `PSO:CDS` aceita bloco EM de 256 B ou `DigestInfo` com EMSA
on-card. A geração RSA-2048 on-device leva segundos (dezenas de tentativas
Miller-Rabin em host; medir no alvo e alimentar o watchdog na tarefa CCID
se exceder o timeout).

### Correções encontradas em hardware

A validação com um cliente real revelou dois bugs de transporte, já corrigidos:

1. **INIT no canal de broadcast** — a resposta ao `CTAPHID_INIT` era enviada no
   canal recém-alocado; o correto é enviá-la no canal de broadcast
   `0xFFFFFFFF`, com o novo canal no payload. Sintoma:
   `ConnectionFailure: Wrong channel`.
2. **Prefixo de status CTAP2** — respostas CBOR de sucesso devem ser
   `status(0x00) || CBOR` (CTAP 2.0 §6.2); o firmware enviava apenas o CBOR, e o
   cliente interpretava o header do mapa (`0xA5`) como status. Sintoma:
   `CtapError: 0xA5 - UNKNOWN`.
3. **Chaves de texto em entidades WebAuthn** — `PublicKeyCredentialRpEntity`,
   `PublicKeyCredentialUserEntity` e `PublicKeyCredentialDescriptor` usam chaves
   de texto (`"id"`, `"name"`, `"type"`), não inteiros. Afetava o parsing de
   `makeCredential` (`rp`/`user`) e a codificação de `getAssertion`
   (`credential`/`user`). Sintoma: `CtapError: 0x12 - INVALID_CBOR`.

## Limitações conhecidas

- **Sem secure element:** OTP + secure boot são endurecimento real, mas ataques
  físicos estão fora de escopo.
- **Backup:** cobre só a identidade determinística — passkeys residentes e
  chaves OpenPGP/PIV não sobrevivem à troca de placa.
- **Keepalive:** durante a espera de User Presence o firmware envia
  `CTAPHID_KEEPALIVE` a cada 100 ms no canal do pedido pendente
  (`PROCESSING` em CTAP2, `UP_NEEDED` em CTAP1/U2F), evitando que o host
  descarte a operação por timeout.
- **Secure boot (AC-014/AC-015):** a execução de imagem inválida/antiga é
  impedida pelo bootrom; exige selar as imagens (`picotool seal`) e fundir as
  chaves/rollback em OTP — etapa de produção.
- **Provisionamento:** a chave mestra de OTP e o attestation key de U2F_REGISTER
  são etapas de produção.
- **Storage persistente de credenciais:** com a chave raiz de OTP provisionada, a
  tarefa FIDO abre o `SealedCredentialStore` no store `19` da região de applets e
  as credenciais/estado de PIN sobrevivem a power cycle; sem a chave, o firmware
  usa store em memória (placa de desenvolvimento). Validação física de AC-008
  segue pendente.
- **Applets em hardware (AC-016..AC-021):** sem dispositivo físico nesta
  sessão; cobertura = testes de host (147), autoteste `applet-select`
  on-target e scripts PC/SC prontos (`validate_ccid/piv/oath/openpgp.py`).
- **Credential management CTAP2.1:** o firmware anuncia `FIDO_2_0` (e não
  `FIDO_2_1`); `changePIN` e a enumeração de credenciais existem, mas a opção
  `credMgmt` só é anunciada quando há PIN configurado, porque todo subcomando
  de credential management exige um token com a permissão `cm`. A mutação de
  *user information* e o `largeBlobKey` não são implementados.
- **PIN obrigatório quando configurado:** com PIN no dispositivo,
  `makeCredential`/`getAssertion` exigem a prova do PIN (`PinRequired` 0x36) e
  rejeitam um `pinUvAuthParam` inválido (`PinAuthInvalid` 0x33). O validador
  precisa ser executado com `--pin <PIN>` nesse caso.
- **Escopo do `pinUvAuthToken`:** o token é escopado por operação (`mc` para
  `makeCredential`, `ga` para `getAssertion`) e por RP (o *permissions RP ID*
  precisa casar com o `rp.id` da requisição); `enumerateRPsBegin` exige token
  sem vínculo de RP e `deleteCredential`/`enumerateCredentialsBegin` ficam
  restritos ao RP vinculado. Divergência → `PinAuthInvalid` (0x33), com a
  operação abortada antes de qualquer efeito. Um token emitido sem *permissions
  RP ID* é vinculado ao RP do **primeiro uso** (§6.5.5.7), inclusive o token
  legado de `getPinToken`.
- **Ciclo de vida do `pinUvAuthToken`:** todo subcomando de credential
  management exige token com a permissão `cm` — inclusive `getCredsMetadata`
  (0x01), que antes respondia sem autenticação; sem `pinUvAuthParam` a
  resposta é `PinRequired` (0x36). O token legado de `getPinToken` concede
  apenas `mc|ga` e **não** autoriza credential management (0x33): o caminho
  suportado é `getPinUvAuthTokenUsingPinWithPermissions` (0x09) com `cm`.
  Após uma `makeCredential`/`getAssertion` bem-sucedida que testou User
  Presence usando o token, o token fica **sem permissões** (uso posterior →
  0x33); `changePIN` e `authenticatorReset` o invalidam. A validação em
  dispositivo físico desse comportamento está **pendente**.
- **RSA (AC-021):** RSA-2048/PKCS#1 v1.5 apenas; RSA-3072 e PSS fora de escopo.
  Sem brainpoolP512r1 / X448 / Ed448 (sem aritmética `no_std` madura em Rust).
  Keygen probabilístico (Miller-Rabin 12 rounds, sem certificação FIPS);
  setup de Montgomery sobre módulos secretos e índice do scan de unpad são
  canais laterais residuais documentados em `crates/aegis-applets/src/rsa.rs`.
