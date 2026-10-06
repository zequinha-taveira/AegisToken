# Compatibilidade com Yubico Authenticator e `ykman`

## Objetivo

O AegisToken deve ser interoperável com os fluxos de usuário do **Yubico Authenticator** e do **Yubico Authenticator CLI (`ykman`)**, sem depender de um aplicativo proprietário AegisToken para as funções padronizadas.

A compatibilidade é definida por **protocolos e classes USB**, não pela alegação de ser um produto YubiKey:

| Função | Transporte | Compatibilidade esperada |
| --- | --- | --- |
| FIDO2 / passkeys / U2F | FIDO HID (`0xF1D0`) | `ykman fido`, navegadores e WebAuthn |
| TOTP/HOTP | CCID + YKOATH | Yubico Authenticator e `ykman oath` |
| PIV | CCID + ISO 7816 | `ykman piv`, `yubico-piv-tool`, OpenSC |
| OpenPGP | CCID + OpenPGP Card | GnuPG/OpenSC; não é uma função `ykman` |
| Gestão AegisToken | Management HID | CLI/Manager próprios; não é exposta como YubiKey |
| OTP Lab (somente perfil autorizado) | HID vendor-defined `0xFF51` | Diagnóstico experimental `PING`/`INFO`; **não compatível** com `ykman otp`/Yubico OTP |

## Requisitos de interoperabilidade

### FIDO

- Enumerar uma interface FIDO HID compatível com CTAPHID.
- Responder CTAP1/U2F e CTAP2/FIDO2 conforme a matriz de validação do projeto.
- Não exigir a interface Management HID, CCID ou Keyboard para autenticação.
- Validar `getInfo`, criação de credencial, assertion, PIN/UV e presença do usuário.

### OATH

- Expor CCID como classe USB `0x0B` e um leitor PC/SC funcional.
- Implementar o AID YKOATH `A0000005272101`.
- Implementar `PUT`, `DELETE`, `LIST`, `CALCULATE`, `CALCULATE ALL`, `SET CODE`, `VALIDATE` e continuação `SEND REMAINING`.
- Preservar o formato YKOATH de nomes, algoritmos, dígitos, período, contador, access code e `touch required`.
- Nunca retornar segredos em `LIST`, `CALCULATE ALL` ou mensagens de erro.
- Como o dispositivo não possui RTC, o moving factor/timestamp é fornecido pelo host, como previsto pelo protocolo.

### PIV

- Expor PIV pelo AID NIST/Yubico esperado pelas ferramentas PC/SC.
- Validar PIN/PUK, management key, geração de chaves, assinatura, certificados públicos e política de presença.
- Testar com `ykman piv`, `yubico-piv-tool`, OpenSC e `pivy` quando disponíveis.

## Política de identidade USB

O perfil padrão continua usando a identidade própria do projeto (`0x1209:0x0001`). Não devemos distribuir um firmware que se apresente como um YubiKey ou use VID/PID da Yubico sem autorização.

Para testes locais de ferramentas que fazem filtragem rígida por VID/PID, pode existir um perfil de laboratório separado, protegido no pipeline e marcado como **não distribuível**. Esse perfil não é requisito de interoperabilidade e não altera os protocolos, os applets ou o comportamento criptográfico.

A validação primária deve funcionar com a identidade própria usando PC/SC, OpenSC e os scripts de protocolo do repositório. A validação com `ykman`/Yubico Authenticator deve ser registrada separadamente quando a ferramenta aceitar o dispositivo ou quando for usado um perfil de teste autorizado.

## Referência USB da Yubico

O Vendor ID (VID) universal historicamente associado à Yubico é `0x1050`
(4176 decimal). O Product ID (PID) varia conforme a família do produto e as
interfaces habilitadas — OTP, FIDO/U2F, CCID e combinações entre elas.

| Família ou configuração | PID(s) de referência |
| --- | --- |
| YubiKey v1/v2 | `0x0010` |
| YubiHSM | `0x0030` |
| YubiKey NEO/NEO-N | `0x0110`–`0x0116` |
| YubiKey Touch U2F / Security Key | `0x0120` |
| Gnubby / Gnubby U2F | `0x0200`, `0x0211` |
| YubiKey 4/5 e séries FIPS | `0x0401`–`0x0407` |
| YubiKey Plus (OTP + U2F) | `0x0410` |
| YubiKey 5Ci | `0x0420` |
| Security Key/Bio e configurações relacionadas | `0x0120`–`0x0406` |

Esses valores são uma referência de descoberta, não uma tabela suficiente para
identificar o modelo exato. PIDs podem ser compartilhados entre variantes e a
configuração de interfaces pode alterar o PID apresentado. Para o AegisToken,
essa referência não autoriza copiar a identidade USB da Yubico.

### Windows PowerShell

Para localizar dispositivos USB com VID `1050`:

```powershell
Get-PnpDevice -Class "USB" -PresentOnly |
  Where-Object { $_.InstanceId -match '^USB\\VID_1050' } |
  Select-Object Status, FriendlyName, InstanceId
```

Para obter as interfaces e os IDs de hardware de forma mais ampla:

```powershell
Get-PnpDevice -PresentOnly |
  Where-Object { $_.InstanceId -match 'VID_1050' } |
  Format-Table Status, Class, FriendlyName, InstanceId -AutoSize
```

O sufixo `&MI_00`, `&MI_01` etc. normalmente identifica interfaces de um
dispositivo USB composto. A classe exibida ajuda a correlacionar a interface:
HID para FIDO/OTP, SmartCard/CCID para PIV/OATH e interfaces adicionais conforme
a configuração do dispositivo.

### Linux

```bash
lsusb -d 1050:
lsusb -t
lsusb -v -d 1050: 2>/dev/null | less
```

`lsusb -d 1050:` mostra VID/PID e `lsusb -t` mostra as classes e drivers
associados. Em `lsusb -v`, procure `bInterfaceClass` e `bInterfaceSubClass`:

- `0x03` — HID, usado pelos caminhos FIDO/OTP;
- `0x0B` — CCID/Smart Card, usado por PIV/OATH;
- outras classes devem ser tratadas como específicas do modelo e confirmadas
  pela documentação oficial.

### Identificar o modelo exato

1. Execute `ykman info` com a YubiKey conectada. O comando normalmente informa
   família/modelo, versão de firmware, número de série e interfaces USB/NFC
   disponíveis.
2. Use `ykman config` para consultar as interfaces configuráveis quando o
   modelo suportar essa operação; não aplique alterações durante a coleta de
   evidências.
3. No **Yubico Authenticator**, abra o seletor de dispositivo ou a tela de
   informações do dispositivo. A aplicação pode mostrar modelo, firmware e
   transporte; para detalhes de interfaces USB, confirme com `ykman info` e
   `lsusb -v`/Gerenciador de Dispositivos.
4. Confirme o modelo pelo número de série e pelo firmware exibidos no aplicativo
   oficial, comparando com a documentação da Yubico. Não use somente o PID para
   concluir o modelo.

O procedimento recomendado é combinar **VID/PID + interfaces USB + versão de
firmware + número de série + relatório do aplicativo oficial**. O AegisToken
deve usar a mesma abordagem baseada em descritores e capabilities, mas mantendo
sua própria identidade USB.

## Build universal YubiKey de laboratório

Com autorização, o repositório oferece o perfil opt-in `yubikey5-lab`. Ele usa
o mesmo artefato universal para RP2350A/B e RP2354A/B; o VID/PID não depende da
variante do chip:

```powershell
& scripts/build-uf2.ps1 -Board universal -BoardProfile yubikey5-lab
```

O perfil apresenta:

```text
VID = 0x1050
PID = 0x0407
Manufacturer = Yubico
Product = YubiKey 5 Series OTP+FIDO+CCID
```

O PID `0x0407` sinaliza a composição **OTP+FIDO+CCID**; o firmware cria uma
interface HID OTP Lab distinta (além de FIDO HID, Management HID e CCID) somente
quando o VID/PID enumerado é `1050:0407`. Seu descritor HID usa usage page
vendor-defined `0xFF51`, dois relatórios de 64 bytes sem report ID, endpoints
interrupt IN/OUT de 64 bytes com polling de 10 ms. A interface **não** afirma
ser o descritor/protocolo HID OTP comercial da Yubico. O perfil genérico continua
sem essa interface (`1209:0001`, FIDO HID + Management HID + CCID).

### Protocolo OTP Lab v1 (experimental)

O enquadramento em `aegis-core::otp_lab` é **próprio do AegisToken**; cada
relatório OUT de 64 bytes recebe no máximo um relatório IN de 64 bytes. Não há
fragmentação, report ID, sessão, criptografia nem autenticação nesta interface.

| Offset | Comprimento | Campo | Regra |
| --- | ---: | --- | --- |
| 0 | 1 | Magic | `A5` |
| 1 | 1 | Versão | `01` |
| 2 | 1 | Command | `01` PING; `02` INFO; demais: erro `01` |
| 3 | 1 | Status | Requisição `00`; resposta `00` sucesso, `01` comando desconhecido, `02` tamanho inválido para INFO |
| 4–7 | 4 | Channel | `u32` big-endian, `1..=0xFFFFFFFE`; correlação opaca, **não** sessão autenticada |
| 8 | 1 | Payload length | `0..=54` |
| 9 | 1 | Reservado | `00` |
| 10–63 | até 54 | Payload + padding | Restante deve ser zerado |

- `PING` (`01`): eco dos `0..=54` bytes; `INFO` (`02`): requisição vazia,
  resposta ASCII `AEGIS-OTP-LAB/1`. INFO com dados devolve status `02`, payload
  vazio. Comando desconhecido em frame válido devolve status `01`, payload vazio
  e o mesmo channel/command. Os erros jamais repetem dados desconhecidos.
- Frame incompleto, magic/versão, reserved/status, channel, comprimento ou
  padding inválidos são descartados **sem resposta**. O endpoint só aceita
  reports interrupt OUT; `SET_REPORT`/`GET_REPORT` no controle HID são rejeitados.
- Não existe suporte a slots OTP, programação de slot, emissão de teclado,
  challenge-response, Yubico OTP AES, HOTP em HID ou comandos `ykman otp`.
  HOTP/TOTP implementados no applet **YKOATH sobre CCID** são outra função;
  a memória OTP do RP2350 (raiz/serial) também é independente. Nenhum segredo
  é processado ou persistido pelo OTP Lab. **Não usar PING para transmitir
  segredos**, pois a resposta os ecoa em claro.
- Nenhum código de Yubico OTP HID/protocolo proprietário foi encontrado no
  repositório para permitir compatibilidade funcional segura; copiar VID/PID e
  compor as interfaces não substitui o wire format nem a criptografia.

O arquivo gerado continua sendo um único UF2 universal, mas esse perfil é
**exclusivamente de laboratório**. Ele não transforma automaticamente o
AegisToken em uma YubiKey real. A enumeração `1050:0407` pode levar `ykman` ou
Yubico Authenticator a tentar comandos OTP comerciais que serão rejeitados ou
ignorar o HID experimental; FIDO/OATH/PIV também exigem testes reais separados.
O pipeline deve rejeitar esse perfil em releases públicas.

## Matriz de aceitação

| ID | Teste | Evidência |
| --- | --- | --- |
| YUB-001 | `ykman fido info` ou fluxo equivalente FIDO2 | `getInfo` e enumeração CTAPHID |
| YUB-002 | Criar e usar uma passkey em navegador/WebAuthn | `validate_fido.py` |
| YUB-003 | `ykman oath accounts list` | LIST YKOATH via PC/SC |
| YUB-004 | `ykman oath accounts code <nome>` | CALCULATE com vetor RFC 6238 |
| YUB-005 | Adicionar/remover conta OATH | PUT/DELETE e persistência |
| YUB-006 | Access code e retry counter OATH | SET CODE/VALIDATE |
| YUB-007 | Yubico Authenticator lista e calcula TOTP | PC/SC + aplicação desktop |
| YUB-008 | `ykman piv info` e operações PIV básicas | SELECT/GET DATA/PIN |
| YUB-009 | Geração e uso de chave PIV | GENERATE/GENERAL AUTHENTICATE |
| YUB-010 | Power cycle preserva OATH/PIV | stores selados e revalidação |
| LAB-OTP-001 | Enumeração `1050:0407` e interfaces FIDO/Management/OTP Lab/CCID | `lsusb -v -d 1050:0407`, strings HID e endpoints; hardware pendente |
| LAB-OTP-002 | PING/INFO e rejeições do protocolo experimental | testes `cargo test -p aegis-core otp_lab`; teste USB físico pendente |

Um teste só pode ser marcado como **compatível** após execução contra hardware físico e registro da versão da ferramenta, sistema operacional, reader PC/SC e firmware.

## Limitações conhecidas

- A identidade do dispositivo não deve ser usada para contornar políticas comerciais ou de distribuição do ecossistema Yubico.
- Alguns comandos de `ykman` são extensões específicas de modelos YubiKey e podem não ser aplicáveis ao AegisToken.
- A compatibilidade com Yubico Authenticator não implica compatibilidade com recursos proprietários fora de FIDO, OATH e PIV padronizados.
- OpenPGP é validado por GnuPG/OpenSC, não como uma função nativa do `ykman`.
- `ykman otp` e comandos OTP comerciais do Yubico Authenticator **não** são implementados; não registrar como interoperáveis a partir do PID.
