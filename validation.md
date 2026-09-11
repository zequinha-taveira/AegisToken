# Validação de hardware — AegisToken Universal RP2350 Firmware

Documento da Fase 10: como validar os critérios de aceitação (AC-001..AC-015)
do MVP em hardware RP2350A (e depois RP2350B).

> **Estado atual:** um dispositivo AegisToken (VID `0x1209`, PID `0x0001`) foi
> validado em hardware. A interface **Management HID** passou **12/12** checks e
> a interface **FIDO HID** passou **13/13**, incluindo `authenticatorGetInfo`,
> `authenticatorMakeCredential` e `authenticatorGetAssertion` com User Presence
> (BOOTSEL) e `clientPIN`. Restam apenas os itens dependentes do bootrom/OTP de
> produção (AC-010, AC-014, AC-015) e o ciclo físico de energia (AC-008).

## Ferramentas

- `probe-rs` — flash e RTT (`probe-rs run --chip RP2350`).
- `picotool` — conversão de UF2 e `picotool info` (valida imagem RP2350).
- `python-fido2` — validação FIDO2/U2F (`scripts/validate_fido.py`).
- `hidapi` + `cbor2` — validação do Management HID (`scripts/validate_management.py`).
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
python scripts/set_pin.py               # define/altera o PIN do clientPIN
```

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

O firmware expõe **FIDO HID** e **Management HID**. A forma de acesso varia por
sistema operacional:

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
| AC-010 | BOOTSEL no boot → Recovery | Bootrom (BOOTSEL → bootloader USB) | Pendente |
| AC-011 | BOOTSEL em `FIDO_WAIT_PRESENCE` → presença | `validate_fido.py` makeCredential/getAssertion | **Verificado** |
| AC-012 | BOOTSEL em outros estados ≠ aprovação | Testes de host (`ContextualPresence`) | Coberto por teste de host |
| AC-013 | Material privado nunca exportado | Ausência de API de exportação + testes | **Verificado** / revisão |
| AC-014 | Firmware inválido não executa | Secure boot do bootrom (secp256k1 + OTP) | Pendente (produção) |
| AC-015 | Rollback não autorizado não executa | `update` (testes) + rollback do bootrom | Lógica OK; OTP pendente |

### Evidência — Management HID (12/12)

```
[PASS] AC-003 Management HID enumeration
[PASS] AC-004 GET_DEVICE_INFO        (AegisToken FIDO2 Authenticator, família RP2350, 0.1.0)
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

- **Keepalive:** durante a espera de User Presence o firmware não envia
  `CTAPHID_KEEPALIVE`; a resposta chega dentro do timeout de presença (15 s).
  Melhoria prevista para a integração final.
- **Secure boot (AC-014/AC-015):** a execução de imagem inválida/antiga é
  impedida pelo bootrom; exige selar as imagens (`picotool seal`) e fundir as
  chaves/rollback em OTP — etapa de produção.
- **Provisionamento:** a chave mestra de OTP e o attestation key de U2F_REGISTER
  são etapas de produção.
- **Storage persistente de credenciais:** o firmware usa store em memória até o
  refactor de compartilhamento de storage (ver `roadmap.md`).
