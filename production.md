# Provisionamento de produção — AegisToken Universal RP2350 Firmware

Guia dos itens que dependem de hardware/produção e que a validação de host/MVP
não cobre: **AC-008** (persistência após ciclo de energia) e **AC-010 / AC-014 /
AC-015** (boot ROM, secure boot e anti-rollback do RP2350).

> **Avisos**
> - A fusão de OTP é **permanente e irreversível**. Um OTP mal gravado pode
>   inutilizar o dispositivo.
> - Guarde as chaves privadas offline e fora do repositório. Nunca faça commit
>   de chaves ou material sensível.
> - O `picotool` local (v2.3.0, build GNU/Windows) **não possui** `seal`/`sign`.
>   Use um `picotool` oficial com signed-boot habilitado (ou compile com
>   `-DPICOTOOL_ENABLE_SIGNED_BOOT=ON`) para assinar imagens.

## AC-008 — Persistência após ciclo de energia

O `COMMIT_CONFIGURATION` grava a configuração via `ConfigStorage` (dois slots
alternados com CRC-32) na base `0x0010_0000`. Procedimento de verificação:

1. Com o dispositivo conectado, grave uma configuração válida e faça commit
   (o `validate_management.py` já faz SET+COMMIT+GET).
2. Anote o valor aplicado (ex.: `led.behavior`) — o `validate_management.py`
   imprime o resultado de `GET_CONFIGURATION`.
3. **Desconecte e reconecte** o USB (power cycle).
4. Leia novamente:
   ```powershell
   python scripts/validate_management.py
   ```
5. O valor deve ser o mesmo do passo 2 (fail-safe: um commit interrompido
   preserva a configuração anterior). O script atual e reverte o valor ao final.

## AC-010 — BOOTSEL no boot → Recovery

O boot ROM do RP2350 entra no bootloader USB (recuperação) quando **BOOTSEL é
mantido no reset**; nesse caso o firmware da aplicação não executa. Validação:

1. Desconecte o dispositivo.
2. Mantenha **BOOTSEL** pressionado e reconecte → deve aparecer a unidade
   `RP2350`/`RPI-RP2` (modo bootloader).
3. Solte sem pressionar novamente → o firmware volta a executar normalmente.

## AC-014 / AC-015 — Secure boot e anti-rollback

O boot ROM verifica uma assinatura **ECDSA secp256k1 + SHA-256** e um número de
versão de rollback contra o OTP. Imagem sem assinatura válida (ou versão antiga)
não executa.

### 1. Chave de secure boot (secp256k1)

```powershell
# Com o picotool oficial:
picotool keygen -t ecdsa -f private.pem
# ou com OpenSSL:
openssl ecparam -name secp256k1 -genkey -noout -out secure_boot_key.pem
```

### 2. Selar a imagem (assinar + versão + rollback)

```powershell
# .elf não assinado -> .elf assinado (+ arquivo de OTP com o hash da bootkey)
picotool seal --sign --hash firmware-unsigned.elf -t elf firmware-signed.elf -t elf `
  secure_boot_key.pem otp_secureboot.json --major 1 --minor 0 --rollback 1

# assinado -> UF2
picotool uf2 convert firmware-signed.elf -t elf rp2350-universal.uf2
```

- `--rollback N` deve **sempre aumentar** entre releases (proteção AC-015).
- O `otp_secureboot.json` contém o fingerprint da chave pública pública.

### 3. Fundir o OTP (irreversível)

```powershell
# Bootsel + picotool:
picotool otp load otp_secureboot.json
picotool otp set OTP_DATA_CRIT1.SECURE_BOOT_ENABLE 1
# endurecimento opcional de produção:
picotool otp set OTP_DATA_CRIT1.DEBUG_DISABLE 1
picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_ENABLE 1
```

### 4. Verificar

```powershell
picotool info -m rp2350-universal.uf2      # versão/rollback da imagem
picotool info -m                            # estado do dispositivo
```

- Gravar uma imagem **não assinada** deve ser rejeitada pelo boot ROM.
- Gravar uma imagem assinada com `--rollback` **menor** deve ser rejeitada.

## Chave mestra do dispositivo (OTP)

O firmware lê a chave mestra de 32 bytes da OTP (linhas `0x0E90`..`0x0E9F`) via
`board-generic-rp2350::otp::read_root_key`. O provisionamento (fusão) é feito
com ferramental do vendor, gravando 16 palavras ECC (16 bits cada) e travando a
página. Sem chave provisionada, o firmware opera em modo de desenvolvimento
(chave ausente) e o store selado não persiste.

## Chave de update do firmware (P-256)

O fluxo de atualização (`aegis-core::update`) assina pacotes com **P-256 /
ES256**. Gere a chave de release e injete a pública no build:

```powershell
python scripts/gen-update-key.py release-update-key.pem
# copie a chave pública (hex) e:
$env:AEGIS_UPDATE_VENDOR_PUBKEY="<hex>"
cargo build -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf --release
& scripts/build-uf2.ps1
```

Sem `AEGIS_UPDATE_VENDOR_PUBKEY`, o build usa uma chave de **desenvolvimento**
(o firmware registra `warning: development firmware-update vendor key in use`).
Nunca libere uma imagem com a chave de desenvolvimento.

## U2F_REGISTER (atestação)

`U2F_REGISTER` exige um certificado de atestação e retorna
`SW_INS_NOT_SUPPORTED`; a atestação *packed self* do CTAP2 não é válida para
U2F. Provisionar um certificado de atestação é etapa de produção separada.

## Provisionamento dos applets (PINs, DOs e certificados)

Os applets saem de fábrica com credenciais padrão e chaves vazias; o
provisionamento usa as ferramentas padrão sobre CCID, sem utilitário
proprietário:

| Applet | Padrão de fábrica | Troca |
|--------|-------------------|-------|
| PIV PIN / PUK | `123456` / `12345678` | `CHANGE REFERENCE DATA`, `pivy`, `yubico-piv-tool` |
| PIV management key | 3DES `0102030405060708` ×3 | ainda fixa (`SET MANAGEMENT KEY` responde `6D00`; trocar exige novo provisionamento) |
| OpenPGP PW1 / PW3 | `123456` / `12345678` | `CHANGE REFERENCE DATA`, `gpg --card-edit` |
| OATH password | ausente (opcional) | `SET CODE` via `ykman oath` |

- **Geração de chaves** (`GENERATE ASYMMETRIC KEY PAIR` PIV, `GENERATE` OpenPGP)
  exige autenticação de administrador (management key / PW3) e acontece
  on-device a partir do TRNG; não existe importação de chave privada. A
  geração RSA-2048 leva segundos — aguardar o status em vez de reenviar.
- **Certificados** (material público) entram por `PUT DATA` com autenticação
  de administrador e persistem selados; chaves privadas nunca saem.
- **Touch policy** por slot/credencial (`never`/`always`/`cached` no PIV,
  `touch required` no OATH) é definida na geração e impõe presença (BOOTSEL)
  por operação.
- Sem chave raiz provisionada na OTP, os applets operam sobre stores
  voláteis: PINs/DOs provisionados se perdem no power cycle. Provisionar a
  chave mestra (seção acima) é pré-requisito de produção.

## Validação FIDO no Windows (opcional)

Para rodar `scripts/validate_fido.py`, a interface FIDO (MI_00) precisa estar
acessível ao hidapi. Se o Windows a vinculou a `fidohid.inf`, remapeie para o
driver HID genérico: Gerenciador de Dispositivos → **HID-compliant fido** →
Atualizar driver → Procurar drivers no computador → **Deixe-me escolher** →
desmarque "Mostrar hardware compatível" → **Microsoft → USB Input Device** (ou
**USB Device** — o rótulo varia conforme a versão do Windows; ambos vinculam
`hidusb.sys`) → confirmar. Passo a passo e reversão em `validation.md`.

O **Management HID**, por outro lado, é acessível sem alterar drivers: use a
ferramenta de host em Rust sobre libusb, que no Windows fala pelo backend HID
do próprio libusb (sem WinUSB/Zadig):

```powershell
cargo run -p aegistoken-host -- validate
```
