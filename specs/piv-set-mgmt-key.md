# Spec — PIV SET MANAGEMENT KEY (provisioning, segurança total)

## Goal
Permitir trocar a management key padrão do PIV (`010203...`, pública) por chave
TDES/AES-128/192/256 gerada off-device, exigindo autenticação prévia. Sem isso
o dispositivo não pode ser considerado provisionado com segurança total.

## Non-goals
- `IMPORT KEY` (`0xFE`), `SET PIN RETRIES` (`0xFA`), `GET METADATA` (`0xF7`),
  `RESET` (`0xFB`): continuam `6D00`.
- Touch policy da management key (P2 `0xFE`): parse aceito, mas sem enforcement
  extra nesta slice (auth continua sem presença; documentado).
- Mudança de PIN/PUK: já existe via `CHANGE REFERENCE DATA`.

## API / protocol
- `CLA=0x00, INS=0xFF, P1=0xFF, P2=0xFF|0xFE`, data=`alg(1) 0x9B len(1) key`.
- `alg`: `0x03`=TDES(24B), `0x08`=AES128(16B), `0x0A`=AES192(24B),
  `0x0C`=AES256(32B). Outros → `6A86`.
- Requer `mgmt_authenticated=true`, senão `6982`. P1/P2 inválidos → `6A86`.
  Formato inválido → `6A80`. Sucesso → `9000`, persiste em `RECORD_MGMT_KEY`,
  mantém `mgmt_authenticated=true`, invalida `witness`.
- `authenticate_management` passa a aceitar o novo algoritmo imediatamente
  (troca de TDES→AES muda `block_len` de 8→16).

## Storage / flash impact
- Reusa `RECORD_MGMT_KEY` (formato `[alg,len,key]` já usado por
  `MgmtKey::encode/decode`); sem mudança de layout, sem migração.
  Selado via `SealedPivStore` como antes.

## Test plan
- `set_mgmt_key_requires_auth`, `set_mgmt_key_tdes_ok_and_authenticates`,
  `set_mgmt_key_aes_variants`, `set_mgmt_key_rejects_bad_alg_len_p1p2`,
  round-trip selado (se aplicável).
- Interop: `yubico-piv-tool -k <old> -n <new> -m AES256 set-mgm-key` +
  `validate_piv.py` estendido.

## Exit criteria
- `cargo fmt --check`, `clippy -p aegis-applets -D warnings`,
  `cargo test -p aegis-applets` verdes.
- `production.md` atualizado (troca deixa de ser "fixa").
- Roadmap Fase 17 marcado na mesma mudança.
