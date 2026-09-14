# Política de Segurança

## Escopo e limitações

Esta política se aplica ao firmware, ao código host, às bibliotecas e aos
scripts mantidos neste repositório.

O AegisToken está em desenvolvimento e na versão 0.x. Não é um produto
certificado e não deve ser usado para proteger ativos críticos sem uma
avaliação de segurança independente. A aprovação no CI ou nos scripts de
validação não substitui uma auditoria.

## Versões suportadas

Enquanto o projeto estiver abaixo da versão 1.0, a correção de segurança é
priorizada para o estado mais recente do branch `main`. Releases e commits
antigos podem não receber backport.

## Como reportar uma vulnerabilidade

Não abra uma issue, pull request ou discussão pública para uma vulnerabilidade.
Use o GitHub Private Vulnerability Reporting:

<https://github.com/zequinha-taveira/AegisToken/security/advisories/new>

Se o recurso não estiver disponível, contate o mantenedor pelo GitHub para
solicitar um canal privado. Não inclua detalhes técnicos em uma mensagem
pública.

Inclua, quando possível:

- descrição do impacto, da gravidade e das condições necessárias para explorar
  o problema;
- componente afetado, versão do firmware, commit, placa e variante do chip;
- dependências do ataque, como acesso físico, USB, presença do usuário ou
  privilégios no host;
- passos de reprodução ou uma prova de conceito segura, sem acessar dados de
  terceiros;
- logs, traces e artefatos que permitam a investigação, com dados sensíveis
  removidos;
- sugestão de mitigação, caso esteja disponível.

Nunca envie PINs, chaves privadas, sementes, segredos de dispositivos,
credenciais de produção ou dumps brutos de memória/flash. Ao investigar um
dispositivo real, preserve apenas o material mínimo necessário para reproduzir
o problema.

## Processo de resposta e divulgação

Os mantenedores confirmarão o recebimento e avaliarão o relato conforme sua
capacidade; este projeto não oferece um prazo de resposta ou correção. Quando
apropriado, será coordenada uma correção, uma nova versão e um aviso de
segurança antes da divulgação pública.

Solicita-se que o pesquisador aguarde a coordenação antes de publicar detalhes
da vulnerabilidade. Crédito será atribuído mediante autorização do pesquisador.

## Desenvolvimento e releases

- Pull requests e pushes para `development` e `main` executam verificações de
  formatação, Clippy, testes e builds definidos em `.github/workflows/ci.yml`.
- O workflow de release é acionado por tags `v*`; a tag precisa apontar para o
  commit atual de `main` e os artefatos UF2 são publicados no GitHub.
- Imagens de produção devem ser construídas com
  `AEGIS_UPDATE_VENDOR_PUBKEY`. Sem essa variável, o build usa uma chave de
  desenvolvimento e não deve ser distribuído como release.

## Observações de segurança do projeto

- As operações FIDO devem permanecer independentes das interfaces de gestão e
  teclado.
- A presença do usuário é contextual e necessária nos fluxos que a exigem.
- Segredos não devem ser exportados nem registrados em logs.
- Atualizações dependem de assinatura, integridade e proteção contra rollback;
  secure boot e o provisionamento de OTP são etapas de produção separadas.
- O modelo de segurança está descrito em
  [`docs/security-model.md`](docs/security-model.md), e as limitações atuais
  estão documentadas no [`README.md`](README.md) e em
  [`validation.md`](validation.md).
