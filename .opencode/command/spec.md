---
description: Spec-first de uma fatia de hardening do AegisToken (delega ao subagente spec)
agent: build
---

Delegue ao subagente `spec` a redação da especificação da fatia de hardening descrita
a seguir, seguindo o template e as regras de `.opencode/agents/spec.md`.

Assunto da fatia (do usuário ou do backlog do loop):
$ARGUMENTS

Requisito: a spec deve ser gravada em `specs/<slice>.md`, em pt-BR, com ameaça,
invariantes em risco, escopo, não-objetivos, critérios de aceitação testáveis, plano de
teste, arquivos afetados, documentação a atualizar e riscos. Confirme cada afirmação no
código antes de escrevê-la.
