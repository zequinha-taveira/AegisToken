---
name: aegis-spec
description: Fluxo spec-first do AegisToken para uma fatia de hardening — transforma um achado de segurança ou pendência de roadmap em specs/<slice>.md com ameaça, invariantes em risco, critérios de aceitação testáveis e plano de teste, antes de qualquer código.
license: MIT
compatibility: opencode
metadata:
  audience: maintainers
  workflow: spec-first
  opencode/slash: "true"
  opencode/autoinvoke: "false"
---

# Skill: aegis-spec

Use quando o pedido for **especificar** uma fatia de melhoria de segurança do
AegisToken antes de implementar. É o passo 2 do loop de melhoria (passo 1 = `sec-audit`).

## Entrada

- Um achado do `sec-audit` (severidade, `arquivo:linha`).
- Ou uma pendência de `roadmap.md` / `validation.md` (AC não fechado).
- Ou uma ideia de hardening vinda do usuário.

## Passo a passo

1. **Confirmar o fato** — leia o código citado (`arquivo:linha`) antes de escrever a
   spec; não especifique sobre suposição. Se o achado não se confirmar, diga e pare.
2. **Enquadrar a ameaça** — o que um atacante consecgue hoje, por qual caminho, com
   qual pré-condição (acesso físico? USB? host malicioso? deviceLost?).
3. **Listar invariantes em risco** — cite `docs/security-model.md` e `AGENTS.md`.
4. **Delimitar o escopo** — uma fatia = uma mudança lógica. Liste explicitamente os
   não-objetivos (o que fica para a próxima fatia).
5. **Escrever os critérios de aceitação** — cada um observável e verificável em host
   (salvo indicação de que exige hardware RP2350 real, que hoje não está disponível).
6. **Planejar o teste** — onde mora o teste (crate + módulo), qual comando de gate
   prova o AC.
7. **Listar arquivos afetados** e **documentação a atualizar** (`roadmap.md`,
   `validation.md`, `docs/security-model.md`).
8. **Registrar riscos e limitações** (p.ex.: sem hardware para AC; sem element seguro;
   canal lateral residual).

## Formato

Escreva `specs/<slice>.md` (kebab-case) seguindo o modelo do subagente `spec`:
ameaça, invariantes, escopo, não-objetivos, critérios de aceitação, plano de teste,
arquivos afetados, documentação, riscos. Texto em **pt-BR**.

## Regras

- Não implemente código na spec.
- Não crie API nova "porneau"; descreva comportamento.
- Um AC por invariante verificável; sem AC, sem fatia.
- Se a fatia exigir hardware, marque `AC (hardware pendente)` e descreva o procedimento
  de validação (`scripts/validate_*.py`, `production.md`) para quando houver placa.

## Saída esperada

Arquivo da spec, resumo com nº de ACs, ACs que dependem de hardware e riscos abertos.
