---
description: Roda os gates de validação do AegisToken e devolve a evidência pass/fail
agent: build
---

Delegue ao subagente `gates` a execução dos gates de validação do `AGENTS.md`
(fmt, clippy -D warnings, testes por crate, e build de firmware/UF2 quando firmware ou
HAL forem tocados).

Contexto da execução (do usuário):
$ARGUMENTS

Requisito: executar de verdade, registrar a contagem de testes por crate e reportar a
saída real do primeiro gate vermelho, sem editar código.
