-- ============================================================================
-- 002: a decisao 'adotado' em na.promotions
-- ============================================================================
-- Um modelo semente, trazido de fora pelo `lifecycle.py adopt`, nao passou por
-- portao nenhum. Registra-lo como 'aprovado' seria mentira; como 'sobreposto'
-- daria a entender que houve um portao reprovando e alguem forcou. Nenhuma das
-- duas descreve o que aconteceu, e o historico de promocoes e justamente onde
-- se olha para entender por que um modelo esta em producao.
--
-- 'adotado' tambem nao exige `motivo` pela regra do CHECK antigo -- mas o
-- comando sempre preenche, porque de onde veio o modelo e a informacao mais
-- util que essa linha pode carregar.
-- ============================================================================

ALTER TABLE na.promotions DROP CONSTRAINT promotions_decisao_check;

ALTER TABLE na.promotions
    ADD CONSTRAINT promotions_decisao_check
    CHECK (decisao IN ('aprovado', 'reprovado', 'sobreposto', 'adotado'));

COMMENT ON COLUMN na.promotions.decisao IS
    'aprovado = passou pelo portao; reprovado = nao passou; sobreposto = '
    'reprovou e um humano promoveu assim mesmo; adotado = modelo semente '
    'trazido de fora, sem portao.';
