import 'node:process'
import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import express from 'express'
import cors from 'cors'
import { neon } from '@neondatabase/serverless'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

// ── env ────────────────────────────────────────────────────────────────────
const __dir = dirname(fileURLToPath(import.meta.url))
try {
  const env = readFileSync(resolve(__dir, '.env'), 'utf8')
  env.split('\n').forEach(line => {
    const [k, ...v] = line.split('=')
    if (k?.trim() && !process.env[k.trim()]) process.env[k.trim()] = v.join('=').trim()
  })
} catch (_) { /* .env ausente em produção — usa variáveis da plataforma */ }

const DATABASE_URL = process.env.DATABASE_URL
const JWT_SECRET   = process.env.JWT_SECRET || 'dev-secret-TROQUE'
const PORT         = process.env.PORT || 3001

if (!DATABASE_URL) { console.error('DATABASE_URL não configurada'); process.exit(1) }

// ── helpers ────────────────────────────────────────────────────────────────
function db() { return neon(DATABASE_URL) }

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' })
}

function verifyToken(req) {
  const auth  = (req.headers.authorization || '').trim()
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth
  if (!token) throw Object.assign(new Error('Não autenticado'), { status: 401 })
  return jwt.verify(token, JWT_SECRET)
}

// ── app ────────────────────────────────────────────────────────────────────
const app = express()
app.use(cors())
app.use(express.json())

function wrap(fn) {
  return async (req, res) => {
    try {
      await fn(req, res)
    } catch (err) {
      res.status(err.status || 500).json({ erro: err.message })
    }
  }
}

// ── /api/auth ──────────────────────────────────────────────────────────────
app.post('/api/auth', wrap(async (req, res) => {
  const body = req.body || {}
  const sql  = db()

  if (body.action === 'login') {
    const { email, senha } = body
    if (!email || !senha) throw new Error('E-mail e senha obrigatórios')
    const rows = await sql`SELECT * FROM usuarios WHERE email = ${email} AND ativo = 1`
    const user = rows[0]
    if (!user || !await bcrypt.compare(senha, user.senha_hash)) {
      throw Object.assign(new Error('E-mail ou senha incorretos'), { status: 401 })
    }
    const token = signToken({ id: user.id, role: user.role })
    return res.json({ token, usuario: { id: user.id, nome: user.nome, email: user.email, role: user.role } })
  }

  if (body.action === 'me') {
    const decoded = verifyToken(req)
    const rows = await sql`SELECT id, nome, email, role FROM usuarios WHERE id = ${decoded.id}`
    if (!rows[0]) throw Object.assign(new Error('Usuário não encontrado'), { status: 404 })
    return res.json(rows[0])
  }

  throw new Error('Ação inválida')
}))

// ── migrate: novas colunas de capital/risco ────────────────────────────────
async function migrateContas(sql) {
  const run = async (q) => { try { await sql(q) } catch(_) {} }
  await run([`ALTER TABLE contas ADD COLUMN IF NOT EXISTS capital_disponivel DECIMAL(12,2) DEFAULT 0`])
  await run([`ALTER TABLE contas ADD COLUMN IF NOT EXISTS risco_pct DECIMAL(5,2) DEFAULT 1.0`])
  await run([`ALTER TABLE contas ADD COLUMN IF NOT EXISTS instrumento VARCHAR(10) DEFAULT 'WIN'`])
  await run([`ALTER TABLE contas ADD COLUMN IF NOT EXISTS tipo_conta VARCHAR(20) DEFAULT 'pessoal'`])
  await run([`ALTER TABLE contas ADD COLUMN IF NOT EXISTS stop_pts_win INT DEFAULT 200`])
  await run([`ALTER TABLE contas ADD COLUMN IF NOT EXISTS stop_pts_wdo INT DEFAULT 100`])
  await run([`ALTER TABLE contas ADD COLUMN IF NOT EXISTS contratos INT DEFAULT 1`])
  await run([`ALTER TABLE contas ADD COLUMN IF NOT EXISTS contratos_wdo INT DEFAULT 1`])
  await run([`ALTER TABLE contas ADD COLUMN IF NOT EXISTS max_operacoes_dia INT DEFAULT 10`])
}

// ── /api/contas ────────────────────────────────────────────────────────────
app.get('/api/contas', wrap(async (req, res) => {
  const user = verifyToken(req)
  const sql  = db()
  await migrateContas(sql)
  const rows = await sql`SELECT * FROM contas WHERE usuario_id = ${user.id} ORDER BY nome`
  res.json(rows)
}))

app.post('/api/contas', wrap(async (req, res) => {
  const user = verifyToken(req)
  const sql  = db()
  await migrateContas(sql)
  const body = req.body || {}

  if (body.action === 'salvar') {
    const { id, nome, meta_diaria, stop_diario, meta_mensal, stop_mensal,
            loss_limit_ciclo, custo_renovacao,
            capital_disponivel, risco_pct, instrumento, tipo_conta,
            stop_pts_win, stop_pts_wdo } = body
    if (!nome?.trim()) throw new Error('Nome é obrigatório')
    if (id) {
      await sql`
        UPDATE contas SET
          nome = ${nome},
          meta_diaria = ${meta_diaria || 0}, stop_diario = ${stop_diario || 0},
          meta_mensal = ${meta_mensal || 0}, stop_mensal = ${stop_mensal || 0},
          loss_limit_ciclo = ${loss_limit_ciclo || 0}, custo_renovacao = ${custo_renovacao || 0},
          capital_disponivel = ${capital_disponivel || 0}, risco_pct = ${risco_pct || 1},
          instrumento = ${instrumento || 'WIN'}, tipo_conta = ${tipo_conta || 'pessoal'},
          stop_pts_win = ${stop_pts_win || 200}, stop_pts_wdo = ${stop_pts_wdo || 100}
        WHERE id = ${id} AND usuario_id = ${user.id}
      `
      return res.json({ ok: true, id })
    } else {
      const [row] = await sql`
        INSERT INTO contas (usuario_id, nome, meta_diaria, stop_diario, meta_mensal, stop_mensal,
          loss_limit_ciclo, custo_renovacao, capital_disponivel, risco_pct,
          instrumento, tipo_conta, stop_pts_win, stop_pts_wdo)
        VALUES (${user.id}, ${nome}, ${meta_diaria || 0}, ${stop_diario || 0},
          ${meta_mensal || 0}, ${stop_mensal || 0},
          ${loss_limit_ciclo || 0}, ${custo_renovacao || 0},
          ${capital_disponivel || 0}, ${risco_pct || 1},
          ${instrumento || 'WIN'}, ${tipo_conta || 'pessoal'},
          ${stop_pts_win || 200}, ${stop_pts_wdo || 100})
        RETURNING id
      `
      return res.json({ ok: true, id: row.id })
    }
  }

  if (body.action === 'excluir') {
    const [conta] = await sql`SELECT id FROM contas WHERE id = ${body.id} AND usuario_id = ${user.id}`
    if (!conta) throw new Error('Conta não encontrada')
    await sql`DELETE FROM contas WHERE id = ${body.id}`
    return res.json({ ok: true })
  }

  if (body.action === 'iniciar_ciclo') {
    const { conta_id, data_inicio, saldo_inicio } = body
    const [conta] = await sql`SELECT id FROM contas WHERE id = ${conta_id} AND usuario_id = ${user.id}`
    if (!conta) throw new Error('Conta não encontrada')
    await sql`UPDATE ciclos SET data_fim = ${data_inicio} WHERE conta_id = ${conta_id} AND data_fim IS NULL`
    await sql`INSERT INTO ciclos (conta_id, data_inicio, saldo_inicio) VALUES (${conta_id}, ${data_inicio}, ${saldo_inicio || 0})`
    return res.json({ ok: true })
  }

  throw new Error('Ação inválida')
}))

// ── /api/dashboard ─────────────────────────────────────────────────────────
app.get('/api/dashboard', wrap(async (req, res) => {
  const user = verifyToken(req)
  const sql  = db()
  const hoje = new Date().toISOString().slice(0, 10)

  const contas = await sql`SELECT * FROM contas WHERE usuario_id = ${user.id} AND ativa = 1 ORDER BY nome`

  const result = await Promise.all(contas.map(async (conta) => {
    const ciclos = await sql`
      SELECT data_inicio FROM ciclos WHERE conta_id = ${conta.id} AND data_fim IS NULL
      ORDER BY data_inicio DESC LIMIT 1
    `
    const periodoIni = ciclos[0]
      ? new Date(ciclos[0].data_inicio).toISOString().slice(0, 10)
      : hoje.slice(0, 7) + '-01'

    const [resumo] = await sql`
      SELECT
        COALESCE(SUM(resultado), 0)                    AS lucro_ciclo,
        COALESCE(SUM(custo), 0)                        AS custo_ciclo,
        COUNT(DISTINCT data_operacao)                  AS pregoes,
        COUNT(*) FILTER (WHERE resultado > 0)          AS gains,
        COUNT(*) FILTER (WHERE resultado < 0)          AS losses
      FROM operacoes
      WHERE conta_id = ${conta.id} AND data_operacao BETWEEN ${periodoIni} AND ${hoje}
    `
    const [hojeRow] = await sql`
      SELECT
        COALESCE(SUM(resultado), 0) AS lucro_hoje,
        COALESCE(SUM(custo), 0)    AS custo_hoje,
        COUNT(*)                   AS ops_hoje
      FROM operacoes WHERE conta_id = ${conta.id} AND data_operacao = ${hoje}
    `

    const lucroCiclo  = parseFloat(resumo.lucro_ciclo)
    const lucroHoje   = parseFloat(hojeRow.lucro_hoje)
    const opsHoje     = parseInt(hojeRow.ops_hoje)
    const lossLimit   = parseFloat(conta.loss_limit_ciclo) || 0
    const metaMensal  = parseFloat(conta.meta_mensal) || 0
    const stopDiario  = parseFloat(conta.stop_diario) || 0
    const stopMensal  = parseFloat(conta.stop_mensal) || 0
    const metaDiaria  = parseFloat(conta.meta_diaria) || 0
    const maxOps      = parseInt(conta.max_operacoes_dia) || 2

    let semaforo = 'verde', alertaCiclo = 'OK', pctCicloConsumido = 0
    if (lossLimit > 0) {
      const lossAcum = Math.abs(Math.min(lucroCiclo, 0))
      pctCicloConsumido = (lossAcum / lossLimit) * 100
      if (pctCicloConsumido >= 100)  { semaforo = 'stop';     alertaCiclo = 'QUEBRADO' }
      else if (pctCicloConsumido >= 70) { semaforo = 'vermelho'; alertaCiclo = 'CRITICO'  }
      else if (pctCicloConsumido >= 40) { semaforo = 'amarelo';  alertaCiclo = 'ATENCAO'  }
    }

    let statusDia = 'LIVRE'
    if (stopDiario > 0 && lucroHoje <= -stopDiario) statusDia = 'STOP_DIA'
    else if (stopDiario > 0 && lucroHoje < 0 && Math.abs(lucroHoje) >= stopDiario * 0.7) statusDia = 'QUASE_STOP'
    else if (metaDiaria > 0 && lucroHoje >= metaDiaria) statusDia = 'META_DIA'
    else if (opsHoje >= maxOps) statusDia = 'MAX_OPS'

    let statusMes = 'OK'
    if (stopMensal > 0 && lucroCiclo <= -stopMensal) statusMes = 'STOP_MES'
    else if (metaMensal > 0 && lucroCiclo >= metaMensal) statusMes = 'META_MES'
    else if (metaMensal > 0 && lucroCiclo >= metaMensal * 0.75) statusMes = 'QUASE_META'

    const faltaMeta = Math.max(0, metaMensal - lucroCiclo)
    const espacoRestante = lossLimit > 0 ? Math.max(0, lossLimit - Math.abs(Math.min(lucroCiclo, 0))) : null
    const progresso = metaMensal > 0 ? Math.min(100, (lucroCiclo / metaMensal) * 100) : 0

    const parts = periodoIni.split('-')
    const periodoLabel = parts[2] + '/' + parts[1]

    return {
      id: conta.id, nome: conta.nome, plataforma: conta.plataforma, tipo: conta.tipo,
      contratos: conta.contratos, meta_mensal: metaMensal, stop_mensal: stopMensal,
      meta_diaria: metaDiaria, stop_diario: stopDiario, max_ops_dia: maxOps,
      loss_limit_ciclo: lossLimit, custo_renovacao: parseFloat(conta.custo_renovacao) || 0,
      lucro_ciclo: lucroCiclo, lucro_hoje: lucroHoje, ops_hoje: opsHoje,
      pregoes: parseInt(resumo.pregoes), gains: parseInt(resumo.gains), losses: parseInt(resumo.losses),
      semaforo, alerta_ciclo: alertaCiclo, status_dia: statusDia, status_mes: statusMes,
      pct_ciclo_consumido: pctCicloConsumido, espaco_restante: espacoRestante,
      falta_meta: faltaMeta, progresso, periodo_ini: periodoIni, periodo_label: periodoLabel,
    }
  }))

  res.json(result)
}))

// ── /api/operacoes ─────────────────────────────────────────────────────────
app.get('/api/operacoes', wrap(async (req, res) => {
  const user     = verifyToken(req)
  const sql      = db()
  const { conta_id, data } = req.query

  if (!conta_id) throw new Error('conta_id obrigatório')
  const [conta] = await sql`SELECT id FROM contas WHERE id = ${conta_id} AND usuario_id = ${user.id}`
  if (!conta) throw new Error('Conta não encontrada')

  const rows = data
    ? await sql`SELECT * FROM operacoes WHERE conta_id = ${conta_id} AND data_operacao = ${data} ORDER BY horario_entrada`
    : await sql`SELECT * FROM operacoes WHERE conta_id = ${conta_id} ORDER BY data_operacao DESC, horario_entrada DESC LIMIT 200`

  res.json(rows)
}))

app.post('/api/operacoes', wrap(async (req, res) => {
  const user = verifyToken(req)
  const sql  = db()
  const body = req.body || {}

  if (body.action === 'salvar') {
    const { conta_id, data_operacao, tipo, horario_entrada, horario_saida,
            pontos, resultado, custo, observacao } = body
    const [conta] = await sql`SELECT id FROM contas WHERE id = ${conta_id} AND usuario_id = ${user.id}`
    if (!conta) throw new Error('Conta não encontrada')
    const [row] = await sql`
      INSERT INTO operacoes (conta_id, data_operacao, tipo, horario_entrada, horario_saida, pontos, resultado, custo, observacao)
      VALUES (${conta_id}, ${data_operacao}, ${tipo}, ${horario_entrada}, ${horario_saida || null},
              ${pontos || 0}, ${resultado || 0}, ${custo || 0}, ${observacao || null})
      RETURNING id
    `
    return res.json({ ok: true, id: row.id })
  }

  if (body.action === 'excluir') {
    await sql`
      DELETE FROM operacoes WHERE id = ${body.id}
        AND conta_id IN (SELECT id FROM contas WHERE usuario_id = ${user.id})
    `
    return res.json({ ok: true })
  }

  if (body.action === 'importar') {
    const { conta_id, ops } = body
    if (!Array.isArray(ops) || !ops.length) throw new Error('Nenhuma operação para importar')
    const [conta] = await sql`SELECT id FROM contas WHERE id = ${conta_id} AND usuario_id = ${user.id}`
    if (!conta) throw new Error('Conta não encontrada')
    let inserted = 0
    for (const op of ops) {
      try {
        await sql`
          INSERT INTO operacoes (conta_id, data_operacao, tipo, horario_entrada, horario_saida, pontos, resultado, custo)
          VALUES (${conta_id}, ${op.data_operacao}, ${op.tipo}, ${op.horario_entrada}, ${op.horario_saida || null},
                  ${op.pontos || 0}, ${op.resultado || 0}, ${op.custo || 0})
          ON CONFLICT DO NOTHING
        `
        inserted++
      } catch (_) { /* duplicata — ignora */ }
    }
    return res.json({ ok: true, inserted })
  }

  throw new Error('Ação inválida')
}))

// ── /api/operar ────────────────────────────────────────────────────────────
async function ensureOperarSchema(sql) {
  await sql`
    CREATE TABLE IF NOT EXISTS checklist_items (
      id SERIAL PRIMARY KEY,
      conta_id INT NOT NULL REFERENCES contas(id) ON DELETE CASCADE,
      lado VARCHAR(10) NOT NULL,
      ordem INT DEFAULT 0,
      titulo VARCHAR(200) NOT NULL,
      descricao TEXT DEFAULT '',
      tag VARCHAR(50) DEFAULT '',
      ativo INT DEFAULT 1,
      criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `
  for (const col of [
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS operar_ativo SMALLINT DEFAULT 0",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS contratos INT DEFAULT 1",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS contratos_wdo INT DEFAULT 1",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS contratos_modo_seguro INT DEFAULT 1",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS stop_pts_win INT DEFAULT 200",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS stop_pts_wdo INT DEFAULT 100",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS max_operacoes_dia INT DEFAULT 5",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS semaforo_ativo INT DEFAULT 1",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS modo_conservador INT DEFAULT 0",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS janela_tipo VARCHAR(20) DEFAULT 'manha'",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS janela_inicio TIME DEFAULT '09:00'",
    "ALTER TABLE contas ADD COLUMN IF NOT EXISTS janela_fim TIME DEFAULT '11:30'",
  ]) {
    await sql.unsafe(col)
  }
}

app.get('/api/operar', wrap(async (req, res) => {
  const user = verifyToken(req)
  const sql  = db()
  await ensureOperarSchema(sql)
  const { action, conta_id } = req.query
  const contaId = parseInt(conta_id)

  if (action === 'checklist') {
    const items = await sql`
      SELECT id, lado, ordem, titulo, descricao, tag, ativo
      FROM checklist_items WHERE conta_id=${contaId} ORDER BY lado, ordem
    `
    return res.json(items)
  }

  if (action === 'gestao') {
    const [conta] = await sql`SELECT * FROM contas WHERE id=${contaId} AND usuario_id=${user.id}`
    if (!conta) throw Object.assign(new Error('Conta não encontrada'), { status: 404 })

    const hoje = new Date().toISOString().slice(0, 10)
    const ciclos = await sql`SELECT data_inicio FROM ciclos WHERE conta_id=${contaId} AND data_fim IS NULL ORDER BY data_inicio DESC LIMIT 1`
    const periodoIni = ciclos[0] ? new Date(ciclos[0].data_inicio).toISOString().slice(0, 10) : hoje.slice(0, 7) + '-01'

    const [hojeRow] = await sql`SELECT COALESCE(SUM(resultado), 0) AS res_dia, COUNT(*) AS ops_hoje FROM operacoes WHERE conta_id=${contaId} AND data_operacao=${hoje}`
    const [cicloRow] = await sql`SELECT COALESCE(SUM(resultado), 0) AS lucro_ciclo FROM operacoes WHERE conta_id=${contaId} AND data_operacao >= ${periodoIni}`
    const recentOps = await sql`SELECT resultado FROM operacoes WHERE conta_id=${contaId} ORDER BY data_operacao DESC, horario_entrada DESC LIMIT 5`

    const resDia = parseFloat(hojeRow.res_dia), opsHoje = parseInt(hojeRow.ops_hoje)
    const lucroCiclo = parseFloat(cicloRow.lucro_ciclo)
    const stopDia = parseFloat(conta.stop_diario) || 0, metaDia = parseFloat(conta.meta_diaria) || 0
    const maxOps = parseInt(conta.max_operacoes_dia) || 5, lossLimit = parseFloat(conta.loss_limit_ciclo) || 0
    const semaforoAtivo = conta.semaforo_ativo != 0

    let dentroJanela = true
    if (semaforoAtivo) {
      const now = new Date(), hh = now.getHours() * 60 + now.getMinutes()
      const tipo = conta.janela_tipo || 'manha'
      let jIni, jFim
      if (tipo === 'manha') { jIni = 9 * 60; jFim = 11 * 60 + 30 }
      else if (tipo === 'tarde') { jIni = 14 * 60; jFim = 17 * 60 }
      else {
        const [h1, m1] = String(conta.janela_inicio || '09:00').slice(0, 5).split(':').map(Number)
        const [h2, m2] = String(conta.janela_fim || '11:30').slice(0, 5).split(':').map(Number)
        jIni = h1 * 60 + m1; jFim = h2 * 60 + m2
      }
      dentroJanela = hh >= jIni && hh <= jFim
    }

    const seq = recentOps.map(o => parseFloat(o.resultado) < 0 ? 'L' : 'G')
    let consLoss = 0
    for (const s of seq) { if (s === 'L') consLoss++; else break }

    const motivos = []
    let semaforo = semaforoAtivo ? 'VERDE' : 'LIVRE'
    if (semaforoAtivo) {
      if (metaDia > 0 && resDia >= metaDia) { semaforo = 'VERDE_META'; motivos.push('🏆 Meta diária atingida!') }
      if (stopDia > 0 && resDia <= -stopDia) { semaforo = 'VERMELHO'; motivos.push(`Stop diário atingido (−R$ ${Math.abs(stopDia).toFixed(2)})`) }
      if (opsHoje >= maxOps) { if (semaforo !== 'VERMELHO') semaforo = 'VERMELHO'; motivos.push(`Máximo de operações atingido (${maxOps})`) }
      if (lossLimit > 0) {
        const pct = Math.abs(Math.min(lucroCiclo, 0)) / lossLimit * 100
        if (pct >= 100) { semaforo = 'VERMELHO'; motivos.push('Ciclo quebrado — loss limit atingido') }
        else if (pct >= 70) { if (semaforo === 'VERDE') semaforo = 'VERMELHO'; motivos.push('Ciclo crítico (' + pct.toFixed(0) + '% consumido)') }
        else if (pct >= 40) { if (semaforo === 'VERDE') semaforo = 'AMARELO'; motivos.push('Atenção: ciclo ' + pct.toFixed(0) + '% consumido') }
      }
      if (consLoss >= 3 && semaforo === 'VERDE') { semaforo = 'AMARELO'; motivos.push(consLoss + ' losses consecutivos — opere com cautela') }
      if (!dentroJanela && semaforo === 'VERDE') motivos.push('Fora da janela de operação')
      if (motivos.length === 0) motivos.push('Tudo certo para operar')
    }

    const pctCiclo = lossLimit > 0 ? Math.min(100, Math.abs(Math.min(lucroCiclo, 0)) / lossLimit * 100) : 0
    let modoAtual = 'normal'
    if (metaDia > 0 && resDia >= metaDia) modoAtual = 'meta'
    else if (stopDia > 0 && resDia <= -stopDia) modoAtual = 'parado'
    else if (pctCiclo >= 70) modoAtual = 'critico'
    else if (pctCiclo >= 40) modoAtual = 'seguro'

    const contratos = parseInt(conta.contratos) || 1, contratosWdo = parseInt(conta.contratos_wdo) || 1
    const stopPtsWin = parseInt(conta.stop_pts_win) || 200, stopPtsWdo = parseInt(conta.stop_pts_wdo) || 100
    const ctsSug    = (modoAtual === 'seguro' || modoAtual === 'critico') ? Math.max(1, Math.floor(contratos / 2)) : contratos
    const ctsSugWdo = (modoAtual === 'seguro' || modoAtual === 'critico') ? Math.max(1, Math.floor(contratosWdo / 2)) : contratosWdo

    return res.json({
      semaforo, motivos, ops_hoje: opsHoje, max_ops: maxOps,
      res_dia: resDia, stop_disponivel: stopDia > 0 ? Math.max(0, stopDia + resDia) : null,
      stop_dia: stopDia, meta_dia: metaDia, ops_restantes: Math.max(0, maxOps - opsHoje),
      pct_ciclo: parseFloat(pctCiclo.toFixed(1)), lucro_ciclo: lucroCiclo, modo_atual: modoAtual,
      dentro_janela: dentroJanela, semaforo_ativo: semaforoAtivo,
      win_si: { cts_sug: ctsSug, stop_pts: stopPtsWin, stop_reais: parseFloat((ctsSug * 0.20 * stopPtsWin).toFixed(2)), alvo_pts: stopPtsWin * 2, alvo_reais: parseFloat((ctsSug * 0.20 * stopPtsWin * 2).toFixed(2)), be_pts: Math.round(stopPtsWin * 0.5) },
      wdo_si: { cts_sug: ctsSugWdo, stop_pts: stopPtsWdo, stop_reais: parseFloat((ctsSugWdo * 10.0 * stopPtsWdo).toFixed(2)), alvo_pts: stopPtsWdo * 2, alvo_reais: parseFloat((ctsSugWdo * 10.0 * stopPtsWdo * 2).toFixed(2)), be_pts: Math.round(stopPtsWdo * 0.5) },
    })
  }

  throw new Error('Ação inválida')
}))

app.post('/api/operar', wrap(async (req, res) => {
  const user = verifyToken(req)
  const sql  = db()
  await ensureOperarSchema(sql)
  const body = req.body || {}

  if (body.action === 'salvar_operar_config') {
    const contaId = parseInt(body.conta_id)
    const [conta] = await sql`SELECT id FROM contas WHERE id=${contaId} AND usuario_id=${user.id}`
    if (!conta) throw Object.assign(new Error('Acesso negado'), { status: 403 })
    await sql`
      UPDATE contas SET
        operar_ativo          = ${body.operar_ativo == 1 ? 1 : 0},
        semaforo_ativo        = ${body.semaforo_ativo == 1 ? 1 : 0},
        contratos             = ${parseInt(body.contratos) || 1},
        contratos_modo_seguro = ${parseInt(body.contratos_modo_seguro) || 1},
        contratos_wdo         = ${parseInt(body.contratos_wdo) || 1},
        max_operacoes_dia     = ${parseInt(body.max_operacoes_dia) || 5},
        stop_pts_win          = ${parseInt(body.stop_pts_win) || 0},
        stop_pts_wdo          = ${parseInt(body.stop_pts_wdo) || 0},
        modo_conservador      = ${body.modo_conservador == 1 ? 1 : 0},
        janela_tipo           = ${body.janela_tipo || 'manha'},
        janela_inicio         = ${body.janela_inicio || '09:00'},
        janela_fim            = ${body.janela_fim || '11:30'}
      WHERE id=${contaId}
    `
    return res.json({ ok: true })
  }

  if (body.action === 'salvar_checklist') {
    const contaId = parseInt(body.conta_id)
    const [conta] = await sql`SELECT id FROM contas WHERE id=${contaId} AND usuario_id=${user.id}`
    if (!conta) throw Object.assign(new Error('Acesso negado'), { status: 403 })
    const [maxOrd] = await sql`SELECT COALESCE(MAX(ordem), -1) AS m FROM checklist_items WHERE conta_id=${contaId} AND lado=${body.lado}`
    await sql`
      INSERT INTO checklist_items (conta_id, lado, ordem, titulo, descricao, tag, ativo)
      VALUES (${contaId}, ${body.lado}, ${maxOrd.m + 1}, ${body.titulo}, ${body.descricao || ''}, ${body.tag || ''}, 1)
    `
    return res.json({ ok: true })
  }

  if (body.action === 'toggle_checklist') {
    await sql`UPDATE checklist_items SET ativo = CASE WHEN ativo=1 THEN 0 ELSE 1 END WHERE id=${parseInt(body.id)}`
    return res.json({ ok: true })
  }

  if (body.action === 'excluir_checklist') {
    await sql`DELETE FROM checklist_items WHERE id=${parseInt(body.id)}`
    return res.json({ ok: true })
  }

  if (body.action === 'resetar_checklist') {
    const contaId = parseInt(body.conta_id)
    const [conta] = await sql`SELECT id FROM contas WHERE id=${contaId} AND usuario_id=${user.id}`
    if (!conta) throw Object.assign(new Error('Acesso negado'), { status: 403 })
    await sql`DELETE FROM checklist_items WHERE conta_id=${contaId}`
    const defaults = [
      { lado: 'COMPRA', ordem: 0, titulo: 'VWAP a favor',     descricao: 'Preço acima da VWAP ou suporte rejeitado',      tag: 'VWAP'    },
      { lado: 'COMPRA', ordem: 1, titulo: 'Weis 5t exaustão', descricao: 'Onda de venda murchando no recuo',              tag: 'WEIS'    },
      { lado: 'COMPRA', ordem: 2, titulo: 'Seta ▲ confirma',  descricao: 'Indicador plotou ▲ com volume',                tag: 'ENTRADA' },
      { lado: 'VENDA',  ordem: 0, titulo: 'VWAP a favor',     descricao: 'Preço abaixo da VWAP ou resistência rejeitada', tag: 'VWAP'    },
      { lado: 'VENDA',  ordem: 1, titulo: 'Weis 5t exaustão', descricao: 'Onda de compra murchando no repique',           tag: 'WEIS'    },
      { lado: 'VENDA',  ordem: 2, titulo: 'Seta ▼ confirma',  descricao: 'Indicador plotou ▼ com volume',                tag: 'ENTRADA' },
    ]
    for (const d of defaults) {
      await sql`INSERT INTO checklist_items (conta_id, lado, ordem, titulo, descricao, tag, ativo) VALUES (${contaId}, ${d.lado}, ${d.ordem}, ${d.titulo}, ${d.descricao}, ${d.tag}, 1)`
    }
    return res.json({ ok: true })
  }

  throw Object.assign(new Error('Ação não reconhecida'), { status: 400 })
}))

// ── /api/performance ───────────────────────────────────────────────────────
app.get('/api/performance', wrap(async (req, res) => {
  const user = verifyToken(req)
  const sql  = db()

  const contas = await sql`SELECT id, nome, plataforma FROM contas WHERE usuario_id=${user.id} AND ativa=1 ORDER BY nome`
  if (!contas.length) return res.json({ contas: [], dados: null })

  const contaId = req.query.conta_id ? parseInt(req.query.conta_id) : contas[0].id
  const mes     = req.query.mes || new Date().toISOString().slice(0, 7)
  const inicio  = mes + '-01'
  const fim     = new Date(mes.split('-')[0], parseInt(mes.split('-')[1]), 0).toISOString().slice(0, 10)

  const ops = await sql`
    SELECT id, data_operacao, tipo, horario_entrada, horario_saida, pontos, resultado, custo, observacao
    FROM operacoes WHERE conta_id=${contaId} AND data_operacao BETWEEN ${inicio} AND ${fim}
    ORDER BY data_operacao, horario_entrada
  `
  if (!ops.length) return res.json({ contas, dados: null, conta_id: contaId, mes })

  const lucroTotal = ops.reduce((s, o) => s + parseFloat(o.resultado), 0)
  const custoTotal = ops.reduce((s, o) => s + parseFloat(o.custo || 0), 0)
  const gains      = ops.filter(o => parseFloat(o.resultado) > 0)
  const losses     = ops.filter(o => parseFloat(o.resultado) < 0)
  const winRate    = ops.length ? (gains.length / ops.length) * 100 : 0
  const mediaGain  = gains.length  ? gains.reduce((s, o) => s + parseFloat(o.resultado), 0) / gains.length : 0
  const mediaLoss  = losses.length ? losses.reduce((s, o) => s + parseFloat(o.resultado), 0) / losses.length : 0
  const maxGain    = gains.length  ? Math.max(...gains.map(o => parseFloat(o.resultado))) : 0
  const maxLoss    = losses.length ? Math.min(...losses.map(o => parseFloat(o.resultado))) : 0

  const porDia = {}
  ops.forEach(o => {
    const d = o.data_operacao.toISOString?.().slice(0, 10) || String(o.data_operacao).slice(0, 10)
    porDia[d] = (porDia[d] || 0) + parseFloat(o.resultado)
  })
  const dias = Object.entries(porDia).sort(([a], [b]) => a.localeCompare(b))
  const resultadosDia = dias.map(([, v]) => v)
  const melhorDia = resultadosDia.length ? Math.max(...resultadosDia) : 0
  const piorDia   = resultadosDia.length ? Math.min(...resultadosDia) : 0
  const seqDia    = dias.map(([d, v]) => ({ data: d, resultado: parseFloat(v.toFixed(2)), tipo: v > 0 ? 'G' : v < 0 ? 'L' : 'N' }))

  let melhorSeq = 0, piorSeq = 0, curPos = 0, curNeg = 0
  resultadosDia.forEach(v => {
    if (v > 0) { curPos++; curNeg = 0; melhorSeq = Math.max(melhorSeq, curPos) }
    else if (v < 0) { curNeg++; curPos = 0; piorSeq = Math.max(piorSeq, curNeg) }
    else { curPos = 0; curNeg = 0 }
  })
  const ultimo = resultadosDia[resultadosDia.length - 1] || 0
  const seqAtual = ultimo > 0 ? curPos : ultimo < 0 ? -curNeg : 0

  let acum = 0
  const evolucao = dias.map(([d, v]) => { acum += v; return { data: d, valor: parseFloat(acum.toFixed(2)) } })
  const ultimas30 = [...ops].reverse().slice(0, 30).map(o => parseFloat(o.resultado) > 0 ? 'G' : parseFloat(o.resultado) < 0 ? 'L' : 'N').reverse()

  res.json({
    contas, conta_id: contaId, mes,
    dados: {
      lucro_total: parseFloat(lucroTotal.toFixed(2)), bruto_total: parseFloat((lucroTotal + custoTotal).toFixed(2)),
      custo_total: parseFloat(custoTotal.toFixed(2)), total_ops: ops.length,
      gains: gains.length, losses: losses.length, win_rate: parseFloat(winRate.toFixed(1)),
      media_gain: parseFloat(mediaGain.toFixed(2)), media_loss: parseFloat(mediaLoss.toFixed(2)),
      max_gain: parseFloat(maxGain.toFixed(2)), max_loss: parseFloat(maxLoss.toFixed(2)),
      melhor_dia: parseFloat(melhorDia.toFixed(2)), pior_dia: parseFloat(piorDia.toFixed(2)),
      seq_atual: seqAtual, melhor_seq: melhorSeq, pior_seq: piorSeq,
      seq_dia: seqDia, ultimas30, evolucao,
      ops: ops.map(o => ({
        ...o,
        data_operacao: o.data_operacao.toISOString?.().slice(0, 10) || String(o.data_operacao).slice(0, 10),
        resultado: parseFloat(o.resultado), pontos: parseFloat(o.pontos), custo: parseFloat(o.custo || 0),
      })),
    },
  })
}))

// ── /api/admin ─────────────────────────────────────────────────────────────
app.get('/api/admin', wrap(async (req, res) => {
  const user = verifyToken(req)
  if (user.role !== 'admin') throw Object.assign(new Error('Acesso negado'), { status: 403 })
  const sql = db()
  const rows = await sql`
    SELECT u.id, u.nome, u.email, u.role, u.ativo, u.criado_em,
           COUNT(c.id) AS contas
    FROM usuarios u
    LEFT JOIN contas c ON c.usuario_id = u.id
    GROUP BY u.id ORDER BY u.criado_em DESC
  `
  res.json(rows)
}))

app.post('/api/admin', wrap(async (req, res) => {
  const user = verifyToken(req)
  if (user.role !== 'admin') throw Object.assign(new Error('Acesso negado'), { status: 403 })
  const sql  = db()
  const body = req.body || {}

  if (body.action === 'salvar_usuario') {
    const { id, nome, email, senha, role } = body
    if (!nome?.trim() || !email?.trim()) throw new Error('Nome e e-mail obrigatórios')
    if (id) {
      if (senha?.trim()) {
        const hash = await bcrypt.hash(senha, 10)
        await sql`UPDATE usuarios SET nome=${nome}, email=${email}, role=${role||'user'}, senha_hash=${hash} WHERE id=${id}`
      } else {
        await sql`UPDATE usuarios SET nome=${nome}, email=${email}, role=${role||'user'} WHERE id=${id}`
      }
      return res.json({ ok: true })
    } else {
      if (!senha?.trim()) throw new Error('Senha obrigatória para novo usuário')
      const hash = await bcrypt.hash(senha, 10)
      const [row] = await sql`
        INSERT INTO usuarios (nome, email, senha_hash, role)
        VALUES (${nome}, ${email}, ${hash}, ${role||'user'}) RETURNING id
      `
      return res.json({ ok: true, id: row.id })
    }
  }

  if (body.action === 'toggle_usuario') {
    await sql`UPDATE usuarios SET ativo=${body.ativo} WHERE id=${body.id}`
    return res.json({ ok: true })
  }

  throw new Error('Ação inválida')
}))

// ── health check ───────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, ts: new Date().toISOString() }))

app.listen(PORT, () => console.log(`Trader Backend rodando na porta ${PORT}`))
