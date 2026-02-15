import React, { useCallback, useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowUpRight,
  Brain,
  Clock3,
  ChevronDown,
  Copy,
  FileText,
  Globe,
  Link2,
  Mail,
  Paperclip,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  X,
} from 'lucide-react'

const VERDICT_CLASS_MAP = {
  phish: 'malicious',
  suspicious: 'suspicious',
  benign: 'non_malicious',
}

const CLASS_TEXT = {
  malicious: 'Phishing',
  suspicious: 'Suspicious',
  non_malicious: 'Benign',
}

const DECISION_OPTIONS = [
  { id: 'benign', label: 'Benign', icon: ShieldCheck },
  { id: 'suspicious', label: 'Suspicious', icon: AlertTriangle },
  { id: 'escalate', label: 'Escalate', icon: ArrowUpRight },
]

function formatDisplayTime(iso) {
  if (!iso) return '-'
  const dt = new Date(iso)
  if (Number.isNaN(dt.getTime())) return String(iso)
  return dt.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })
}

function formatPct(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '-'
  return `${Math.round(Number(value) * 100)}%`
}

function formatRisk(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '-'
  const n = Number(value)
  if (Math.abs(n - Math.round(n)) < 0.05) return String(Math.round(n))
  return n.toFixed(1)
}

function mapVerdictToClassification(verdict) {
  const v = String(verdict || '').toLowerCase()
  return VERDICT_CLASS_MAP[v] || 'suspicious'
}

function classText(classification) {
  return CLASS_TEXT[classification] || 'Pending'
}

function normalizeOutcome(outcome, classification, semanticOverride = false) {
  const value = String(outcome || '').toLowerCase()
  if (!value) return 'could_be_malicious'
  if (semanticOverride && classification !== 'non_malicious' && value === 'not_malicious') {
    return 'could_be_malicious'
  }
  return value
}

function outcomeLabel(outcome, classification, semanticOverride = false) {
  const normalized = normalizeOutcome(outcome, classification, semanticOverride)
  if (normalized === 'known_phishing_ioc') return 'Malicious'
  if (normalized === 'not_malicious') return 'Benign'
  return 'Suspicious'
}

function outcomeBadgeClass(outcome, classification, semanticOverride = false) {
  const normalized = normalizeOutcome(outcome, classification, semanticOverride)
  if (normalized === 'known_phishing_ioc') return 'badge badge-danger'
  if (normalized === 'not_malicious') return 'badge badge-safe'
  return 'badge badge-warn'
}

function verdictBadgeClass(verdict) {
  const v = String(verdict || '').toLowerCase()
  if (v === 'phish') return 'badge badge-danger'
  if (v === 'benign') return 'badge badge-safe'
  if (v === 'suspicious') return 'badge badge-warn'
  return 'badge badge-neutral'
}

function verdictBadgeIcon(verdict) {
  const v = String(verdict || '').toLowerCase()
  if (v === 'phish') return <Shield className="h-3.5 w-3.5" />
  if (v === 'benign') return <ShieldCheck className="h-3.5 w-3.5" />
  if (v === 'suspicious') return <AlertTriangle className="h-3.5 w-3.5" />
  return null
}

function statusBadgeClass(status) {
  const s = String(status || '').toLowerCase()
  if (s === 'complete') return 'badge badge-safe'
  if (s === 'failed') return 'badge badge-danger'
  return 'badge badge-neutral'
}

function statusLabel(status) {
  const text = String(status || '').trim()
  if (!text) return 'Queued'
  return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase()
}

function statusBadgeIcon(status) {
  const s = String(status || '').toLowerCase()
  if (s === 'complete') return <ShieldCheck className="h-3.5 w-3.5" />
  if (s === 'failed') return <AlertTriangle className="h-3.5 w-3.5" />
  return <RefreshCw className="h-3.5 w-3.5" />
}

function classificationHeadline(classification) {
  if (classification === 'malicious') return 'This appears malicious.'
  if (classification === 'non_malicious') return 'This appears benign.'
  return 'This appears suspicious.'
}

function classificationToneClass(classification) {
  if (classification === 'malicious') return 'text-red-600'
  if (classification === 'non_malicious') return 'text-emerald-600'
  return 'text-amber-600'
}

function panelIcon(panelId) {
  const id = String(panelId || '').toLowerCase()
  if (id === 'urls') return <Link2 className="h-5 w-5" />
  if (id === 'domains') return <Globe className="h-5 w-5" />
  if (id === 'ips') return <Server className="h-5 w-5" />
  return <Paperclip className="h-5 w-5" />
}

function panelLevelStyle(level) {
  const lv = String(level || 'yellow')
  if (lv === 'red') return 'border-red-200 bg-red-50/50'
  if (lv === 'green') return 'border-emerald-200 bg-emerald-50/60'
  if (lv === 'neutral') return 'border-slate-200 bg-slate-100/65'
  return 'border-amber-200 bg-amber-50/60'
}

function panelIconStyle(level) {
  const lv = String(level || 'yellow')
  if (lv === 'red') return 'border-red-200 bg-red-50 text-red-600'
  if (lv === 'green') return 'border-emerald-200 bg-emerald-50 text-emerald-600'
  if (lv === 'neutral') return 'border-slate-300 bg-slate-100 text-slate-500'
  return 'border-amber-200 bg-amber-50 text-amber-700'
}

function analysisCardLevel(level) {
  const lv = String(level || 'yellow')
  if (lv === 'red') return 'analysis-level-red'
  if (lv === 'green') return 'analysis-level-green'
  return 'analysis-level-yellow'
}

function semanticLevelText(level) {
  if (level === 'red') return 'Phishing'
  if (level === 'green') return 'Benign'
  return 'Suspicious'
}

function semanticLevelBadge(level) {
  if (level === 'red') return 'badge badge-danger'
  if (level === 'green') return 'badge badge-safe'
  return 'badge badge-warn'
}

function threatTagBadgeClass(severity) {
  const s = String(severity || '').toLowerCase()
  if (s === 'critical' || s === 'high') return 'badge badge-danger'
  if (s === 'medium') return 'badge badge-warn'
  if (s === 'info') return 'badge badge-neutral'
  return 'badge badge-safe'
}

function buildEvidenceHighlights(report, keyPoints, classification) {
  const provided = Array.isArray(report?.evidence_highlights) ? report.evidence_highlights : []
  if (provided.length > 0) {
    return provided.slice(0, 5)
  }

  const fallback = []
  keyPoints.slice(0, 3).forEach((point, idx) => {
    fallback.push({
      id: `kp_${idx + 1}`,
      title: `Key finding ${idx + 1}`,
      detail: point,
      outcome: classification === 'non_malicious' ? 'not_malicious' : 'could_be_malicious',
    })
  })

  return fallback
}

async function copyText(value) {
  const text = String(value || '')
  if (!text) return
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return
    }
  } catch {
    // fallback below
  }
  const el = document.createElement('textarea')
  el.value = text
  el.style.position = 'fixed'
  el.style.opacity = '0'
  document.body.appendChild(el)
  el.select()
  document.execCommand('copy')
  document.body.removeChild(el)
}

function RiskRing({ riskScore, classification }) {
  const target = Number.isFinite(Number(riskScore)) ? Math.max(0, Math.min(100, Number(riskScore))) : 0
  const [displayRisk, setDisplayRisk] = useState(target)
  const previousRef = useRef(target)
  const showDecimal = Math.abs(target - Math.round(target)) >= 0.05

  useEffect(() => {
    const start = previousRef.current
    const end = target
    previousRef.current = end
    const startAt = performance.now()
    const duration = 520

    let frame = 0
    function tick(now) {
      const elapsed = now - startAt
      const t = Math.min(1, elapsed / duration)
      const eased = 1 - (1 - t) ** 3
      const nextValue = start + (end - start) * eased
      setDisplayRisk(nextValue)
      if (t < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [target])

  const ringColor =
    classification === 'malicious'
      ? '#ef4444'
      : classification === 'non_malicious'
        ? '#10b981'
        : '#f59e0b'

  return (
    <div
      className="risk-ring mx-auto"
      style={{
        '--ring-angle': `${Math.round(displayRisk * 3.6)}deg`,
        '--ring-color': ringColor,
      }}
    >
      <div className="relative z-10 flex flex-col items-center justify-center text-center leading-none">
        <span className={`tabular-nums text-[2.25rem] font-extrabold ${classificationToneClass(classification)}`}>
          {showDecimal ? displayRisk.toFixed(1) : Math.round(displayRisk)}
        </span>
        <span className="mt-1 text-[0.7rem] font-bold tracking-[0.14em] text-slate-400">RISK</span>
      </div>
    </div>
  )
}

function StageList({ runtime }) {
  const stages = Array.isArray(runtime?.stages) ? runtime.stages : []
  return (
    <div className="mt-4 grid gap-2">
      {stages.map((stage) => {
        const state = stage?.state || 'pending'
        const rowClass =
          state === 'done'
            ? 'border-emerald-200 bg-emerald-50'
            : state === 'running'
              ? 'border-sky-200 bg-sky-50'
              : 'border-slate-200 bg-white'
        return (
          <div
            key={stage.id || stage.label}
            className={`flex items-center justify-between rounded-xl border px-3 py-2 ${rowClass}`}
          >
            <span className="text-sm font-bold text-slate-700">{stage?.label || stage?.id || 'stage'}</span>
            <span className="text-[0.72rem] font-bold uppercase tracking-[0.1em] text-slate-400">{state}</span>
          </div>
        )
      })}
    </div>
  )
}

function RuntimeLog({ runtime }) {
  const messages = Array.isArray(runtime?.messages) ? runtime.messages.slice(-14).reverse() : []
  return (
    <div className="mt-3 max-h-36 overflow-y-auto rounded-xl border border-slate-200 bg-slate-50 p-2 case-scroll">
      {messages.length === 0 ? (
        <p className="px-1 py-1 text-xs text-slate-500">Waiting for runtime logs...</p>
      ) : (
        messages.map((msg, idx) => (
          <div
            key={`${msg.timestamp || idx}_${idx}`}
            className="border-b border-dashed border-slate-200 px-1 py-1 text-xs text-slate-600 last:border-b-0"
          >
            {formatDisplayTime(msg.timestamp)} {msg.text || ''}
          </div>
        ))
      )}
    </div>
  )
}

function ModalShell({ title, subtitle, open, onClose, children }) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-3">
      <button type="button" className="absolute inset-0 bg-slate-900/50" onClick={onClose} aria-label="Close" />
      <div className="relative z-10 w-full max-w-6xl rounded-2xl border border-slate-200 bg-white p-4 shadow-soft">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <h3 className="m-0 text-[1.45rem] font-extrabold text-slate-800">{title}</h3>
            {subtitle ? <p className="mt-1 text-[0.95rem] text-slate-500">{subtitle}</p> : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-slate-200 bg-slate-50 p-2 text-slate-600 transition hover:bg-slate-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[68vh] overflow-y-auto rounded-xl border border-slate-200 bg-slate-50 p-3 case-scroll">{children}</div>
      </div>
    </div>
  )
}

export default function App() {
  const fileInputRef = useRef(null)
  const eventSourceRef = useRef(null)
  const activeCaseIdRef = useRef(null)
  const refreshIntervalRef = useRef(null)
  const refreshTimeoutRef = useRef(null)

  const [config, setConfig] = useState({
    app_name: 'Phishing Triage',
    default_mode: 'mock',
    max_upload_mb: 30,
  })
  const [mode, setMode] = useState('mock')
  const [uploading, setUploading] = useState(false)

  const [uiMode, setUiMode] = useState('upload')
  const [cases, setCases] = useState([])
  const [activeCaseId, setActiveCaseId] = useState(null)
  const [activeCase, setActiveCase] = useState(null)
  const [uploadLabel, setUploadLabel] = useState('Running investigation pipeline')
  const [dragOver, setDragOver] = useState(false)
  const [switchingReport, setSwitchingReport] = useState(false)
  const [indicatorPanel, setIndicatorPanel] = useState(null)
  const [analysisModalOpen, setAnalysisModalOpen] = useState(false)
  const [decisionDraft, setDecisionDraft] = useState('undecided')
  const [noteDraft, setNoteDraft] = useState('')
  const [savingDecision, setSavingDecision] = useState(false)
  const [copiedValue, setCopiedValue] = useState('')

  useEffect(() => {
    activeCaseIdRef.current = activeCaseId
  }, [activeCaseId])

  useEffect(() => {
    if (!activeCase) {
      setDecisionDraft('undecided')
      setNoteDraft('')
      return
    }
    setDecisionDraft(String(activeCase?.analyst_decision || 'undecided').toLowerCase())
    setNoteDraft(activeCase?.analyst_note || '')
  }, [activeCase?.case_id, activeCase?.analyst_decision, activeCase?.analyst_note])

  const disconnectStream = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
  }, [])

  const scheduleCaseRefresh = useCallback((delayMs = 260) => {
    if (refreshTimeoutRef.current) clearTimeout(refreshTimeoutRef.current)
    refreshTimeoutRef.current = setTimeout(() => {
      refreshTimeoutRef.current = null
      refreshCases().catch(() => {})
    }, delayMs)
  }, [])

  const applyCaseData = useCallback(
    (caseData, jumpPanel = true) => {
      setActiveCase(caseData)
      if (caseData?.filename) setUploadLabel(`Investigating: ${caseData.filename}`)

      if (caseData.status === 'complete') {
        setUiMode('report')
        setUploading(false)
        disconnectStream()
        scheduleCaseRefresh(0)
        return
      }

      if (caseData.status === 'failed') {
        setUiMode('progress')
        setUploading(false)
        disconnectStream()
        scheduleCaseRefresh(0)
        return
      }

      if (caseData.status === 'running' || caseData.status === 'queued') {
        if (jumpPanel) setUiMode('progress')
        return
      }

      if (jumpPanel) setUiMode('upload')
    },
    [disconnectStream, scheduleCaseRefresh],
  )

  const loadCase = useCallback(
    async (caseId, jumpPanel = true, animateSwitch = true) => {
      if (!caseId) return
      const shouldAnimate =
        animateSwitch && activeCaseIdRef.current && activeCaseIdRef.current !== caseId && uiMode === 'report'
      if (shouldAnimate) setSwitchingReport(true)

      const resp = await fetch(`/api/cases/${encodeURIComponent(caseId)}`)
      if (!resp.ok) {
        if (shouldAnimate) setSwitchingReport(false)
        return
      }

      const caseData = await resp.json()
      setActiveCaseId(caseData.case_id)
      applyCaseData(caseData, jumpPanel)

      if (shouldAnimate) {
        window.setTimeout(() => setSwitchingReport(false), 300)
      }

      if (caseData.status === 'running' || caseData.status === 'queued') {
        connectCaseStream(caseData.case_id)
      }
    },
    [applyCaseData, uiMode],
  )

  const connectCaseStream = useCallback(
    (caseId) => {
      if (!caseId) return
      if (eventSourceRef.current && activeCaseIdRef.current === caseId) return

      disconnectStream()
      const source = new EventSource(`/api/cases/${encodeURIComponent(caseId)}/events`)
      eventSourceRef.current = source

      source.addEventListener('snapshot', (evt) => {
        if (activeCaseIdRef.current !== caseId) return
        try {
          const payload = JSON.parse(evt.data || '{}')
          if (payload.case) applyCaseData(payload.case, false)
        } catch {
          // ignore malformed payload
        }
      })

      source.addEventListener('case_event', () => {
        if (activeCaseIdRef.current !== caseId) return
        loadCase(caseId, false, false).catch(() => {})
        scheduleCaseRefresh(160)
      })

      source.onerror = () => {
        // browser auto-retries
      }
    },
    [applyCaseData, disconnectStream, loadCase, scheduleCaseRefresh],
  )

  const refreshCases = useCallback(async () => {
    const resp = await fetch('/api/cases')
    if (!resp.ok) return
    const payload = await resp.json()
    const rows = Array.isArray(payload.cases) ? payload.cases : []
    setCases(rows)

    if (activeCaseIdRef.current && !rows.some((row) => row.case_id === activeCaseIdRef.current)) {
      setActiveCaseId(null)
      setActiveCase(null)
      setUiMode('upload')
      disconnectStream()
    }
  }, [disconnectStream])

  useEffect(() => {
    ;(async () => {
      const cfgResp = await fetch('/api/config')
      if (cfgResp.ok) {
        const cfg = await cfgResp.json()
        setConfig(cfg)
        setMode(cfg.default_mode || 'mock')
      }
      await refreshCases()
    })().catch(() => {})

    refreshIntervalRef.current = setInterval(() => {
      refreshCases().catch(() => {})
    }, 20000)

    return () => {
      disconnectStream()
      if (refreshIntervalRef.current) clearInterval(refreshIntervalRef.current)
      if (refreshTimeoutRef.current) clearTimeout(refreshTimeoutRef.current)
    }
  }, [disconnectStream, refreshCases])

  const resetToUpload = useCallback(() => {
    disconnectStream()
    setActiveCaseId(null)
    setActiveCase(null)
    setUiMode('upload')
    setSwitchingReport(false)
    setIndicatorPanel(null)
    setAnalysisModalOpen(false)
    setUploading(false)
    if (fileInputRef.current) fileInputRef.current.value = ''
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }, [disconnectStream])

  const uploadFile = useCallback(
    async (file) => {
      if (!file || !String(file.name || '').toLowerCase().endsWith('.eml')) {
        window.alert('Please upload a valid .eml file.')
        return
      }

      setUploading(true)
      disconnectStream()
      setUploadLabel(`Starting: ${file.name}`)
      setUiMode('progress')
      setActiveCase(null)

      const formData = new FormData()
      formData.append('file', file)
      formData.append('mode', mode)

      const resp = await fetch('/api/cases', { method: 'POST', body: formData })
      if (!resp.ok) {
        const text = await resp.text()
        setUiMode('upload')
        setUploading(false)
        window.alert(`Upload failed: ${text}`)
        return
      }

      const payload = await resp.json()
      setActiveCaseId(payload.case_id)
      await refreshCases()
      await loadCase(payload.case_id, true, false)
    },
    [disconnectStream, loadCase, mode, refreshCases],
  )

  const saveAnalystDecision = useCallback(async () => {
    if (!activeCaseIdRef.current || savingDecision) return
    setSavingDecision(true)
    try {
      const resp = await fetch(`/api/cases/${encodeURIComponent(activeCaseIdRef.current)}/analyst-decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision: decisionDraft, note: noteDraft }),
      })
      if (!resp.ok) {
        const text = await resp.text()
        window.alert(`Failed to save analyst decision: ${text}`)
        return
      }
      const payload = await resp.json()
      if (payload.case) setActiveCase(payload.case)
      await refreshCases()
    } finally {
      setSavingDecision(false)
    }
  }, [decisionDraft, noteDraft, refreshCases, savingDecision])

  const onDrop = useCallback(
    (evt) => {
      evt.preventDefault()
      setDragOver(false)
      const file = evt.dataTransfer?.files?.[0]
      uploadFile(file).catch((err) => window.alert(`Upload failed: ${err.message}`))
    },
    [uploadFile],
  )

  const report = activeCase?.web_report || {}
  const classification = report.classification || mapVerdictToClassification(activeCase?.verdict)
  const riskScore = activeCase?.risk_score ?? 0
  const confidence = formatPct(activeCase?.confidence_score)
  const subject = report.subject_line || activeCase?.subject_line || activeCase?.filename || activeCase?.case_id || '-'
  const senderFromIoc = (report.ioc_items || []).find((item) => String(item?.type || '').toLowerCase() === 'email')
  const senderAddress = report.sender_address || senderFromIoc?.value || senderFromIoc?.display_value || 'sender unavailable'
  const senderDomain = report.sender_domain || (String(senderAddress).includes('@') ? String(senderAddress).split('@')[1] : '')
  const timeText = formatDisplayTime(activeCase?.updated_at || activeCase?.created_at)
  const keyPoints = Array.isArray(report.key_points) ? report.key_points : []
  const indicatorPanels = Array.isArray(report.indicator_panels) ? report.indicator_panels : []
  const analysisDetails = Array.isArray(report.analysis_details) ? report.analysis_details : []
  const analysisSnippets = Array.isArray(report.analysis_snippets) ? report.analysis_snippets : []
  const bodyPreview =
    report.body_preview ||
    (analysisSnippets.length > 0 ? analysisSnippets.slice(0, 2).join('\n') : report.body_plain || '(No plain body text extracted)')
  const evidenceHighlights = buildEvidenceHighlights(report, keyPoints, classification)
  const threatTags = Array.isArray(report?.threat_tags) ? report.threat_tags : []
  const runtime = activeCase?.runtime || { stages: [], messages: [] }

  const caseQueueTitle = `${cases.length} investigation${cases.length === 1 ? '' : 's'}`
  const showUpload = uiMode === 'upload'
  const showProgress = uiMode === 'progress'
  const showReport = uiMode === 'report' && !!activeCase

  const indicatorTitle = indicatorPanel?.title || 'Indicator Details'
  const indicatorSubtitle = indicatorPanel?.summary || ''
  const indicatorGroups = Array.isArray(indicatorPanel?.groups)
    ? indicatorPanel.groups.filter((group) => Array.isArray(group?.items) && group.items.length > 0)
    : []

  return (
    <div className="mx-auto max-w-[1500px] px-3 pb-5 pt-2 text-[12px] lg:text-[12px]">
      <header className="panel-card mb-3 flex items-center justify-between gap-3 px-5 py-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#0a1736] text-slate-100">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <h1 className="m-0 text-[1.8rem] font-extrabold leading-tight text-[#10203a]">{config.app_name || 'Phishing Triage'}</h1>
            <p className="m-0 text-[0.86rem] font-semibold text-slate-400">AI-Powered Email Investigation</p>
          </div>
        </div>
        <button
          type="button"
          onClick={resetToUpload}
          className="rounded-xl border border-slate-200 bg-slate-100 px-5 py-2 text-sm font-bold text-slate-600 transition hover:bg-slate-200"
        >
          New Analysis
        </button>
      </header>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_352px]">
        <main className="min-w-0 space-y-3">
          {showUpload ? (
            <section className="panel-card p-5">
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[#0a1736] text-slate-100">
                  <FileText className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="m-0 text-[1.95rem] font-extrabold leading-tight text-[#10203a]">Analyze New Email</h2>
                  <p className="m-0 text-[0.95rem] text-slate-400">Drop an .eml file to begin investigation</p>
                </div>
              </div>

              <div
                role="presentation"
                onDragEnter={(evt) => {
                  evt.preventDefault()
                  setDragOver(true)
                }}
                onDragOver={(evt) => {
                  evt.preventDefault()
                  setDragOver(true)
                }}
                onDragLeave={(evt) => {
                  evt.preventDefault()
                  setDragOver(false)
                }}
                onDrop={onDrop}
                className={`rounded-2xl border-2 border-dashed px-6 py-12 text-center transition ${
                  dragOver ? 'border-sky-400 bg-sky-50 shadow-soft' : 'border-slate-300 bg-gradient-to-b from-slate-50 to-white'
                }`}
              >
                <div className="mx-auto mb-5 flex h-[74px] w-[74px] items-center justify-center rounded-2xl bg-slate-100 text-slate-500">
                  {uploading ? (
                    <div className="h-8 w-8 animate-spin rounded-full border-[3px] border-slate-300 border-t-sky-700" />
                  ) : (
                    <FileText className="h-8 w-8 text-[#203963]" />
                  )}
                </div>
                <p className="m-0 text-[1.25rem] font-extrabold text-[#12274a]">Drop your .eml file here</p>
                <p className="mt-2 text-[0.92rem] text-slate-500">or browse from your computer to launch analysis</p>
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="mt-4 rounded-xl bg-[#10254f] px-6 py-2.5 text-sm font-bold text-white transition hover:bg-[#0a1d3f]"
                >
                  Browse Files
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".eml"
                  className="hidden"
                  onChange={(evt) => {
                    const file = evt.target.files?.[0]
                    uploadFile(file).catch((err) => window.alert(`Upload failed: ${err.message}`))
                  }}
                />
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-slate-200 pt-4">
                <span className="text-sm font-bold text-slate-500">Investigation Mode</span>
                <select
                  value={mode}
                  onChange={(evt) => setMode(evt.target.value)}
                  className="rounded-xl border border-slate-300 bg-slate-50 px-3 py-2 text-sm font-semibold text-slate-600"
                >
                  <option value="mock">Mock</option>
                  <option value="live">Live</option>
                </select>
                <span className="text-sm font-bold text-slate-300">Upload limit: {config.max_upload_mb}MB</span>
              </div>
            </section>
          ) : null}

          {showProgress ? (
            <section className="panel-card p-5">
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[#0a1736] text-slate-100">
                  <RefreshCw className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="m-0 text-[1.7rem] font-extrabold leading-tight text-[#10203a]">Analyzing Email</h2>
                  <p className="m-0 text-base text-slate-400">{uploadLabel}</p>
                </div>
              </div>

              <div className="grid min-h-[210px] place-items-center rounded-2xl border border-dashed border-slate-300 bg-slate-50 px-5 py-7 text-center">
                <div>
                  <div className="mx-auto h-11 w-11 animate-spin rounded-full border-4 border-slate-300 border-t-[#183a67]" />
                  <p className="mb-0 mt-4 text-lg font-extrabold text-slate-700">Running full investigation...</p>
                  <p className="m-0 text-sm text-slate-500">Live stage updates from runtime</p>
                </div>
              </div>

              <StageList runtime={runtime} />
              <RuntimeLog runtime={runtime} />
            </section>
          ) : null}

          {showReport ? (
            <div className={`transition-panel space-y-3 ${switchingReport ? 'switching' : ''}`}>
              <section className="panel-card p-5">
                <div className="mb-4 flex items-center justify-between gap-3">
                  <button
                    type="button"
                    onClick={resetToUpload}
                    className="text-sm font-bold text-slate-400 transition hover:text-slate-600"
                  >
                    ← Back to Upload
                  </button>
                  <span
                    className={
                      classification === 'malicious'
                        ? 'badge badge-danger'
                        : classification === 'non_malicious'
                          ? 'badge badge-safe'
                          : 'badge badge-warn'
                    }
                  >
                    {classification === 'malicious' ? <Shield className="h-3.5 w-3.5" /> : null}
                    {classification === 'suspicious' ? <AlertTriangle className="h-3.5 w-3.5" /> : null}
                    {classification === 'non_malicious' ? <ShieldCheck className="h-3.5 w-3.5" /> : null}
                    {classText(classification)}
                  </span>
                </div>

                <div className="grid items-center gap-6 lg:grid-cols-[170px_minmax(0,1fr)]">
                  <RiskRing riskScore={riskScore} classification={classification} />
                  <div>
                    <h2 className="m-0 text-[2.1rem] font-extrabold tracking-tight text-[#0f2142]">{subject}</h2>
                    <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-2 text-[0.9rem] font-semibold text-slate-400">
                      <span className="inline-flex items-center gap-2">
                        <Mail className="h-4 w-4" />
                        <span className="max-w-[620px] truncate" title={senderAddress}>
                          {senderAddress}
                        </span>
                      </span>
                      <span className="inline-flex items-center gap-2">
                        <Clock3 className="h-4 w-4" />
                        {timeText}
                      </span>
                      <span className="inline-flex items-center gap-2">
                        <Brain className="h-4 w-4" />
                        Confidence: {confidence}
                      </span>
                    </div>
                    <p className="mt-2 text-[0.9rem] font-semibold text-slate-400">Sender domain: {senderDomain || '-'}</p>
                    {threatTags.length > 0 ? (
                      <div className="mt-2 flex flex-wrap gap-2">
                        {threatTags.slice(0, 4).map((tag) => (
                          <span key={tag.id || tag.label} className={threatTagBadgeClass(tag.severity)}>
                            {tag.label || tag.id}
                          </span>
                        ))}
                      </div>
                    ) : null}
                    <p className={`mb-0 mt-2 text-[1.8rem] font-extrabold leading-tight ${classificationToneClass(classification)}`}>
                      {report.result_heading || classificationHeadline(classification)}
                    </p>
                  </div>
                </div>
              </section>

              <section className="panel-card p-5">
                <div className="mb-3 flex items-center gap-2 text-[#1d3152]">
                  <Brain className="h-5 w-5 text-slate-400" />
                  <h3 className="m-0 text-[1.3rem] font-extrabold">AI Analysis Summary</h3>
                </div>

                <p className="mb-0 text-[0.95rem] leading-7 text-slate-600">{report.analyst_summary || 'No summary available.'}</p>

                <h4 className="mb-2 mt-6 text-[0.92rem] font-extrabold uppercase tracking-[0.11em] text-slate-400">Key Findings</h4>
                <div className="grid gap-2">
                  {keyPoints.map((point, idx) => (
                    <div key={`${idx}_${point}`} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-[0.95rem] text-slate-600">
                      <span className="mr-3 inline-flex h-6 w-6 items-center justify-center rounded-full bg-slate-200 text-xs font-extrabold text-slate-500">
                        {idx + 1}
                      </span>
                      {point}
                    </div>
                  ))}
                </div>
              </section>

              <section className="panel-card p-5">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 text-[#1d3152]">
                    <Mail className="h-5 w-5 text-slate-400" />
                    <h3 className="m-0 text-[1.3rem] font-extrabold">Subject &amp; Body Analysis</h3>
                  </div>
                  {(analysisDetails.length > 0 || analysisSnippets.length > 0) && classification !== 'non_malicious' ? (
                    <button
                      type="button"
                      onClick={() => setAnalysisModalOpen(true)}
                      className="rounded-xl border border-slate-200 bg-slate-100 px-3 py-1.5 text-xs font-bold text-slate-600 transition hover:bg-slate-200"
                    >
                      View Detailed Review
                    </button>
                  ) : null}
                </div>

                <p className="mb-2 mt-0 text-sm text-slate-400">Subject: {report.subject_line || '(no subject)'}</p>

                <div className={`rounded-xl border p-3 ${analysisCardLevel(report.subject_level)}`}>
                  <h4 className="mb-1 text-[0.85rem] font-extrabold uppercase tracking-[0.09em] text-slate-600">Subject Assessment</h4>
                  <p className="m-0 text-[0.95rem] text-slate-600">{report.subject_analysis || 'No subject assessment available.'}</p>
                </div>

                <div className={`mt-3 rounded-xl border p-3 ${analysisCardLevel(report.body_level)}`}>
                  <h4 className="mb-1 text-[0.85rem] font-extrabold uppercase tracking-[0.09em] text-slate-600">Body Assessment</h4>
                  <p className="m-0 text-[0.95rem] text-slate-600">{report.body_analysis || 'No body assessment available.'}</p>
                </div>

                {classification !== 'non_malicious' ? (
                  <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="mb-2 text-[0.82rem] font-extrabold uppercase tracking-[0.12em] text-slate-400">Suspicious Snippet Preview</p>
                    {analysisSnippets.length > 0 ? (
                      <div className="grid gap-2">
                        {analysisSnippets.slice(0, 3).map((snippet, idx) => (
                          <pre key={`preview_snippet_${idx}`} className="mono whitespace-pre-wrap break-words rounded-xl border border-slate-200 bg-white p-3 text-sm leading-6 text-slate-600">
                            {snippet}
                          </pre>
                        ))}
                      </div>
                    ) : (
                      <p className="m-0 text-sm text-slate-500">{bodyPreview}</p>
                    )}
                  </div>
                ) : null}
              </section>

              <section>
                <h3 className="mb-1 pl-1 text-[1.35rem] font-extrabold text-[#1d3152]">Indicators of Compromise</h3>
                <div className="grid gap-3 md:grid-cols-2">
                  {indicatorPanels.map((panel) => {
                    const count = Array.isArray(panel?.items) ? panel.items.length : 0
                    const disabled = panel?.level === 'neutral' || (panel?.id === 'attachments' && count === 0)
                    return (
                      <button
                        key={panel.id || panel.label}
                        type="button"
                        onClick={() => {
                          if (!disabled) setIndicatorPanel(panel)
                        }}
                        className={`h-[192px] rounded-2xl border p-4 text-left transition ${panelLevelStyle(panel.level)} ${
                          disabled ? 'cursor-default opacity-85' : 'hover:-translate-y-[1px] hover:shadow-soft'
                        }`}
                      >
                        <div className="flex h-full flex-col">
                          <div className="mb-2 flex items-start gap-3">
                            <span className={`inline-flex h-11 w-11 items-center justify-center rounded-xl border ${panelIconStyle(panel.level)}`}>
                              {panelIcon(panel.id)}
                            </span>
                            <div className="min-w-0 flex-1">
                              <h4 className="m-0 text-[1.08rem] font-extrabold text-[#1f3356]">{panel.title || panel.label}</h4>
                              <p className="mt-1 line-clamp-3 text-[0.9rem] leading-6 text-slate-500">{panel.summary || panel.empty_note}</p>
                            </div>
                            {!disabled ? <ChevronDown className="h-5 w-5 text-slate-400" /> : null}
                          </div>
                          <p className="mt-auto text-[0.95rem] font-bold text-slate-400">
                            {panel.label || 'Entries'} · {count} item{count === 1 ? '' : 's'}
                          </p>
                        </div>
                      </button>
                    )
                  })}
                </div>
              </section>

              {evidenceHighlights.length > 0 ? (
                <section className="panel-card p-5">
                  <h3 className="m-0 text-[1.25rem] font-extrabold text-[#1d3152]">Evidence Drivers</h3>
                  <div className="mt-3 grid gap-2">
                    {evidenceHighlights.map((highlight, idx) => (
                      <div key={highlight.id || idx} className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <span className={outcomeBadgeClass(highlight.outcome, classification, highlight.semantic_override)}>
                            {outcomeLabel(highlight.outcome, classification, highlight.semantic_override)}
                          </span>
                          <span className="text-sm font-bold text-slate-700">{highlight.title || 'Evidence'}</span>
                        </div>
                        <p className="m-0 text-sm text-slate-500">{highlight.detail}</p>
                      </div>
                    ))}
                  </div>
                </section>
              ) : null}

              <section className="panel-card p-5">
                <h3 className="m-0 text-[1.25rem] font-extrabold text-[#1d3152]">Analyst Decision</h3>
                <p className="mt-1 text-[0.95rem] text-slate-400">Review the AI analysis and make your determination</p>

                <div className="mt-3 flex flex-wrap gap-2">
                  {DECISION_OPTIONS.map((option) => {
                    const Icon = option.icon
                    const active = decisionDraft === option.id
                    const tone =
                      option.id === 'benign'
                        ? active
                          ? 'bg-emerald-500 text-white border-emerald-400'
                          : 'bg-slate-100 text-slate-500 border-slate-200'
                        : option.id === 'suspicious'
                          ? active
                            ? 'bg-amber-500 text-white border-amber-400'
                            : 'bg-slate-100 text-slate-500 border-slate-200'
                          : active
                            ? 'bg-slate-700 text-white border-slate-600'
                            : 'bg-slate-100 text-slate-500 border-slate-200'
                    return (
                      <button
                        key={option.id}
                        type="button"
                        onClick={() => setDecisionDraft(option.id)}
                        className={`inline-flex items-center gap-2 rounded-2xl border px-4 py-2 text-[0.92rem] font-bold transition ${tone}`}
                      >
                        <Icon className="h-5 w-5" />
                        {option.label}
                      </button>
                    )
                  })}
                </div>

                <textarea
                  value={noteDraft}
                  onChange={(evt) => setNoteDraft(evt.target.value)}
                  placeholder="Add analyst notes (optional)..."
                  className="mt-4 min-h-[120px] w-full rounded-2xl border border-slate-200 bg-white p-4 text-base text-slate-600 outline-none ring-sky-200 focus:ring"
                />

                <button
                  type="button"
                  onClick={() => saveAnalystDecision().catch(() => {})}
                  disabled={savingDecision}
                  className="mt-4 w-full rounded-2xl bg-[#08183d] px-4 py-3 text-[1.05rem] font-bold text-white transition hover:bg-[#0a1f4b] disabled:cursor-not-allowed disabled:opacity-70"
                >
                  {savingDecision ? 'Saving...' : 'Save Decision'}
                </button>
                {activeCase?.analyst_updated_at ? (
                  <div className="mt-2 text-sm text-slate-400">Updated {formatDisplayTime(activeCase.analyst_updated_at)}</div>
                ) : null}
              </section>
            </div>
          ) : null}
        </main>

        <aside className="panel-card case-scroll h-fit max-h-[calc(100vh-16px)] overflow-y-auto p-4 xl:sticky xl:top-2">
          <div className="mb-2 flex items-start justify-between gap-2">
            <div>
              <h2 className="m-0 text-[1.45rem] font-extrabold text-[#162b4c]">Case Queue</h2>
              <p className="m-0 text-[0.9rem] text-slate-400">{caseQueueTitle}</p>
            </div>
            <button
              type="button"
              onClick={() => refreshCases().catch(() => {})}
              className="rounded-xl border border-slate-200 bg-slate-100 p-2 text-slate-500 transition hover:bg-slate-200"
              aria-label="Refresh queue"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>

          <div className="grid gap-3">
            {cases.length === 0 ? (
              <p className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-500">No investigations yet.</p>
            ) : (
              cases.map((row) => {
                const isActive = showReport && row.case_id === activeCaseId
                const rowClass = mapVerdictToClassification(row.verdict)
                const riskTone = classificationToneClass(rowClass)
                return (
                  <button
                    type="button"
                    key={row.case_id}
                    onClick={() => loadCase(row.case_id, true, true).catch(() => {})}
                    className={`queue-card rounded-2xl border p-3 text-left transition ${
                      isActive
                        ? 'border-[#0f2552] bg-[#0a1736] text-slate-100 shadow-soft'
                        : 'border-slate-200 bg-slate-50 hover:-translate-y-[1px] hover:shadow-soft'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <p
                        className={`m-0 line-clamp-2 text-[0.98rem] font-extrabold leading-6 ${
                          isActive ? 'text-slate-100' : 'text-[#162b4c]'
                        }`}
                        title={row.subject_line || row.filename || row.case_id}
                      >
                        {row.subject_line || row.filename || row.case_id}
                      </p>
                      <span className={statusBadgeClass(row.status)}>
                        {statusBadgeIcon(row.status)}
                        {statusLabel(row.status)}
                      </span>
                    </div>

                    <div className="mt-2 flex items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={verdictBadgeClass(row.verdict)}>
                          {verdictBadgeIcon(row.verdict)}
                          {classText(mapVerdictToClassification(row.verdict))}
                        </span>
                        {String(row.analyst_decision || '').toLowerCase() !== 'undecided' ? (
                          <span className="badge badge-neutral">Analyst: {String(row.analyst_decision || '').toLowerCase()}</span>
                        ) : null}
                      </div>
                      <span className={`text-[1.75rem] font-extrabold ${riskTone}`}>{formatRisk(row.risk_score)}</span>
                    </div>

                    <p className={`mt-auto text-[0.9rem] ${isActive ? 'text-slate-300' : 'text-slate-400'}`}>
                      {formatDisplayTime(row.updated_at || row.created_at)}
                    </p>
                  </button>
                )
              })
            )}
          </div>
        </aside>
      </div>

      <ModalShell title={indicatorTitle} subtitle={indicatorSubtitle} open={Boolean(indicatorPanel)} onClose={() => setIndicatorPanel(null)}>
        {indicatorGroups.length > 0 ? (
          <div className="grid gap-3">
            {indicatorGroups.map((group, groupIdx) => {
              const groupItems = Array.isArray(group?.items) ? group.items : []
              const descriptions = groupItems
                .map((item) => String(item?.description || '').trim())
                .filter(Boolean)
              const repeatedDescription =
                groupItems.length > 1 && descriptions.length === groupItems.length && new Set(descriptions).size === 1
              const summaryLine = repeatedDescription ? descriptions[0] : ''

              return (
                <section key={`${group.id || group.title || 'group'}_${groupIdx}`} className="rounded-xl border border-slate-200 bg-white p-3">
                  <h4 className="m-0 text-[1.1rem] font-extrabold text-slate-700">{group.title || 'Group'}</h4>
                  {group.summary ? <p className="mt-1 text-sm text-slate-500">{group.summary}</p> : null}
                  {summaryLine ? <p className="mt-1 text-sm text-slate-500">{summaryLine}</p> : null}
                  <div className="mt-2 grid gap-2">
                    {groupItems.map((item, idx) => (
                      <div key={`${item.value || idx}_${idx}`} className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="mono hidden-scroll-x rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs text-slate-600" title={item.value || ''}>
                            {item.display_value || item.value}
                          </span>
                          <button
                            type="button"
                            onClick={() => {
                              copyText(item.value || '').catch(() => {})
                              setCopiedValue(String(item.value || ''))
                              setTimeout(() => setCopiedValue(''), 1200)
                            }}
                            className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px] font-bold text-slate-500 transition hover:bg-slate-100"
                          >
                            <Copy className="h-3 w-3" /> {copiedValue === String(item.value || '') ? 'Copied' : 'Copy'}
                          </button>
                          <span className={outcomeBadgeClass(item.outcome, classification, item.semantic_override)}>
                            {outcomeLabel(item.outcome, classification, item.semantic_override)}
                          </span>
                        </div>
                        {!repeatedDescription && item.description ? <p className="mt-1 text-sm text-slate-500">{item.description}</p> : null}
                      </div>
                    ))}
                  </div>
                </section>
              )
            })}
          </div>
        ) : indicatorPanel && Array.isArray(indicatorPanel.items) && indicatorPanel.items.length > 0 ? (
          indicatorPanel.items.map((item, idx) => (
            <div key={`${item.value || idx}_${idx}`} className="mb-2 rounded-xl border border-slate-200 bg-white p-3 text-left last:mb-0">
              <div className="flex items-center gap-2">
                <span className="mono hidden-scroll-x rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-slate-600" title={item.value || ''}>
                  {item.display_value || item.value}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    copyText(item.value || '').catch(() => {})
                    setCopiedValue(String(item.value || ''))
                    setTimeout(() => setCopiedValue(''), 1200)
                  }}
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] font-bold text-slate-500 transition hover:bg-slate-100"
                >
                  <Copy className="h-3 w-3" /> {copiedValue === String(item.value || '') ? 'Copied' : 'Copy'}
                </button>
                <span className={outcomeBadgeClass(item.outcome, classification, item.semantic_override)}>
                  {outcomeLabel(item.outcome, classification, item.semantic_override)}
                </span>
              </div>
              <p className="mt-1 text-sm text-slate-500">{item.description}</p>
            </div>
          ))
        ) : (
          <p className="rounded-xl bg-white px-3 py-2 text-sm text-slate-500">{indicatorPanel?.empty_note || 'No entries in this category.'}</p>
        )}
      </ModalShell>

      <ModalShell
        title="Detailed Subject & Body Review"
        subtitle="Suspicious and malicious snippets with semantic assessments"
        open={analysisModalOpen}
        onClose={() => setAnalysisModalOpen(false)}
      >
        <div className="grid gap-2">
          {analysisDetails.length === 0 ? (
            <p className="rounded-xl bg-white px-3 py-2 text-sm text-slate-500">No semantic findings were detected for this case.</p>
          ) : (
            analysisDetails.map((detail, idx) => (
              <div key={`${detail.signal_id || 'detail'}_${idx}`} className="rounded-xl border border-slate-200 bg-white p-3 text-left">
                <div className="mb-1 flex items-center gap-2">
                  <span className={semanticLevelBadge(detail.level)}>{semanticLevelText(detail.level)}</span>
                  <span className="text-sm font-bold text-slate-700">{detail.title || 'Assessment'}</span>
                </div>
                <p className="m-0 text-sm text-slate-500">{detail.detail}</p>
              </div>
            ))
          )}

          {analysisSnippets.length > 0 ? (
            <div className="rounded-xl border border-slate-200 bg-white p-3">
              <h4 className="m-0 text-lg font-extrabold text-slate-700">Snippet Evidence</h4>
              <p className="mt-1 text-sm text-slate-500">Extracted text fragments that contributed to the current classification.</p>
              <div className="mt-2 grid gap-2">
                {analysisSnippets.map((snippet, idx) => (
                  <pre key={`snippet_${idx}`} className="mono whitespace-pre-wrap break-words rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
                    {snippet}
                  </pre>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </ModalShell>
    </div>
  )
}
