const state = {
  activeCaseId: null,
  streamCaseId: null,
  eventSource: null,
  queueRefreshTimer: null,
  listTimer: null,
  cachedCases: [],
  analysisDetails: [],
};

const elements = {
  uploadPanel: document.getElementById("upload-panel"),
  progressPanel: document.getElementById("progress-panel"),
  reportPanel: document.getElementById("report-panel"),
  dropzone: document.getElementById("dropzone"),
  browseBtn: document.getElementById("browse-btn"),
  fileInput: document.getElementById("file-input"),
  modeSelect: document.getElementById("mode-select"),
  progressFilename: document.getElementById("progress-filename"),
  stagesList: document.getElementById("stages-list"),
  runtimeMessages: document.getElementById("runtime-messages"),
  reportTitle: document.getElementById("report-title"),
  subjectMeta: document.getElementById("subject-meta"),
  reportStatusBadge: document.getElementById("report-status-badge"),
  senderMeta: document.getElementById("sender-meta"),
  timeMeta: document.getElementById("time-meta"),
  confidenceMeta: document.getElementById("confidence-meta"),
  classificationMeta: document.getElementById("classification-meta"),
  resultHeading: document.getElementById("result-heading"),
  analystSummary: document.getElementById("analyst-summary"),
  keyPoints: document.getElementById("key-points"),
  subjectLine: document.getElementById("subject-line"),
  subjectCard: document.getElementById("subject-card"),
  subjectAnalysis: document.getElementById("subject-analysis"),
  bodyCard: document.getElementById("body-card"),
  bodyAnalysis: document.getElementById("body-analysis"),
  textViewer: document.getElementById("text-viewer"),
  iocList: document.getElementById("ioc-list"),
  indicatorCards: document.getElementById("indicator-cards"),
  caseList: document.getElementById("case-list"),
  queueCount: document.getElementById("queue-count"),
  refreshCases: document.getElementById("refresh-cases"),
  newAnalysisTop: document.getElementById("new-analysis-top"),
  backToUploadBtn: document.getElementById("back-to-upload-btn"),
  riskRing: document.getElementById("risk-ring"),
  riskRingValue: document.getElementById("risk-ring-value"),
  decisionState: document.getElementById("decision-state"),
  decisionNote: document.getElementById("decision-note"),
  decisionUpdatedAt: document.getElementById("decision-updated-at"),
  decisionBenign: document.getElementById("decision-benign"),
  decisionSuspicious: document.getElementById("decision-suspicious"),
  decisionEscalate: document.getElementById("decision-escalate"),
  analysisDetailBtn: document.getElementById("analysis-detail-btn"),
  indicatorModal: document.getElementById("indicator-modal"),
  indicatorModalBackdrop: document.getElementById("indicator-modal-backdrop"),
  indicatorModalClose: document.getElementById("indicator-modal-close"),
  indicatorModalTitle: document.getElementById("indicator-modal-title"),
  indicatorModalSummary: document.getElementById("indicator-modal-summary"),
  indicatorModalList: document.getElementById("indicator-modal-list"),
  analysisModal: document.getElementById("analysis-modal"),
  analysisModalBackdrop: document.getElementById("analysis-modal-backdrop"),
  analysisModalClose: document.getElementById("analysis-modal-close"),
  analysisModalSummary: document.getElementById("analysis-modal-summary"),
  analysisModalList: document.getElementById("analysis-modal-list"),
};

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDisplayTime(iso) {
  if (!iso) return "-";
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return String(iso);
  return dt.toLocaleString();
}

function formatPct(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "-";
  return `${Math.round(Number(value) * 100)}%`;
}

function formatRisk(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "-";
  return String(Math.round(Number(value)));
}

function decisionLabel(decision) {
  const d = String(decision || "").toLowerCase();
  if (d === "benign") return "Benign";
  if (d === "suspicious") return "Suspicious";
  if (d === "escalate") return "Escalated";
  return "Undecided";
}

function verdictLabel(verdict) {
  const v = String(verdict || "").toLowerCase();
  if (v === "phish") return "Phishing";
  if (v === "benign") return "Benign";
  if (v === "suspicious") return "Suspicious";
  return "Pending";
}

function verdictClass(verdict) {
  const v = String(verdict || "").toLowerCase();
  if (v === "phish") return "phish";
  if (v === "benign") return "benign";
  if (v === "suspicious") return "suspicious";
  return "pending";
}

function outcomeLabel(outcome) {
  const o = String(outcome || "").toLowerCase();
  if (o === "known_phishing_ioc") return "Malicious";
  if (o === "not_malicious") return "Clean";
  return "Suspicious";
}

function mapVerdictToClassification(verdict) {
  const v = String(verdict || "").toLowerCase();
  if (v === "phish") return "malicious";
  if (v === "benign") return "non_malicious";
  return "suspicious";
}

function classificationLabel(classification) {
  const c = String(classification || "").toLowerCase();
  if (c === "malicious") return "Phishing";
  if (c === "non_malicious") return "Benign";
  if (c === "suspicious") return "Suspicious";
  return "Pending";
}

function panelIconSvg(panelId) {
  const id = String(panelId || "").toLowerCase();
  if (id === "urls") {
    return '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M10 13a5 5 0 0 0 7.07 0l2.12-2.12a5 5 0 0 0-7.07-7.07L11 5" stroke="currentColor" stroke-width="1.8"/><path d="M14 11a5 5 0 0 0-7.07 0L4.8 13.12a5 5 0 0 0 7.07 7.07L13 19" stroke="currentColor" stroke-width="1.8"/></svg>';
  }
  if (id === "domains") {
    return '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M3 12h18M12 3c2.8 2.8 2.8 15.2 0 18M12 3c-2.8 2.8-2.8 15.2 0 18" stroke="currentColor" stroke-width="1.5"/></svg>';
  }
  if (id === "ips") {
    return '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><rect x="3" y="4" width="18" height="7" rx="2" stroke="currentColor" stroke-width="1.8"/><rect x="3" y="13" width="18" height="7" rx="2" stroke="currentColor" stroke-width="1.8"/><circle cx="8" cy="7.5" r="1" fill="currentColor"/><circle cx="8" cy="16.5" r="1" fill="currentColor"/></svg>';
  }
  return '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M21 11.5a8.4 8.4 0 0 1-1.6 2.5l-7.8 7.8a5 5 0 0 1-7.1-7.1l8.1-8.1a3.2 3.2 0 1 1 4.5 4.5l-8 8a1.5 1.5 0 1 1-2.1-2.1l7.2-7.2" stroke="currentColor" stroke-width="1.8"/></svg>';
}

function iocTypeIcon(type) {
  const t = String(type || "").toLowerCase();
  if (t === "email") return "✉";
  if (t === "url") return "↗";
  if (t === "domain") return "◎";
  if (t === "ip") return "◍";
  if (t === "hash") return "#";
  return "•";
}

function closeAnalysisModal() {
  if (!elements.analysisModal) return;
  elements.analysisModal.classList.add("is-hidden");
  elements.analysisModal.setAttribute("aria-hidden", "true");
}

function closeIndicatorModal() {
  if (!elements.indicatorModal) return;
  elements.indicatorModal.classList.add("is-hidden");
  elements.indicatorModal.setAttribute("aria-hidden", "true");
}

function disconnectCaseStream() {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
  state.streamCaseId = null;
}

function setPanel(name) {
  const panelMap = {
    upload: elements.uploadPanel,
    progress: elements.progressPanel,
    report: elements.reportPanel,
  };
  Object.values(panelMap).forEach((panel) => panel?.classList.remove("is-active"));
  panelMap[name]?.classList.add("is-active");
}

function resetToUpload() {
  disconnectCaseStream();
  setPanel("upload");
  closeIndicatorModal();
  closeAnalysisModal();
  state.activeCaseId = null;
  if (elements.fileInput) elements.fileInput.value = "";
  renderCaseList(state.cachedCases);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function applyDecisionState(caseData) {
  const decision = String(caseData?.analyst_decision || "undecided").toLowerCase();
  if (elements.decisionState) {
    elements.decisionState.className = `decision-state ${decision}`;
    elements.decisionState.textContent = decisionLabel(decision);
  }
  if (elements.decisionNote) {
    elements.decisionNote.value = caseData?.analyst_note || "";
  }
  if (elements.decisionUpdatedAt) {
    elements.decisionUpdatedAt.textContent = caseData?.analyst_updated_at
      ? `Updated ${formatDisplayTime(caseData.analyst_updated_at)}`
      : "";
  }
}

function renderStages(runtime) {
  if (!elements.stagesList) return;
  const stages = Array.isArray(runtime?.stages) ? runtime.stages : [];
  elements.stagesList.innerHTML = "";
  for (const stage of stages) {
    const stateValue = stage?.state || "pending";
    const item = document.createElement("div");
    item.className = `stage-item state-${stateValue}`;
    item.innerHTML = `
      <span class="stage-label">${escapeHtml(stage?.label || stage?.id || "stage")}</span>
      <span class="stage-state">${escapeHtml(stateValue)}</span>
    `;
    elements.stagesList.appendChild(item);
  }
}

function renderRuntimeMessages(runtime) {
  if (!elements.runtimeMessages) return;
  const messages = Array.isArray(runtime?.messages) ? runtime.messages : [];
  const latest = messages.slice(-14).reverse();
  elements.runtimeMessages.innerHTML = "";
  for (const msg of latest) {
    const row = document.createElement("div");
    row.className = "runtime-msg";
    row.textContent = `${formatDisplayTime(msg.timestamp)}  ${msg.text || ""}`;
    elements.runtimeMessages.appendChild(row);
  }
}

function applyRiskRing(classification, riskScore) {
  if (!elements.riskRing || !elements.riskRingValue) return;
  const numericRisk = Number(riskScore);
  const target = Number.isFinite(numericRisk) ? Math.max(0, Math.min(100, numericRisk)) : 0;
  const current = Number(elements.riskRing.dataset.riskValue || "0");
  const start = Number.isFinite(current) ? current : 0;
  const durationMs = 420;
  const startAt = performance.now();

  elements.riskRing.className = `risk-ring ${classification}`;
  elements.riskRing.dataset.riskValue = String(target);

  function frame(now) {
    const elapsed = now - startAt;
    const t = Math.min(1, elapsed / durationMs);
    const eased = 1 - Math.pow(1 - t, 3);
    const value = start + (target - start) * eased;
    elements.riskRing.style.setProperty("--risk-angle", `${Math.round(value * 3.6)}deg`);
    elements.riskRingValue.textContent = String(Math.round(value));
    if (t < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

function queueCountLabel(count) {
  return `${count} investigation${count === 1 ? "" : "s"}`;
}

function renderCaseList(cases) {
  if (!elements.caseList) return;
  const rows = Array.isArray(cases) ? cases : [];
  state.cachedCases = rows;

  if (elements.queueCount) {
    elements.queueCount.textContent = queueCountLabel(rows.length);
  }

  elements.caseList.innerHTML = "";
  if (rows.length === 0) {
    const empty = document.createElement("p");
    empty.className = "queue-note";
    empty.textContent = "No investigations yet.";
    elements.caseList.appendChild(empty);
    return;
  }

  for (const row of rows) {
    const item = document.createElement("div");
    item.className = "case-item";
    if (row.case_id === state.activeCaseId) item.classList.add("active");

    const analystDecision = String(row.analyst_decision || "undecided").toLowerCase();
    const analystChip =
      analystDecision !== "undecided"
        ? `<span class="analyst-pill ${escapeHtml(analystDecision)}">Analyst: ${escapeHtml(decisionLabel(analystDecision).toLowerCase())}</span>`
        : "";

    item.innerHTML = `
      <p class="case-item-title">${escapeHtml(row.subject_line || row.filename || row.case_id)}</p>
      <div class="case-item-meta">
        <span>${escapeHtml(formatDisplayTime(row.updated_at || row.created_at))}</span>
        <span class="case-state ${escapeHtml(row.status || "queued")}">${escapeHtml(String(row.status || "queued"))}</span>
      </div>
      <div class="case-item-meta">
        <div class="case-meta-left">
          <span class="verdict-chip ${escapeHtml(verdictClass(row.verdict))}">${escapeHtml(verdictLabel(row.verdict))}</span>
          ${analystChip}
        </div>
        <span class="case-risk">${escapeHtml(formatRisk(row.risk_score))}</span>
      </div>
    `;

    item.addEventListener("click", () => {
      state.activeCaseId = row.case_id;
      disconnectCaseStream();
      loadCase(row.case_id, true).catch(() => {});
      renderCaseList(state.cachedCases);
    });
    elements.caseList.appendChild(item);
  }
}

async function copyText(text) {
  const value = String(text || "");
  if (!value) return;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return;
    }
  } catch {
    // Continue to fallback.
  }

  const el = document.createElement("textarea");
  el.value = value;
  el.style.position = "fixed";
  el.style.opacity = "0";
  document.body.appendChild(el);
  el.select();
  document.execCommand("copy");
  document.body.removeChild(el);
}

function openIndicatorModal(panel) {
  if (!elements.indicatorModal) return;
  elements.indicatorModalTitle.textContent = panel?.title || "Indicator Details";
  elements.indicatorModalSummary.textContent = panel?.summary || "";
  elements.indicatorModalList.innerHTML = "";

  const items = Array.isArray(panel?.items) ? panel.items : [];
  if (items.length === 0) {
    const empty = document.createElement("p");
    empty.className = "queue-note";
    empty.textContent = panel?.empty_note || "No entries in this category.";
    elements.indicatorModalList.appendChild(empty);
  } else {
    for (const item of items) {
      const row = document.createElement("div");
      row.className = "indicator-row";
      row.innerHTML = `
        <div class="indicator-row-head">
          <span class="ioc-value" title="${escapeHtml(item.value || "")}">${escapeHtml(item.display_value || item.value || "")}</span>
          <button class="copy-btn" type="button" data-copy="${escapeHtml(item.value || "")}">Copy</button>
          <span class="ioc-badge ${escapeHtml(item.outcome || "could_be_malicious")}">${escapeHtml(item.outcome || "could_be_malicious")}</span>
        </div>
        <div class="indicator-row-desc">${escapeHtml(item.description || "")}</div>
      `;
      elements.indicatorModalList.appendChild(row);
    }
  }

  elements.indicatorModal.classList.remove("is-hidden");
  elements.indicatorModal.setAttribute("aria-hidden", "false");
}

function openAnalysisModal() {
  if (!elements.analysisModal) return;
  elements.analysisModalList.innerHTML = "";
  const details = Array.isArray(state.analysisDetails) ? state.analysisDetails : [];
  if (details.length === 0) {
    const empty = document.createElement("p");
    empty.className = "queue-note";
    empty.textContent = "No suspicious subject/body excerpts were detected for this case.";
    elements.analysisModalList.appendChild(empty);
  } else {
    for (const item of details) {
      const row = document.createElement("div");
      row.className = "indicator-row";
      row.innerHTML = `
        <div class="ioc-row">
          <span class="ioc-badge ${escapeHtml(item.level === "red" ? "known_phishing_ioc" : "could_be_malicious")}">${escapeHtml(String(item.level || "yellow").toUpperCase())}</span>
          <strong>${escapeHtml(item.title || "Assessment")}</strong>
        </div>
        <div class="indicator-row-desc">${escapeHtml(item.detail || "")}</div>
      `;
      elements.analysisModalList.appendChild(row);
    }
  }
  elements.analysisModal.classList.remove("is-hidden");
  elements.analysisModal.setAttribute("aria-hidden", "false");
}

function renderIndicatorCards(panels) {
  if (!elements.indicatorCards) return;
  const rows = Array.isArray(panels) ? panels : [];
  elements.indicatorCards.innerHTML = "";

  if (rows.length === 0) {
    const empty = document.createElement("p");
    empty.className = "queue-note";
    empty.textContent = "No indicator groups available.";
    elements.indicatorCards.appendChild(empty);
    return;
  }

  for (const panel of rows) {
    const count = Array.isArray(panel.items) ? panel.items.length : 0;
    const disabled = panel.level === "neutral" || (panel.id === "attachments" && count === 0);
    const level = disabled ? "neutral" : String(panel.level || "yellow");

    const card = document.createElement("button");
    card.type = "button";
    card.className = `indicator-card level-${level}${disabled ? " is-disabled" : ""}`;

    const first = Array.isArray(panel.items) && panel.items.length > 0 ? panel.items[0] : null;
    const preview = first
      ? `
        <div class="indicator-card-row">
          <div class="indicator-card-row-head">
            <p class="indicator-card-value">${escapeHtml(first.display_value || first.value || "")}</p>
            <span class="ioc-badge ${escapeHtml(first.outcome || "could_be_malicious")}">${escapeHtml(first.outcome || "could_be_malicious")}</span>
          </div>
          <p class="indicator-card-desc">${escapeHtml(first.description || "")}</p>
        </div>
      `
      : "";

    card.innerHTML = `
      <div class="indicator-card-head">
        <span class="indicator-icon">${panelIconSvg(panel.id)}</span>
        <h4 class="indicator-card-title">${escapeHtml(panel.title || panel.label || "Indicator")}</h4>
      </div>
      <p class="indicator-card-summary">${escapeHtml(panel.summary || panel.empty_note || "")}</p>
      <span class="indicator-card-meta">${escapeHtml(panel.label || "Entries")} · ${count} item${count === 1 ? "" : "s"}</span>
      ${preview}
    `;

    if (!disabled) {
      card.addEventListener("click", () => openIndicatorModal(panel));
    }
    elements.indicatorCards.appendChild(card);
  }
}

function renderReport(caseData) {
  const report = caseData.web_report || {};
  const classification = report.classification || mapVerdictToClassification(caseData.verdict);

  const title = report.subject_line || caseData.subject_line || caseData.filename || caseData.case_id;
  if (elements.reportTitle) elements.reportTitle.textContent = title;
  if (elements.subjectMeta) elements.subjectMeta.textContent = title;

  if (elements.reportStatusBadge) {
    elements.reportStatusBadge.className = `status-pill ${classification}`;
    elements.reportStatusBadge.textContent = classificationLabel(classification);
  }

  if (elements.resultHeading) {
    elements.resultHeading.className = `result-heading ${classification}`;
    elements.resultHeading.textContent = report.result_heading || `This appears ${classification.replace("_", "-")}.`;
  }

  const iocItems = Array.isArray(report.ioc_items) ? report.ioc_items : [];
  const senderIoc = iocItems.find((item) => String(item.type || "").toLowerCase() === "email");
  if (elements.senderMeta) elements.senderMeta.textContent = senderIoc?.value || senderIoc?.display_value || "sender: unavailable";
  if (elements.timeMeta) elements.timeMeta.textContent = formatDisplayTime(caseData.updated_at || caseData.created_at);
  if (elements.confidenceMeta) elements.confidenceMeta.textContent = formatPct(caseData.confidence_score);
  if (elements.classificationMeta) {
    elements.classificationMeta.textContent = classificationLabel(classification);
    elements.classificationMeta.className = `meta-value meta-classification ${classification}`;
  }

  applyRiskRing(classification, caseData.risk_score);

  if (elements.analystSummary) {
    elements.analystSummary.textContent = report.analyst_summary || "No summary available.";
  }

  if (elements.keyPoints) {
    elements.keyPoints.innerHTML = "";
    const points = Array.isArray(report.key_points) ? report.key_points : [];
    points.forEach((point, idx) => {
      const li = document.createElement("li");
      li.setAttribute("data-index", String(idx + 1));
      li.textContent = point;
      elements.keyPoints.appendChild(li);
    });
  }

  if (elements.subjectLine) {
    elements.subjectLine.textContent = `Subject: ${report.subject_line || "(no subject)"}`;
  }
  if (elements.subjectAnalysis) elements.subjectAnalysis.textContent = report.subject_analysis || "";
  if (elements.bodyAnalysis) elements.bodyAnalysis.textContent = report.body_analysis || "";
  if (elements.subjectCard) elements.subjectCard.className = `analysis-card level-${report.subject_level || "yellow"}`;
  if (elements.bodyCard) elements.bodyCard.className = `analysis-card level-${report.body_level || "yellow"}`;
  if (elements.textViewer) {
    elements.textViewer.textContent = report.body_plain || "(No plain body text extracted)";
  }
  state.analysisDetails = Array.isArray(report.analysis_details) ? report.analysis_details : [];
  if (elements.analysisDetailBtn) {
    const showBtn = state.analysisDetails.length > 0;
    elements.analysisDetailBtn.style.display = showBtn ? "inline-flex" : "none";
  }

  if (elements.iocList) {
    elements.iocList.innerHTML = "";
    for (const ioc of iocItems) {
      const item = document.createElement("li");
      item.className = "ioc-item";
      const value = ioc.display_value || ioc.value || ioc.ioc || "";
      item.innerHTML = `
        <div class="ioc-row">
          <span class="ioc-icon">${escapeHtml(iocTypeIcon(ioc.type))}</span>
          <span class="ioc-value" title="${escapeHtml(ioc.value || ioc.ioc || "")}">${escapeHtml(value)}</span>
          <span class="ioc-badge ${escapeHtml(ioc.outcome || "could_be_malicious")}">${escapeHtml(outcomeLabel(ioc.outcome || "could_be_malicious"))}</span>
        </div>
        <div>${escapeHtml(ioc.description || "")}</div>
      `;
      elements.iocList.appendChild(item);
    }
    if (report.urls_clean_note) {
      const item = document.createElement("li");
      item.className = "ioc-item";
      item.textContent = report.urls_clean_note;
      elements.iocList.appendChild(item);
    }
  }

  renderIndicatorCards(report.indicator_panels || []);
  applyDecisionState(caseData);
}

async function setAnalystDecision(decision) {
  if (!state.activeCaseId) return;
  const note = elements.decisionNote?.value || "";

  const resp = await fetch(`/api/cases/${encodeURIComponent(state.activeCaseId)}/analyst-decision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ decision, note }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    alert(`Failed to save analyst decision: ${text}`);
    return;
  }

  const payload = await resp.json();
  if (payload?.case) renderReport(payload.case);
  await refreshCases();
}

function scheduleQueueRefresh(delayMs = 300) {
  if (state.queueRefreshTimer) clearTimeout(state.queueRefreshTimer);
  state.queueRefreshTimer = setTimeout(() => {
    refreshCases().catch(() => {});
    state.queueRefreshTimer = null;
  }, delayMs);
}

function connectCaseStream(caseId) {
  if (!caseId) return;
  if (state.eventSource && state.streamCaseId === caseId) return;

  disconnectCaseStream();
  const source = new EventSource(`/api/cases/${encodeURIComponent(caseId)}/events`);
  state.eventSource = source;
  state.streamCaseId = caseId;

  source.addEventListener("snapshot", (evt) => {
    if (state.activeCaseId !== caseId) return;
    try {
      const payload = JSON.parse(evt.data || "{}");
      if (payload.case) applyCaseData(payload.case, false);
    } catch {
      // Ignore malformed payload.
    }
  });

  source.addEventListener("case_event", () => {
    if (state.activeCaseId !== caseId) return;
    loadCase(caseId, false).catch(() => {});
    scheduleQueueRefresh(150);
  });
}

async function refreshCases() {
  const resp = await fetch("/api/cases");
  if (!resp.ok) return;
  const payload = await resp.json();
  const rows = Array.isArray(payload.cases) ? payload.cases : [];
  if (state.activeCaseId && !rows.some((c) => c.case_id === state.activeCaseId)) {
    state.activeCaseId = null;
  }
  renderCaseList(rows);
}

function applyCaseData(caseData, jumpPanel) {
  if (elements.progressFilename) {
    elements.progressFilename.textContent = caseData.filename
      ? `Investigating: ${caseData.filename}`
      : "Running investigation pipeline";
  }
  renderStages(caseData.runtime || {});
  renderRuntimeMessages(caseData.runtime || {});

  if (caseData.status === "complete") {
    renderReport(caseData);
    setPanel("report");
    if (elements.reportPanel) {
      setTimeout(() => elements.reportPanel.classList.remove("report-switching"), 70);
    }
    disconnectCaseStream();
    scheduleQueueRefresh(0);
    return;
  }

  if (caseData.status === "failed") {
    setPanel("progress");
    const runtime = caseData.runtime || {};
    runtime.messages = Array.isArray(runtime.messages) ? runtime.messages : [];
    runtime.messages.push({
      timestamp: new Date().toISOString(),
      text: `Case failed: ${caseData.error || "Unknown error"}`,
    });
    renderRuntimeMessages(runtime);
    disconnectCaseStream();
    scheduleQueueRefresh(0);
    return;
  }

  if (caseData.status === "running" || caseData.status === "queued") {
    if (jumpPanel) setPanel("progress");
    connectCaseStream(caseData.case_id);
    return;
  }

  if (jumpPanel) setPanel("upload");
}

async function loadCase(caseId, jumpPanel) {
  const shouldSwitchAnim =
    !!state.activeCaseId &&
    state.activeCaseId !== caseId &&
    elements.reportPanel?.classList.contains("is-active");
  if (shouldSwitchAnim && elements.reportPanel) {
    elements.reportPanel.classList.add("report-switching");
  }
  const resp = await fetch(`/api/cases/${encodeURIComponent(caseId)}`);
  if (!resp.ok) return;
  const caseData = await resp.json();
  state.activeCaseId = caseData.case_id;
  applyCaseData(caseData, jumpPanel);
}

async function uploadFile(file) {
  if (!file || !String(file.name || "").toLowerCase().endsWith(".eml")) {
    alert("Please upload a valid .eml file.");
    return;
  }

  const formData = new FormData();
  formData.append("file", file);
  formData.append("mode", elements.modeSelect?.value || window.APP_CONFIG?.defaultMode || "mock");

  disconnectCaseStream();
  setPanel("progress");
  if (elements.progressFilename) elements.progressFilename.textContent = `Starting: ${file.name}`;
  if (elements.stagesList) elements.stagesList.innerHTML = "";
  if (elements.runtimeMessages) elements.runtimeMessages.innerHTML = "";

  const resp = await fetch("/api/cases", {
    method: "POST",
    body: formData,
  });
  if (!resp.ok) {
    const text = await resp.text();
    setPanel("upload");
    alert(`Upload failed: ${text}`);
    return;
  }

  const payload = await resp.json();
  state.activeCaseId = payload.case_id;
  await refreshCases();
  await loadCase(payload.case_id, true);
}

function bindClick(el, cb) {
  if (el) el.addEventListener("click", cb);
}

function wireDropzone() {
  bindClick(elements.browseBtn, () => elements.fileInput?.click());

  elements.fileInput?.addEventListener("change", (evt) => {
    const [file] = evt.target.files || [];
    uploadFile(file).catch((err) => alert(`Upload failed: ${err.message}`));
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    elements.dropzone?.addEventListener(eventName, (evt) => {
      evt.preventDefault();
      evt.stopPropagation();
      elements.dropzone?.classList.add("drag-over");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    elements.dropzone?.addEventListener(eventName, (evt) => {
      evt.preventDefault();
      evt.stopPropagation();
      elements.dropzone?.classList.remove("drag-over");
    });
  });

  elements.dropzone?.addEventListener("drop", (evt) => {
    const [file] = evt.dataTransfer?.files || [];
    uploadFile(file).catch((err) => alert(`Upload failed: ${err.message}`));
  });
}

function wireModal() {
  bindClick(elements.indicatorModalClose, closeIndicatorModal);
  bindClick(elements.indicatorModalBackdrop, closeIndicatorModal);

  elements.indicatorModalList?.addEventListener("click", (evt) => {
    const target = evt.target;
    if (!(target instanceof HTMLElement)) return;
    const button = target.closest("button[data-copy]");
    if (!button) return;
    copyText(button.getAttribute("data-copy") || "").then(() => {
      button.textContent = "Copied";
      setTimeout(() => {
        button.textContent = "Copy";
      }, 900);
    });
  });

  window.addEventListener("keydown", (evt) => {
    if (evt.key === "Escape") {
      closeIndicatorModal();
      closeAnalysisModal();
    }
  });
}

function wireActions() {
  bindClick(elements.newAnalysisTop, resetToUpload);
  bindClick(elements.backToUploadBtn, resetToUpload);
  bindClick(elements.refreshCases, () => refreshCases().catch(() => {}));

  bindClick(elements.decisionBenign, () => setAnalystDecision("benign").catch(() => {}));
  bindClick(elements.decisionSuspicious, () => setAnalystDecision("suspicious").catch(() => {}));
  bindClick(elements.decisionEscalate, () => setAnalystDecision("escalate").catch(() => {}));
  bindClick(elements.analysisDetailBtn, openAnalysisModal);
  bindClick(elements.analysisModalClose, closeAnalysisModal);
  bindClick(elements.analysisModalBackdrop, closeAnalysisModal);
}

function initialize() {
  wireDropzone();
  wireModal();
  wireActions();
  refreshCases().catch(() => {});
  state.listTimer = setInterval(() => {
    refreshCases().catch(() => {});
  }, 20000);
}

window.addEventListener("beforeunload", () => {
  disconnectCaseStream();
});

initialize();
