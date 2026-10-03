import { useState } from 'react'
import { phishing, ai } from '../services/api'
import AiExplanation from '../components/AiExplanation'
import './PhishingPage.css'

const LEVEL_META = {
  safe:     { label: 'No indicators found', color: '#3fb950', bg: '#3fb95015' },
  low:      { label: 'Low risk',             color: '#58a6ff', bg: '#58a6ff15' },
  medium:   { label: 'Medium risk',          color: '#d29922', bg: '#d2992215' },
  high:     { label: 'High risk',            color: '#f0883e', bg: '#f0883e15' },
  critical: { label: 'Critical risk',        color: '#f85149', bg: '#f8514915' },
}

const SEVERITY_COLOR = {
  info:   '#58a6ff',
  low:    '#8b949e',
  medium: '#d29922',
  high:   '#f85149',
}

const EMPTY_FORM = {
  sender: '',
  replyTo: '',
  subject: '',
  body: '',
  linksRaw: '',
  attachmentsRaw: '',
}

export default function PhishingPage() {
  const [form,    setForm]    = useState(EMPTY_FORM)
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')

  function handleChange(e) {
    const { name, value } = e.target
    setForm(f => ({ ...f, [name]: value }))
    if (result) setResult(null)
    if (error) setError('')
  }

  function parseLinks(raw) {
    return raw.split('\n').map(s => s.trim()).filter(Boolean)
  }

  function parseAttachments(raw) {
    return raw.split(',').map(s => s.trim()).filter(Boolean)
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (!form.body.trim()) return

    setLoading(true)
    setError('')
    setResult(null)

    try {
      const data = await phishing.analyze({
        sender:           form.sender.trim(),
        reply_to:         form.replyTo.trim(),
        subject:          form.subject.trim(),
        body:             form.body,
        links:            parseLinks(form.linksRaw),
        attachment_names: parseAttachments(form.attachmentsRaw),
      })
      setResult(data)
    } catch (err) {
      setError(err.message ?? 'Analysis failed.')
    } finally {
      setLoading(false)
    }
  }

  function handleClear() {
    setForm(EMPTY_FORM)
    setResult(null)
    setError('')
  }

  const meta = result ? (LEVEL_META[result.risk_level] ?? LEVEL_META.medium) : null

  return (
    <div className="ph-page">
      <div className="ph-intro">
        <h2 className="ph-heading">Phishing Email Analysis</h2>
        <p className="ph-sub">
          Paste email details to detect phishing indicators — spoofed senders, suspicious
          links, credential requests, and social-engineering tactics.
        </p>
        <p className="ph-caveat">
          Heuristic analysis only. Links are never opened; attachments are never executed.
          All submitted content is treated as untrusted.
        </p>
      </div>

      <form className="ph-form" onSubmit={handleSubmit}>
        {/* Row 1: Sender + Reply-To */}
        <div className="ph-row">
          <div className="ph-field">
            <label className="ph-label" htmlFor="ph-sender">From / Sender</label>
            <input
              id="ph-sender"
              className="ph-input"
              type="text"
              name="sender"
              value={form.sender}
              onChange={handleChange}
              placeholder="sender@example.com"
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div className="ph-field">
            <label className="ph-label" htmlFor="ph-reply-to">Reply-To <span style={{ color: 'var(--text-muted)' }}>(optional)</span></label>
            <input
              id="ph-reply-to"
              className="ph-input"
              type="text"
              name="replyTo"
              value={form.replyTo}
              onChange={handleChange}
              placeholder="replyto@example.com or leave blank"
              autoComplete="off"
              spellCheck={false}
            />
          </div>
        </div>

        {/* Row 2: Subject (full width) */}
        <div className="ph-field ph-field--full">
          <label className="ph-label" htmlFor="ph-subject">Subject</label>
          <input
            id="ph-subject"
            className="ph-input"
            type="text"
            name="subject"
            value={form.subject}
            onChange={handleChange}
            placeholder="Email subject line"
            autoComplete="off"
          />
        </div>

        {/* Row 3: Body (full width, required) */}
        <div className="ph-field ph-field--full">
          <label className="ph-label" htmlFor="ph-body">
            Email Body <span style={{ color: 'var(--danger)' }}>*</span>
          </label>
          <textarea
            id="ph-body"
            className="ph-textarea ph-textarea--body"
            name="body"
            value={form.body}
            onChange={handleChange}
            placeholder="Paste the email body here…"
            spellCheck={false}
            aria-required="true"
          />
        </div>

        {/* Row 4: Links + Attachments */}
        <div className="ph-row">
          <div className="ph-field">
            <label className="ph-label" htmlFor="ph-links">
              Links in Email <span style={{ color: 'var(--text-muted)' }}>(one per line)</span>
            </label>
            <textarea
              id="ph-links"
              className="ph-textarea ph-textarea--links"
              name="linksRaw"
              value={form.linksRaw}
              onChange={handleChange}
              placeholder={"https://example.com/verify\nhttps://bit.ly/abc"}
              spellCheck={false}
            />
          </div>
          <div className="ph-field">
            <label className="ph-label" htmlFor="ph-attachments">
              Attachment Names <span style={{ color: 'var(--text-muted)' }}>(comma-separated)</span>
            </label>
            <textarea
              id="ph-attachments"
              className="ph-textarea ph-textarea--links"
              name="attachmentsRaw"
              value={form.attachmentsRaw}
              onChange={handleChange}
              placeholder="invoice.pdf, document.docx"
              spellCheck={false}
            />
          </div>
        </div>

        {/* Actions */}
        <div className="ph-actions">
          <button
            className="ph-btn"
            type="submit"
            disabled={loading || !form.body.trim()}
            aria-busy={loading}
          >
            {loading ? 'Analysing…' : 'Analyse Email'}
          </button>
          {(form.body || form.sender || result) && (
            <button type="button" className="ph-clear-btn" onClick={handleClear}>
              Clear
            </button>
          )}
        </div>
      </form>

      {error && <div className="ph-error" role="alert">{error}</div>}

      {result && meta && (
        <div className="ph-result">
          {/* Header */}
          <div
            className="ph-result-header"
            style={{ borderColor: meta.color, background: meta.bg }}
          >
            <div className="ph-result-left">
              <span className="ph-risk-level" style={{ color: meta.color }}>
                {meta.label}
              </span>
              <span className="ph-risk-score">{result.risk_score} / 100</span>
            </div>
            <div className="ph-scan-meta">
              <span className="ph-scan-id">Scan #{result.scan_id}</span>
              <span className="ph-scan-time">
                {new Date(result.scanned_at).toLocaleString()}
              </span>
            </div>
          </div>

          {/* Score bar */}
          <div className="ph-bar-track">
            <div
              className="ph-bar-fill"
              style={{ width: `${result.risk_score}%`, background: meta.color }}
            />
          </div>

          {/* Indicators */}
          {result.indicators.length > 0 ? (
            <div className="ph-section">
              <h3 className="ph-section-title">⚠️ Detected Indicators</h3>
              <div className="ph-indicators">
                {result.indicators.map((ind, i) => (
                  <div key={i} className="ph-indicator">
                    <div className="ph-indicator-header">
                      <span
                        className="ph-indicator-badge"
                        style={{
                          background: (SEVERITY_COLOR[ind.severity] ?? '#8b949e') + '22',
                          color: SEVERITY_COLOR[ind.severity] ?? '#8b949e',
                        }}
                      >
                        {ind.severity}
                      </span>
                      <span className="ph-indicator-name">{ind.name}</span>
                    </div>
                    <p className="ph-indicator-detail">{ind.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="ph-no-indicators">
              No phishing indicators detected. Always verify the sender domain before acting on any email.
            </p>
          )}

          {/* Recommendations */}
          {result.recommendations.length > 0 && (
            <div className="ph-section">
              <h3 className="ph-section-title ph-section-title--info">💡 Recommendations</h3>
              <ul className="ph-recs">
                {result.recommendations.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </div>
          )}

          {result.analysis_version && (
            <div className="ph-footer">
              Analysis engine: {result.analysis_version}
            </div>
          )}
        </div>
      )}

      {/* AI explanation — subject + sender domain only, never the email body */}
      {result && (
        <AiExplanation
          resetKey={result.scan_id}
          fetchFn={() => ai.explain({
            scan_type:    'email',
            risk_score:   result.risk_score,
            risk_level:   result.risk_level,
            indicators:   result.indicators.map(i => ({
              id:       i.id,
              name:     i.name,
              detail:   i.detail,
              severity: i.severity,
            })),
            context_fields: {
              subject:       form.subject.trim().slice(0, 120) || '(no subject)',
              sender_domain: form.sender.includes('@')
                               ? form.sender.split('@').pop().trim()
                               : '',
            },
          })}
        />
      )}
    </div>
  )
}
