import { useState } from 'react'
import { urlAnalysis, ai } from '../services/api'
import AiExplanation from '../components/AiExplanation'
import './UrlAnalysisPage.css'

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

/** Defang a URL for safe display: https→hxxps, dots→[.] */
function defang(url) {
  return url
    .replace(/^https/i, 'hxxps')
    .replace(/^http/i,  'hxxp')
    .replace(/\./g, '[.]')
}

export default function UrlAnalysisPage() {
  const [url,      setUrl]      = useState('')
  const [result,   setResult]   = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState('')
  const [showRaw,  setShowRaw]  = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    const trimmed = url.trim()
    if (!trimmed) return
    if (!/^https?:\/\/.+/i.test(trimmed)) {
      setError('URL must start with http:// or https:// and contain a host.')
      return
    }
    setLoading(true)
    setError('')
    setResult(null)
    setShowRaw(false)
    try {
      const data = await urlAnalysis.analyze(trimmed)
      setResult(data)
    } catch (err) {
      setError(err.message ?? 'Analysis failed.')
    } finally {
      setLoading(false)
    }
  }

  const meta = result ? (LEVEL_META[result.risk_level] ?? LEVEL_META.medium) : null

  return (
    <div className="url-page">
      <div className="url-intro">
        <h2 className="url-heading">URL Analysis</h2>
        <p className="url-sub">
          Scan a URL for phishing indicators, suspicious patterns, and structural anomalies.
        </p>
        <p className="url-caveat">
          Heuristic analysis of the URL string only. It cannot see page content, domain age or reputation.
        </p>
      </div>

      <form className="url-form" onSubmit={handleSubmit}>
        <input
          className="url-input"
          type="text"
          placeholder="https://example.com/page"
          value={url}
          onChange={e => { setUrl(e.target.value); setResult(null); setError('') }}
          autoComplete="off"
          spellCheck={false}
          aria-label="URL to analyse"
        />
        <button className="url-btn" type="submit" disabled={loading || !url.trim()}>
          {loading ? 'Scanning…' : 'Scan URL'}
        </button>
      </form>

      {error && <div className="url-error" role="alert">{error}</div>}

      {result && meta && (
        <div className="url-result">
          {/* Header */}
          <div className="url-result-header" style={{ borderColor: meta.color, background: meta.bg }}>
            <div className="url-result-left">
              <span className="url-risk-level" style={{ color: meta.color }}>{meta.label}</span>
              <span className="url-risk-score">{result.risk_score} / 100</span>
            </div>
            <div className="url-scan-meta">
              <span className="url-scan-id">Scan #{result.scan_id}</span>
              <span className="url-scan-time">{new Date(result.scanned_at).toLocaleString()}</span>
            </div>
          </div>

          {/* Score bar */}
          <div className="url-bar-track">
            <div className="url-bar-fill" style={{ width: `${result.risk_score}%`, background: meta.color }} />
          </div>

          {/* Defanged normalized URL */}
          <div className="url-normalized">
            <div className="url-normalized-top">
              <span className="url-normalized-label">Normalised URL</span>
              <button
                className="url-raw-toggle"
                type="button"
                onClick={() => setShowRaw(r => !r)}
                aria-pressed={showRaw}
              >
                {showRaw ? 'Hide raw' : 'Show raw'}
              </button>
            </div>
            <span className="url-normalized-value">
              {showRaw ? result.normalized_url : defang(result.normalized_url)}
            </span>
          </div>

          {/* Indicators — sorted by severity then weight */}
          {result.indicators.length > 0 ? (
            <div className="url-section">
              <h3 className="url-section-title">⚠️ Detected Indicators</h3>
              <div className="url-indicators">
                {result.indicators.map((ind, i) => (
                  <div key={i} className="url-indicator">
                    <div className="url-indicator-header">
                      <span
                        className="url-indicator-badge"
                        style={{
                          background: SEVERITY_COLOR[ind.severity] + '22',
                          color: SEVERITY_COLOR[ind.severity],
                        }}
                      >
                        {ind.severity}
                      </span>
                      <span className="url-indicator-name">{ind.name}</span>
                      {ind.weight != null && (
                        <span className="url-indicator-weight">w={ind.weight}</span>
                      )}
                    </div>
                    <p className="url-indicator-detail">{ind.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="url-no-indicators">
              No structural indicators detected. This does not confirm the URL is safe —
              heuristics cannot inspect page content or reputation.
            </p>
          )}

          {/* Recommendations */}
          {result.recommendations.length > 0 && (
            <div className="url-section">
              <h3 className="url-section-title url-section-title--info">💡 Recommendations</h3>
              <ul className="url-recs">
                {result.recommendations.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </div>
          )}

          {result.analysis_version && (
            <div className="url-footer">
              Analysis engine: {result.analysis_version}
            </div>
          )}
        </div>
      )}

      {/* AI explanation — shown below the result card, evidence-only */}
      {result && (
        <AiExplanation
          resetKey={result.scan_id}
          fetchFn={() => ai.explain({
            scan_type:    'url',
            risk_score:   result.risk_score,
            risk_level:   result.risk_level,
            indicators:   result.indicators.map(i => ({
              id:       i.id,
              name:     i.name,
              detail:   i.detail,
              severity: i.severity,
            })),
            context_fields: {
              host: result.normalized_url
                      ? new URL(result.normalized_url).hostname
                      : '',
            },
          })}
        />
      )}
    </div>
  )
}
