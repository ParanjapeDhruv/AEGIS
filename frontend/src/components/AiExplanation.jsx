/**
 * AiExplanation — collapsible AI explanation panel.
 *
 * Props:
 *   fetchFn   {() => Promise<object>}  called once when user opens the panel
 *   resetKey  {any}                    changing this resets the panel (new scan)
 *
 * The parent builds the fetchFn closure and passes in evidence — this
 * component knows nothing about scan types or raw data.
 */
import { useState, useEffect, useRef } from 'react'
import './AiExplanation.css'

export default function AiExplanation({ fetchFn, resetKey }) {
  const [open,    setOpen]    = useState(false)
  const [loading, setLoading] = useState(false)
  const [data,    setData]    = useState(null)   // AiExplanation response
  const [error,   setError]   = useState('')
  const fetched = useRef(false)

  // Reset whenever the parent signals a new scan result
  useEffect(() => {
    setOpen(false)
    setLoading(false)
    setData(null)
    setError('')
    fetched.current = false
  }, [resetKey])

  async function handleToggle() {
    if (open) { setOpen(false); return }
    setOpen(true)
    // Only fetch once per scan result
    if (fetched.current) return
    fetched.current = true
    setLoading(true)
    setError('')
    try {
      const result = await fetchFn()
      setData(result)
    } catch (err) {
      setError(err.message ?? 'AI explanation unavailable.')
    } finally {
      setLoading(false)
    }
  }

  const statusLabel = loading
    ? 'loading…'
    : data
      ? (data.ai_available ? '' : 'offline')
      : ''

  return (
    <div className="ai-panel">
      {/* Trigger row */}
      <button
        className="ai-trigger"
        type="button"
        onClick={handleToggle}
        aria-expanded={open}
      >
        <span className="ai-trigger-icon">🤖</span>
        <span className="ai-trigger-label">Explain with AI</span>
        {statusLabel && (
          <span className="ai-trigger-status">{statusLabel}</span>
        )}
        <span className={`ai-trigger-caret${open ? ' ai-trigger-caret--open' : ''}`}>
          ▾
        </span>
      </button>

      {/* Expanded content */}
      {open && (
        <div className="ai-content" role="region" aria-label="AI explanation">
          {loading && (
            <div className="ai-loading">
              <div className="ai-spinner" aria-hidden="true" />
              Generating explanation…
            </div>
          )}

          {error && !loading && (
            <div className="ai-error">{error}</div>
          )}

          {data && !loading && (
            <>
              {/* Overview */}
              <div className="ai-section">
                <span className="ai-section-title">
                  AI Summary
                  {!data.ai_available && (
                    <span className="ai-fallback-badge">deterministic fallback</span>
                  )}
                </span>
                <p className="ai-overview">{data.overview}</p>
              </div>

              {/* Indicator notes */}
              {data.indicator_notes?.length > 0 && (
                <div className="ai-section">
                  <span className="ai-section-title">Indicator Breakdown</span>
                  <ul className="ai-list ai-list--notes">
                    {data.indicator_notes.map((note, i) => (
                      <li key={i}>{note}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Recommendations */}
              {data.recommendations?.length > 0 && (
                <div className="ai-section">
                  <span className="ai-section-title">AI Recommendations</span>
                  <ul className="ai-list ai-list--recs">
                    {data.recommendations.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}

              <p className="ai-disclaimer">{data.disclaimer}</p>
            </>
          )}
        </div>
      )}
    </div>
  )
}
