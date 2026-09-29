import { useState } from 'react'
import { password as passwordApi } from '../services/api'
import './PasswordPage.css'

const LEVEL_META = {
  very_weak:   { label: 'Very Weak',   color: '#f85149', pct: 10 },
  weak:        { label: 'Weak',        color: '#f0883e', pct: 30 },
  moderate:    { label: 'Moderate',    color: '#d29922', pct: 55 },
  strong:      { label: 'Strong',      color: '#3fb950', pct: 78 },
  very_strong: { label: 'Very Strong', color: '#00d4aa', pct: 100 },
}

export default function PasswordPage() {
  const [pwd,     setPwd]     = useState('')
  const [show,    setShow]    = useState(false)
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')

  async function handleAnalyse(e) {
    e.preventDefault()
    if (!pwd) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const data = await passwordApi.analyze(pwd)
      setResult(data)
    } catch (err) {
      setError(err.message ?? 'Analysis failed.')
    } finally {
      setLoading(false)
      // Clear the password from state — never keep it longer than needed
      setPwd('')
    }
  }

  const meta = result ? (LEVEL_META[result.level] ?? LEVEL_META.moderate) : null

  return (
    <div className="pw-page">
      <div className="pw-intro">
        <h2 className="pw-heading">Password Analysis</h2>
        <p className="pw-sub">
          Evaluate your password against deterministic security rules.
          Your password is never stored or sent to any external service.
        </p>
      </div>

      <form className="pw-form" onSubmit={handleAnalyse}>
        <div className="pw-input-wrap">
          <input
            className="pw-input"
            type={show ? 'text' : 'password'}
            placeholder="Enter a password to analyse…"
            value={pwd}
            onChange={e => { setPwd(e.target.value); setResult(null); setError('') }}
            autoComplete="off"
            aria-label="Password to analyse"
          />
          <button
            type="button"
            className="pw-toggle"
            onClick={() => setShow(s => !s)}
            aria-label={show ? 'Hide password' : 'Show password'}
          >
            {show ? '🙈' : '👁️'}
          </button>
        </div>
        <button className="pw-btn" type="submit" disabled={loading || !pwd}>
          {loading ? 'Analysing…' : 'Analyse'}
        </button>
      </form>

      {error && <div className="pw-error" role="alert">{error}</div>}

      {result && meta && (
        <div className="pw-result">
          {/* Score bar */}
          <div className="pw-score-row">
            <span className="pw-level-label" style={{ color: meta.color }}>
              {meta.label}
            </span>
            <span className="pw-score-num">{result.score} / 100</span>
          </div>
          <div className="pw-bar-track">
            <div
              className="pw-bar-fill"
              style={{ width: `${result.score}%`, background: meta.color }}
            />
          </div>

          {/* Stats grid */}
          <div className="pw-stats">
            <Stat label="Entropy"      value={`${result.entropy_bits} bits`} />
            <Stat label="Length"       value={result.character_stats.length} />
            <Stat label="Uppercase"    value={result.character_stats.uppercase} />
            <Stat label="Lowercase"    value={result.character_stats.lowercase} />
            <Stat label="Digits"       value={result.character_stats.digits} />
            <Stat label="Symbols"      value={result.character_stats.symbols} />
            <Stat label="Unique chars" value={result.character_stats.unique_chars} />
          </div>

          {/* Weaknesses */}
          {result.weaknesses.length > 0 && (
            <div className="pw-section">
              <h3 className="pw-section-title pw-section-title--danger">⚠️ Weaknesses</h3>
              <ul className="pw-list pw-list--danger">
                {result.weaknesses.map((w, i) => <li key={i}>{w}</li>)}
              </ul>
            </div>
          )}

          {/* Recommendations */}
          {result.recommendations.length > 0 && (
            <div className="pw-section">
              <h3 className="pw-section-title pw-section-title--info">💡 Recommendations</h3>
              <ul className="pw-list pw-list--info">
                {result.recommendations.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </div>
          )}

          {result.weaknesses.length === 0 && result.recommendations.length === 0 && (
            <p className="pw-all-good">✅ No issues detected. Excellent password!</p>
          )}
        </div>
      )}
    </div>
  )
}

function Stat({ label, value }) {
  return (
    <div className="pw-stat">
      <span className="pw-stat-label">{label}</span>
      <span className="pw-stat-value">{value}</span>
    </div>
  )
}
