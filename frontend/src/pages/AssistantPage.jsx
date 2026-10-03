import { useState, useRef, useEffect, useCallback } from 'react'
import { assistant } from '../services/api'
import './AssistantPage.css'

// ---------------------------------------------------------------------------
// Error code → user-friendly message mapping
// ---------------------------------------------------------------------------
const ERROR_MESSAGES = {
  not_configured: 'AI assistant is not configured (API key missing). Scan results still work normally.',
  init_failed:    'AI assistant failed to initialise. Please contact your administrator.',
  timeout:        'AI assistant timed out. Please try again — this is usually temporary.',
  api_error:      'AI service returned an error. Please wait a moment and try again.',
  empty_response: 'AI returned an empty response. Try rephrasing your question.',
}

function errorMessage(code) {
  return ERROR_MESSAGES[code] ?? 'AI assistant is temporarily unavailable.'
}

// Transient errors that make sense to retry
const RETRYABLE = new Set(['timeout', 'api_error', 'empty_response'])
const SUGGESTIONS = [
  'What is phishing and how do I spot it?',
  'Why is a long password better than a complex short one?',
  'What does a high-entropy URL mean?',
  'How do I know if an email sender is spoofed?',
  'What should I do if I clicked a suspicious link?',
  'What makes a password strong?',
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function timestamp() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function makeUserMsg(text) {
  return { id: crypto.randomUUID(), role: 'user', content: text, time: timestamp() }
}

function makeAssistantMsg(text, aiAvailable = true, error = null) {
  return {
    id: crypto.randomUUID(),
    role: 'assistant',
    content: text,
    aiAvailable,
    error,
    time: timestamp(),
  }
}

// ---------------------------------------------------------------------------
// Message bubble
// ---------------------------------------------------------------------------

function MessageBubble({ msg }) {
  const isUser = msg.role === 'user'
  const isError = msg.role === 'assistant' && !msg.aiAvailable

  return (
    <div
      className={
        `chat-msg ${isUser ? 'chat-msg--user' : isError ? 'chat-msg--error' : 'chat-msg--assistant'}`
      }
      role="listitem"
    >
      <div className="chat-avatar" aria-hidden="true">
        {isUser ? '👤' : '🤖'}
      </div>
      <div className="chat-msg-body">
        <p className="chat-msg-text">{msg.content}</p>
        <span className="chat-msg-meta">
          {msg.time}
          {msg.role === 'assistant' && !msg.aiAvailable && (
            <span className="chat-fallback-badge">offline</span>
          )}
        </span>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Typing indicator
// ---------------------------------------------------------------------------

function TypingIndicator() {
  return (
    <div className="chat-typing" role="status" aria-label="Assistant is typing">
      <div className="chat-avatar" aria-hidden="true">🤖</div>
      <div className="chat-typing-dots" aria-hidden="true">
        <span /><span /><span />
      </div>
      <span className="chat-typing-label">Thinking…</span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function AssistantPage() {
  const [messages,  setMessages]  = useState([])
  const [input,     setInput]     = useState('')
  const [loading,   setLoading]   = useState(false)
  const [banner,    setBanner]    = useState(null)  // { type, text, retryMsg? }
  const [lastMsg,   setLastMsg]   = useState(null)  // for retry
  const bottomRef   = useRef(null)
  const inputRef    = useRef(null)

  // Check AI availability on mount — show upfront banner if not ready
  useEffect(() => {
    assistant.status()
      .then(data => {
        if (!data.available) {
          setBanner({
            type: 'warn',
            text: errorMessage(data.error_code),
          })
        }
      })
      .catch(() => {
        // Status check failed (network error, auth error) — don't block UI
      })
  }, [])

  // Auto-scroll to bottom whenever messages change
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  // Build conversation history for the API (role + content only, no UI fields)
  const buildHistory = useCallback((msgs) => {
    return msgs.map(m => ({ role: m.role, content: m.content }))
  }, [])

  const sendMessage = useCallback(async (text) => {
    const trimmed = text.trim()
    if (!trimmed || loading) return

    setBanner(null)
    setLastMsg(trimmed)
    const userMsg = makeUserMsg(trimmed)
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const history = buildHistory(messages)
      const data = await assistant.chat(trimmed, history, null)

      setMessages(prev => [
        ...prev,
        makeAssistantMsg(data.reply, data.ai_available, data.error ?? null),
      ])

      // Surface a non-blocking warning for fallback responses
      if (!data.ai_available) {
        const code = data.error ?? ''
        const isRetryable = RETRYABLE.has(code)
        setBanner({
          type: 'warn',
          text: errorMessage(code),
          retryable: isRetryable,
        })
      }
    } catch (err) {
      const msg = err.message ?? 'Something went wrong.'
      if (msg.includes('rate limit') || msg.includes('429')) {
        // Rate limit — banner only, the user message stays visible
        setBanner({
          type: 'error',
          text: 'Rate limit reached. Please wait a moment before sending another message.',
          retryable: false,
        })
      } else if (msg.includes('Session expired')) {
        // Auth error handled by api.js redirect — nothing extra needed
      } else {
        // Network or unexpected error — inline message with retry option
        setBanner({
          type: 'error',
          text: `Request failed: ${msg}`,
          retryable: true,
        })
      }
    } finally {
      setLoading(false)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [loading, messages, buildHistory])

  function handleRetry() {
    if (!lastMsg) return
    // Remove the last user message so it doesn't duplicate on retry
    setMessages(prev => {
      const idx = [...prev].reverse().findIndex(m => m.role === 'user')
      if (idx === -1) return prev
      const realIdx = prev.length - 1 - idx
      return prev.slice(0, realIdx)
    })
    setBanner(null)
    sendMessage(lastMsg)
  }

  function handleSubmit(e) {
    e.preventDefault()
    sendMessage(input)
  }

  function handleKeyDown(e) {
    // Send on Enter (without Shift)
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage(input)
    }
  }

  function handleClear() {
    setMessages([])
    setInput('')
    setBanner(null)
    inputRef.current?.focus()
  }

  const canSend = input.trim().length > 0 && !loading

  return (
    <div className="chat-page">
      {/* Header */}
      <div className="chat-header">
        <h2 className="chat-heading">AI Security Assistant</h2>
        <p className="chat-sub">
          Ask cybersecurity questions or get explanations for your scan results.
        </p>
        <p className="chat-caveat">
          Advisory only — cannot access external systems or execute actions.
          AI responses may contain errors; always verify important information.
        </p>
      </div>

      {/* Message list */}
      <div
        className="chat-messages"
        role="list"
        aria-label="Conversation"
        aria-live="polite"
      >
        {messages.length === 0 && !loading ? (
          /* Empty state with suggestions */
          <div className="chat-empty">
            <span className="chat-empty-icon">🤖</span>
            <p className="chat-empty-title">AEGIS Security Assistant</p>
            <p className="chat-empty-desc">
              Ask about cybersecurity concepts, threats, best practices, or
              paste in the details of a scan result to get an explanation.
            </p>
            <div className="chat-suggestions">
              {SUGGESTIONS.map((s, i) => (
                <button
                  key={i}
                  className="chat-suggestion"
                  type="button"
                  onClick={() => sendMessage(s)}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <>
            {messages.map(msg => (
              <MessageBubble key={msg.id} msg={msg} />
            ))}
            {loading && <TypingIndicator />}
          </>
        )}
        <div ref={bottomRef} aria-hidden="true" />
      </div>

      {/* Banners */}
      {banner && (
        <div className={`chat-banner chat-banner--${banner.type}`} role="alert">
          <span>{banner.text}</span>
          {banner.retryable && lastMsg && !loading && (
            <button
              type="button"
              className="chat-banner-retry"
              onClick={handleRetry}
            >
              Retry
            </button>
          )}
        </div>
      )}

      {/* Input area */}
      <form className="chat-input-area" onSubmit={handleSubmit}>
        <div className="chat-input-row">
          <textarea
            ref={inputRef}
            className="chat-input"
            value={input}
            onChange={e => { setInput(e.target.value); setBanner(null) }}
            onKeyDown={handleKeyDown}
            placeholder="Ask a cybersecurity question…"
            rows={1}
            aria-label="Message input"
            disabled={loading}
            spellCheck={true}
            autoFocus
          />
          <button
            className="chat-send-btn"
            type="submit"
            disabled={!canSend}
            aria-label="Send message"
          >
            {loading ? '…' : 'Send'}
          </button>
        </div>
        <div className="chat-input-footer">
          <span className="chat-input-hint">
            Enter to send · Shift+Enter for new line
          </span>
          {messages.length > 0 && (
            <button type="button" className="chat-clear-btn" onClick={handleClear}>
              Clear conversation
            </button>
          )}
        </div>
      </form>
    </div>
  )
}
