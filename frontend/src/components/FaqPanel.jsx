/**
 * FaqPanel — scrollable right-side FAQ sidebar for the AI Assistant page.
 *
 * Each FAQ item is an accordion: click the question to expand/collapse
 * the answer. Only one item is open at a time.
 */
import { useState } from 'react'
import './FaqPanel.css'

// ---------------------------------------------------------------------------
// FAQ data — standard cybersecurity topics relevant to AEGIS
// ---------------------------------------------------------------------------
const FAQ_SECTIONS = [
  {
    section: 'Phishing Defence',
    items: [
      {
        q: 'What is phishing?',
        a: 'Phishing is a social-engineering attack where an adversary impersonates a trusted entity — a bank, employer, or service — via email, SMS, or a fake website to trick you into handing over credentials or clicking a malicious link.',
      },
      {
        q: 'How do I recognise a phishing email?',
        a: 'Look for mismatched sender domains (e.g. support@paypa1.com), unexpected urgency ("act now or your account will be closed"), suspicious links that differ from the displayed text, and generic greetings like "Dear Customer".',
      },
      {
        q: 'What should I do if I clicked a suspicious link?',
        a: 'Disconnect from the internet immediately if you suspect malware. Change passwords for any accounts you visited. Run an antivirus scan. Report the incident to your IT team or email provider.',
      },
      {
        q: 'How does email spoofing work?',
        a: 'Attackers manipulate the From: header so it shows a trusted address while the actual sending server is unrelated. DMARC, DKIM, and SPF records allow mail servers to verify sender authenticity and reject spoofed messages.',
      },
      {
        q: 'What is spear phishing?',
        a: 'Spear phishing targets a specific individual or organisation using personalised information (job title, recent activity, colleague names) to make the attack far more convincing than generic phishing emails.',
      },
    ],
  },
  {
    section: 'Password Safety',
    items: [
      {
        q: 'What makes a password strong?',
        a: 'Length is the most important factor. A 16-character passphrase of random words is far stronger than a short but "complex" password. Avoid dictionary words, names, and reused passwords across sites.',
      },
      {
        q: 'Should I use a password manager?',
        a: 'Yes. Password managers generate and store unique, high-entropy passwords for every site. You only need to remember one strong master password. Reputable options include Bitwarden, 1Password, and KeePassXC.',
      },
      {
        q: 'How do brute-force attacks work?',
        a: 'Attackers systematically try every possible combination of characters. A 6-character password can be cracked in seconds; a 16-character random password would take billions of years with current hardware.',
      },
      {
        q: 'What is multi-factor authentication (MFA)?',
        a: 'MFA requires a second proof of identity beyond your password — typically a time-based one-time code (TOTP) from an authenticator app. Even if your password is stolen, MFA prevents unauthorised access.',
      },
      {
        q: 'What is credential stuffing?',
        a: 'Attackers take username/password pairs leaked from one data breach and automatically try them on other services. This works because many people reuse passwords. Using a unique password everywhere eliminates this risk.',
      },
    ],
  },
  {
    section: 'URL & Link Scanning',
    items: [
      {
        q: 'What makes a URL suspicious?',
        a: 'Red flags include IP addresses instead of domain names, excessive subdomains, lookalike domains (paypa1.com vs paypal.com), unusual TLDs (.xyz, .tk), URL shorteners hiding the destination, and mismatched link text vs href.',
      },
      {
        q: 'How do URL shorteners hide malicious links?',
        a: 'Shorteners (bit.ly, tinyurl.com) replace a long URL with a short opaque one. Attackers use them to hide malicious destinations. You can preview shortened URLs by appending "+" to the URL on many services.',
      },
      {
        q: 'What is typosquatting?',
        a: 'Typosquatting registers domains nearly identical to popular sites (googel.com, micros0ft.com) to capture users who mistype a URL or click without checking carefully. Always verify the full domain in the address bar.',
      },
      {
        q: 'Is HTTPS always safe?',
        a: 'HTTPS means the connection is encrypted — not that the site is legitimate. Phishing sites commonly use HTTPS certificates because they are free and easy to obtain. Always verify the domain, not just the padlock icon.',
      },
    ],
  },
  {
    section: 'AEGIS Features',
    items: [
      {
        q: 'What does the AEGIS risk score mean?',
        a: 'The risk score (0–100) is calculated from weighted heuristic checks. 0–29 is low risk, 30–59 is medium, 60–79 is high, and 80+ is critical. A higher score means more suspicious signals were detected.',
      },
      {
        q: 'How accurate is the URL analyser?',
        a: 'AEGIS uses 30+ heuristic checks covering domain age, entropy, brand impersonation, suspicious patterns, and more. Heuristics cannot guarantee 100% accuracy — always treat high-risk results as a strong warning, not a definitive verdict.',
      },
      {
        q: 'Does AEGIS store my passwords?',
        a: 'No. The password analyser measures strength locally — your password is never stored or logged by AEGIS after the analysis completes. Never paste a real password into any system you do not fully trust.',
      },
      {
        q: 'What is the AI assistant used for?',
        a: 'The AI assistant answers cybersecurity questions, explains scan results in plain language, and suggests defensive actions. It is advisory only — it cannot execute commands, access external systems, or take actions on your behalf.',
      },
    ],
  },
]

// ---------------------------------------------------------------------------
// FaqItem — single accordion row
// ---------------------------------------------------------------------------
function FaqItem({ item, isOpen, onToggle }) {
  return (
    <div className={`faq-item ${isOpen ? 'faq-item--open' : ''}`}>
      <button
        className="faq-question"
        type="button"
        aria-expanded={isOpen}
        onClick={onToggle}
      >
        <span className="faq-question-text">{item.q}</span>
        <span className="faq-chevron" aria-hidden="true">
          {isOpen ? '▲' : '▼'}
        </span>
      </button>
      {isOpen && (
        <div className="faq-answer" role="region">
          <p>{item.a}</p>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// FaqSection — a labelled group of accordion items
// ---------------------------------------------------------------------------
function FaqSection({ section, openKey, onToggle }) {
  return (
    <div className="faq-section">
      <h3 className="faq-section-title">{section.section}</h3>
      {section.items.map((item, i) => {
        const key = `${section.section}::${i}`
        return (
          <FaqItem
            key={key}
            item={item}
            isOpen={openKey === key}
            onToggle={() => onToggle(key)}
          />
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// FaqPanel — exported component
// ---------------------------------------------------------------------------
export default function FaqPanel() {
  // Track which single item is open; null = all collapsed
  const [openKey, setOpenKey] = useState(null)

  function handleToggle(key) {
    setOpenKey(prev => (prev === key ? null : key))
  }

  return (
    <aside className="faq-panel" aria-label="Frequently asked questions">
      <div className="faq-panel-header">
        <h2 className="faq-panel-title">
          <span aria-hidden="true">📖</span> FAQ
        </h2>
        <p className="faq-panel-sub">Common cybersecurity questions</p>
      </div>
      <div className="faq-panel-body">
        {FAQ_SECTIONS.map(section => (
          <FaqSection
            key={section.section}
            section={section}
            openKey={openKey}
            onToggle={handleToggle}
          />
        ))}
      </div>
    </aside>
  )
}
