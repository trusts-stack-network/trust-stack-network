import { useState, useEffect } from 'react'
import { Link, useParams } from 'react-router-dom'
import './Docs.css'

interface DocPage {
  path: string
  title: string
  description: string
  icon: string
}

const DOC_PAGES: DocPage[] = [
  {
    path: 'index',
    title: 'Guide Utilisateur',
    description: 'Vue d\'ensemble complète de Trust Stack Network',
    icon: '📖'
  },
  {
    path: 'getting-started',
    title: 'Premiers Pas',
    description: 'Guide débutant — votre première transaction TSN en 10 minutes',
    icon: '🚀'
  },
  {
    path: 'node',
    title: 'Déployer un Node',
    description: 'Installation et configuration d\'un nœud TSN',
    icon: '🏗️'
  },
  {
    path: 'mining',
    title: 'Guide Mining',
    description: 'Miner des TSN — configuration, optimisation, récompenses',
    icon: '⛏️'
  },
  {
    path: 'wallet',
    title: 'Wallet Guide',
    description: 'Gestion sécurisée de vos TSN',
    icon: '💼'
  },
  {
    path: 'api',
    title: 'API Reference',
    description: 'Documentation développeur — intégrer TSN dans vos apps',
    icon: '🔧'
  },
  {
    path: 'security',
    title: 'Sécurité',
    description: 'Guide sécurité et bonnes pratiques post-quantiques',
    icon: '🔒'
  },
  {
    path: 'troubleshooting',
    title: 'Troubleshooting',
    description: 'Solutions aux problèmes courants',
    icon: '⚡'
  }
]

export default function Docs() {
  const { section = 'index' } = useParams()
  const [content, setContent] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const currentDoc = DOC_PAGES.find(doc => doc.path === section) || DOC_PAGES[0]

  useEffect(() => {
    const loadDoc = async () => {
      setLoading(true)
      setError(null)

      try {
        const response = await fetch(`/docs/${section}.md`)
        if (!response.ok) {
          throw new Error(`Documentation non trouvée: ${section}`)
        }
        const text = await response.text()
        setContent(text)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Erreur de chargement')
        setContent('')
      } finally {
        setLoading(false)
      }
    }

    loadDoc()
  }, [section])

  // Convert Markdown to basic HTML for display
  const renderMarkdown = (markdown: string): string => {
    return markdown
      // Headers
      .replace(/^### (.*$)/gim, '<h3>$1</h3>')
      .replace(/^## (.*$)/gim, '<h2>$1</h2>')
      .replace(/^# (.*$)/gim, '<h1>$1</h1>')
      // Bold
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      // Italic
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      // Code blocks
      .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
      // Inline code
      .replace(/`(.*?)`/g, '<code>$1</code>')
      // Links
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
      // Line breaks
      .replace(/\n/g, '<br/>')
      // Tables (basic)
      .replace(/\|(.+)\|/g, (match, content) => {
        const cells = content.split('|').map((cell: string) => `<td>${cell.trim()}</td>`).join('')
        return `<tr>${cells}</tr>`
      })
  }

  return (
    <div className="docs">
      {/* Header with navigation back to wallet */}
      <header className="docs-header">
        <div className="docs-nav">
          <Link to="/" className="back-link">
            ← Accueil TSN
          </Link>
          <div className="docs-title">
            <h1>📚 Documentation TSN</h1>
            <p>Guide complet de Trust Stack Network</p>
          </div>
          <Link to="/wallet" className="wallet-link">
            Ouvrir Wallet →
          </Link>
        </div>
      </header>

      <div className="docs-container">
        {/* Sidebar Navigation */}
        <nav className="docs-sidebar">
          <div className="docs-menu">
            <h3>📖 Guides</h3>
            {DOC_PAGES.map(doc => (
              <Link
                key={doc.path}
                to={`/docs/${doc.path}`}
                className={`docs-menu-item ${section === doc.path ? 'active' : ''}`}
              >
                <span className="docs-icon">{doc.icon}</span>
                <div>
                  <span className="docs-menu-title">{doc.title}</span>
                  <span className="docs-menu-desc">{doc.description}</span>
                </div>
              </Link>
            ))}
          </div>

          {/* Quick Stats */}
          <div className="docs-stats">
            <h4>⚡ Réseau TSN</h4>
            <div className="stat-item">
              <span className="stat-label">Version</span>
              <span className="stat-value">v0.4.0</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Crypto</span>
              <span className="stat-value">ML-DSA-65 + Plonky3</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Temps bloc</span>
              <span className="stat-value">~10 sec</span>
            </div>
          </div>

          {/* Community Links */}
          <div className="docs-community">
            <h4>🤝 Communauté</h4>
            <a href="https://discord.gg/truststack" className="community-link" target="_blank" rel="noopener noreferrer">
              Discord
            </a>
            <a href="https://github.com/Trust-Stack-Network/tsn" className="community-link" target="_blank" rel="noopener noreferrer">
              GitHub
            </a>
            <a href="/whitepaper" className="community-link" target="_blank" rel="noopener noreferrer">
              Whitepaper
            </a>
          </div>
        </nav>

        {/* Main Content */}
        <main className="docs-content">
          <div className="docs-page-header">
            <h1>
              <span className="docs-page-icon">{currentDoc.icon}</span>
              {currentDoc.title}
            </h1>
            <p className="docs-page-description">{currentDoc.description}</p>
          </div>

          <div className="docs-body">
            {loading && (
              <div className="docs-loading">
                <div className="loading-spinner">◐</div>
                <p>Chargement de la documentation...</p>
              </div>
            )}

            {error && (
              <div className="docs-error">
                <h3>⚠️ Erreur de chargement</h3>
                <p>{error}</p>
                <Link to="/docs" className="error-link">
                  ← Retour à l'accueil docs
                </Link>
              </div>
            )}

            {!loading && !error && content && (
              <div
                className="docs-markdown"
                dangerouslySetInnerHTML={{ __html: renderMarkdown(content) }}
              />
            )}
          </div>

          {/* Navigation Footer */}
          <footer className="docs-footer">
            <div className="docs-nav-footer">
              {section !== 'index' && (
                <Link to="/docs" className="nav-footer-link">
                  ← Guide principal
                </Link>
              )}
              <div className="nav-footer-center">
                <p>Trust Stack Network • Documentation v0.4.0</p>
              </div>
              <a href="https://discord.gg/truststack" className="nav-footer-link" target="_blank" rel="noopener noreferrer">
                Support Discord →
              </a>
            </div>
          </footer>
        </main>
      </div>
    </div>
  )
}