import { useState, useEffect } from "react"
import { sendToBackground } from "@plasmohq/messaging"

interface EndpointInfo {
  url: string
  method?: string
  type: 'api' | 'static' | 'page' | 'unknown'
  source: string
  line?: number
}

interface ScrapeResult {
  endpoints: EndpointInfo[]
  totalCount: number
  domain: string
}

function IndexPopup() {
  const [url, setUrl] = useState("")
  const [results, setResults] = useState<ScrapeResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [filter, setFilter] = useState<'all' | 'api' | 'static' | 'page' | 'unknown'>('all')

  const extractFromCurrentPage = async (): Promise<EndpointInfo[]> => {
    try {
      // Send message to content script to extract endpoints
      const response = await chrome.tabs.query({ active: true, currentWindow: true })
      if (response[0]?.id) {
        const result = await chrome.tabs.sendMessage(response[0].id, { action: 'extractEndpoints' })
        return result?.endpoints || []
      }
    } catch (error) {
      console.error('Content script extraction failed:', error)
    }
    return []
  }

  const handleScrape = async () => {
    if (!url.trim()) {
      setError("Please enter a URL")
      return
    }

    // Validate URL format
    try {
      new URL(url.trim())
    } catch {
      setError("Please enter a valid URL (e.g., https://example.com)")
      return
    }

    setLoading(true)
    setError("")
    setResults(null)

    try {
      const response = await sendToBackground({
        name: "scrape-website",
        body: { url: url.trim() }
      })

      if (response.error) {
        setError(`Error: ${response.error}`)
      } else {
        setResults(response)
      }
    } catch (err) {
      console.error('Scraping error:', err)
      
      // Try fallback method using content script if available
      try {
        const currentUrl = new URL(url.trim())
        if (window.location.hostname === currentUrl.hostname) {
          // We're on the same domain, try content script extraction
          const contentEndpoints = await extractFromCurrentPage()
          if (contentEndpoints.length > 0) {
            setResults({
              endpoints: contentEndpoints,
              totalCount: contentEndpoints.length,
              domain: currentUrl.hostname
            })
            setError("") // Clear error since we got some results
          } else {
            setError("Failed to scrape website. This might be due to CORS restrictions or the website blocking automated requests.")
          }
        } else {
          setError("Failed to scrape website. This might be due to CORS restrictions or the website blocking automated requests.")
        }
      } catch (fallbackErr) {
        console.error('Fallback error:', fallbackErr)
        setError("Failed to scrape website. This might be due to CORS restrictions or the website blocking automated requests.")
      }
    } finally {
      setLoading(false)
    }
  }

  const filteredEndpoints = results?.endpoints.filter(endpoint => 
    filter === 'all' || endpoint.type === filter
  ) || []

  const exportResults = (format: 'txt' | 'csv') => {
    if (!results) return

    let content = ""
    const headers = ["URL", "Type", "Method", "Source", "Line"]
    
    if (format === 'csv') {
      content = headers.join(",") + "\n"
      content += filteredEndpoints.map(endpoint => 
        `"${endpoint.url}","${endpoint.type}","${endpoint.method || 'N/A'}","${endpoint.source}","${endpoint.line || 'N/A'}"`
      ).join("\n")
    } else {
      content = `Endpoint Analysis Results\n`
      content += `Domain: ${results.domain}\n`
      content += `Total Endpoints: ${results.totalCount}\n`
      content += `Filtered Endpoints: ${filteredEndpoints.length}\n\n`
      
      filteredEndpoints.forEach(endpoint => {
        content += `URL: ${endpoint.url}\n`
        content += `Type: ${endpoint.type}\n`
        content += `Method: ${endpoint.method || 'N/A'}\n`
        content += `Source: ${endpoint.source}\n`
        content += `Line: ${endpoint.line || 'N/A'}\n`
        content += "---\n"
      })
    }

    const blob = new Blob([content], { type: format === 'csv' ? 'text/csv' : 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `endpoints-${results.domain}-${new Date().toISOString().split('T')[0]}.${format}`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{ 
      width: 500, 
      height: 600, 
      padding: 16,
      fontFamily: 'Arial, sans-serif',
      backgroundColor: '#f5f5f5'
    }}>
      <div style={{ marginBottom: 16 }}>
        <h2 style={{ margin: '0 0 16px 0', color: '#333' }}>
          Endpoint Scanner
        </h2>
        
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <input
            type="text"
            placeholder="Enter website URL (e.g., https://example.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            style={{
              flex: 1,
              padding: 8,
              border: '1px solid #ddd',
              borderRadius: 4,
              fontSize: 14
            }}
            onKeyPress={(e) => e.key === 'Enter' && handleScrape()}
          />
          <button
            onClick={handleScrape}
            disabled={loading}
            style={{
              padding: '8px 16px',
              backgroundColor: loading ? '#ccc' : '#007bff',
              color: 'white',
              border: 'none',
              borderRadius: 4,
              cursor: loading ? 'not-allowed' : 'pointer',
              fontSize: 14
            }}
          >
            {loading ? 'Scanning...' : 'Scan'}
          </button>
        </div>

        {error && (
          <div style={{
            padding: 8,
            backgroundColor: '#f8d7da',
            color: '#721c24',
            border: '1px solid #f5c6cb',
            borderRadius: 4,
            marginBottom: 16,
            fontSize: 14
          }}>
            {error}
          </div>
        )}

        {results && (
          <div style={{ marginBottom: 16 }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: 12
            }}>
              <div>
                <strong>Domain:</strong> {results.domain}<br/>
                <strong>Total Endpoints:</strong> {results.totalCount}
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  onClick={() => exportResults('txt')}
                  style={{
                    padding: '4px 8px',
                    backgroundColor: '#28a745',
                    color: 'white',
                    border: 'none',
                    borderRadius: 4,
                    cursor: 'pointer',
                    fontSize: 12
                  }}
                >
                  Export TXT
                </button>
                <button
                  onClick={() => exportResults('csv')}
                  style={{
                    padding: '4px 8px',
                    backgroundColor: '#17a2b8',
                    color: 'white',
                    border: 'none',
                    borderRadius: 4,
                    cursor: 'pointer',
                    fontSize: 12
                  }}
                >
                  Export CSV
                </button>
              </div>
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={{ marginRight: 8, fontSize: 14 }}>Filter:</label>
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value as any)}
                style={{
                  padding: 4,
                  border: '1px solid #ddd',
                  borderRadius: 4,
                  fontSize: 14
                }}
              >
                <option value="all">All ({filteredEndpoints.length})</option>
                <option value="api">API ({results.endpoints.filter(e => e.type === 'api').length})</option>
                <option value="page">Pages ({results.endpoints.filter(e => e.type === 'page').length})</option>
                <option value="static">Static ({results.endpoints.filter(e => e.type === 'static').length})</option>
                <option value="unknown">Unknown ({results.endpoints.filter(e => e.type === 'unknown').length})</option>
              </select>
            </div>
          </div>
        )}
      </div>

      <div style={{
        height: 400,
        overflowY: 'auto',
        border: '1px solid #ddd',
        borderRadius: 4,
        backgroundColor: 'white'
      }}>
        {loading && (
          <div style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            height: '100%',
            color: '#666'
          }}>
            Scanning website for endpoints...
          </div>
        )}

        {results && !loading && (
          <div style={{ padding: 8 }}>
            {filteredEndpoints.length === 0 ? (
              <div style={{ textAlign: 'center', color: '#666', padding: 20 }}>
                No endpoints found matching the current filter.
              </div>
            ) : (
              filteredEndpoints.map((endpoint, index) => (
                <div
                  key={index}
                  style={{
                    padding: 8,
                    borderBottom: '1px solid #eee',
                    fontSize: 13
                  }}
                >
                  <div style={{ marginBottom: 4 }}>
                    <strong style={{ color: '#007bff' }}>{endpoint.url}</strong>
                    {endpoint.method && (
                      <span style={{
                        marginLeft: 8,
                        padding: '2px 6px',
                        backgroundColor: '#e9ecef',
                        borderRadius: 3,
                        fontSize: 11
                      }}>
                        {endpoint.method}
                      </span>
                    )}
                    <span style={{
                      marginLeft: 8,
                      padding: '2px 6px',
                      backgroundColor: getTypeColor(endpoint.type),
                      color: 'white',
                      borderRadius: 3,
                      fontSize: 11
                    }}>
                      {endpoint.type.toUpperCase()}
                    </span>
                  </div>
                  <div style={{ color: '#666', fontSize: 11 }}>
                    Source: {endpoint.source}
                    {endpoint.line && ` • Line: ${endpoint.line}`}
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  )
}

const getTypeColor = (type: string): string => {
  switch (type) {
    case 'api': return '#dc3545'
    case 'page': return '#28a745'
    case 'static': return '#ffc107'
    case 'unknown': return '#6c757d'
    default: return '#6c757d'
  }
}

export default IndexPopup
