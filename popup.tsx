import { useState, useEffect } from "react"
import { sendToBackground } from "@plasmohq/messaging"
import { buildLfiPayloadList } from "./lfiPayloads"

// ---------- Type Definitions ----------
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

interface LfiSingleResult {
  parameter: string
  originalValue: string | null
  testedUrl: string
  payload: string
  status: number
  contentLength: number
  indicators: string[]
  vulnerable: boolean
  detection: 'CONFIRMED_LFI' | 'POSSIBLE_LFI' | 'SUSPICIOUS' | 'NOT_VULNERABLE'
  confidence: 'Low' | 'Medium' | 'High'
  sample?: string
}

interface LfiScanSummary {
  baseUrl: string
  parametersTested: {
    name: string
    originalValue: string | null
    totalTests: number
    vulnerableCount: number
  }[]
  totalTests: number
  vulnerableCount: number
  results: LfiSingleResult[]
}

// ---------- Helper Functions ----------
const getTypeColor = (type: string): string => {
  switch (type) {
    case 'api': return '#dc3545'
    case 'page': return '#28a745'
    case 'static': return '#ffc107'
    case 'unknown': return '#6c757d'
    default: return '#6c757d'
  }
}

const buildLfiTestUrls = (baseUrl: string, param: string, payloads: string[]): { url: string, payload: string }[] => {
  const u = new URL(baseUrl)
  const hasParam = Array.from(u.searchParams.keys()).includes(param)
  return payloads.map(p => {
    const test = new URL(u.toString())
    if (hasParam) {
      test.searchParams.set(param, p)
    } else {
      test.searchParams.append(param, p)
    }
    return { url: test.toString(), payload: p }
  })
}

const fetchWithTimeout = async (input: RequestInfo | URL, ms: number): Promise<Response> => {
  const controller = new AbortController()
  const id = setTimeout(() => controller.abort(), ms)
  try {
    const res = await fetch(input, { signal: controller.signal as AbortSignal })
    return res
  } finally {
    clearTimeout(id)
  }
}

const safeReadText = async (res: Response): Promise<string> => {
  try {
    return await res.text()
  } catch {
    return ''
  }
}

const detectLfiIndicators = (body: string): string[] => {
  const indicators: { label: string, regex: RegExp }[] = [
    // Linux passwd / shells
    { label: 'etc/passwd', regex: /root:x:0:0:|:\/bin\/(bash|sh|csh|zsh)|daemon:x:/i },
    { label: 'etc/shadow', regex: /root:.*:1[0-9]{4,}:/i },
    { label: 'Unix hosts file', regex: /127\.0\.0\.1\s+localhost|::1\s+localhost/i },
    { label: 'proc/environ', regex: /PATH=|HOME=|SHELL=|USER=|PWD=/i },
    { label: 'proc/version', regex: /Linux version \d+\.\d+\.\d+/i },
    // Windows INI files
    { label: 'Windows win.ini', regex: /\[fonts\]|\[extensions\]|\[mci extensions\]|\[drivers\]|for 16-bit app support/i },
    { label: 'Windows boot.ini', regex: /\[boot loader\]|\[operating systems\]|multi\(0\)disk/i },
    { label: 'Windows hosts', regex: /127\.0\.0\.1\s+localhost.*::1/i },
    { label: 'PHP source', regex: /<\?php|<\?=|phpinfo\(\)|echo\s+\$_/i },
    { label: 'Apache config', regex: /<Directory|LoadModule|ServerRoot/i },
    { label: 'SSH config', regex: /Host \*|IdentityFile|UserKnownHostsFile/i },
    { label: 'MySQL config', regex: /\[mysqld\]|\[client\]|datadir=/i },
    { label: 'Bash history', regex: /^#\d{10}$|^ls\s|^cd\s|^cat\s/i },
    { label: 'Error disclosure', regex: /Warning:.*include|Failed opening.*for inclusion|No such file or directory/i }
  ]
  const hits: string[] = []
  for (const i of indicators) {
    if (i.regex.test(body)) hits.push(i.label)
  }
  return hits
}

const analyzeLfiHeuristics = (
  indicators: string[],
  baselineStatus: number | null,
  baselineLength: number | null,
  status: number,
  length: number
): { detection: LfiSingleResult['detection'], confidence: LfiSingleResult['confidence'] } => {
  // 1) Known file indicators present → CONFIRMED LFI
  if (indicators.length > 0) {
    return { detection: 'CONFIRMED_LFI', confidence: 'High' }
  }

  // 2) Response length changes significantly (>30%) → POSSIBLE LFI
  if (baselineLength !== null && baselineLength > 0) {
    const diffRatio = Math.abs(length - baselineLength) / baselineLength
    if (diffRatio > 0.3) {
      return { detection: 'POSSIBLE_LFI', confidence: 'Medium' }
    }
  }

  // 3) Status code changes from baseline → SUSPICIOUS
  if (baselineStatus !== null && baselineStatus !== status) {
    return { detection: 'SUSPICIOUS', confidence: 'Low' }
  }

  // 4) Else → NOT VULNERABLE
  return { detection: 'NOT_VULNERABLE', confidence: 'Low' }
}

// ---------- Main Component ----------
function IndexPopup() {
  const [url, setUrl] = useState("")
  const [results, setResults] = useState<ScrapeResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [filter, setFilter] = useState<'all' | 'api' | 'static' | 'page' | 'unknown'>('all')

  // LFI Scanner state
  const [lfiUrl, setLfiUrl] = useState("")
  const [lfiParam, setLfiParam] = useState("file")
  const [lfiLoading, setLfiLoading] = useState(false)
  const [lfiResults, setLfiResults] = useState<LfiScanSummary | null>(null)
  const [expandedParams, setExpandedParams] = useState<Record<string, boolean>>({})
  const [showLfiDetails, setShowLfiDetails] = useState<boolean>(true)
  const [wordlist, setWordlist] = useState<string[]>([])
  const [wordlistLoading, setWordlistLoading] = useState(true)
  const [payloadCap, setPayloadCap] = useState<number>(500)
  const [currentProgress, setCurrentProgress] = useState({ current: 0, total: 0 })

  // Load SecLists wordlist on mount
  useEffect(() => {
    const loadWordlist = async () => {
      try {
        setWordlistLoading(true)
        // Start with our categorized, locally-defined payloads
        const basePayloads = buildLfiPayloadList()

        const response = await fetch('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt')
        if (!response.ok) throw new Error('Failed to fetch wordlist')
        const text = await response.text()
        const payloads = text
          .split(/\r?\n/)
          .map(line => line.trim())
          .filter(line => line && !line.startsWith('#') && line.length > 0)

        // Combine categorized payloads with SecLists for broader coverage
        const combined = Array.from(new Set([...basePayloads, ...payloads]))
        setWordlist(combined)
      } catch (err) {
        console.error('Failed to load wordlist:', err)
        // Fallback to categorized, local payloads
        setWordlist(buildLfiPayloadList())
      } finally {
        setWordlistLoading(false)
      }
    }
    loadWordlist()
  }, [])

  const sendToBackgroundWithRetry = async <T = any>(message: { name: string, body?: any }, retries = 1): Promise<T> => {
    try {
      return await sendToBackground(message as any)
    } catch (e: any) {
      const msg = String(e?.message || e)
      if (retries > 0 && /context invalidated/i.test(msg)) {
        // Wait briefly and retry to re-wake service worker
        await new Promise(r => setTimeout(r, 100))
        return await sendToBackgroundWithRetry<T>(message, retries - 1)
      }
      throw e
    }
  }

  const sendContentMessageWithRetry = async <T = any>(tabId: number, payload: any, retries = 1): Promise<T> => {
    try {
      return await chrome.tabs.sendMessage(tabId, payload)
    } catch (e: any) {
      const msg = String(e?.message || e)
      if (retries > 0 && /context invalidated|Receiving end does not exist/i.test(msg)) {
        await new Promise(r => setTimeout(r, 150))
        return await sendContentMessageWithRetry<T>(tabId, payload, retries - 1)
      }
      throw e
    }
  }

  const extractFromCurrentPage = async (): Promise<EndpointInfo[]> => {
    try {
      // Send message to content script to extract endpoints
      const response = await chrome.tabs.query({ active: true, currentWindow: true })
      if (response[0]?.id) {
        const result = await sendContentMessageWithRetry(response[0].id, { action: 'extractEndpoints' })
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
      const response = await sendToBackgroundWithRetry({
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

  const handleRunLfi = async () => {
    const targetUrl = (lfiUrl.trim() || url.trim())
    if (!targetUrl) {
      setError("Enter a URL for LFI scan or run endpoint scan first")
      return
    }

    let parsedUrl: URL
    try {
      parsedUrl = new URL(targetUrl)
    } catch {
      setError("Please enter a valid URL (e.g., https://example.com)")
      return
    }

    if (wordlist.length === 0) {
      setError("Wordlist not loaded yet. Please wait...")
      return
    }

    setError("")
    setLfiLoading(true)
    setLfiResults(null)

    // Discover parameters from URL (ignore empty names)
    const discoveredParams = Array.from(parsedUrl.searchParams.keys())
      .map((name) => name.trim())
      .filter((name) => name.length > 0)
    const uniqueDiscoveredParams = Array.from(new Set(discoveredParams))

    let paramsToTest: string[]
    if (lfiParam.trim()) {
      // User explicitly specified a parameter – only test that one
      paramsToTest = [lfiParam.trim()]
    } else {
      // Auto-discover all parameters from the URL
      paramsToTest = uniqueDiscoveredParams
    }

    if (paramsToTest.length === 0) {
      setError("No query parameters found to test for LFI. Add parameters to the URL or specify a parameter name.")
      setLfiLoading(false)
      setCurrentProgress({ current: 0, total: 0 })
      return
    }

    // Store original value for each parameter (may be null if it doesn't exist on URL)
    const originalValues = new Map<string, string | null>()
    for (const name of paramsToTest) {
      originalValues.set(name, parsedUrl.searchParams.get(name))
    }

    // Use SecLists + categorized payloads wordlist
    const payloadList = wordlist.slice(0, payloadCap)

    try {
      const results: LfiSingleResult[] = []
      const perParameterSummary: {
        name: string
        originalValue: string | null
        totalTests: number
        vulnerableCount: number
      }[] = []

      const total = paramsToTest.length * payloadList.length
      let currentIndex = 0

      // Establish a baseline response for heuristics (original URL)
      let baselineStatus: number | null = null
      let baselineLength: number | null = null
      try {
        const baselineRes = await fetchWithTimeout(targetUrl, 8000)
        const baselineBody = baselineRes.ok ? await safeReadText(baselineRes) : ""
        baselineStatus = baselineRes.status
        baselineLength = baselineBody.length
      } catch (baselineErr) {
        console.warn(`Failed to fetch baseline for ${targetUrl}:`, baselineErr)
      }

      for (const paramName of paramsToTest) {
        const testUrls = buildLfiTestUrls(targetUrl, paramName, payloadList)
        let paramVulnerableCount = 0

        for (let i = 0; i < testUrls.length; i++) {
          const { url: testUrl, payload } = testUrls[i]
          currentIndex += 1
          setCurrentProgress({ current: currentIndex, total })

          try {
            const res = await fetchWithTimeout(testUrl, 8000)
            const bodyText = res.ok ? await safeReadText(res) : ""
            const indicators = detectLfiIndicators(bodyText)

            const { detection, confidence } = analyzeLfiHeuristics(
              indicators,
              baselineStatus,
              baselineLength,
              res.status,
              bodyText.length
            )
            const vulnerable = detection !== 'NOT_VULNERABLE'

            if (vulnerable) {
              paramVulnerableCount += 1
            }

            // Record every response with its heuristic classification
            results.push({
              parameter: paramName,
              originalValue: originalValues.get(paramName) ?? null,
              testedUrl: testUrl,
              payload,
              status: res.status,
              contentLength: bodyText.length,
              indicators,
              vulnerable,
              detection,
              confidence,
              sample: bodyText.slice(0, 300)
            })
          } catch (fetchErr) {
            // Skip failed requests, continue scanning
            console.warn(`Failed to test ${testUrl}:`, fetchErr)
          }
        }

        perParameterSummary.push({
          name: paramName,
          originalValue: originalValues.get(paramName) ?? null,
          totalTests: testUrls.length,
          vulnerableCount: paramVulnerableCount
        })
      }

      const summary: LfiScanSummary = {
        baseUrl: targetUrl,
        parametersTested: perParameterSummary,
        totalTests: total,
        vulnerableCount: results.filter(r => r.vulnerable).length,
        results
      }
      setLfiResults(summary)
      setCurrentProgress({ current: 0, total: 0 })
    } catch (e: any) {
      setError(`LFI scan failed: ${e?.message || e}`)
      setCurrentProgress({ current: 0, total: 0 })
    } finally {
      setLfiLoading(false)
    }
  }

  const exportLfiResults = (format: 'txt' | 'csv') => {
    if (!lfiResults) return

    if (format === 'csv') {
      const headers = [
        'Parameter',
        'Original Value',
        'Detection',
        'Confidence',
        'Payload',
        'Indicators',
        'Status',
        'Content Length',
        'Tested URL'
      ]
      const rows = lfiResults.results.map(r => ([
        r.parameter,
        r.originalValue ?? '',
        r.detection,
        r.confidence,
        r.payload,
        r.indicators.join('; '),
        String(r.status),
        String(r.contentLength),
        r.testedUrl
      ]))

      const csv = [
        headers.join(','),
        ...rows.map(row => row.map(value => `"${String(value).replace(/"/g, '""')}"`).join(','))
      ].join('\n')

      const blob = new Blob([csv], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `lfi-results-${new Date().toISOString().split('T')[0]}.csv`
      a.click()
      URL.revokeObjectURL(url)
      return
    }

    // TXT export (human readable, similar to endpoint TXT export)
    const lines: string[] = []
    lines.push("LFI Scan Results")
    lines.push(`Target: ${lfiResults.baseUrl}`)
    if (lfiResults.parametersTested && lfiResults.parametersTested.length > 0) {
      const paramsSummary = lfiResults.parametersTested
        .map(p => p.originalValue !== null ? `${p.name} (original: ${p.originalValue})` : p.name)
        .join(", ")
      lines.push(`Parameters Tested: ${paramsSummary}`)
    }
    lines.push(`Total Tests: ${lfiResults.totalTests}`)
    lines.push(`Vulnerable Findings (non-NOT_VULNERABLE): ${lfiResults.vulnerableCount}`)
    lines.push("---")
    for (const r of lfiResults.results) {
      lines.push(`Parameter: ${r.parameter}`)
      if (r.originalValue !== null) {
        lines.push(`Original Value: ${r.originalValue}`)
      }
      lines.push(`Detection: ${r.detection} (confidence: ${r.confidence})`)
      lines.push(`Payload: ${r.payload}`)
      lines.push(`Status: ${r.status}`)
      lines.push(`Content Length: ${r.contentLength}`)
      lines.push(`Indicators: ${r.indicators.join(', ') || 'None'}`)
      lines.push(`Tested URL: ${r.testedUrl}`)
      if (r.sample) {
        lines.push(`Sample: ${r.sample.replace(/\n/g, ' ')}`)
      }
      lines.push("---")
    }
    const blob = new Blob([lines.join("\n")], { type: 'text/plain' })
    const link = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = link
    a.download = `lfi-results-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`
    a.click()
    URL.revokeObjectURL(link)
  }

  return (
    <div style={{ 
      width: 580, 
      maxHeight: 750,
      height: 'auto',
      padding: 16,
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      background: 'linear-gradient(135deg, #eff3ff 0%, #f8f9ff 100%)',
      overflowY: 'auto'
    }}>
      <div style={{ marginBottom: 16 }}>
        <h2 style={{ margin: '0 0 4px 0', color: '#222' }}>Security Toolkit</h2>
        <div style={{ color: '#666', fontSize: 12, marginBottom: 12 }}>Scan endpoints and test for LFI vulnerabilities</div>
        <div style={{ 
          background: 'white', 
          border: '1px solid #e9edf5', 
          borderRadius: 8, 
          padding: 12,
          boxShadow: '0 2px 6px rgba(0,0,0,0.04)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
            <div style={{
              background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              color: 'white',
              fontWeight: 700,
              fontSize: 12,
              padding: '4px 8px',
              borderRadius: 4,
              marginRight: 8
            }}>Endpoints</div>
            <div style={{ color: '#333', fontWeight: 600 }}>Endpoint Scanner</div>
          </div>
        
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
      </div>

      <div style={{
        height: 280,
        overflowY: 'auto',
        border: '1px solid #e9edf5',
        borderRadius: 8,
        backgroundColor: 'white',
        boxShadow: '0 2px 6px rgba(0,0,0,0.04)'
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

      {/* LFI Scanner */}
      <div style={{ marginTop: 16 }}>
        <div style={{ 
          background: 'linear-gradient(135deg, #ffffff 0%, #f8fafc 100%)',
          border: '2px solid #e2e8f0', 
          borderRadius: 12, 
          padding: 16,
          boxShadow: '0 4px 12px rgba(0,0,0,0.08)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                background: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
                color: 'white',
                fontWeight: 800,
                fontSize: 14,
                padding: '6px 12px',
                borderRadius: 6,
                boxShadow: '0 2px 4px rgba(239,68,68,0.3)'
              }}>⚠️ LFI</div>
              <div style={{ color: '#1e293b', fontWeight: 700, fontSize: 15 }}>
                Local File Inclusion Scanner
              </div>
            </div>
            {wordlistLoading && (
              <div style={{ fontSize: 11, color: '#64748b', display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 14 }}>⏳</span>
                Loading wordlist...
              </div>
            )}
            {!wordlistLoading && wordlist.length > 0 && (
              <div style={{ fontSize: 11, color: '#10b981', fontWeight: 600 }}>
                ✓ {wordlist.length} payloads ready
              </div>
            )}
          </div>

          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <input
              type="text"
              placeholder="Target URL (leave blank to use above)"
              value={lfiUrl}
              onChange={(e) => setLfiUrl(e.target.value)}
              style={{ 
                flex: 1, 
                padding: '10px 14px', 
                border: '2px solid #e2e8f0', 
                borderRadius: 8, 
                fontSize: 14,
                transition: 'all 0.2s',
                outline: 'none'
              }}
              onFocus={(e) => e.target.style.borderColor = '#ef4444'}
              onBlur={(e) => e.target.style.borderColor = '#e2e8f0'}
            />
            <input
              type="text"
              placeholder="Parameter"
              value={lfiParam}
              onChange={(e) => setLfiParam(e.target.value)}
              style={{ 
                width: 130, 
                padding: '10px 14px', 
                border: '2px solid #e2e8f0', 
                borderRadius: 8, 
                fontSize: 14,
                transition: 'all 0.2s',
                outline: 'none'
              }}
              onFocus={(e) => e.target.style.borderColor = '#ef4444'}
              onBlur={(e) => e.target.style.borderColor = '#e2e8f0'}
            />
            <button
              onClick={handleRunLfi}
              disabled={lfiLoading || wordlistLoading}
              style={{
                padding: '10px 20px',
                background: lfiLoading || wordlistLoading 
                  ? 'linear-gradient(135deg, #cbd5e1 0%, #94a3b8 100%)'
                  : 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
                color: 'white',
                border: 'none',
                borderRadius: 8,
                cursor: lfiLoading || wordlistLoading ? 'not-allowed' : 'pointer',
                fontSize: 14,
                fontWeight: 700,
                boxShadow: lfiLoading || wordlistLoading ? 'none' : '0 4px 8px rgba(239,68,68,0.3)',
                transition: 'all 0.2s',
                transform: lfiLoading || wordlistLoading ? 'none' : 'translateY(0)'
              }}
              onMouseEnter={(e) => {
                if (!lfiLoading && !wordlistLoading) {
                  e.currentTarget.style.transform = 'translateY(-2px)'
                  e.currentTarget.style.boxShadow = '0 6px 12px rgba(239,68,68,0.4)'
                }
              }}
              onMouseLeave={(e) => {
                if (!lfiLoading && !wordlistLoading) {
                  e.currentTarget.style.transform = 'translateY(0)'
                  e.currentTarget.style.boxShadow = '0 4px 8px rgba(239,68,68,0.3)'
                }
              }}
            >
              {lfiLoading ? `Scanning... ${currentProgress.current}/${currentProgress.total}` : '🔍 Scan LFI'}
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12, padding: '8px 12px', background: '#f1f5f9', borderRadius: 8 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#475569', fontWeight: 600 }}>
              Payload Limit:
            </label>
            <input 
              type="number" 
              min={50} 
              max={5000} 
              value={payloadCap} 
              onChange={(e) => setPayloadCap(Number(e.target.value) || 500)} 
              style={{ 
                width: 80, 
                padding: '4px 8px', 
                border: '1px solid #cbd5e1', 
                borderRadius: 6, 
                fontSize: 12,
                fontWeight: 600
              }} 
            />
            <div style={{ fontSize: 11, color: '#64748b', marginLeft: 'auto' }}>
              Using SecLists LFI-Jhaddix wordlist
            </div>
          </div>

          {lfiLoading && currentProgress.total > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ 
                width: '100%', 
                height: 8, 
                background: '#e2e8f0', 
                borderRadius: 4, 
                overflow: 'hidden',
                marginBottom: 6
              }}>
                <div style={{ 
                  width: `${(currentProgress.current / currentProgress.total) * 100}%`, 
                  height: '100%', 
                  background: 'linear-gradient(90deg, #ef4444 0%, #dc2626 100%)',
                  transition: 'width 0.3s ease',
                  borderRadius: 4
                }} />
              </div>
              <div style={{ fontSize: 11, color: '#64748b', textAlign: 'center' }}>
                Testing payload {currentProgress.current} of {currentProgress.total}
              </div>
            </div>
          )}

          {lfiResults && (
            <div style={{ marginTop: 12 }}>
              {/* Overall LFI summary + export controls */}
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: 12,
                padding: '12px',
                background: lfiResults.vulnerableCount > 0 
                  ? 'linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%)'
                  : 'linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%)',
                borderRadius: 8,
                border: `2px solid ${lfiResults.vulnerableCount > 0 ? '#fca5a5' : '#86efac'}`
              }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: lfiResults.vulnerableCount > 0 ? '#991b1b' : '#166534' }}>
                  {lfiResults.vulnerableCount > 0 ? (
                    <>🚨 {lfiResults.vulnerableCount} Finding{lfiResults.vulnerableCount > 1 ? 's' : ''} flagged / {lfiResults.totalTests} tested</>
                  ) : (
                    <>✓ No LFI vulnerabilities detected ({lfiResults.totalTests} tested)</>
                  )}
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    onClick={() => exportLfiResults('txt')}
                    style={{ 
                      padding: '6px 10px', 
                      background: 'linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%)',
                      color: 'white', 
                      border: 'none', 
                      borderRadius: 6, 
                      fontSize: 11, 
                      cursor: 'pointer',
                      fontWeight: 600
                    }}
                  >
                    TXT
                  </button>
                  <button
                    onClick={() => exportLfiResults('csv')}
                    style={{ 
                      padding: '6px 10px', 
                      background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                      color: 'white', 
                      border: 'none', 
                      borderRadius: 6, 
                      fontSize: 11, 
                      cursor: 'pointer',
                      fontWeight: 600
                    }}
                  >
                    CSV
                  </button>
                </div>
              </div>

              {/* Per-parameter compact overview */}
              {lfiResults.parametersTested.length > 0 && (
                <div style={{
                  marginBottom: 12,
                  padding: 10,
                  borderRadius: 8,
                  border: '1px solid #e2e8f0',
                  background: '#f8fafc'
                }}>
                  <div style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center',
                    marginBottom: 6
                  }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
                      Parameter Overview
                    </div>
                    <div style={{ fontSize: 11, color: '#64748b' }}>
                      Click a row to toggle payload details
                    </div>
                  </div>
                  <div>
                    {lfiResults.parametersTested.map((p) => {
                      const paramResults = lfiResults.results.filter(r => r.parameter === p.name)
                      // Determine strongest detection for this parameter
                      const bySeverity = (d: LfiSingleResult['detection']) =>
                        d === 'CONFIRMED_LFI' ? 3 : d === 'POSSIBLE_LFI' ? 2 : d === 'SUSPICIOUS' ? 1 : 0
                      let best: LfiSingleResult | undefined
                      for (const r of paramResults) {
                        if (!best || bySeverity(r.detection) > bySeverity(best.detection)) {
                          best = r
                        }
                      }

                      const statusLabel =
                        !best || best.detection === 'NOT_VULNERABLE'
                          ? 'Not Vulnerable'
                          : best.detection === 'CONFIRMED_LFI'
                          ? 'Confirmed LFI'
                          : 'Possible LFI'

                      const color =
                        !best || best.detection === 'NOT_VULNERABLE'
                          ? '#16a34a'
                          : best.detection === 'CONFIRMED_LFI'
                          ? '#dc2626'
                          : '#f59e0b'

                      const bg =
                        !best || best.detection === 'NOT_VULNERABLE'
                          ? '#dcfce7'
                          : best.detection === 'CONFIRMED_LFI'
                          ? '#fee2e2'
                          : '#fef9c3'

                      const isExpanded = !!expandedParams[p.name]

                      return (
                        <div
                          key={p.name}
                          onClick={() =>
                            setExpandedParams(prev => ({
                              ...prev,
                              [p.name]: !prev[p.name]
                            }))
                          }
                          style={{
                            padding: '8px 10px',
                            borderRadius: 6,
                            border: '1px solid #e2e8f0',
                            background: 'white',
                            marginBottom: 6,
                            cursor: 'pointer'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{
                              fontSize: 11,
                              fontFamily: 'monospace',
                              padding: '2px 6px',
                              borderRadius: 4,
                              background: '#e2e8f0',
                              color: '#0f172a'
                            }}>
                              {p.name}
                            </span>
                            <span style={{
                              fontSize: 11,
                              padding: '2px 8px',
                              borderRadius: 999,
                              background: bg,
                              color,
                              fontWeight: 700
                            }}>
                              {statusLabel}
                            </span>
                            {best && best.detection !== 'NOT_VULNERABLE' && (
                              <span style={{ fontSize: 10, color: '#64748b' }}>
                                {best.confidence} confidence
                              </span>
                            )}
                            <span style={{ marginLeft: 'auto', fontSize: 10, color: '#94a3b8' }}>
                              {isExpanded ? 'Hide payloads ▲' : 'Show payloads ▼'}
                            </span>
                          </div>
                          {best && best.detection !== 'NOT_VULNERABLE' && (
                            <div style={{ marginTop: 4, fontSize: 11, color: '#475569' }}>
                              <strong>Trigger payload:</strong>{' '}
                              <code style={{
                                background: '#f1f5f9',
                                padding: '2px 6px',
                                borderRadius: 4,
                                fontFamily: 'monospace',
                                fontSize: 10
                              }}>
                                {best.payload}
                              </code>
                              {best.indicators.length > 0 && (
                                <span style={{ marginLeft: 6, color: '#b91c1c' }}>
                                  ({best.indicators.join(', ')})
                                </span>
                              )}
                            </div>
                          )}
                          {isExpanded && paramResults.length > 0 && (
                            <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px dashed #e2e8f0' }}>
                              <div style={{ fontSize: 10, color: '#64748b', marginBottom: 4 }}>
                                {paramResults.length} payload response{paramResults.length > 1 ? 's' : ''}
                              </div>
                              <div style={{ maxHeight: 120, overflowY: 'auto' }}>
                                {paramResults.map((r, idx) => (
                                  <div
                                    key={idx}
                                    style={{
                                      padding: '4px 6px',
                                      borderRadius: 4,
                                      background: '#f9fafb',
                                      border: '1px solid #e5e7eb',
                                      marginBottom: 4,
                                      fontSize: 10
                                    }}
                                  >
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                                      <span style={{ fontWeight: 600 }}>
                                        {r.detection.replace(/_/g, ' ')}
                                      </span>
                                      <span style={{ fontSize: 9, color: '#6b7280' }}>
                                        ({r.confidence})
                                      </span>
                                      <span style={{ marginLeft: 'auto', fontSize: 9, color: '#9ca3af' }}>
                                        {r.status} • {r.contentLength} bytes
                                      </span>
                                    </div>
                                    <div style={{ marginTop: 2 }}>
                                      <code style={{
                                        background: '#e5e7eb',
                                        padding: '1px 4px',
                                        borderRadius: 3
                                      }}>
                                        {r.payload}
                                      </code>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Detailed per-response list (optional, collapsible for efficiency) */}
              <div style={{
                border: '2px solid #e2e8f0',
                borderRadius: 8,
                background: 'white'
              }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 10px',
                    borderBottom: '1px solid #e2e8f0',
                    background: '#f8fafc'
                  }}
                >
                  <div style={{ fontSize: 12, fontWeight: 600, color: '#0f172a' }}>
                    Payload Responses
                  </div>
                  <button
                    onClick={() => setShowLfiDetails(v => !v)}
                    style={{
                      fontSize: 11,
                      padding: '4px 8px',
                      borderRadius: 999,
                      border: '1px solid #cbd5e1',
                      background: 'white',
                      cursor: 'pointer',
                      color: '#0f172a'
                    }}
                  >
                    {showLfiDetails ? 'Hide details' : 'Show details'}
                  </button>
                </div>
                {showLfiDetails && (
                  <div style={{
                    maxHeight: 260,
                    overflowY: 'auto'
                  }}>
                    {lfiResults.results.length === 0 ? (
                      <div style={{ padding: 24, textAlign: 'center', color: '#64748b' }}>
                        No interesting responses found. All tests completed.
                      </div>
                    ) : (
                      lfiResults.results.map((r, idx) => (
                    <div key={idx} style={{ 
                      padding: 12, 
                      borderBottom: '1px solid #f1f5f9', 
                      fontSize: 12,
                      background: r.vulnerable ? '#fef2f2' : 'white',
                      transition: 'background 0.2s'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 6, gap: 8 }}>
                        <span style={{ 
                          fontWeight: 700, 
                          color: r.vulnerable ? '#dc2626' : '#059669',
                          fontSize: 13,
                          padding: '2px 8px',
                          background: r.vulnerable ? '#fee2e2' : '#d1fae5',
                          borderRadius: 4
                        }}>
                          {r.detection === 'CONFIRMED_LFI'
                            ? '🚨 CONFIRMED LFI'
                            : r.detection === 'POSSIBLE_LFI'
                            ? '⚠️ POSSIBLE LFI'
                            : r.detection === 'SUSPICIOUS'
                            ? '⚠️ SUSPICIOUS'
                            : '✓ NOT VULNERABLE'}
                        </span>
                        <span style={{
                          padding: '3px 8px',
                          borderRadius: 4,
                          backgroundColor: r.vulnerable ? '#ef4444' : '#10b981',
                          color: 'white',
                          fontSize: 11,
                          fontWeight: 600
                        }}>{r.status}</span>
                        <span style={{ marginLeft: 'auto', color: '#64748b', fontSize: 11 }}>
                          {r.contentLength} bytes
                        </span>
                      </div>
                      <div style={{ marginBottom: 6 }}>
                        <div style={{ 
                          color: '#1e40af', 
                          fontSize: 11, 
                          wordBreak: 'break-all',
                          fontFamily: 'monospace',
                          background: '#eff6ff',
                          padding: '4px 8px',
                          borderRadius: 4
                        }}>
                          {r.testedUrl}
                        </div>
                      </div>
                      <div style={{ color: '#475569', marginBottom: 4, fontSize: 11 }}>
                        <strong>Parameter:</strong>{' '}
                        <code style={{ 
                          background: '#f1f5f9', 
                          padding: '2px 6px', 
                          borderRadius: 4,
                          fontFamily: 'monospace',
                          fontSize: 10
                        }}>{r.parameter}</code>
                        {r.originalValue !== null && (
                          <span style={{ marginLeft: 4, color: '#94a3b8' }}>
                            (original: {r.originalValue})
                          </span>
                        )}
                      </div>
                      <div style={{ color: '#475569', marginBottom: 6, fontSize: 11 }}>
                        <strong>Payload:</strong> <code style={{ 
                          background: '#f1f5f9', 
                          padding: '2px 6px', 
                          borderRadius: 4,
                          fontFamily: 'monospace',
                          fontSize: 10
                        }}>{r.payload}</code>
                      </div>
                      <div style={{ color: '#475569', marginBottom: 4, fontSize: 11 }}>
                        <strong>Detection:</strong> {r.detection.replace(/_/g, ' ')} ({r.confidence} confidence)
                      </div>
                      {r.indicators.length > 0 && (
                        <div style={{ marginTop: 8 }}>
                          <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 6, color: '#991b1b' }}>
                            🎯 Detection Indicators:
                          </div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            {r.indicators.map((i, j) => (
                              <span key={j} style={{ 
                                padding: '4px 10px', 
                                background: 'linear-gradient(135deg, #fed7aa 0%, #fdba74 100%)',
                                color: '#7c2d12', 
                                border: '1px solid #f97316',
                                borderRadius: 6,
                                fontSize: 11,
                                fontWeight: 600,
                                boxShadow: '0 1px 2px rgba(249,115,22,0.2)'
                              }}>
                                {i}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))
                )}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default IndexPopup
