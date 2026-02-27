// Content script to detect endpoints on the current page
// This runs in the context of web pages to extract additional endpoint information

interface EndpointInfo {
  url: string
  method?: string
  type: 'api' | 'static' | 'page' | 'unknown'
  source: string
  line?: number
}

const extractEndpointsFromPage = (): EndpointInfo[] => 
  const endpoints: EndpointInfo[] = []
  
  // Extract from all script tags
  const scripts = document.querySelectorAll('script')
  scripts.forEach((script, index) => {
    if (script.textContent) {
      const scriptEndpoints = extractEndpointsFromText(script.textContent, `Script ${index + 1}`)
      endpoints.push(...scriptEndpoints)
    }
  })
  
  // Extract from inline event handlers
  const elementsWithEvents = document.querySelectorAll('[onclick], [onload], [onerror]')
  elementsWithEvents.forEach((element, index) => {
    const onclick = element.getAttribute('onclick')
    const onload = element.getAttribute('onload')
    const onerror = element.getAttribute('onerror')
    
    [onclick, onload, onerror].forEach(handler => {
      if (handler) {
        const handlerEndpoints = extractEndpointsFromText(handler, `Event Handler ${index + 1}`)
        endpoints.push(...handlerEndpoints)
      }
    })
  })
  
  // Extract from data attributes
  const elementsWithData = document.querySelectorAll('[data-url], [data-src], [data-href]')
  elementsWithData.forEach((element, index) => {
    const dataUrl = element.getAttribute('data-url')
    const dataSrc = element.getAttribute('data-src')
    const dataHref = element.getAttribute('data-href')
    
    [dataUrl, dataSrc, dataHref].forEach(url => {
      if (url && isValidEndpoint(url)) {
        endpoints.push({
          url: normalizeUrl(url),
          type: categorizeEndpoint(url),
          source: `Data Attribute ${index + 1}`,
          line: 0
        })
      }
    })
  })
  
  return endpoints
}

const extractEndpointsFromText = (text: string, source: string): EndpointInfo[] => {
  const endpoints: EndpointInfo[] = []
  
  // Common API endpoint patterns
  const patterns = [
    // REST API patterns
    /["']\/api\/[^"']*["']/gi,
    /["']\/v\d+\/[^"']*["']/gi,
    /["']\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+["']/gi,
    
    // Common endpoint patterns
    /["']\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]*["']/gi,
    /["']\/[a-zA-Z0-9_-]+\.json["']/gi,
    /["']\/[a-zA-Z0-9_-]+\.xml["']/gi,
    
    // URL patterns
    /https?:\/\/[^\s"']+/gi,
    /["']https?:\/\/[^"']*["']/gi,
    
    // Fetch/axios patterns
    /fetch\s*\(\s*["']([^"']+)["']/gi,
    /axios\.[a-z]+\s*\(\s*["']([^"']+)["']/gi,
    /\.get\s*\(\s*["']([^"']+)["']/gi,
    /\.post\s*\(\s*["']([^"']+)["']/gi,
    /\.put\s*\(\s*["']([^"']+)["']/gi,
    /\.delete\s*\(\s*["']([^"']+)["']/gi,
    
    // jQuery patterns
    /\$\.(get|post|ajax)\s*\(\s*["']([^"']+)["']/gi,
    
    // XMLHttpRequest patterns
    /open\s*\(\s*["'](GET|POST|PUT|DELETE)["']\s*,\s*["']([^"']+)["']/gi,
  ]

  patterns.forEach(pattern => {
    let match
    while ((match = pattern.exec(text)) !== null) {
      let url = match[1] || match[0]
      
      // Clean up the URL
      url = url.replace(/["']/g, '').trim()
      
      if (url && isValidEndpoint(url)) {
        const endpoint: EndpointInfo = {
          url: normalizeUrl(url),
          type: categorizeEndpoint(url),
          source: source,
          line: getLineNumber(text, match.index)
        }
        
        // Extract HTTP method if available
        if (match[0].includes('GET')) endpoint.method = 'GET'
        else if (match[0].includes('POST')) endpoint.method = 'POST'
        else if (match[0].includes('PUT')) endpoint.method = 'PUT'
        else if (match[0].includes('DELETE')) endpoint.method = 'DELETE'
        
        endpoints.push(endpoint)
      }
    }
  })

  return endpoints
}

const isValidEndpoint = (url: string): boolean => {
  // Filter out common non-endpoint patterns
  const excludePatterns = [
    /^#/,
    /^javascript:/,
    /^mailto:/,
    /^tel:/,
    /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/i,
    /^\/$/, // Just root path
    /^\/\s*$/, // Root with whitespace
  ]
  
  return !excludePatterns.some(pattern => pattern.test(url))
}

const normalizeUrl = (url: string): string => {
  // Remove query parameters and fragments for cleaner display
  return url.split('?')[0].split('#')[0]
}

const categorizeEndpoint = (url: string): EndpointInfo['type'] => {
  if (url.includes('/api/') || url.includes('/v1/') || url.includes('/v2/')) {
    return 'api'
  }
  if (url.match(/\.(html|htm|php|asp|aspx)$/i)) {
    return 'page'
  }
  if (url.match(/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/i)) {
    return 'static'
  }
  return 'unknown'
}

const getLineNumber = (text: string, index: number): number => {
  return text.substring(0, index).split('\n').length
}

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'extractEndpoints') {
    const endpoints = extractEndpointsFromPage()
    sendResponse({ endpoints })
  }
})

// Auto-extract endpoints when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    const endpoints = extractEndpointsFromPage()
    chrome.runtime.sendMessage({
      action: 'endpointsDetected',
      endpoints: endpoints,
      url: window.location.href
    })
  })
} else {
  const endpoints = extractEndpointsFromPage()
  chrome.runtime.sendMessage({
    action: 'endpointsDetected',
    endpoints: endpoints,
    url: window.location.href
  })
}
