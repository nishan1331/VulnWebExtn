import type { PlasmoMessaging } from "@plasmohq/messaging"

export interface EndpointInfo {
  url: string
  method?: string
  type: 'api' | 'static' | 'page' | 'unknown'
  source: string
  line?: number
}

export interface ScrapeResult {
  endpoints: EndpointInfo[]
  totalCount: number
  domain: string
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

const scrapeWebsite = async (url: string): Promise<ScrapeResult> => {
  const endpoints: EndpointInfo[] = []
  const domain = new URL(url).hostname
  
  try {
    // Fetch the main page with better error handling
    const response = await fetch(url, {
      method: 'GET',
      mode: 'cors',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
      }
    })
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }
    
    const html = await response.text()
    
    // Extract endpoints from HTML content
    const htmlEndpoints = extractEndpointsFromText(html, 'HTML')
    endpoints.push(...htmlEndpoints)
    
    // Find and scrape JavaScript files with better filtering
    const scriptMatches = html.match(/<script[^>]*src=["']([^"']+)["'][^>]*>/gi) || []
    
    // Limit the number of scripts to prevent overwhelming requests
    const maxScripts = 10
    const scriptsToProcess = scriptMatches.slice(0, maxScripts)
    
    for (const scriptMatch of scriptsToProcess) {
      const srcMatch = scriptMatch.match(/src=["']([^"']+)["']/)
      if (srcMatch) {
        let scriptUrl = srcMatch[1]
        
        // Skip external CDNs and minified files that might cause issues
        if (scriptUrl.includes('cdn') || scriptUrl.includes('min.js') || 
            scriptUrl.includes('bundle') || scriptUrl.includes('vendor')) {
          continue
        }
        
        // Convert relative URLs to absolute
        if (scriptUrl.startsWith('/')) {
          scriptUrl = `${new URL(url).origin}${scriptUrl}`
        } else if (!scriptUrl.startsWith('http')) {
          scriptUrl = new URL(scriptUrl, url).href
        }
        
        try {
          const scriptResponse = await fetch(scriptUrl, {
            method: 'GET',
            mode: 'cors',
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
              'Accept': 'application/javascript, text/javascript, */*'
            }
          })
          
          if (scriptResponse.ok) {
            const scriptContent = await scriptResponse.text()
            
            // Skip scripts that contain WebSocket or other problematic code
            if (scriptContent.includes('WebSocket') || 
                scriptContent.includes('eval(') || 
                scriptContent.includes('Function(') ||
                scriptContent.length > 100000) { // Skip very large files
              continue
            }
            
            const scriptEndpoints = extractEndpointsFromText(scriptContent, `JS: ${scriptUrl}`)
            endpoints.push(...scriptEndpoints)
          }
        } catch (error) {
          console.warn(`Failed to fetch script: ${scriptUrl}`, error)
          // Continue with other scripts instead of failing completely
        }
      }
    }
    
    // Also extract from inline scripts in HTML
    const inlineScripts = html.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || []
    for (const inlineScript of inlineScripts) {
      const scriptContent = inlineScript.replace(/<script[^>]*>|<\/script>/gi, '')
      if (scriptContent.trim() && !scriptContent.includes('WebSocket')) {
        const inlineEndpoints = extractEndpointsFromText(scriptContent, 'Inline Script')
        endpoints.push(...inlineEndpoints)
      }
    }
    
    // Remove duplicates
    const uniqueEndpoints = endpoints.filter((endpoint, index, self) => 
      index === self.findIndex(e => e.url === endpoint.url)
    )
    
    return {
      endpoints: uniqueEndpoints,
      totalCount: uniqueEndpoints.length,
      domain
    }
    
  } catch (error) {
    console.error('Error scraping website:', error)
    throw error
  }
}

const handler: PlasmoMessaging.MessageHandler = async (req, res) => {
  const { url } = req.body
  
  if (!url) {
    res.send({ error: 'URL is required' })
    return
  }
  
  try {
    // Validate URL
    new URL(url)
    
    const result = await scrapeWebsite(url)
    res.send(result)
  } catch (error) {
    res.send({ 
      error: error instanceof Error ? error.message : 'Failed to scrape website' 
    })
  }
}

export default handler
