# Endpoint Scanner Extension

A Chrome extension built with Plasmo framework that scans websites to detect and extract all endpoints, API routes, and links. Similar to the EndPointer extension, this tool helps security researchers and developers discover potentially vulnerable endpoints on web applications.

## Features

- **URL/Endpoint Detection**: Automatically scans websites for endpoints, API routes, and links
- **JavaScript File Analysis**: Parses and analyzes externally linked JavaScript files
- **Dynamic Content Support**: Handles dynamically loaded scripts and content
- **Endpoint Categorization**: Categorizes endpoints as API, static files, pages, or unknown
- **HTTP Method Detection**: Identifies HTTP methods (GET, POST, PUT, DELETE) from code patterns
- **Filtering & Search**: Filter results by endpoint type
- **Export Functionality**: Export results in TXT or CSV format
- **Real-time Scanning**: Live scanning with progress indicators

## Installation

1. Clone this repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Build the extension:
   ```bash
   npm run build
   ```
4. Load the extension in Chrome:
   - Open Chrome and go to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked" and select the `build/chrome-mv3-dev` folder

## Usage

1. Click on the extension icon in your browser toolbar
2. Enter the URL of the website you want to scan
3. Click "Scan" to start the analysis
4. View the detected endpoints in the popup
5. Use the filter dropdown to view specific types of endpoints
6. Export results using the TXT or CSV export buttons

## Endpoint Detection Patterns

The extension detects endpoints using various patterns:

- REST API routes (`/api/`, `/v1/`, `/v2/`)
- Common endpoint patterns (`/users`, `/products`, etc.)
- Fetch/axios calls in JavaScript
- jQuery AJAX requests
- XMLHttpRequest patterns
- URL patterns in HTML and JavaScript

## Endpoint Categories

- **API**: REST API endpoints and versioned APIs
- **Page**: HTML pages and server-side rendered content
- **Static**: Static assets (CSS, JS, images, fonts)
- **Unknown**: Other endpoints that don't fit the above categories

## Development

To run in development mode:
```bash
npm run dev
```

To build for production:
```bash
npm run build
```

## Security Notice

This tool is intended for:
- Security research and penetration testing
- Bug bounty programs
- Educational purposes
- Authorized security assessments

Always ensure you have proper authorization before scanning any website. The developers are not responsible for any misuse of this tool.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.