# Phishing URL Analyzer

A defensive cybersecurity application that inspects suspicious URLs without opening them. It combines local structural analysis with existing VirusTotal threat-intelligence reports to produce a clear risk assessment.

Built by **Fayyad Dahweesh** as a practical cybersecurity portfolio project.

## Features

- Static URL inspection without visiting the destination
- Automatic URL normalization and domain extraction
- Risk score from 0 to 100
- Low Risk, Suspicious, and High Risk classifications
- HTTPS verification
- IP-address detection
- Suspicious keyword detection
- URL-shortener detection
- Punycode and unusual subdomain detection
- Live VirusTotal reputation lookup
- Security-engine verdict statistics
- Community reputation and URL categories
- Responsive SOC-inspired interface
- Server-side API-key protection

## Technology Stack

- Next.js
- React
- TypeScript
- Tailwind CSS
- VirusTotal API v3
- ESLint

## How It Works

1. The user submits a URL.
2. The application normalizes and validates the input.
3. A local engine checks structural phishing indicators.
4. A server-side API route creates the VirusTotal URL identifier.
5. The route retrieves the existing VirusTotal report.
6. Local and external intelligence are combined into a risk score.
7. The interface displays the findings and engine statistics.

The application does not navigate to the submitted destination.

## Risk Indicators

The local engine evaluates indicators such as:

- Missing HTTPS
- Raw IP address instead of a domain
- `@` symbols that may obscure the destination
- Punycode domains
- Excessive URL length
- Suspicious words such as `login`, `verify`, and `password`
- Excessive subdomains
- Known URL-shortening services

VirusTotal detections can increase the final score when security engines classify the URL as suspicious or malicious.

## Local Setup

### Requirements

- Node.js 20.9 or newer
- npm
- A free VirusTotal Community API key

### Installation

Clone the repository and enter the project directory:

```bash
git clone YOUR_REPOSITORY_URL
cd phishing-url-analyzer
```

Install dependencies:

```bash
npm install
```

Create a `.env.local` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_private_api_key
```

Never expose the API key in client-side code or commit `.env.local`.

Start the development server:

```bash
npm run dev
```

Open:

```text
http://localhost:3000
```

## Testing

Safe documentation test:

```text
example.com
```

Expected result: Low Risk with no malicious VirusTotal detections.

Controlled phishing-warning test:

```text
https://testsafebrowsing.appspot.com/s/phishing.html
```

This is an official Safe Browsing test URL. Paste it into the analyzer; do not navigate to it directly.

Quality checks:

```bash
npm run lint
npm run build
```

## Security and Privacy

- The VirusTotal API key is stored in a server-only environment variable.
- The key is never returned to the browser.
- `.env.local` is excluded from Git.
- Only HTTP and HTTPS URLs are accepted.
- URLs containing embedded credentials are rejected.
- Input length is limited.
- The application retrieves existing VirusTotal reports and does not automatically submit new URLs for scanning.

Do not analyze private reset links, internal company URLs, authentication tokens, or confidential addresses using public threat-intelligence services.

## Limitations

- A Low Risk result does not guarantee that a URL is safe.
- An undetected result means an engine has no verdict, not that the URL is harmless.
- VirusTotal Community API quotas apply.
- Previously unseen URLs may not have an existing VirusTotal report.
- Static indicators can produce false positives or false negatives.

## Disclaimer

This project is intended for defensive security education and portfolio demonstration. Results should support—not replace—professional investigation and security controls.

## Author

**Fayyad Dahweesh**

Technical Support Specialist | IT Support Professional | Aspiring Cybersecurity Analyst