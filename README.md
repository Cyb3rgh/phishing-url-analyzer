# Phishing URL Analyzer

A defensive cybersecurity application that inspects suspicious URLs without opening them. It combines local structural analysis with existing VirusTotal threat-intelligence reports to produce a clear risk assessment.

Built by **Fayyad Dahweesh** as a practical cybersecurity portfolio project.

## Live Demo

[Launch the Phishing URL Analyzer](https://phishing-url-analyzer-three.vercel.app)

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
- Fifteen-minute report caching
- Best-effort VirusTotal API rate limiting
- Input validation and length restrictions
- Embedded URL credential rejection

## Technology Stack

- Next.js
- React
- TypeScript
- Tailwind CSS
- VirusTotal API v3
- ESLint
- Vercel

## How It Works

1. The user submits a URL.
2. The application normalizes and validates the input.
3. A local engine checks structural phishing indicators.
4. A server-side API route creates the VirusTotal URL identifier.
5. The route checks for a cached report.
6. If no cached report exists, it retrieves an existing VirusTotal report.
7. Local and external intelligence are combined into a risk score.
8. The interface displays the findings and engine statistics.

The application does not navigate to the submitted destination.

## Risk Indicators

The local analysis engine evaluates indicators such as:

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
- A VirusTotal Community API key

### Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/Cyb3rgh/phishing-url-analyzer.git
cd phishing-url-analyzer
```

Install the dependencies:

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

Open the local application:

```text
http://localhost:3000
```

## Testing

### Safe Documentation Test

Submit:

```text
example.com
```

Expected result:

- Low Risk
- No malicious VirusTotal detections
- Existing VirusTotal reputation information

### Controlled Phishing-Warning Test

Submit:

```text
https://testsafebrowsing.appspot.com/s/phishing.html
```

This is an official Safe Browsing test URL. Paste it into the analyzer; do not navigate to it directly.

Expected result:

- High Risk
- Malicious or suspicious VirusTotal detections
- A combined risk score reflecting the external intelligence

### Quality Checks

```bash
npm run lint
npm run build
```

## Security and Privacy

- The VirusTotal API key is stored in a server-only environment variable.
- The API key is never returned to the browser.
- `.env.local` is excluded from Git.
- Only HTTP and HTTPS URLs are accepted.
- URLs containing embedded credentials are rejected.
- Input length is limited.
- The application retrieves existing VirusTotal reports and does not automatically submit new URLs for scanning.
- Successful and not-found reports are cached for fifteen minutes.
- A best-effort request limiter reduces the risk of exceeding the VirusTotal Community API quota.

Do not analyze private password-reset links, internal company URLs, authentication tokens, confidential addresses, or other sensitive URLs using public threat-intelligence services.

## API Usage

This project uses the VirusTotal Community API for educational and portfolio purposes.

The public API is subject to VirusTotal’s usage restrictions and quotas, including:

- 4 requests per minute
- 500 requests per day
- No commercial product or service usage

The application includes caching and best-effort rate limiting to reduce unnecessary requests. In-memory protection may reset between deployments or serverless instances and should not be considered a distributed production-grade rate limiter.

## Limitations

- A Low Risk result does not guarantee that a URL is safe.
- An undetected result means an engine has no verdict, not that the URL is harmless.
- VirusTotal Community API quotas apply.
- Previously unseen URLs may not have an existing VirusTotal report.
- Static indicators can produce false positives or false negatives.
- Cached threat-intelligence results may be up to fifteen minutes old.
- Serverless instances may not share the same in-memory cache or request counter.
- The tool supports investigation but does not replace professional security controls.

## Deployment

The application is deployed on Vercel:

[https://phishing-url-analyzer-three.vercel.app](https://phishing-url-analyzer-three.vercel.app)

The `VIRUSTOTAL_API_KEY` environment variable must be configured securely in the deployment platform and must never be added to the repository.

## Disclaimer

This project is intended for defensive security education and portfolio demonstration. Results should support—not replace—professional investigation and security controls.

## Author

**Fayyad Dahweesh**

Technical Support Specialist | IT Support Professional | Aspiring Cybersecurity Analyst

- GitHub: [Cyb3rgh](https://github.com/Cyb3rgh)
- Live Project: [Phishing URL Analyzer](https://phishing-url-analyzer-three.vercel.app)