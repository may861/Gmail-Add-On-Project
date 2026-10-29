# Malicious Email Scorer

A Gmail add-on that analyzes the currently opened email and displays a risk score, verdict, and explainable findings based on configurable rules.

## Features

- Reads the opened email's subject, sender, body, and attachment filenames.
- Calculates a risk score from 0 to 100.
- Displays one of three verdicts: Low Risk, Suspicious, or High Risk.
- Explains which signals contributed to the score.
- Includes a disclaimer that the score is an estimate, not proof of malicious activity.

## Project Structure

```text
Gmail-Add-On-Project/
├── apps-script/
│   ├── Code.gs
│   └── appsscript.json
├── server/
│   ├── server.js
│   └── scorer.js
├── package.json
└── package-lock.json
```

## How It Works

When a user opens an email in Gmail and clicks Analyze email, the add-on extracts the email's subject, sender, body, and attachment filenames and sends them to the Node.js/Express backend over HTTPS. The backend evaluates the email using predefined rules and returns a risk score, verdict, and explanations of the detected indicators.

# How the evaluation works
1. Receives the email: The Gmail add-on sends the subject, sender, body, and attachment filenames to the backend.
2. Checks for suspicious indicators: The scorer looks for patterns such as urgent language, requests for passwords, financial requests, shortened URLs, unusual link destinations, and risky attachment extensions.
3. Adds risk points: Each detected indicator contributes a predefined number of points.
4. Calculates the final score: The points are added together, with the total capped at 100.
5. Returns a verdict and explanations: The backend returns the score, category, and findings explaining which rules were triggered.
## Scoring Rules

| Signal | Points |
|---|---:|
| Urgent or threatening language | 15 |
| Possible credential theft | 25 |
| Potentially risky financial request | 20 |
| Shortened URL | 10 |
| Unusual link destination | 20 |
| Potentially dangerous attachment | 20 |

The total score is capped at 100.

- **0–29:** Low Risk
- **30–59:** Suspicious
- **60–100:** High Risk

These rules are heuristic signals. A low score does not guarantee that an email is safe, and a high score does not prove malicious intent.

## Gmail Add-on Setup

1. Open the project in the Google Apps Script editor.
2. Enable the manifest file in **Project Settings** if it is not already visible.
3. Copy `apps-script/Code.gs` into the Apps Script editor's `Code.gs` file.
4. Copy `apps-script/appsscript.json` into the editor's `appsscript.json` manifest.
5. Save the project.
6. Use **Deploy → Test deployments** to install and test the Gmail add-on.
7. Open an email in Gmail and select **Analyze email**.

Google may request Gmail permissions during installation.

## Backend API

The project also includes a Node.js/Express scoring API.

Run it locally:

```bash
npm install
node server/server.js
```

The API runs on port 3000 by default.

Health check:

```text
GET /health
```

Analyze an email:

```text
POST /analyze
Content-Type: application/json
```

Example request:

```json
{
  "subject": "Urgent: Verify your account",
  "sender": "security@example.com",
  "body": "Your account will be suspended. Verify your password.",
  "attachments": []
}
```

The API returns a score, verdict, findings, analyzed signals, and a disclaimer.

**Architecture note:** The current Gmail add-on runs its scoring rules locally in Apps Script. The Node.js API is deployed separately and is not called by the current add-on implementation.

## Limitations and Privacy

- The scorer uses rules rather than a trained machine-learning model.
- It may miss sophisticated phishing emails or flag legitimate messages.
- It does not follow links, download attachments, or prove whether a sender is trustworthy.
- Email content is analyzed by the add-on's local scoring function. The separately deployed API receives email content only when a client explicitly sends a request to it.
- This project is a demonstration and should not be treated as a replacement for email security controls.

## Technology Stack

- Google Apps Script and Gmail Add-ons
- JavaScript
- Node.js
- Express

## Deployment

The backend is deployed at:

https://gmail-add-on-project.onrender.com

Health endpoint:

https://gmail-add-on-project.onrender.com/health
