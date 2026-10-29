## How It Works

The Malicious Email Scorer uses a Gmail add-on as its user interface and a Node.js/Express backend to analyze emails.

1. **Email selection:** The user opens an email in Gmail and clicks **Analyze email** in the add-on.
2. **Email extraction:** Google Apps Script reads the opened message's subject, sender, plain-text body, and attachment filenames, using the permissions granted to the add-on.
3. **Backend request:** The add-on sends these fields as a JSON request over HTTPS to the backend's `/analyze` endpoint.
4. **Rule-based analysis:** The backend evaluates the email against a set of predefined suspicious indicators. Each detected indicator contributes points to the risk score.
5. **Score and verdict:** The points are added together, with the final score capped at 100. The backend assigns a verdict based on the score range.
6. **Explainable result:** The backend returns the score, verdict, detected findings, and an explanatory message for each finding. The Gmail add-on displays these results to the user.

The analysis is heuristic and deterministic: the same input produces the same result under the same scoring rules. The system does not use a trained machine-learning model.

## Scoring Methodology

The scorer examines the email's subject and body for suspicious language, inspects URLs found in the body, and checks attachment filenames for potentially dangerous extensions. Each rule is evaluated independently, and its points are added when its condition is met.

| Indicator | Detection criteria | Points |
|---|---|---:|
| Urgent or threatening language | Contains phrases such as "urgent", "act now", "final warning", or "account will be suspended". | +15 |
| Possible credential theft | Contains authentication-related terms, such as "password", "passcode", or "verification code", together with an action term such as "verify", "confirm", "provide", or "enter". | +25 |
| Potentially risky financial request | Contains phrases such as "gift card", "wire transfer", "bank details", "payment overdue", or "send payment". | +20 |
| Shortened URL | Contains a link using a recognized shortening domain, such as `bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, or `cutt.ly`. | +10 |
| Unusual link destination | Contains a URL whose hostname is an IPv4 address or uses an internationalized hostname with the `xn--` prefix. | +20 |
| Potentially dangerous attachment | An attachment filename ends in an executable or script-related extension, including `.exe`, `.scr`, `.bat`, `.cmd`, `.com`, `.js`, `.vbs`, `.ps1`, `.msi`, `.hta`, or `.jar`. | +20 |

### Score Calculation and Verdicts

The score is the sum of all detected indicator points, capped at 100:

`Final score = min(sum of detected indicator points, 100)`

| Score range | Verdict | Interpretation |
|---|---|---|
| 0–29 | **Low Risk** | Few or no configured suspicious indicators were detected. |
| 30–59 | **Suspicious** | Multiple or higher-weight indicators warrant closer inspection. |
| 60–100 | **High Risk** | The configured indicators produced a high risk score. |

For example, an email containing urgent language (+15), a credential-related request (+25), and a shortened URL (+10) receives a score of **50/100 — Suspicious**.

The score represents the presence of configured indicators, not a statistically calibrated probability that the email is malicious. A message may be malicious even if none of the rules match, and legitimate messages may trigger one or more rules.

## Architecture

The system consists of two main components:

- **Gmail add-on (`gmail_addon/apps_script/`):** Provides the user interface, accesses the currently opened email, sends the analysis request, and displays the returned result.
- **Backend (`server/`):** The Express API validates the request, invokes the scoring rules, and returns a JSON response containing the score, verdict, findings, analyzed signals, and disclaimer.

The `GET /health` endpoint provides a basic service health check. The `POST /analyze` endpoint accepts the email fields and returns the analysis result.

## Security and Privacy Considerations

- The backend validates the request structure and limits the sizes of email fields and attachment lists.
- Email content is treated as untrusted input. The scorer does not execute email content, follow links, or open attachments.
- The add-on uses Google Apps Script permissions to access the currently opened email and sends the selected fields to the backend over HTTPS.
- Attachment analysis is limited to filenames; the actual attachment contents are not inspected.
- URL checks are heuristic and do not establish whether a website is safe.
- The score is intended to support user judgment, not replace Gmail's built-in protections or dedicated email security tools.

