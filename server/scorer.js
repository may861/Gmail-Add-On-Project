
const MAX_SCORE = 100;

function analyzeEmail(email) {
    const subject = email.subject || "";
    const sender = email.sender || "";
    const body = email.body || "";
    const attachments = Array.isArray(email.attachments)
        ? email.attachments
        : [];

    // Treat email content as untrusted text, not executable code.
    const text = `${subject}\n${body}`.toLowerCase();

    const findings = [];
    let score = 0;

    function addFinding(id, label, points, evidence) {
        score += points;
        findings.push({
            id,
            label,
            points,
            evidence
        });
    }

    // Urgency or threats.
    if (
        /\b(urgent|immediately|act now|final warning|account will be suspended|expires today)\b/i.test(text)
    ) {
        addFinding(
            "urgency",
            "Urgent or threatening language",
            15,
            "The message pressures the recipient to act quickly."
        );
    }

    // Requests for credentials or authentication secrets.
    if (
        /\b(password|passcode|one-time code|verification code|login credentials)\b/i.test(text) &&
        /\b(confirm|verify|send|share|provide|enter|reset)\b/i.test(text)
    ) {
        addFinding(
            "credential_request",
            "Possible credential theft",
            25,
            "The message combines authentication-related terms with a request to take action."
        );
    }

    // Requests involving money or payment details.
    if (
        /\b(gift card|wire transfer|bank details|payment overdue|send payment)\b/i.test(text)
    ) {
        addFinding(
            "financial_request",
            "Potentially risky financial request",
            20,
            "The message mentions a payment or financial action commonly abused in scams."
        );
    }

    // Examine URLs without opening or visiting them.
    const urls = body.match(/https?:\/\/[^\s<>"']+/gi) || [];
    const uniqueUrls = [...new Set(urls)].slice(0, 30);

    const shortenerDomains = new Set([
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly"
    ]);

    let foundShortener = false;
    let foundUnusualHost = false;

    for (const rawUrl of uniqueUrls) {
        // Remove common punctuation at the end of a URL.
        const cleanedUrl = rawUrl.replace(/[),.!?;]+$/g, "");

        try {
            const parsed = new URL(cleanedUrl);
            const hostname = parsed.hostname.toLowerCase();

            if (shortenerDomains.has(hostname)) {
                foundShortener = true;
            }

            // Flag IP-address URLs and internationalized hostnames for review.
            const isIPv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);

            if (isIPv4 || hostname.startsWith("xn--") || hostname.includes(".xn--")) {
                foundUnusualHost = true;
            }
        } catch {
            // Ignore malformed URLs rather than trusting or visiting them.
        }
    }

    if (foundShortener) {
        addFinding(
            "shortened_url",
            "Shortened link detected",
            10,
            "A link uses a known URL-shortening service, which hides its final destination."
        );
    }

    if (foundUnusualHost) {
        addFinding(
            "unusual_host",
            "Unusual link destination",
            20,
            "A link uses an IP address or an internationalized hostname that deserves closer inspection."
        );
    }

    //Potentially dangerous attachment extensions.
    const riskyExtensions = /\.(exe|scr|bat|cmd|com|js|vbs|ps1|msi|hta|jar)$/i;

    if (
        attachments.some(
            (item) =>
                typeof item === "string" && riskyExtensions.test(item)
        )
    ) {
        addFinding(
            "risky_attachment",
            "Potentially dangerous attachment",
            20,
            "An attachment filename has an executable or script-related extension."
        );
    }

    const finalScore = Math.min(score, MAX_SCORE);

    let verdict;
    if (finalScore >= 60) {
        verdict = "High Risk";
    } else if (finalScore >= 30) {
        verdict = "Suspicious";
    } else {
        verdict = "Low Risk";
    }

    return {
        score: finalScore,
        verdict,
        findings,
        analyzedSignals: [
            "urgency",
            "credential_request",
            "financial_request",
            "shortened_url",
            "unusual_host",
            "risky_attachment"
        ],
        disclaimer:
            "This is a rules-based risk estimate, not proof that a message is malicious."
    };
}

module.exports = { analyzeEmail };
