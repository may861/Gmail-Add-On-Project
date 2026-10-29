
function onGmailMessageOpen(e) {
  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Malicious Email Scorer")
        .setSubtitle("Analyze the opened message")
    );

  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText("Check this email for suspicious signals.")
    )
    .addWidget(
      CardService.newTextButton()
        .setText("Analyze email")
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName("analyzeCurrentEmail")
        )
    );

  card.addSection(section);
  return card.build();
}

function analyzeCurrentEmail(e) {
  const messageId = e.gmail && e.gmail.messageId;

  if (!messageId || !e.gmail.accessToken) {
    return showMessage("Could not access the opened email. Reopen it and try again.");
  }

  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(messageId);

  if (!message) {
    return showMessage("Could not read the opened email.");
  }

  const email = {
    subject: message.getSubject() || "",
    sender: message.getFrom() || "",
    body: message.getPlainBody() || "",
    attachments: message.getAttachments().map(function (a) {
      return a.getName() || "";
    })
  };

  const result = scoreEmail(email);
  return showAnalysisCard(email, result);
}

function scoreEmail(email) {
  const text = (email.subject + "\n" + email.body).toLowerCase();
  const findings = [];
  let score = 0;

  function add(id, label, points, evidence) {
    score += points;
    findings.push({ id: id, label: label, points: points, evidence: evidence });
  }

  if (/\b(urgent|immediately|act now|final warning|account will be suspended|expires today)\b/i.test(text)) {
    add("urgency", "Urgent or threatening language", 15,
      "The message pressures the recipient to act quickly.");
  }

  if (/\b(password|passcode|one-time code|verification code|login credentials)\b/i.test(text) &&
      /\b(confirm|verify|send|share|provide|enter|reset)\b/i.test(text)) {
    add("credential_request", "Possible credential theft", 25,
      "Authentication-related terms appear alongside a request to take action.");
  }

  if (/\b(gift card|wire transfer|bank details|payment overdue|send payment)\b/i.test(text)) {
    add("financial_request", "Potentially risky financial request", 20,
      "The message mentions a financial action commonly abused in scams.");
  }

  const urls = email.body.match(/https?:\/\/[^\s<>"']+/gi) || [];
  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"];
  let hasShortener = false;
  let hasUnusualHost = false;

  urls.forEach(function (rawUrl) {
    try {
      const host = new URL(rawUrl.replace(/[),.!?;]+$/g, "")).hostname.toLowerCase();
      if (shorteners.indexOf(host) !== -1) hasShortener = true;
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ||
          host.startsWith("xn--") || host.includes(".xn--")) {
        hasUnusualHost = true;
      }
    } catch (err) {
      // Ignore malformed URLs.
    }
  });

  if (hasShortener) {
    add("shortened_url", "Shortened link detected", 10,
      "A known URL-shortening service hides the link's final destination.");
  }

  if (hasUnusualHost) {
    add("unusual_host", "Unusual link destination", 20,
      "A link uses an IP address or internationalized hostname.");
  }

  const risky = /\.(exe|scr|bat|cmd|com|js|vbs|ps1|msi|hta|jar)$/i;
  if (email.attachments.some(function (name) { return risky.test(name); })) {
    add("risky_attachment", "Potentially dangerous attachment", 20,
      "An attachment has an executable or script-related extension.");
  }

  score = Math.min(score, 100);

  return {
    score: score,
    verdict: score >= 60 ? "High Risk" : score >= 30 ? "Suspicious" : "Low Risk",
    findings: findings,
    disclaimer: "Rules-based estimate only; this is not proof that an email is malicious."
  };
}

function showAnalysisCard(email, result) {
  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Risk Analysis")
        .setSubtitle(result.verdict + " — Score: " + result.score + "/100")
    );

  const section = CardService.newCardSection()
    .addWidget(
      CardService.newKeyValue()
        .setTopLabel("Subject")
        .setContent(email.subject || "(No subject)")
    );

  if (result.findings.length) {
    section.addWidget(
      CardService.newTextParagraph().setText("<b>Reasons detected</b>")
    );

    result.findings.forEach(function (f) {
      section.addWidget(
        CardService.newTextParagraph().setText(
          "<b>" + escapeHtml(f.label) + "</b> (+" + f.points + " points)<br>" +
          escapeHtml(f.evidence)
        )
      );
    });
  } else {
    section.addWidget(
      CardService.newTextParagraph()
        .setText("No configured risk signals were detected.")
    );
  }

  section.addWidget(
    CardService.newTextParagraph().setText(escapeHtml(result.disclaimer))
  );

  card.addSection(section);
  return card.build();
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function showMessage(text) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text))
    .build();
}

function authorizeExternalRequest() {
  UrlFetchApp.fetch(
    "https://gmail-add-on-project.onrender.com/health"
  );
}
