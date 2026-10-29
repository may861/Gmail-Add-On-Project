
const express = require("express");
const { analyzeEmail } = require("./scorer");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "100kb" }));

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "Malicious Email Scorer API"
  });
});

app.post("/analyze", (req, res) => {
  const email = req.body;

  if (!email || typeof email !== "object" || Array.isArray(email)) {
    return res.status(400).json({
      error: "Request body must be a JSON object."
    });
  }

  for (const field of ["subject", "sender", "body"]) {
    if (typeof email[field] !== "string") {
      return res.status(400).json({
        error: `The '${field}' field must be a string.`
      });
    }

    if (email[field].length > 20000) {
      return res.status(400).json({
        error: `The '${field}' field is too long.`
      });
    }
  }

  if (
    email.attachments !== undefined &&
    (
      !Array.isArray(email.attachments) ||
      email.attachments.length > 30 ||
      !email.attachments.every(
        item => typeof item === "string" && item.length <= 255
      )
    )
  ) {
    return res.status(400).json({
      error: "'attachments' must be an array of filename strings."
    });
  }

  const input = {
    subject: email.subject,
    sender: email.sender,
    body: email.body,
    attachments: email.attachments || []
  };

  try {
    const result = analyzeEmail(input);
    return res.json(result);
  } catch (error) {
    console.error("Email analysis failed:", error.message);
    return res.status(500).json({
      error: "Email analysis failed."
    });
  }
});


app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});