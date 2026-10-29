
function onGmailMessageOpen(e) {
  const card = CardService.newCardBuilder();

  const header = CardService.newCardHeader()
    .setTitle("Malicious Email Scorer")
    .setSubtitle("Analyze the currently opened email");

  const analyzeAction = CardService.newAction()
    .setFunctionName("analyzeCurrentEmail");

  const analyzeButton = CardService.newTextButton()
    .setText("Analyze email")
    .setOnClickAction(analyzeAction);

  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText(
          "Check the opened message for suspicious signals and receive an explainable risk score."
        )
    )
    .addWidget(analyzeButton);

  card.setHeader(header);
  card.addSection(section);

  return card.build();
}

function analyzeCurrentEmail(e) {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification()
        .setText("Email analysis will be connected to the scoring API next.")
    )
    .build();
}
