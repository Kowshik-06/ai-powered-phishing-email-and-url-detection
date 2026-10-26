// Curated, verified glossary used by the explanation UI.
// Only terms with a definition here are annotated. If a term is not listed,
// it is rendered as plain text rather than given an invented meaning.

export const GLOSSARY = {
  'phishing': 'A scam that tries to trick you into revealing passwords, payment details, or personal information, often by pretending to be a trusted service.',
  'legitimate': 'In this app, the detector\'s final verdict that no strong phishing signals were found. It does not guarantee that the item is safe.',
  'suspicious': 'Some signals look risky, but the evidence is not strong enough for a confident phishing verdict.',
  'review': 'The scanner could not make a confident automatic decision, so a person should check the item.',
  'hostname': 'The part of a web address that identifies the site, such as example.com in https://example.com/login.',
  'subdomain': 'An extra label in front of the main domain, such as mail in mail.example.com.',
  'spoofing': 'Pretending to be a trusted person, brand, or website in order to mislead you.',
  'trusted domain': 'A hostname on a short built-in list that receives a low-risk override. The list can be incomplete, and trust does not guarantee every page on the hostname is safe.',
  'decision source': 'The part of the detector that made the final call, such as the trained model, a trusted-domain rule, or a review rule.',
  'model score': 'A number produced by the trained model. It is not automatically a probability that the item is malicious.',
  'model prediction': 'The label produced by the trained model before any rule override.',
  'risk score': 'The detector\'s final risk figure after any rule overrides. It is not a guarantee of safety or maliciousness.',
  'confidence': 'In this app, a measure of how far the model\'s raw score is from the 50% decision boundary. It is not a calibrated probability that the verdict is correct.',
  'calibration': 'A process that turns raw model scores into reliable probabilities. The scores in this app have not been calibrated.',
  'ensemble': 'A combination of several models\' scores. This app weights HistGradientBoosting 80%, Random Forest 10%, and the deep-learning model 10%.',
  'outside training range': 'The input contains a property outside the range seen during model training, so the model output may be unreliable and the item is marked for review.',
  'false positive': 'A warning that turns out to be wrong: something is flagged as unsafe but is actually harmless.',
  'false negative': 'A missed warning: something unsafe is not flagged.',
  'https': 'A secure connection between your browser and a website. It protects data in transit but does not prove the site is trustworthy.',
  'punycode': 'An encoding used for international domain names. Attackers can use it to create look-alike addresses.',
  'idn': 'Internationalized Domain Name: a domain name that uses non-English characters. It can be abused for look-alike attacks.',
  'qr code': 'A square barcode that can contain a web address or other text. This scanner decodes it and checks URLs with the URL detector.',
  'attachment': 'A file sent with a message. This scanner inspects the file type, visible bytes, and embedded links; it does not run the file.',
  'executable': 'A file that can run code on your computer, such as .exe or .bat.',
  'macro': 'A script embedded in an Office document that can run automatically. Macro-enabled files can carry malware.',
  'ocr': 'Optical Character Recognition: software that extracts text from images.',
  'spf': 'An email authentication record that helps receiving servers check whether a sender is authorized. This app reads header values but does not verify them.',
  'dkim': 'An email signature standard. This app reads header presence but does not verify the signature.',
  'dmarc': 'An email policy standard that builds on SPF and DKIM. This app reads header values but does not verify them.',
  'dns': 'The system that translates domain names into IP addresses.',
  'rdap': 'Registration Data Access Protocol: a way to look up domain registration details.',
  'virustotal': 'An optional external reputation service. It is disabled unless a server-side API key is configured.',
};

export const GLOSSARY_TERMS = Object.keys(GLOSSARY).sort((a, b) => b.length - a.length);

export function glossaryDefinition(term) {
  if (typeof term !== 'string') return null;
  return GLOSSARY[term.toLowerCase()] || null;
}

export function hasGlossaryTerm(term) {
  return glossaryDefinition(term) !== null;
}
