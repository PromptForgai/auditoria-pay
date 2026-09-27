// extraction.js — extraction structurée via l'API Claude
// Prend un document (texte déjà extrait du PDF, ou lignes CSV) et renvoie des champs normalisés.
// Le modèle ne "décide" jamais des alertes : il ne fait qu'extraire des données factuelles,
// que le moteur de règles (rules.js) comparera ensuite. Ça évite qu'une hallucination du LLM
// ne devienne directement une alerte affichée au client.

const SCHEMAS = {
  invoice: `{
  "invoice_number": string|null,
  "supplier_name": string|null,
  "supplier_iban": string|null,
  "po_number": string|null,
  "amount": number,            // montant TTC, en unité décimale (ex: 3240.50)
  "currency": string,          // ex: "EUR"
  "invoice_date": string|null, // ISO 8601 (YYYY-MM-DD)
  "due_date": string|null
}`,
  purchase_order: `{
  "po_number": string,
  "supplier_name": string|null,
  "amount": number,
  "currency": string,
  "order_date": string|null
}`,
  contract: `{
  "contract_ref": string|null,
  "supplier_name": string|null,
  "amount": number|null,
  "currency": string,
  "start_date": string|null,
  "end_date": string|null,
  "auto_renew": boolean
}`,
  bank_statement: `{
  "transactions": [
    {
      "tx_date": string,        // ISO 8601
      "amount": number,         // négatif = sortie, positif = entrée
      "counterparty_name": string|null,
      "counterparty_iban": string|null,
      "label": string|null
    }
  ]
}`
};

/**
 * @param {string} kind 'invoice' | 'purchase_order' | 'contract' | 'bank_statement'
 * @param {{ text?: string, pdfBase64?: string }} input soit du texte brut (CSV, texte déjà extrait),
 *        soit un PDF encodé en base64 (Claude lit le PDF nativement, pas besoin de parser à part)
 * @param {string} apiKey clé API Anthropic (env.ANTHROPIC_API_KEY)
 */
export async function extractDocument(kind, input, apiKey) {
  const schema = SCHEMAS[kind];
  if (!schema) throw new Error(`Type de document inconnu: ${kind}`);

  const system = `Tu extrais des données financières factuelles d'un document. ` +
    `Réponds UNIQUEMENT avec un objet JSON valide correspondant exactement à ce schéma, sans texte autour, sans balises markdown:\n${schema}\n` +
    `Si une valeur est absente du document, mets null (jamais une valeur inventée). ` +
    `N'ajoute aucun champ, aucun commentaire, aucune interprétation.`;

  const content = input.pdfBase64
    ? [
        { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: input.pdfBase64 } },
        { type: 'text', text: 'Extrait les champs demandés de ce document.' }
      ]
    : (input.text || '').slice(0, 60000);

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1024,
      system,
      messages: [{ role: 'user', content }]
    })
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Échec extraction Claude (${res.status}): ${errText}`);
  }

  const data = await res.json();
  const textBlock = data.content.find(b => b.type === 'text');
  if (!textBlock) throw new Error('Réponse du modèle sans bloc texte');

  const cleaned = textBlock.text.replace(/```json|```/g, '').trim();
  let parsed;
  try {
    parsed = JSON.parse(cleaned);
  } catch (e) {
    throw new Error(`JSON invalide renvoyé par le modèle: ${cleaned.slice(0, 300)}`);
  }

  return parsed;
}
