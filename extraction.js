// extraction.js — extraction structurée via l'API Gemini (Google AI Studio).
// Choisi pour son vrai tier gratuit sans carte bancaire (contrairement à Anthropic/OpenAI qui
// exigent un compte payant ou n'offrent qu'un petit crédit d'essai qui expire).
// Prend un document (texte déjà extrait du PDF, ou lignes CSV) et renvoie des champs normalisés.
// Le modèle ne "décide" jamais des alertes : il ne fait qu'extraire des données factuelles,
// que le moteur de règles (rules.js) comparera ensuite. Ça évite qu'une hallucination du LLM
// ne devienne directement une alerte affichée au client.
//
// GEMINI_MODEL : vérifie sur https://ai.google.dev/gemini-api/docs/pricing lequel est marqué
// "Free of charge" au moment où tu déploies — la liste des modèles gratuits change avec le temps.
// gemini-2.5-flash est gratuit au moment où ce fichier a été écrit (sept. 2026).

const GEMINI_MODEL = 'gemini-2.5-flash';
const GEMINI_API = 'https://generativelanguage.googleapis.com/v1beta/models';

// Schémas au format attendu par responseSchema de Gemini (sous-ensemble d'OpenAPI/JSON Schema).
// C'est Gemini lui-même qui garantit la forme de la réponse — pas un parsing "à l'aveugle" d'un
// texte qui pourrait contenir des balises markdown ou du texte parasite.
const SCHEMAS = {
  invoice: {
    type: 'object',
    properties: {
      invoice_number: { type: 'string', nullable: true },
      supplier_name: { type: 'string', nullable: true },
      supplier_iban: { type: 'string', nullable: true },
      po_number: { type: 'string', nullable: true },
      amount: { type: 'number', description: 'Montant TTC, en unité décimale (ex: 3240.50)' },
      currency: { type: 'string', description: 'Ex: EUR' },
      invoice_date: { type: 'string', nullable: true, description: 'ISO 8601 (YYYY-MM-DD)' },
      due_date: { type: 'string', nullable: true }
    },
    required: ['amount', 'currency']
  },
  purchase_order: {
    type: 'object',
    properties: {
      po_number: { type: 'string' },
      supplier_name: { type: 'string', nullable: true },
      amount: { type: 'number' },
      currency: { type: 'string' },
      order_date: { type: 'string', nullable: true }
    },
    required: ['po_number', 'amount', 'currency']
  },
  contract: {
    type: 'object',
    properties: {
      contract_ref: { type: 'string', nullable: true },
      supplier_name: { type: 'string', nullable: true },
      amount: { type: 'number', nullable: true },
      currency: { type: 'string' },
      start_date: { type: 'string', nullable: true },
      end_date: { type: 'string', nullable: true },
      auto_renew: { type: 'boolean' }
    },
    required: ['currency']
  },
  bank_statement: {
    type: 'object',
    properties: {
      transactions: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            tx_date: { type: 'string', description: 'ISO 8601' },
            amount: { type: 'number', description: 'négatif = sortie, positif = entrée' },
            counterparty_name: { type: 'string', nullable: true },
            counterparty_iban: { type: 'string', nullable: true },
            label: { type: 'string', nullable: true }
          },
          required: ['tx_date', 'amount']
        }
      }
    },
    required: ['transactions']
  }
};

/**
 * @param {string} kind 'invoice' | 'purchase_order' | 'contract' | 'bank_statement'
 * @param {{ text?: string, pdfBase64?: string }} input soit du texte brut (CSV, texte déjà extrait),
 *        soit un PDF encodé en base64 (Gemini lit le PDF nativement, pas besoin de parser à part)
 * @param {string} apiKey clé API Gemini (env.GEMINI_API_KEY, générée sur aistudio.google.com)
 */
export async function extractDocument(kind, input, apiKey) {
  const schema = SCHEMAS[kind];
  if (!schema) throw new Error(`Type de document inconnu: ${kind}`);

  const instruction = 'Tu extrais des données financières factuelles de ce document. ' +
    'Si une valeur est absente du document, mets null (jamais une valeur inventée). ' +
    "N'ajoute aucun champ, aucun commentaire, aucune interprétation.";

  const parts = input.pdfBase64
    ? [
        { text: instruction },
        { inline_data: { mime_type: 'application/pdf', data: input.pdfBase64 } }
      ]
    : [{ text: instruction + '\n\nDocument:\n' + (input.text || '').slice(0, 60000) }];

  const res = await fetch(`${GEMINI_API}/${GEMINI_MODEL}:generateContent`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': apiKey
    },
    body: JSON.stringify({
      contents: [{ parts }],
      generationConfig: {
        responseMimeType: 'application/json',
        responseSchema: schema
      }
    })
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Échec extraction Gemini (${res.status}): ${errText}`);
  }

  const data = await res.json();
  const candidate = data.candidates && data.candidates[0];
  const textPart = candidate && candidate.content && candidate.content.parts && candidate.content.parts.find(p => p.text);
  if (!textPart) throw new Error('Réponse du modèle sans contenu exploitable');

  let parsed;
  try {
    parsed = JSON.parse(textPart.text);
  } catch (e) {
    throw new Error(`JSON invalide renvoyé par le modèle: ${textPart.text.slice(0, 300)}`);
  }

  return parsed;
}
