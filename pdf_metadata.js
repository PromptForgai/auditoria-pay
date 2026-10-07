// pdf_metadata.js — lecture best-effort des métadonnées /Producer et /Creator d'un PDF, pour repérer
// un document financier (facture, bon de commande, contrat) produit ou retouché avec un logiciel
// d'édition d'image plutôt qu'un vrai logiciel de comptabilité/bureautique.
//
// Limite assumée et documentée : ceci scanne le texte brut du fichier à la recherche des motifs
// standards `/Producer (...)` et `/Creator (...)`. Ça couvre la grande majorité des PDF réels, mais
// pas ceux dont les métadonnées sont enfermées dans un flux d'objets compressé (PDF récents avec
// /ObjStm) ou encodées en UTF-16. C'est un indice supplémentaire, pas une analyse forensique
// exhaustive — l'absence de résultat ne prouve rien, la présence d'un logiciel suspect si.

// Un PDF peut contenir PLUSIEURS /Producer (une mise à jour incrémentale en ajoute un nouveau sans
// retirer l'ancien) : exactement le cas d'un document légitime rouvert et modifié dans un éditeur
// d'image après coup. On capture donc toutes les occurrences, pas seulement la première.
function extractAll(text, key) {
  const re = new RegExp(`/${key}\\s*\\(((?:[^()\\\\]|\\\\.)*)\\)`, 'g');
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const unescaped = m[1].replace(/\\\(/g, '(').replace(/\\\)/g, ')').replace(/\\\\/g, '\\');
    if (unescaped.trim()) out.push(unescaped.trim());
  }
  return out;
}

export function extractPdfInfo(buffer) {
  // latin1 : correspondance un octet = un caractère, sûre pour repérer des motifs ASCII même dans un
  // fichier par ailleurs binaire (les mots-clés de structure PDF sont toujours en ASCII).
  const text = new TextDecoder('latin1').decode(buffer);
  const producers = extractAll(text, 'Producer');
  const creators = extractAll(text, 'Creator');
  return {
    // Toutes les valeurs trouvées, dans l'ordre d'apparition dans le fichier (utile pour voir une
    // chaîne d'outils : "LibreOffice" puis "Adobe Photoshop" trahit une retouche après coup).
    producer: producers.length ? producers.join(' | ').slice(0, 300) : null,
    creator: creators.length ? creators.join(' | ').slice(0, 300) : null
  };
}

// Logiciels d'édition d'image/graphisme : légitimes pour un visuel, pas pour une facture/BC/contrat
// qui doit normalement sortir d'un logiciel de comptabilité, de bureautique, ou d'une imprimante PDF.
const IMAGE_EDITOR_PATTERNS = [
  /photoshop/i, /gimp/i, /illustrator/i, /affinity\s*(photo|designer)/i,
  /paint\.?net/i, /pixlr/i, /canva/i, /corel\s*draw/i, /inkscape/i
];

export function looksLikeImageEditor(value) {
  if (!value) return false;
  return IMAGE_EDITOR_PATTERNS.some(re => re.test(value));
}
