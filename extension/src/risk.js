// Combines rule-tier signals into one risk score. The ML tier plugs in here: scoreWithModel() will
// run a small ONNX model (URL char-CNN first, page-content model later) in an offscreen document and
// return a calibrated probability, which is fused with the rule score. Until then it returns null.
export async function scoreWithModel(/* features */) {
  return null; // TODO: onnxruntime-web in offscreen document; model under 10MB; calibrated output
}

export function fuse(ruleScore, modelProb) {
  if (modelProb == null) return ruleScore;
  // Noisy-OR: either tier being confident is enough; both weak stays weak.
  return 1 - (1 - ruleScore) * (1 - modelProb);
}
