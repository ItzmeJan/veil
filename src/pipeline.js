/**
 * Pipeline: rules -> entropy -> model -> merge -> redact.
 *
 * Each stage is optional except the deterministic ones, so the tool still works
 * with the network off and no model pulled.
 */

import { detectWithRules } from './detectors.js';
import { detectHighEntropy } from './entropy.js';
import { detectWithModel } from './context.js';
import { mergeSpans, redact, residualRisk } from './redact.js';

/**
 * @param {string} text
 * @param {{client?: ReturnType<import('./model.js').createClient>, useModel?: boolean, mode?: 'placeholder'|'mask'}} [options]
 */
export async function scan(text, options = {}) {
  const started = Date.now();
  const ruleSpans = detectWithRules(text);
  const entropySpans = detectHighEntropy(text);

  let modelSpans = [];
  let modelError;
  let dropped = 0;

  if (options.useModel && options.client) {
    const result = await detectWithModel(options.client, text);
    modelSpans = result.spans;
    dropped = result.dropped;
    modelError = result.error;
  }

  const spans = mergeSpans([...ruleSpans, ...entropySpans, ...modelSpans]);
  const result = redact(text, spans, { mode: options.mode });
  const risk = residualRisk(text, spans);

  return {
    ...result,
    residual: risk,
    timingMs: Date.now() - started,
    model: options.useModel
      ? { used: true, dropped, error: modelError }
      : { used: false, dropped: 0 },
  };
}

export { detectWithRules, detectHighEntropy, detectWithModel, mergeSpans, redact };
