/**
 * Environment Variable Normalization
 *
 * Re-exports normalizeEnvString from its canonical location in env-validation.ts.
 * The canonical module is used for all environment variable normalization across
 * the codebase, including both GitHub App bootstrap and LLM provider configuration.
 */

export { normalizeEnvString } from "../env-validation.js";
