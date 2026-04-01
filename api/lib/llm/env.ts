/**
 * Environment Variable Normalization
 *
 * Re-exports the shared normalization utility from env-validation.ts.
 * LLM-specific env var handling uses the same normalization as GitHub App
 * env vars — strips whitespace, removes matching quote pairs, returns
 * undefined for empty strings.
 */

export { normalizeEnvString } from "../env-validation.js";
