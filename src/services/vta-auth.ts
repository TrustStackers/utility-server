/**
 * Re-exports from the canonical shared VTA auth service.
 * All challenge/response logic lives in ../../src/services/vta-auth.ts.
 *
 * This file was previously a SQLite-only duplicate (~156 lines).
 * It now serves as a thin re-export so existing import paths continue to work.
 */

export {
  issueChallenge,
  verifyChallenge,
  VtaAuthValidationError,
  VtaAuthNotFoundError,
} from '@p2p-trust-stack/core/services/vta-auth.js';

export type {
  IssueChallengeInput,
  IssueChallengeResult,
  VerifyChallengeInput,
  VerifyChallengeResult,
} from '@p2p-trust-stack/core/services/vta-auth.js';
