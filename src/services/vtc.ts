/**
 * Re-exports from the canonical shared VTC/VTN service.
 * All VTC/VTN logic lives in ../../src/services/vtc.ts.
 *
 * This file was previously a duplicate of src/services/vtc.ts (~536 lines).
 * It now serves as a thin re-export so existing import paths continue to work.
 */

export {
  createVtc,
  listVtcs,
  checkCommunityNameAvailable,
  mintMembershipVmc,
  joinCommunityByDid,
  affiliateVtc,
  unaffiliateVtc,
  getVtnHierarchy,
  resolveEffectivePolicy,
  CREDENTIAL_TYPES,
  validateCredentialType,
  CreateVtcValidationError,
  CreateVtcNotFoundError,
  CreateVtcConflictError,
  AffiliateCycleError,
} from '@p2p-trust-stack/core/services/vtc.js';

export type {
  VtcKind,
  CreateVtcInput,
  CreateVtcResult,
  VtcListItem,
  VtnHierarchyChildVtc,
  VtnHierarchyResult,
  EffectivePolicyLevel,
  EffectivePolicyResult,
} from '@p2p-trust-stack/core/services/vtc.js';
