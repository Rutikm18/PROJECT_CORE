/**
 * Single source of truth for "not built yet" features, so a page's nav badge,
 * its placeholder, and anything elsewhere that depends on it (e.g. Dashboard's
 * CIS heatmap widget) flip together when the feature ships — never edit one
 * without the other.
 */
export const CIS_COMPLIANCE_LIVE = false;
