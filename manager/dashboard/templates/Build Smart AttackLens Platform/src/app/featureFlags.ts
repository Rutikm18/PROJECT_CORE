/**
 * Single source of truth for "not built yet" features, so a page's nav badge,
 * its placeholder, and anything elsewhere that depends on it (e.g. Dashboard's
 * CIS heatmap widget) flip together when the feature ships — never edit one
 * without the other.
 */
export const CIS_COMPLIANCE_LIVE = false;

/**
 * Customer portal (/portal) and its provisioning tab in Settings.
 *
 * The whole feature is built and tested — scoped data, a separate principal,
 * licence issuing, invites — but it is held behind this flag until we are ready
 * to put a real customer on it. Flipping this to true also needs
 * ATTACKLENS_CUSTOMER_PORTAL=true on the manager, or the pages will render
 * against routes that are not registered.
 */
export const CUSTOMER_PORTAL_LIVE = false;
