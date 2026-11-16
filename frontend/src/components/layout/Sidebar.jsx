import clsx from "clsx";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronsLeft, ChevronsRight, X } from "lucide-react";

// Grouped nav — same route ids/roles as before, organized into the
// four sections CipherQ's identity is built around (Command / Security
// / Intelligence / Quantum) so Quantum reads as a first-class pillar
// of the product rather than a single buried menu item. No route,
// role check, or feature was removed or renamed — only regrouped and
// relabeled for display.
const NAV_GROUPS = [
  {
    heading: "Command",
    items: [{ id: "dashboard", label: "Overview", icon: "grid_view" }],
  },
  {
    heading: "Security",
    items: [
      { id: "face-test", label: "Identity", icon: "face" },
      { id: "visualize", label: "Risk Intelligence", icon: "radar" },
      { id: "audit", label: "Audit", icon: "policy" },
    ],
  },
  {
    heading: "Intelligence",
    items: [
      { id: "intent-history", label: "Intent History", icon: "history" },
      { id: "create-intent", label: "Create Intent", icon: "center_focus_strong" },
    ],
  },
  {
    heading: "Quantum",
    items: [
      { id: "encrypt", label: "Encryption", icon: "lock" },
      { id: "decrypt", label: "Decryption", icon: "lock_open" },
      { id: "sharing", label: "Secure Share", icon: "share" },
      { id: "direct-messages", label: "Direct Messages", icon: "forum" },
      { id: "bb84", label: "Quantum Lab", icon: "hub" },
    ],
  },
];

// Admin-only nav entries: shown only when the authenticated user's
// role permits it (server-side enforcement lives in the backend
// RBAC/rbac.py — this is purely a UI convenience, never the actual
// authorization boundary).
const ADMIN_NAV = [{ id: "admin", label: "Admin Dashboard", icon: "admin_panel_settings" }];
const ADMIN_ROLES = new Set(["ADMIN", "USER_LEVEL_2"]);

// Auth responses are persisted exactly as returned by the API. Normalize the
// display role before applying navigation visibility so harmless casing or
// surrounding whitespace cannot make an administrator lose the workspace
// navigation after opening the Admin Dashboard. This is presentation only;
// every protected operation continues to be authorized by the backend.
function normalizeRole(role) {
  return String(role ?? "").trim().toUpperCase();
}

// Policy Engine is ADMIN-ONLY (fix pass section D) — deliberately not
// in `ADMIN_ROLES`/`ADMIN_NAV` above, which also include
// USER_LEVEL_2. This is UI convenience only: direct URL access by a
// non-admin is still rejected by the backend (`GET/POST/PUT/DELETE
// /api/policies` all require ADMIN, see api/routers/policies.py).
const POLICY_NAV = [{ id: "policies", label: "Policy Engine", icon: "gavel" }];

function NavItem({ item, currentPage, navigate, collapsed, onNavigate }) {
  const active = currentPage === item.id;
  return (
    <button
      onClick={() => {
        navigate(item.id);
        onNavigate?.();
      }}
      title={collapsed ? item.label : undefined}
      className={clsx(
        "group relative w-full flex items-center px-cq-stack-md py-3 rounded-cq-md transition-all",
        collapsed && "justify-center px-0",
        active
          ? "bg-cq-primary-container/20 text-cq-primary font-bold"
          : "text-cq-on-surface-variant hover:bg-cq-surface-container-highest hover:text-cq-on-surface"
      )}
    >
      {active && (
        <motion.span
          layoutId="sidebar-active-bar"
          className="absolute right-0 top-1.5 bottom-1.5 w-[2px] rounded-full bg-cq-primary"
        />
      )}
      <span className={clsx("material-symbols-outlined text-[20px]", !collapsed && "mr-3")}>{item.icon}</span>
      {!collapsed && (
        <span className="font-label-md text-cq-label-md uppercase tracking-widest truncate">{item.label}</span>
      )}
    </button>
  );
}

export default function Sidebar({ currentPage, navigate, collapsed, setCollapsed, mobileOpen, setMobileOpen, user, monitoringBlocked }) {
  const role = normalizeRole(user?.role);
  const isAdmin = ADMIN_ROLES.has(role);
  const isFullAdmin = role === "ADMIN";

  // Keep the complete application workspace visible for administrators at
  // all times, including while their monitoring session is waiting for
  // re-authentication. Monitoring still gates the actual protected actions;
  // it must not remove the navigation entry points from the admin's UI.
  // Non-admin users retain the existing monitoring-based menu behavior.
  const groups = NAV_GROUPS.map((g) => ({
    ...g,
    items: monitoringBlocked && !isAdmin
      ? g.items.filter((item) => !["create-intent", "intent-history"].includes(item.id))
      : [...g.items],
  })).filter((g) => g.items.length > 0);

  // The admin workspace always exposes the standard application modules:
  // Overview, Identity, Risk Intelligence, Audit, Intent History, Create
  // Intent, Encryption, Decryption, Secure Share, Direct Messages and
  // Quantum Lab. The only additional role-gated item is Policy Engine.
  // Admin Dashboard remains a separate destination, not a replacement for
  // the rest of CipherQ.
  if (isFullAdmin) {
    groups.push({ heading: "Governance", items: [...POLICY_NAV, ...ADMIN_NAV] });
  } else if (isAdmin) {
    groups.push({ heading: "Governance", items: [...ADMIN_NAV] });
  }

  const content = (
    <div className="cq-glass-sidebar flex h-full flex-col pt-cq-stack-lg pb-cq-stack-lg">
      {/* Brand */}
      <div className={clsx("flex items-center gap-cq-stack-sm px-cq-stack-lg mb-8", collapsed && "justify-center px-0")}>
        <div className="relative flex items-center justify-center w-8 h-8 rounded-cq-md bg-cq-primary-container shadow-cq-glow-primary shrink-0">
          <span className="material-symbols-outlined text-[18px] text-cq-on-primary-container">shield_lock</span>
          <span className="absolute inset-0 rounded-cq-md cq-orbit-cw opacity-40" aria-hidden="true">
            <span className="absolute -top-0.5 left-1/2 w-0.5 h-0.5 rounded-full bg-cq-secondary" />
          </span>
        </div>
        {!collapsed && (
          <span className="font-headline-md text-cq-headline-md text-cq-on-surface tracking-tight">CipherQ</span>
        )}
        <button
          className="ml-auto hidden lg:inline-flex items-center justify-center w-7 h-7 rounded-cq-sm text-cq-on-surface-variant hover:bg-cq-surface-container-highest transition-colors"
          onClick={() => setCollapsed((v) => !v)}
        >
          {collapsed ? <ChevronsRight size={15} /> : <ChevronsLeft size={15} />}
        </button>
        <button
          className="ml-auto lg:hidden inline-flex items-center justify-center w-7 h-7 rounded-cq-sm text-cq-on-surface-variant hover:bg-cq-surface-container-highest"
          onClick={() => setMobileOpen(false)}
        >
          <X size={16} />
        </button>
      </div>

      {/* Nav — grouped into CipherQ's visual pillars (Command / Security /
          Intelligence / Quantum [/ Governance for admins]) rather than one
          flat list, so Quantum reads as first-class rather than buried. */}
      <nav className="flex-1 overflow-y-auto cq-no-scrollbar px-cq-stack-md flex flex-col gap-4">
        {groups.map((group) => (
          <div key={group.heading}>
            {!collapsed && (
              <div className="px-cq-stack-md mb-1.5 text-[10px] font-bold tracking-[0.2em] text-cq-on-surface-variant/50 uppercase">
                {group.heading}
              </div>
            )}
            <div className="flex flex-col gap-1">
              {group.items.map((item) => (
                <NavItem
                  key={item.id}
                  item={item}
                  currentPage={currentPage}
                  navigate={navigate}
                  collapsed={collapsed}
                  onNavigate={() => setMobileOpen(false)}
                />
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* System status + Settings, pinned bottom */}
      <div className="mt-auto border-t border-cq-outline-variant/20 pt-3 px-cq-stack-md">
        {!collapsed && (
          <div className="flex items-center gap-2 px-cq-stack-md py-2 mb-1">
            <span className="w-1.5 h-1.5 rounded-full bg-cq-secondary cq-telemetry-dot shadow-cq-dot-secondary" />
            <span className="text-[10px] font-bold tracking-[0.18em] text-cq-secondary uppercase">System Secure</span>
          </div>
        )}
        <NavItem
          item={{ id: "settings", label: "Settings", icon: "settings" }}
          currentPage={currentPage}
          navigate={navigate}
          collapsed={collapsed}
          onNavigate={() => setMobileOpen(false)}
        />
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop sidebar — Stitch spec is a fixed 280px rail; kept collapsible
          (existing IBQC feature) rather than removed, per "do not remove features". */}
      <motion.aside
        animate={{ width: collapsed ? 76 : 280 }}
        transition={{ duration: 0.22, ease: "easeInOut" }}
        className="hidden lg:block fixed left-0 top-0 h-screen z-50 overflow-hidden"
      >
        {content}
      </motion.aside>

      {/* Mobile drawer */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/40 z-40 lg:hidden"
              onClick={() => setMobileOpen(false)}
            />
            <motion.aside
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ duration: 0.24, ease: "easeOut" }}
              className="fixed left-0 top-0 h-screen w-[82vw] max-w-[280px] z-50 lg:hidden"
            >
              {content}
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
