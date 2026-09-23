export function SeededBanner() {
  return (
    <aside className="seeded-banner" aria-label="Seeded development data">
      <span className="seeded-banner__label">Seeded environment</span>
      <span>Data shown here is deterministic demonstration data, not a production system.</span>
    </aside>
  );
}
