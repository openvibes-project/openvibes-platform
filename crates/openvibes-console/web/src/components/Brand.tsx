type BrandProps = {
  compact: boolean;
};

export function Brand({ compact }: BrandProps) {
  return (
    <a className="brand" href="/" aria-label="OpenVIBES Console home" data-brand-status="placeholder">
      <span className="brand__mark" aria-hidden="true">
        <span className="brand__v">V</span>
        <span className="brand__signal">)))</span>
      </span>
      {!compact && (
        <span className="brand__wordmark" aria-hidden="true">
          <span className="brand__open">open</span>
          <span className="brand__vibes">VIBES</span>
        </span>
      )}
    </a>
  );
}
