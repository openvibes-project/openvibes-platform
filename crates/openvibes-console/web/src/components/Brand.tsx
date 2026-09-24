type BrandProps = {
  compact: boolean;
};

export function Brand({ compact }: BrandProps) {
  return (
    <a className="brand" href="/" aria-label="OpenVIBES Console home">
      {compact ? (
        <img className="brand__mark" src="/brand/openvibes-mark.svg" alt="" />
      ) : (
        <span className="brand__wordmark">
          <img
            className="brand__wordmark-light"
            src="/brand/openvibes-wordmark-light.svg"
            alt=""
          />
          <img
            className="brand__wordmark-dark"
            src="/brand/openvibes-wordmark-dark.svg"
            alt=""
          />
        </span>
      )}
    </a>
  );
}
