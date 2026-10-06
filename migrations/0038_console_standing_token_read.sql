-- OpenVIBES platform schema version 38: the console may read the standing
-- enrollment token's secret, so the agent install package it generates can
-- carry the token. Only users with the global tokens.create permission are
-- served it (the console checks); no other role gains access.
GRANT SELECT ON standing_token_secret TO "openvibes-console";
