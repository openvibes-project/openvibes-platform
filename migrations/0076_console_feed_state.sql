-- The About and Vulnerabilities pages show how old the signed feed's data is
-- (spec section 8): the console role reads the accepted feed and the key that
-- signed it. Both hold ids, sequence numbers, dates and public keys only.
GRANT SELECT ON feed_state, feed_trust_keys TO "openvibes-console";
