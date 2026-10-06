-- Original P17 evidence lives with its observation, never with current inventory.
ALTER TABLE findings ADD COLUMN detection jsonb;
ALTER TABLE current_findings ADD COLUMN detection jsonb;
ALTER TABLE alarms ADD COLUMN detection jsonb;
