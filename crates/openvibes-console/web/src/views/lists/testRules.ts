// The test-trigger rules (platform rules::TEST_RULES): harmless events
// raised on purpose by `openvibes-test`. Only these exact pairs count.
const TEST_RULES = new Set(["baseline-alarms/alarm.openvibes.test", "baseline/test.openvibes.running"]);

export const isTest = (ruleSet: string, rule: string) => TEST_RULES.has(`${ruleSet}/${rule}`);
