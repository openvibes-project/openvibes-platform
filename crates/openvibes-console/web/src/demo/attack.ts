// Demo ATT&CK catalog: the real 19.2 tactics and the techniques the demo
// rules use (the console bundles the full release server-side; the demo
// keeps the browser bundle small).
import type { AttackCatalog } from "../api/types";

export const demoAttack: AttackCatalog = {
  version: "19.2",
  notice: "MITRE ATT&CK, (c) The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.",
  tactics: [{"id": "TA0043", "name": "Reconnaissance", "phase": "Reconnaissance"}, {"id": "TA0042", "name": "Resource Development", "phase": "Weaponization"}, {"id": "TA0001", "name": "Initial Access", "phase": "Delivery"}, {"id": "TA0002", "name": "Execution", "phase": "Exploitation"}, {"id": "TA0003", "name": "Persistence", "phase": "Installation"}, {"id": "TA0004", "name": "Privilege Escalation", "phase": "Installation"}, {"id": "TA0005", "name": "Stealth", "phase": "Installation"}, {"id": "TA0112", "name": "Defense Impairment", "phase": "Installation"}, {"id": "TA0006", "name": "Credential Access", "phase": "Actions on Objectives"}, {"id": "TA0007", "name": "Discovery", "phase": "Actions on Objectives"}, {"id": "TA0008", "name": "Lateral Movement", "phase": "Actions on Objectives"}, {"id": "TA0009", "name": "Collection", "phase": "Actions on Objectives"}, {"id": "TA0011", "name": "Command and Control", "phase": "Command and Control"}, {"id": "TA0010", "name": "Exfiltration", "phase": "Actions on Objectives"}, {"id": "TA0040", "name": "Impact", "phase": "Actions on Objectives"}],
  techniques: [{"id": "T1003.008", "name": "/etc/passwd and /etc/shadow", "tactics": ["TA0006"]}, {"id": "T1021", "name": "Remote Services", "tactics": ["TA0008"]}, {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactics": ["TA0008"]}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactics": ["TA0008"]}, {"id": "T1021.004", "name": "SSH", "tactics": ["TA0008"]}, {"id": "T1021.005", "name": "VNC", "tactics": ["TA0008"]}, {"id": "T1021.006", "name": "Windows Remote Management", "tactics": ["TA0008"]}, {"id": "T1039", "name": "Data from Network Shared Drive", "tactics": ["TA0009"]}, {"id": "T1040", "name": "Network Sniffing", "tactics": ["TA0006", "TA0007"]}, {"id": "T1046", "name": "Network Service Discovery", "tactics": ["TA0007"]}, {"id": "T1053.003", "name": "Cron", "tactics": ["TA0002", "TA0003", "TA0004"]}, {"id": "T1056.001", "name": "Keylogging", "tactics": ["TA0009", "TA0006"]}, {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["TA0002"]}, {"id": "T1059.004", "name": "Unix Shell", "tactics": ["TA0002"]}, {"id": "T1078", "name": "Valid Accounts", "tactics": ["TA0005", "TA0003", "TA0004", "TA0001"]}, {"id": "T1082", "name": "System Information Discovery", "tactics": ["TA0007"]}, {"id": "T1095", "name": "Non-Application Layer Protocol", "tactics": ["TA0011"]}, {"id": "T1105", "name": "Ingress Tool Transfer", "tactics": ["TA0011"]}, {"id": "T1113", "name": "Screen Capture", "tactics": ["TA0009"]}, {"id": "T1133", "name": "External Remote Services", "tactics": ["TA0003", "TA0001"]}, {"id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["TA0001"]}, {"id": "T1496", "name": "Resource Hijacking", "tactics": ["TA0040"]}, {"id": "T1505.003", "name": "Web Shell", "tactics": ["TA0003"]}, {"id": "T1548.001", "name": "Setuid and Setgid", "tactics": ["TA0004"]}, {"id": "T1552.007", "name": "Container API", "tactics": ["TA0006"]}, {"id": "T1564", "name": "Hide Artifacts", "tactics": ["TA0005"]}, {"id": "T1602.001", "name": "SNMP (MIB Dump)", "tactics": ["TA0009"]}, {"id": "T1609", "name": "Container Administration Command", "tactics": ["TA0002"]}, {"id": "T1611", "name": "Escape to Host", "tactics": ["TA0004"]}],
};

type Pair = { tactic: string; technique?: string | null };
const p = (tactic: string, technique: string): Pair => ({ tactic, technique });

/** The demo rules' mappings, as in openvibes-rules (alarms use the demo's own ids). */
export const demoMappings: Record<string, Pair[]> = {
  "port.docker_api.exposed": [p("TA0002", "T1609"), p("TA0004", "T1611")],
  "port.telnet.exposed": [p("TA0001", "T1133"), p("TA0006", "T1040")],
  "port.rsh.exposed": [p("TA0001", "T1133"), p("TA0006", "T1040")],
  "port.vnc.exposed": [p("TA0001", "T1133"), p("TA0008", "T1021.005")],
  "port.redis.exposed": [p("TA0001", "T1190")],
  "port.mongodb.exposed": [p("TA0001", "T1190")],
  "port.elasticsearch.exposed": [p("TA0001", "T1190")],
  "port.memcached.exposed": [p("TA0001", "T1190")],
  "port.ftp.exposed": [p("TA0001", "T1190"), p("TA0006", "T1040")],
  "port.smb.exposed": [p("TA0008", "T1021.002"), p("TA0009", "T1039")],
  "port.snmp.exposed": [p("TA0009", "T1602.001")],
  "port.postgresql.exposed": [p("TA0001", "T1190")],
  "port.mysql.exposed": [p("TA0001", "T1190")],
  "port.ssh.exposed": [p("TA0001", "T1133"), p("TA0008", "T1021.004")],
  "package.telnet_server.installed": [p("TA0001", "T1133")],
  "package.rsh_server.installed": [p("TA0001", "T1133")],
  "web-server-spawns-shell": [p("TA0003", "T1505.003"), p("TA0002", "T1059.004")],
  "shell-from-database": [p("TA0002", "T1059.004"), p("TA0001", "T1190")],
  "download-and-run": [p("TA0011", "T1105"), p("TA0002", "T1059.004")],
};

/** A pair as the console API resolves it. */
export function pairView(pair: Pair) {
  const technique = pair.technique ? demoAttack.techniques.find((t) => t.id === pair.technique) : undefined;
  const tactic = demoAttack.tactics.some((t) => t.id === pair.tactic);
  return {
    tactic: pair.tactic, technique: pair.technique ?? null, technique_name: technique?.name ?? null,
    known: tactic && (!pair.technique || (technique?.tactics.includes(pair.tactic) ?? false)),
  };
}
