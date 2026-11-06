import type { Row } from './model.ts';
export interface Weakness { id: string; title: string; severity: 'high' | 'medium'; detail: string; action: string; fr: number[]; packets: number[]; assets: string[] }
export function reviewCapture(rows: Row[]): Weakness[] {
  const checks: { id: string; title: string; severity: 'high' | 'medium'; detail: string; action: string; fr: number[]; match: (r: Row) => boolean }[] = [
    { id: 'credentials', title: 'Credentials carried without transport encryption', severity: 'high', detail: 'The decoder identified authentication material in a plaintext application protocol. Values are intentionally omitted here.', action: 'Validate the service and account with the owner; rotate exposed secrets and protect the communication path.', fr: [1,4], match: r => !!(r.httpAuth || r.mqttPass || r.smtpAuth || (r.ftpCmd?.toUpperCase() === 'PASS')) },
    { id: 'modbus', title: 'Modbus write operation observed', severity: 'high', detail: 'A write function is visible. This may be authorised maintenance; the packet alone cannot establish permissions or malicious intent.', action: 'Check the change ticket, engineering workstation logs and controller diagnostics. Restrict permitted write paths.', fr: [2,3,5], match: r => [5,6,15,16,22,23].includes(r.modbusFunc ?? -1) },
    { id: 'http', title: 'Unencrypted HTTP communication', severity: 'medium', detail: 'HTTP is visible in this capture. The capture does not establish the sensitivity of the application data.', action: 'Confirm data sensitivity and whether supported TLS or a protected conduit is required.', fr: [4], match: r => !!r.httpMethod },
    { id: 'ftp', title: 'Legacy plaintext FTP service', severity: 'medium', detail: 'An FTP command was decoded. Service exposure is observed; software version and CVE applicability are unknown.', action: 'Confirm business need and replace or isolate the service where practical.', fr: [4,5], match: r => !!r.ftpCmd },
  ];
  return checks.flatMap(c => { const hits=rows.filter(c.match); return hits.length ? [{id:c.id,title:c.title,severity:c.severity,detail:c.detail,action:c.action,fr:c.fr,packets:hits.map(r=>r.n),assets:[...new Set(hits.flatMap(r=>[r.src,r.dst]).filter(Boolean))]}] : []; });
}
export const FOUNDATIONS = [
  ['Identification and authentication control','Account inventory, authentication configuration and remote access policy.'],
  ['Use control','Role permissions, approved changes and operator authorisation.'],
  ['System integrity','Firmware inventory, program checksums and integrity controls.'],
  ['Data confidentiality','Data classification, cryptographic configuration and key management.'],
  ['Restricted data flow','Approved zone/conduit design and firewall rule review.'],
  ['Timely response to events','Logging coverage, incident procedures and response exercise records.'],
  ['Resource availability','Capacity baseline, recovery tests and backup evidence.'],
] as const;
