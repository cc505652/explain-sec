/**
 * Collection Event Templates (MITRE Tactic: Collection - TA0009)
 */

export const collectionTemplates = [
  {
    templateId: "COLL_ARCHIVE_STAGING_01",
    name: "Data Staging in Password-Protected Zip Archive",
    source: "DefenderForEndpoint",
    provider: "Microsoft",
    product: "Defender EDR",
    category: "collection",
    severity: "medium",
    confidence: 84,
    mitreTechnique: {
      id: "T1560.001",
      name: "Archive Collected Data: Archive via Utility",
      tactic: "Collection"
    },
    detectionRule: {
      ruleId: "RULE-ZIP-STAGING-01",
      ruleName: "7Zip/WinRAR Archiving Sensitive Documents in Temp",
      mitreId: "T1560.001",
      threshold: "7z.exe a -p with .docx / .xlsx files",
      confidence: 84,
      ruleVersion: "1.1",
      author: "ExplainSec Detection Engineering"
    },
    description: "7Zip command line archiving sensitive corporate documents into encrypted archive prior to exfiltration",
    rawEvent: JSON.stringify({
      ProcessName: "7z.exe",
      CommandLine: "7z.exe a -pP@ssw0rd123 C:\\Windows\\Temp\\fin_data.7z C:\\Users\\j.doe\\Documents\\*.xlsx"
    })
  }
];
