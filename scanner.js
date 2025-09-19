// scanner.js
import fs from 'fs';
import fetch from 'node-fetch'; // Node 18+ has global fetch, remove if not needed
import path from 'path';

// --- Exported function for CLI ---
export async function runScanner(projectPath = ".") {
  // Load Snyk report
  const snykFile = path.join(projectPath, "snyk-report.json");
  if (!fs.existsSync(snykFile)) {
    throw new Error(`Could not find snyk-report.json in ${projectPath}`);
  }

  const report = JSON.parse(fs.readFileSync(snykFile, "utf8"));
  const vulnerabilities = report.vulnerabilities || [];
  if (!Array.isArray(vulnerabilities)) {
    throw new Error("Expected snyk-report.json to contain vulnerabilities array.");
  }
  // console.log('vulnerabilities', vulnerabilities);
  const seenCVEs = new Set();
  const result = [];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };

  // Prepare text report
  const outputFile = path.join(projectPath, "epss-report.txt");
  let reportContent = '';

  // Fetch EPSS for each CVE
  async function fetchEPSS(cve) {
    if (!cve) return null; // no CVE = no EPSS
    try {
      const url = `https://api.first.org/data/v1/epss?cve=${cve}`;
      const res = await fetch(url);
      const data = await res.json();
      return data.data?.[0] || null;
    } catch (err) {
      console.error(`❌ Failed to fetch EPSS for ${cve}:`, err.message);
      return null;
    }
  }

  let totalVulnerabilities = 0;

  // classify CVSS into severity
  function classifyCVSS(score) {
    if (score === null || score === undefined) return null;
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }

  for (const vuln of vulnerabilities) {
    const cves = vuln.identifiers?.CVE || [];
    const cvssScore = vuln.cvssSources?.[0]?.baseScore || null;

    // If no CVE → still try EPSS (will fail gracefully) then fallback to CVSS
    const targets = cves.length > 0 ? cves : [null];



    for (const cve of targets) {
      if (cve && seenCVEs.has(cve)) continue;
      if (cve) seenCVEs.add(cve);
      totalVulnerabilities++;

      const epssData = await fetchEPSS(cve);

      if (epssData) {
        reportContent += `
        Vulnerability: ${vuln.title}
        Package: ${vuln.moduleName} (${vuln.version})
        CVE: ${cve || "N/A"}
        EPSS Score (Probability): ${epssData.epss}
        Percentile: ${epssData.percentile}
        🔗 ${vuln.references[0]?.url || 'No reference'}
        ------------------------------------------------
        `;

        result.push({
          moduleName: vuln.moduleName,
          title: vuln.title,
          cve,
          epss: epssData.epss,
          percentile: epssData.percentile,
          cvss: null, // ignore CVSS since EPSS is available
          severity: null,
          references: vuln.references || [],
          metric: "EPSS"
        });
      } else {
        // No EPSS → fallback to CVSS
        const severity = classifyCVSS(cvssScore);
        if (severity) severityCounts[severity]++;

        reportContent += `
        ⚠️  No EPSS found for ${cve || vuln.moduleName}, fallback to CVSS
        Package: ${vuln.moduleName} (${vuln.version})
        CVE: ${cve || "N/A"}
        CVSS Score: ${cvssScore || "N/A"} → Severity: ${severity || "N/A"}
        🔗 ${vuln.references[0]?.url || 'No reference'}
        ------------------------------------------------
        `;

        result.push({
          moduleName: vuln.moduleName,
          title: vuln.title,
          cve,
          epss: null,
          percentile: null,
          cvss: cvssScore,
          severity,
          references: vuln.references || [],
          metric: "CVSS"
        });
      }
    }
  }


  // Summary
  // const summary = `\n🔴 Total vulnerabilities found: ${totalVulnerabilities}\n`;
  // console.log(summary);
  // reportContent += summary;

  // Severity summary
  const severitySummary = `
  Severity counts (CVSS fallback):
    Critical: ${severityCounts.critical}
    High:     ${severityCounts.high}
    Medium:   ${severityCounts.medium}
    Low:      ${severityCounts.low}
  `;
  console.log(severitySummary);
  reportContent += severitySummary;


  // Write text report
  fs.writeFileSync(outputFile, reportContent, 'utf8');
  console.log(`✅ EPSS report saved to ${outputFile}`);

  // Return JSON for CLI
  return {
    totalVulnerabilities: result.length,
    vulnerabilities: result,
    severityCounts
  };
}
