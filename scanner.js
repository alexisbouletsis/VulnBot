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

  const seenCVEs = new Set();
  const result = [];

  // Prepare text report
  const outputFile = path.join(projectPath, "epss-report.txt");
  let reportContent = '';

  // Fetch EPSS for each CVE
  async function fetchEPSS(cve) {
    const url = `https://api.first.org/data/v1/epss?cve=${cve}`;
    const res = await fetch(url);
    const data = await res.json();
    return data.data[0]; // returns {cve, epss, percentile}
  }

  let totalVulnerabilities = 0;

  for (const vuln of vulnerabilities) {
    const cves = vuln.identifiers?.CVE || [];
    if (cves.length === 0) {
      reportContent += `⚠️  No CVE found for ${vuln.moduleName}\n`;
      result.push({
        moduleName: vuln.moduleName,
        title: vuln.title,
        cve: null,
        epss: null,
        percentile: null,
        cvss: vuln.cvssSources?.[0]?.baseScore || null,
        references: vuln.references || [],
        note: 'No CVE found'
      });
      continue;
    }

    for (const cve of cves) {
      if (seenCVEs.has(cve)) continue;
      seenCVEs.add(cve);
      totalVulnerabilities++;

      const epssData = await fetchEPSS(cve);

      const output = `
Vulnerability: ${vuln.title}
Package: ${vuln.moduleName} (${vuln.version})
CVE: ${cve}
EPSS Score (Probability): ${epssData?.epss || 'N/A'}
Percentile: ${epssData?.percentile || 'N/A'}
CVSS Score: ${vuln.cvssSources?.[0]?.baseScore || 'N/A'}
🔗 ${vuln.references[0]?.url || 'No reference'}
------------------------------------------------
      `;

      reportContent += output + '\n';

      result.push({
        moduleName: vuln.moduleName,
        title: vuln.title,
        cve,
        epss: epssData?.epss || null,
        percentile: epssData?.percentile || null,
        cvss: vuln.cvssSources?.[0]?.baseScore || null,
        references: vuln.references || []
      });
    }
  }

  // Summary
  const summary = `\n🔴 Total vulnerabilities found: ${totalVulnerabilities}\n`;
  console.log(summary);
  reportContent += summary;

  // Write text report
  fs.writeFileSync(outputFile, reportContent, 'utf8');
  console.log(`✅ EPSS report saved to ${outputFile}`);

  // Return JSON for CLI
  return {
    totalVulnerabilities: result.length,
    vulnerabilities: result
  };
}
