// epss-comparison.js
import fs from 'fs';
import path from 'path';

export function runComparison(
  snykFile = "snyk-report.json",
  epssFile = "epss-report.txt",
  outputFile = "epss-plain-table.txt",
  config
) {

  const { epss, snyk } = config.weights;
  const { avgThreshold, criticalThreshold, cvssCutoff } = config.thresholds;
  const { thresholds: { severityCounts: { critical, high, medium, low } } } = config;



  // --- Load Snyk report (JSON) ---
  const snykReport = JSON.parse(fs.readFileSync(snykFile, "utf-8"));
  const snykVulnerabilities = snykReport.vulnerabilities || [];

  // --- Load EPSS report (text) ---
  const epssText = fs.readFileSync(epssFile, "utf-8");

  // --- Parse EPSS report into dictionary ---
  const epssData = {};
  const epssLines = epssText.split('\n');
  let currentCVE = "";
  for (const line of epssLines) {
    if (line.includes("CVE:")) {
      currentCVE = line.split("CVE: ")[1].trim();
    } else if (line.includes("EPSS Score (Probability):")) {
      epssData[currentCVE] = epssData[currentCVE] || {};
      epssData[currentCVE].epss = parseFloat(line.split(": ")[1].trim());
    } else if (line.includes("Percentile:")) {
      epssData[currentCVE] = epssData[currentCVE] || {};
      epssData[currentCVE].percentile = parseFloat(line.split(": ")[1].trim());
    }
  }

  // --- Extract Snyk data ---
  const snykData = {};
  for (const vuln of snykVulnerabilities) {
    const cves = vuln.identifiers?.CVE || [];
    const epssDetails = vuln.epssDetails || {};
    for (const cve of cves) {
      snykData[cve] = {
        percentile: epssDetails.percentile || 0,
        probability: epssDetails.probability || 0,
        cvss: vuln.cvssSources?.[0]?.baseScore || 0
      };
    }
  }

  // --- Helper: format numbers for table ---
  function formatNumber(value, width = 18) {
    if (typeof value === "number" && !isNaN(value)) {
      return String(parseFloat(value.toPrecision(8))).padEnd(width);
    }
    if (!isNaN(Number(value))) {
      return String(parseFloat(Number(value).toPrecision(8))).padEnd(width);
    }
    return "N/A".padEnd(width);
  }

  // --- Generate table ---
  let output = "";
  output +=
    "CVE               | Snyk %            | EPSS %            | Snyk Prob         | EPSS Score     | Vulnerability Score\n";
  output +=
    "------------------|-------------------|-------------------|-------------------|-----------------|------------------\n";

  let count = 0;
  let totalScore = 0;

  for (const cve of Object.keys(snykData)) {
    const s = snykData[cve];
    const e = epssData[cve] || {};

    const sPercentile = formatNumber(s.percentile);
    const ePercentile = formatNumber(e.percentile);
    const sProb = parseFloat(s.probability) || 0;
    const eScore = e.epss || 0;

    // Weighted score: (epssWeight * EPSS) + (snykWeight * Snyk Probability)
    const vulnScore =
      config.weights.epss * (isNaN(eScore) ? 0 : eScore) +
      config.weights.snyk * (isNaN(sProb) ? 0 : sProb);

    totalScore += vulnScore;
    count++;

    output += `${cve.padEnd(18)}| ${sPercentile}| ${ePercentile}| ${formatNumber(
      sProb
    )}| ${formatNumber(eScore)}| ${vulnScore.toFixed(6)} \n`;
    // console.log(`${config.weights.epss} * ${eScore} + ${config.weights.snyk}* ${sProb} = ${vulnScore}`);
  }

  fs.writeFileSync(outputFile, output, "utf-8");

  // --- Decision making ---
  const avgScore = count > 0 ? totalScore / count : 0;
  let decision = "ACCEPT";
  let rejectReason = "";

  for (const cve of Object.keys(epssData)) {
    if (epssData[cve].epss > criticalThreshold) {
      // console.log("epssData[cve].epss= ", epssData[cve].epss);
      decision = "REJECT";
      rejectReason = `High EPSS CVE: ${cve}`;
      break;
    }
  }

  if (decision === "ACCEPT" && avgScore > avgThreshold) {
    decision = "REJECT";
    rejectReason = `Average EPSS too high (${avgScore.toFixed(6)})`;
  }

  // --- Print summary ---

  // if (rejectReason) console.log(`Reason: ${rejectReason}`);
  // console.log(`Average score per vulnerability: ${avgScore.toFixed(6)}`);
  // console.log(`✅ Plain text comparison table saved to ${outputFile}`);

  return { decision, reason: rejectReason, avgScore };
}
