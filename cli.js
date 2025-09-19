#!/usr/bin/env node
import fs from 'fs';
import inquirer from 'inquirer';
import chalk from 'chalk';
import Table from 'cli-table3';
import { runScanner } from './scanner.js';
import { runComparison } from './epss-comparison.js';


const CONFIG_FILE = './config.json';
let config;
if (fs.existsSync(CONFIG_FILE)) {
  config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
} else {
  const epss = 0.7;
  config = {
    weights: { epss, snyk: 1 - epss },
    thresholds: {
      avgThreshold: 0.05,
      criticalThreshold: 0.3,
      cvssCutoff: 7,
      severityCounts: {
        critical: 1,
        high: 2,
        medium: 5,
        low: null
      }
    }
  };
}

async function main() {

  console.log(chalk.blue.bold("=== Digital PR Code Reviewer CLI ==="));

  const { choice } = await inquirer.prompt({
    type: 'list',
    name: 'choice',
    message: 'Select an action:',
    choices: [
      'Configure thresholds & weights',
      'Run PR scan',
      'Exit'
    ]
  });

  if (choice === 'Configure thresholds & weights') await configure();
  else if (choice === 'Run PR scan') await runReview();
  else process.exit();

  main(); // loop back
}

// --- Configure thresholds & weights ---
async function configure() {
  const answers = await inquirer.prompt([
    {
      type: 'input', name: 'epssWeight', message: 'EPSS weight (0-1):', default: config.weights.epss, validate: (value) => {
        const num = parseFloat(value);
        if (isNaN(num) || num < 0 || num > 1) {
          return "Please enter a number between 0 and 1";
        }
        return true;
      }
    },
    // { type: 'input', name: 'snykWeight', message: 'Snyk weight:', default: config.weights.snyk },
    { type: 'input', name: 'epssCutoff', message: 'EPSS cutoff (0-1):', default: config.thresholds.avgThreshold },
    { type: 'input', name: 'epssCritical', message: 'EPSS Critical (0-1):', default: config.thresholds.criticalThreshold },
    { type: 'input', name: 'cvssCutoff', message: 'CVSS cutoff (0-10):', default: config.thresholds.cvssCutoff },
    { type: 'input', name: 'nOfCriticals', message: 'Count of critical severities', default: config.thresholds.severityCounts.critical },
    { type: 'input', name: 'nOfHighs', message: 'Count of high severities', default: config.thresholds.severityCounts.high },
    { type: 'input', name: 'nOfMediums', message: 'Count of medium severities', default: config.thresholds.severityCounts.medium },
    { type: 'input', name: 'nOfLows', message: 'Count of low severities', default: config.thresholds.severityCounts.low },
  ]);

  const epssWeight = parseFloat(answers.epssWeight);
  const snykWeight = 1 - epssWeight;


  config.weights.epss = epssWeight;
  config.weights.snyk = snykWeight
  config.thresholds.avgThreshold = parseFloat(answers.epssCutoff);
  config.thresholds.criticalThreshold = parseFloat(answers.epssCritical);
  config.thresholds.cvssCutoff = parseFloat(answers.cvssCutoff);
  config.thresholds.severityCounts.critical = parseFloat(answers.nOfCriticals);
  config.thresholds.severityCounts.high = parseFloat(answers.nOfHighs);
  config.thresholds.severityCounts.medium = parseFloat(answers.nOfMediums);
  config.thresholds.severityCounts.low = parseFloat(answers.nOfLows);

  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  console.log(chalk.green("✅ Configuration saved!"));
}

async function runReview() {
  const { path } = await inquirer.prompt({
    type: 'input',
    name: 'path',
    message: 'Path to PR files or branch:',
    default: '.' // fallback to current folder
  });

  console.log(chalk.yellow("Running scanner..."));
  const scanResult = await runScanner(path);
  console.log(chalk.yellow(`Found ${scanResult.totalVulnerabilities} vulnerabilities`));

  console.log(chalk.yellow("Comparing vulnerabilities..."));
  const { decision, reason, avgScore } = await runComparison(
    "snyk-report.json",
    "epss-report.txt",
    "epss-plain-table.txt",
    config
  );

  // --- Final decision print ---
  console.log(chalk.blue.bold("\nPR Decision:"),
    decision === 'REJECT' ? chalk.red(decision) : chalk.green(decision)
  );

  if (reason) {
    console.log(chalk.red(`Reason: ${reason}`));
  }
  console.log(chalk.yellow(`Average Score: ${avgScore.toFixed(6)}`));
  console.log(chalk.green("✅ Comparison complete. See epss-plain-table.txt for details."));


}


main();
