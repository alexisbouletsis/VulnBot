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
  // fallback default config
  config = {
    weights: { epss: 0.5, snyk: 0.5 },
    thresholds: {
      avgThreshold: 0.05,
      criticalThreshold: 0.3,
      highCVSS: 7,
      critical: null,
      high: null,
      medium: null,
      low: null
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
    { type: 'input', name: 'epssWeight', message: 'EPSS weight:', default: config.weights.epss },
    { type: 'input', name: 'snykWeight', message: 'Snyk weight:', default: config.weights.snyk },
    { type: 'input', name: 'cutoff', message: 'EPSS cutoff:', default: config.thresholds.avgThreshold },
    { type: 'input', name: 'critical', message: 'EPSS threshold Critical:', default: config.thresholds.criticalThreshold },
    // { type: 'input', name: 'high', message: 'EPSS threshold High:', default: config.thresholds.high },
    // { type: 'input', name: 'medium', message: 'EPSS threshold Medium:', default: config.thresholds.medium },
    // { type: 'input', name: 'low', message: 'EPSS threshold Low:', default: config.thresholds.low }
  ]);

  config.weights.epss = parseFloat(answers.epssWeight);
  config.weights.snyk = parseFloat(answers.snykWeight);
  config.thresholds.avgThreshold = parseFloat(answers.cutoff);
  config.thresholds.criticalThreshold = parseFloat(answers.critical);
  // config.thresholds.high = parseFloat(answers.high);
  // config.thresholds.medium = parseFloat(answers.medium);
  // config.thresholds.low = parseFloat(answers.low);

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
  console.log(chalk.gray(`Found ${scanResult.totalVulnerabilities} vulnerabilities`));

  console.log(chalk.yellow("Comparing vulnerabilities..."));
  const { decision, reason, avgScore } = await runComparison(
    "snyk-report.json",
    "epss-report.txt",
    "epss-plain-table.txt"
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

  // --- Ask LLM for explanation & advice ---
  if (apiKey) {
    console.log(chalk.yellow("\n🤖 Asking AI for explanation..."));
    try {
      const response = await client.chat.completions.create({
        model: "gpt-4o-mini", // cheaper, faster model
        messages: [
          {
            role: "system",
            content: "You are a helpful security reviewer. Explain scan results simply and suggest next steps.",
          },
          {
            role: "user",
            content: `Here is the decision from my scanner:
Decision: ${decision}
Reason: ${reason || "None"}
Average Score: ${avgScore.toFixed(6)}

Please explain this decision and give advice on how to improve the code/project.`,
          },
        ],
      });

      console.log(chalk.cyan("\n--- AI Review Summary ---"));
      console.log(response.choices[0].message.content);
      console.log(chalk.cyan("--- End of AI Review ---\n"));
    } catch (err) {
      console.error(chalk.red("❌ Error calling OpenAI API:"), err.message);
    }
  } else {
    console.log(chalk.red("⚠️ No OpenAI API key found. Skipping AI step."));
  }

}


main();
