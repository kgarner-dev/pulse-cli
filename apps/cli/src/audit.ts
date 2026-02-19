import { chromium } from 'playwright';
import chalk from 'chalk';
import {
    RuleLoader,
    NetworkScanner,
    SecurityScanner,
    FormScanner,
    ContextService,
    Finding
} from '@kaleb.garner/pulse-core';

interface ReportCategory {
    name: string;
    totalRules: number;
    passedRules: number;
    failedRules: number;
}

const HEARTBEAT_FRAMES = ['---', '--^', '-^⌄', '^⌄-', '⌄--', '---'];

async function runStep<T>(label: string, action: () => Promise<T>): Promise<T> {
    process.stdout.write('\x1B[?25l');
    const start = Date.now();
    let frameIdx = 0;

    const interval = setInterval(() => {
        const frame = HEARTBEAT_FRAMES[frameIdx];
        process.stdout.write(`\r${chalk.cyan(frame)} ${chalk.white(label)}`);
        frameIdx = (frameIdx + 1) % HEARTBEAT_FRAMES.length;
    }, 80);

    try {
        return await action();
    } finally {
        clearInterval(interval);
        const duration = ((Date.now() - start) / 1000).toFixed(2);
        process.stdout.write(`\r${chalk.green('✓')} ${chalk.white(label)} ${chalk.gray(`(${duration}s)`)}\n`);
        process.stdout.write('\x1B[?25h');
    }
}

async function runAudit(url: string) {
    const loader = new RuleLoader();
    const manifest = loader.loadManifest();

    if (!manifest) throw new Error('Failed to load rule manifest.');

    console.log(chalk.bold(`Pulse | v${manifest.version}`));
    console.log(chalk.bold(`Initializing scan for ${chalk.cyan(url)}...\n`));

    const { rules } = await runStep('Loading rules and services...', async () => {
        return { rules: loader.loadRules() };
    });

    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
    });
    const page = await context.newPage();

    const networkScanner = new NetworkScanner();
    await networkScanner.init(page, rules);

    const securityScanner = new SecurityScanner();
    await securityScanner.init(page, rules);

    const phiPatterns = loader.getContextDefinition('phi')?.form_field_patterns || [];
    const formScanner = new FormScanner();
    await formScanner.init(page, rules, phiPatterns);

    const contextService = new ContextService(loader.loadAllContexts());

    let isPhiContext = false;

    try {
        await runStep('Scanning page health...', async () => {
            try {
                await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45000 });
                await page.mouse.wheel(0, 5000);
                await page.waitForTimeout(3000);
                isPhiContext = await contextService.detectPhi(page, url);
            } catch (error: any) {
                if (!error.message.includes('Timeout')) throw error;
            }
        });
    } catch (e: any) {
        console.error(chalk.red(`\nScan error: ${e.message}`));
    }

    const networkFindings = await networkScanner.analyze();
    const securityFindings = await securityScanner.analyze();
    const formFindings = await formScanner.analyze();
    const rawFindings = [...networkFindings, ...securityFindings, ...formFindings];

    await browser.close();

    const failedRuleIds = new Set<string>();
    const ruleExamples = new Map<string, Finding>();

    rawFindings.forEach(finding => {
        const contextRequired = finding.rule.check.context_required;
        if (!contextRequired || (contextRequired && isPhiContext)) {
            failedRuleIds.add(finding.rule.id);
            if (!ruleExamples.has(finding.rule.id)) {
                ruleExamples.set(finding.rule.id, finding);
            }
        }
    });

    const categories: Record<string, ReportCategory> = {};
    for (const [key, config] of Object.entries(manifest.categories)) {
        if (config.active) {
            categories[key] = {
                name: config.name || key,
                totalRules: 0,
                passedRules: 0,
                failedRules: 0
            };
        }
    }

    rules.forEach(rule => {
        if (categories[rule.category]) {
            categories[rule.category].totalRules++;
            if (failedRuleIds.has(rule.id)) {
                categories[rule.category].failedRules++;
            }
        }
    });

    Object.values(categories).forEach(cat => {
        cat.passedRules = Math.max(0, cat.totalRules - cat.failedRules);
    });

    console.log('');

    const groupedFindings = {
        critical: new Map<string, Finding>(),
        high: new Map<string, Finding>(),
        medium: new Map<string, Finding>(),
        low: new Map<string, Finding>()
    };

    ruleExamples.forEach((finding, id) => {
        const sev = (finding.rule.severity || 'low') as keyof typeof groupedFindings;
        groupedFindings[sev].set(id, finding);
    });

    renderReport(categories, groupedFindings, url);
}

function renderReport(
    categories: Record<string, ReportCategory>,
    groupedFindings: Record<string, Map<string, Finding>>,
    url: string
) {
    const width = 60;
    console.log(chalk.gray('═'.repeat(width) + '\n'));
    console.log(chalk.bold(chalk.underline(chalk.cyan('RESULTS:'))) + '\n');

    Object.values(categories).forEach(cat => {
        if (cat.totalRules === 0) return;
        const isPass = cat.passedRules === cat.totalRules;
        const statusColor = isPass ? chalk.green : (cat.passedRules === 0 ? chalk.red : chalk.yellow);
        const statusIcon = isPass ? '✓' : '!';
        console.log(`${cat.name.padEnd(25)} ${statusColor(cat.passedRules + '/' + cat.totalRules)} ${statusColor(statusIcon)}`);
    });

    const totalIssues = Object.values(groupedFindings).reduce((acc, map) => acc + map.size, 0);
    console.log('\n' + chalk.bold(chalk.underline(chalk.cyan('FINDINGS:'))) + ` (${totalIssues})\n`);

    if (totalIssues === 0) {
        console.log(chalk.green('No issues found.'));
    }

    const severityOrder: (keyof typeof groupedFindings)[] = ['critical', 'high', 'medium', 'low'];
    const severityColors: Record<keyof typeof groupedFindings, (msg: string) => string> = {
        critical: chalk.red,
        high: chalk.redBright,
        medium: chalk.yellow,
        low: chalk.green
    };

    const severityLabels: Record<keyof typeof groupedFindings, string> = {
        critical: chalk.bold(chalk.underline(severityColors.critical('CRITICAL'))),
        high: chalk.bold(chalk.underline(severityColors.high('HIGH'))),
        medium: chalk.bold(chalk.underline(severityColors.medium('MEDIUM'))),
        low: chalk.bold(chalk.underline(severityColors.low('LOW')))
    };

    severityOrder.forEach((sev) => {
        const findings = groupedFindings[sev];
        if (findings.size === 0) return;

        const label = severityLabels[sev];
        const color = severityColors[sev];
        console.log(`\n${label}`);

        findings.forEach(f => {
            console.log('\n' + color(`[${f.rule.id}] ${f.rule.title}`));
            console.log('\nWhat happened:');
            console.log(`  → ${f.rule.what_happened}`);
            console.log(`    • Detected at: ${chalk.dim(f.targetUrl.substring(0, 50))}...`);
            console.log('\nWhy it matters:');
            console.log(`  → ${f.rule.why_it_matters}`);
            console.log('\nCitations:');
            f.rule.citations?.forEach((citation: string) => {
                console.log(`  → ${citation}`);
            });
            console.log('\nResolution:');
            console.log(`  → ${f.rule.resolution}`);
        });
    });

    console.log(chalk.bold(chalk.underline(chalk.cyan('\nACTION PLAN'))));

    if (totalIssues > 0) {
        console.log(chalk.bold('\nHIGHEST PRIORITY'));
        let counter = 1;
        severityOrder.forEach(sev => {
            groupedFindings[sev].forEach(f => {
                console.log(`  ${counter}. [${f.rule.id}] ${f.rule.resolution}`);
                counter++;
            });
        });
    } else {
        console.log(chalk.green('\n  No immediate actions required.'));
    }

    console.log('\n' + chalk.italic(chalk.dim('Pulse is not a legal tool and does not provide legal advice.')));
    console.log(chalk.gray('\n' + '═'.repeat(width)));
}

const targetUrl = process.argv[2];

if (!targetUrl) {
    console.error(chalk.red('Error: URL is required'));
    console.log(chalk.white('\nUsage: npx tsx src/audit.ts <url>'));
    console.log(chalk.gray('Example: npx tsx src/audit.ts https://example.com\n'));
    process.exit(1);
}

try {
    new URL(targetUrl);
} catch (error) {
    console.error(chalk.red('Error: Invalid URL format'));
    console.log(chalk.gray('Please provide a valid URL including the protocol (http:// or https://)\n'));
    process.exit(1);
}

runAudit(targetUrl);
