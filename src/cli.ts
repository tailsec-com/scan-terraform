import { readFileSync } from 'fs';
import { glob } from 'glob';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { scanTerraform, formatTerraformOutput } from './terraform';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface CliFlags {
  path: string;
  format: 'text' | 'json';
}

function parseArgs(argv: string[]): CliFlags {
  const flags: CliFlags = { path: '.', format: 'text' };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--format' && argv[i + 1] === 'json') {
      flags.format = 'json';
      i++;
    } else if (!argv[i].startsWith('-') && argv[i] !== process.argv[0] && argv[i] !== process.argv[1]) {
      flags.path = argv[i];
    }
  }
  return flags;
}

async function main() {
  const args = parseArgs(process.argv);

  const files = await glob('**/*.tf', { cwd: args.path, absolute: true });

  if (files.length === 0) {
    console.log(formatTerraformOutput([], args.format));
    return;
  }

  const allFindings = [];

  for (const file of files) {
    const content = readFileSync(file, 'utf-8');
    const findings = scanTerraform(content);
    allFindings.push(...findings);
  }

  console.log(formatTerraformOutput(allFindings, args.format));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});