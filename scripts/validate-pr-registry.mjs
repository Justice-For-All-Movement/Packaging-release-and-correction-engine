import {readFile} from 'node:fs/promises';
import {parsePrRegistry} from '../registry/pr-contract.mjs';
const body = await readFile(new URL('../registry/prs.json', import.meta.url), 'utf8');
// The registry is a historical record and keeps the repository identity it was written under. The repository has since
// moved organizations: CI may run under the recorded identity or under the same repository name in the current
// organization. Any other repository is still rejected, and the registry content is validated unchanged.
const recorded = JSON.parse(body).repository;
const ACCEPTED_OWNERS = ['neophilism', 'Justice-For-All-Movement'];
const current = process.env.GITHUB_REPOSITORY;
if (current) {
  const [owner, name, ...rest] = current.split('/');
  if (rest.length > 0 || !ACCEPTED_OWNERS.includes(owner) || typeof name !== 'string' ||
      name.toLowerCase() !== String(recorded).split('/')[1]?.toLowerCase())
    throw new Error('PR registry belongs to a different repository');
}
const repository = recorded;
const {document} = parsePrRegistry(body, repository);
const retired = JSON.parse(await readFile(new URL('../registry/roadmap.json', import.meta.url), 'utf8'));
if (retired.repository !== repository || retired.deprecated !== true || retired.redirectTo !== 'registry/prs.json' ||
    Object.hasOwn(retired, 'milestones') || Object.hasOwn(retired, 'units') || Object.hasOwn(retired, 'plannedPrCount'))
  throw new Error('Only registry/prs.json may contain the active PR plan');
console.log(`Valid PR registry: ${repository}, ${document.units.length} approved units; runtime acceptance is separate.`);
