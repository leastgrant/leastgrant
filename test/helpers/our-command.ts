/**
 * Is this hook command one LeastGrant wrote?
 *
 * Tests kept answering this ad hoc — `.includes('leastgrant')` in one file,
 * `/leastgrant/i` in another, a regex on `leastgrant\.js` in a third — and every
 * one of them missed the same case. From a checkout whose path contains a space,
 * the installer writes the Windows 8.3 short form of our entry point to keep the
 * command free of quotes: `LEASTG~1.JS`, which contains no `leastgrant` at all.
 * So on any developer machine under `C:\Users\First Last\` those tests could not
 * find handlers that were sitting right there in the file, and no CI runner ever
 * disagreed, because no runner has a space in its path.
 *
 * Deliberately NOT the product's own predicate: a test that reuses the code it
 * is checking will agree with that code's bugs. This is an independent reading
 * of the two spellings the installer is known to emit.
 */
const SPELLINGS = /(leastgrant\.js|LEASTG~\d+\.JS)["']?\s+hook(\s|$)/i;

export function isOurCommand(command: unknown): boolean {
  return SPELLINGS.test(String(command ?? ''));
}
