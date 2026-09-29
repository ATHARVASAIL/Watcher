/**
 * Popup rendering: summary bar and finding cards. Pure DOM builders; all
 * state lives in popup.js and is passed in.
 */
import { h } from './dom.js';

const { SEVERITIES, SEVERITY_LABELS } = globalThis.__WATCHER.config;
const MAX_INLINE_LOCATIONS = 3;

export const formatBytes = (n) =>
  n < 1024 ? `${n} B` : n < 1_048_576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1_048_576).toFixed(1)} MB`;

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

/* ------------------------------------------------------------ summary */

function severityChips(counts, filters, onToggle) {
  return h(
    'div',
    { class: 'chips', role: 'group', 'aria-label': 'Filter by severity' },
    SEVERITIES.map((sev) =>
      h(
        'button',
        {
          class: `chip sev-${sev}`,
          type: 'button',
          'aria-pressed': String(filters.has(sev)),
          title: `${filters.has(sev) ? 'Hide' : 'Show'} ${SEVERITY_LABELS[sev].toLowerCase()} findings`,
          on: { click: () => onToggle(sev) },
        },
        h('span', { class: 'chip-count', text: counts[sev] }),
        h('span', { text: SEVERITY_LABELS[sev] }),
      ),
    ),
  );
}

function foldList(title, rows) {
  return h('details', { class: 'fold' }, h('summary', { text: title }), h('ul', { class: 'plain' }, rows));
}

/**
 * @param {object} result          scan result
 * @param {object} view            { counts, acceptedCount, filters, query, showAccepted }
 * @param {object} handlers        { onToggleSeverity, onSearch, onToggleAccepted }
 */
export function renderSummary(result, view, handlers) {
  const stats = result.stats;
  const seconds = ((result.finishedAt - result.startedAt) / 1000).toFixed(1);

  const search = h('input', {
    class: 'search',
    type: 'search',
    placeholder: 'Filter findings…',
    'aria-label': 'Filter findings by text',
    autocomplete: 'off',
    spellcheck: 'false',
    value: view.query,
    on: { input: (e) => handlers.onSearch(e.currentTarget.value) },
  });

  const acceptedToggle = view.acceptedCount
    ? h(
        'label',
        { class: 'accepted-toggle' },
        h('input', {
          type: 'checkbox',
          checked: view.showAccepted,
          on: { change: (e) => handlers.onToggleAccepted(e.currentTarget.checked) },
        }),
        ` Show accepted (${view.acceptedCount})`,
      )
    : null;

  const sourceRows = result.sources.map((s) =>
    h(
      'li',
      { title: s.url || s.label },
      h('span', { class: 'src-label', text: s.label }),
      h('span', {
        class: 'dim',
        text: ` — ${formatBytes(s.bytes)}${s.truncated ? ' (truncated)' : ''}, ${plural(s.findings, 'hit')}${
          s.originals !== undefined ? `, ${plural(s.originals, 'original file')} scanned` : ''
        }`,
      }),
    ),
  );
  const skippedRows = result.skipped.map((s) =>
    h(
      'li',
      { title: s.label },
      h('span', { class: 'src-label', text: s.label }),
      h('span', { class: 'dim', text: ` — ${s.reason}` }),
    ),
  );

  const notes = [];
  if (stats.cancelled)
    notes.push(h('p', { class: 'warn small', text: 'Scan stopped early; results are partial.' }));
  if (stats.findingsTruncated) {
    notes.push(
      h('p', { class: 'warn small', text: 'Finding limit reached; narrow the scan options and rescan.' }),
    );
  }
  if (stats.pageIsNonProd) {
    notes.push(
      h('p', {
        class: 'dim small',
        text: 'This host looks non-production, so references to other non-production hosts are shown as Info.',
      }),
    );
  }

  return [
    severityChips(view.counts, view.filters, handlers.onToggleSeverity),
    h('div', { class: 'toolbar' }, search, acceptedToggle),
    h(
      'p',
      { class: 'meta' },
      `${plural(stats.sourcesScanned, 'source')} · ${formatBytes(stats.bytesScanned)} · ${seconds}s`,
      result.skipped.length ? ` · ${result.skipped.length} skipped` : '',
    ),
    notes,
    foldList(`Sources scanned (${result.sources.length})`, sourceRows),
    result.skipped.length ? foldList(`Skipped (${result.skipped.length})`, skippedRows) : null,
  ];
}

/* ------------------------------------------------------------ cards */

function contextLine(finding, revealed) {
  if (!finding.context) return null;
  const c = finding.context;
  return h(
    'code',
    { class: 'ctx' },
    c.truncatedBefore ? '…' : '',
    revealed ? c.before : c.beforeMasked,
    h('mark', { text: revealed || !finding.redact ? finding.value : finding.display }),
    revealed ? c.after : c.afterMasked,
    c.truncatedAfter ? '…' : '',
  );
}

function locationItem(finding, revealed) {
  const { source, where } = finding;
  const origin = source.parent ? ` ← ${source.parent}` : '';
  return h(
    'li',
    { class: 'loc' },
    h(
      'div',
      { class: 'loc-head' },
      h('span', { class: 'src-label', title: source.url || source.label, text: source.label + origin }),
      where && where !== source.label ? h('span', { class: 'where', text: where }) : null,
    ),
    contextLine(finding, revealed),
  );
}

/**
 * @param {object} group     { key, fp, severity, head, items }
 * @param {object} opts      { revealed, accepted, onReveal, onCopy, onAccept }
 */
export function renderCard(group, { revealed, accepted, onReveal, onCopy, onAccept }) {
  const f = group.head;
  const secret = group.items.some((i) => i.redact);
  const count = group.items.length;
  const inline = group.items.slice(0, MAX_INLINE_LOCATIONS);
  const rest = group.items.slice(MAX_INLINE_LOCATIONS);

  return h(
    'article',
    { class: `card sev-${group.severity}${accepted ? ' is-accepted' : ''}`, 'data-group': group.fp || '' },
    h(
      'header',
      { class: 'card-head' },
      h('span', { class: `badge sev-${group.severity}`, text: SEVERITY_LABELS[group.severity] }),
      h('h2', { class: 'card-title', text: f.title }),
      f.confidence === 'heuristic'
        ? h('span', { class: 'tag', title: 'Keyword/entropy match — verify manually', text: 'needs review' })
        : null,
      accepted ? h('span', { class: 'tag', text: 'accepted' }) : null,
    ),
    h(
      'div',
      { class: 'value-row' },
      h('code', { class: 'value', text: revealed || !secret ? f.value : f.display }),
      secret
        ? h('button', {
            class: 'mini',
            type: 'button',
            'aria-pressed': String(revealed),
            text: revealed ? 'Hide' : 'Reveal',
            on: { click: () => onReveal(group) },
          })
        : null,
      h('button', {
        class: 'mini',
        type: 'button',
        text: 'Copy',
        on: { click: (e) => onCopy(f.value, e.currentTarget) },
      }),
      h('button', {
        class: 'mini',
        type: 'button',
        title: accepted ? 'Show this finding again' : 'Mark as reviewed / accepted risk and hide it',
        text: accepted ? 'Reopen' : 'Accept',
        on: { click: () => onAccept(group, !accepted) },
      }),
    ),
    f.note ? h('p', { class: 'note', text: f.note }) : null,
    h('p', { class: 'dim small', text: `Found in ${plural(count, 'location')}` }),
    h(
      'ul',
      { class: 'locs' },
      inline.map((i) => locationItem(i, revealed)),
    ),
    rest.length
      ? h(
          'details',
          { class: 'fold' },
          h('summary', { text: `${plural(rest.length, 'more location')}` }),
          h(
            'ul',
            { class: 'locs' },
            rest.map((i) => locationItem(i, revealed)),
          ),
        )
      : null,
  );
}
