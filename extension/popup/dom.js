/**
 * Safe DOM construction for the popup.
 *
 * Everything shown in the popup (secret values, file names, code context, page
 * titles, storage keys) is attacker-influenced: it comes from the scanned page. So:
 *  - text only ever goes in through textContent / text nodes, never innerHTML;
 *  - attributes go through an allowlist (no href, src, style or on* handlers);
 *  - the extension CSP adds `require-trusted-types-for 'script'` with no policies,
 *    so any accidental innerHTML / outerHTML / insertAdjacentHTML assignment throws.
 */

const ALLOWED_ATTRS = new Set([
  'id',
  'title',
  'type',
  'role',
  'for',
  'name',
  'tabindex',
  'lang',
  'value',
  'max',
  'placeholder',
  'autocomplete',
  'spellcheck',
  'aria-label',
  'aria-pressed',
  'aria-expanded',
  'aria-controls',
  'aria-live',
  'aria-hidden',
  'aria-describedby',
]);

const BOOLEAN_PROPS = new Set(['checked', 'disabled', 'hidden', 'open']);

/**
 * Create an element.
 * @example h('button', { class: 'mini', text: 'Copy', on: { click: fn } })
 * @param {string} tag
 * @param {Record<string, unknown>} [props]
 * @param {...(Node|string|number|null|false|Array)} children
 * @returns {HTMLElement}
 */
export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') el.className = String(value);
    else if (key === 'text') el.textContent = String(value);
    else if (key === 'on') {
      for (const [event, handler] of Object.entries(value)) el.addEventListener(event, handler);
    } else if (BOOLEAN_PROPS.has(key)) el[key] = Boolean(value);
    else if (/^data-[a-z0-9-]+$/.test(key) || ALLOWED_ATTRS.has(key)) el.setAttribute(key, String(value));
    else throw new Error(`h(): attribute "${key}" is not allowed`);
  }
  return append(el, children);
}

/** Append children as nodes or text nodes (strings are never parsed as HTML). */
export function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return parent;
}

export function clear(el) {
  el.replaceChildren();
  return el;
}
