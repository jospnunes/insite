// Runs the webappanalyzer JavaScript core (wappalyzer.js, see SOURCE.toml) on
// the inputs the conformance test sends: one JSON object per line on stdin,
// {"site", "items"}. Prints one line per site, {"site", "technologies"}, with
// each technology's name and version.
//
// The signatures are the ones insite embeds: the webappanalyzer base pinned in
// crates/core/data, with our corrections replacing whole definitions by name.
// Technologies that require another one, or a category, are tried only once
// that one is found, as the Wappalyzer browser extension did.

'use strict'

const fs = require('fs')
const path = require('path')
const Wappalyzer = require('./wappalyzer')

const data = path.join(__dirname, '../../crates/core/data')
const read = (file) => JSON.parse(fs.readFileSync(path.join(data, file), 'utf8'))

const technologies = {}
const dir = path.join(data, 'webappanalyzer/technologies')
for (const file of fs.readdirSync(dir).sort()) {
  Object.assign(technologies, read(path.join('webappanalyzer/technologies', file)))
}
Object.assign(technologies, read('corrections.json'))

// The core escapes every slash of a pattern, so one written as `\/`, as
// webappanalyzer now often does, would ask for a backslash before the slash.
// Those slashes are unescaped first, which is what the patterns mean.
const PATTERN_FIELDS = [
  'certIssuer', 'cookies', 'css', 'dns', 'headers', 'html', 'js', 'meta',
  'probe', 'robots', 'scriptSrc', 'scripts', 'text', 'url', 'xhr',
]
function unescapeSlashes(value) {
  if (typeof value === 'string') {
    return value.replace(/(?<!\\)((?:\\\\)*)\\\//g, '$1/')
  }
  if (Array.isArray(value)) {
    return value.map(unescapeSlashes)
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, unescapeSlashes(v)]))
  }
  return value
}
for (const technology of Object.values(technologies)) {
  for (const field of PATTERN_FIELDS) {
    if (field in technology) {
      technology[field] = unescapeSlashes(technology[field])
    }
  }
}

Wappalyzer.setTechnologies(technologies)
Wappalyzer.setCategories(read('webappanalyzer/categories.json'))

function detect(items) {
  let detections = Wappalyzer.analyze(items)
  const tried = new Set()
  for (;;) {
    const resolved = Wappalyzer.resolve(detections)
    const found = (name) => resolved.some((t) => t.name === name)
    const inCategory = (id) => resolved.some((t) => t.categories.some((c) => c.id === id))
    const next = [
      ...Wappalyzer.requires
        .filter(({ name }) => !tried.has(`t:${name}`) && found(name))
        .map(({ name, technologies }) => [`t:${name}`, technologies]),
      ...Wappalyzer.categoryRequires
        .filter(({ categoryId }) => !tried.has(`c:${categoryId}`) && inCategory(categoryId))
        .map(({ categoryId, technologies }) => [`c:${categoryId}`, technologies]),
    ]
    if (!next.length) {
      return resolved
    }
    for (const [key, required] of next) {
      tried.add(key)
      detections = detections.concat(Wappalyzer.analyze(items, required))
    }
  }
}

function handle(line) {
  if (!line.trim()) {
    return
  }
  let site
  try {
    const parsed = JSON.parse(line)
    site = parsed.site
    const technologies = detect(parsed.items).map(({ name, version }) => ({ name, version }))
    process.stdout.write(`${JSON.stringify({ site, technologies })}\n`)
  } catch (error) {
    // Short: the default report would print the whole input line.
    process.stderr.write(`reference.js: ${site ?? 'unparsed line'}: ${error.stack}\n`)
    process.exit(1)
  }
}

// Lines end only at \n: readline also breaks at U+2028 and U+2029, which JSON
// leaves as they are inside strings.
let pending = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => {
  pending += chunk
  let end
  while ((end = pending.indexOf('\n')) !== -1) {
    handle(pending.slice(0, end))
    pending = pending.slice(end + 1)
  }
})
process.stdin.on('end', () => handle(pending))
