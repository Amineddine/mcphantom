// Parse-only extraction of tool definitions from JS sources with the TypeScript compiler API.
// Usage: node extract_js.cjs <typescript-module-path> <out.json> <file>...
// A tool definition = an object literal with `name`, `description` and `inputSchema` properties (the shape
// returned from a ListTools handler), or the arguments of `server.tool(name, description, schema, ...)` /
// `registerTool(name, {description, inputSchema})`. Only literal expressions are evaluated (strings,
// no-substitution templates, `+` of literals, numbers, booleans, null, object/array literals); anything
// else makes the definition non-extractable and is listed, not guessed.
const ts = require(process.argv[2]);
const fs = require('node:fs');
const [outPath, ...files] = process.argv.slice(3);

class NotLiteral extends Error {}
function lit(n) {
  if (ts.isParenthesizedExpression(n)) return lit(n.expression);
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text;
  if (ts.isNumericLiteral(n)) return Number(n.text);
  if (n.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (n.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (n.kind === ts.SyntaxKind.NullKeyword) return null;
  if (ts.isPrefixUnaryExpression(n) && n.operator === ts.SyntaxKind.MinusToken) return -lit(n.operand);
  if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) return lit(n.left) + lit(n.right);
  if (ts.isArrayLiteralExpression(n)) return n.elements.map(lit);
  if (ts.isObjectLiteralExpression(n)) {
    const o = {};
    for (const p of n.properties) {
      if (!ts.isPropertyAssignment(p)) throw new NotLiteral(`property kind ${ts.SyntaxKind[p.kind]}`);
      const k = ts.isIdentifier(p.name) || ts.isStringLiteral(p.name) ? p.name.text : null;
      if (k === null) throw new NotLiteral('computed key');
      o[k] = lit(p.initializer);
    }
    return o;
  }
  throw new NotLiteral(`${ts.SyntaxKind[n.kind]}: ${n.getText().slice(0, 80)}`);
}

const out = [];
for (const file of files) {
  const src = fs.readFileSync(file, 'utf8');
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const visit = (n) => {
    if (ts.isObjectLiteralExpression(n)) {
      const keys = n.properties.filter(ts.isPropertyAssignment).map((p) => p.name.getText().replace(/["']/g, ''));
      if (keys.includes('name') && keys.includes('description') && keys.includes('inputSchema')) {
        const line = sf.getLineAndCharacterOfPosition(n.getStart()).line + 1;
        try {
          const o = lit(n);
          out.push({ file, line, tool: { name: o.name, description: o.description, inputSchema: o.inputSchema }, extra_keys: Object.keys(o).filter((k) => !['name', 'description', 'inputSchema'].includes(k)) });
        } catch (e) {
          if (!(e instanceof NotLiteral)) throw e;
          out.push({ file, line, not_extractable: e.message });
        }
      }
    }
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ['tool', 'registerTool'].includes(n.expression.name.text)) {
      const line = sf.getLineAndCharacterOfPosition(n.getStart()).line + 1;
      out.push({ file, line, not_extractable: `call form ${n.expression.name.text}() — handled manually if present` });
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
}
fs.writeFileSync(outPath, JSON.stringify(out, null, 1));
for (const o of out) console.log(o.file.replace(/.*dl[\\/]/, ''), o.line, o.not_extractable ? `NOT EXTRACTABLE: ${o.not_extractable}` : o.tool.name);
