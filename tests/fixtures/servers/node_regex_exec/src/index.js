// Regex.prototype.exec — not child_process.exec. Must NOT trigger NODE-CMDI-001.
function findFoo(s) {
  const re = /foo/;
  const m = re.exec(s);
  return m;
}

function matchThing(s) {
  const matcher = new RegExp("bar");
  return matcher.exec(s);
}

module.exports = { findFoo, matchThing };
