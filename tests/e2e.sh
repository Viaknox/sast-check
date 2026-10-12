#!/usr/bin/env bash
# End-to-end test: builds a throwaway repo with a "PR" and checks the gate's decisions.
# Needs on PATH: opengrep or semgrep, ruff, gitleaks. zizmor/osv-scanner optional.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cd "$T"
git init -q -b main && git config user.email t@example.com && git config user.name t
mkdir -p src
cat > src/app.js <<'EOF'
const express = require('express');
const app = express();
app.get('/old', (req, res) => { eval(req.query.code); });
module.exports = app;
EOF
echo "x = 1" > src/util.py
git add -A && git commit -qm base

cat >> src/app.js <<'EOF'
app.get('/run', (req, res) => {
  eval(req.query.expr);
});
app.get('/ok', (req, res) => {
  // sast-ignore[sast.js.code-eval]: reviewed sandbox endpoint
  eval(req.query.safe);
});
app.get('/r', (req, res) => res.redirect(req.query.next));
EOF
printf 'import yaml\ndef cfg(s):\n    return yaml.load(s)\n' > src/util.py
echo 'AWS = "AKIAIOSFODNN7ABCDEFG"' > src/keys.py
git add -A && git commit -qm change

set +e
python3 "$HERE/scripts/sast.py" --mode diff --base main~1 --only opengrep,ruff,gitleaks >/dev/null
code=$?
set -e
F=sast-results/findings.json
q() { python3 -c "import json,sys;d=json.load(open('$F'));print($1)"; }
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   - $1"; else echo "FAIL - $1 (got $2, want $3)"; fail=1; fi; }

check "exit code is 1 (blocking findings)"            "$code" "1"
check "new eval blocks"                               "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='sast.js.code-eval' and f['line']==6)")" "1"
check "pre-existing eval does not block"              "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='sast.js.code-eval' and f['line']==3)")" "0"
check "inline sast-ignore with reason suppresses"     "$(q "sum(1 for f in d['findings'] if f['suppressed'] and f['line']==10)")" "1"
check "high (open redirect) warns, does not block"    "$(q "[f['blocking'] for f in d['findings'] if f['rule']=='sast.js.open-redirect']")" "[False]"
check "ruff S506 yaml.load blocks"                    "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='ruff.S506')")" "1"
check "gitleaks secret blocks"                        "$(q "sum(f['blocking'] for f in d['findings'] if f['kind']=='secret')")" "1"
check "SARIF: every rule has a CWE tag"              "$(python3 -c "import json;d=json.load(open('sast-results/results.sarif'));print(all(any(t.startswith('CWE-') for t in r['properties']['tags']) for r in d['runs'][0]['tool']['driver']['rules']))")" "True"
check "SARIF: ruleIds are stable sast./ruff./secret. ids" "$(python3 -c "import json;d=json.load(open('sast-results/results.sarif'));print(all(r['ruleId'].split('.')[0] in ('sast','ruff','zizmor','secret','dep','trivy') for r in d['runs'][0]['results']))")" "True"
FP1=$(python3 -c "import json;d=json.load(open('sast-results/results.sarif'));print([r['partialFingerprints']['sastCheck/v1'] for r in d['runs'][0]['results'] if r['ruleId']=='sast.js.code-eval' and r['locations'][0]['physicalLocation']['region']['startLine']==6][0])")
check "SARIF: every result has a fingerprint"         "$(python3 -c "import json;d=json.load(open('sast-results/results.sarif'));print(all(len(r['partialFingerprints']['sastCheck/v1'])==64 for r in d['runs'][0]['results']))")" "True"
check "all requested scanners ran"                    "$(q "sorted(r['status'] for r in d['runs'])")" "['ran', 'ran', 'ran']"

# same finding moved down 3 lines keeps its fingerprint
sed -i '1i // a\n// b\n// c' src/app.js
python3 "$HERE/scripts/sast.py" --mode full --only opengrep >/dev/null || true
FP2=$(python3 -c "import json;d=json.load(open('sast-results/results.sarif'));print([r['partialFingerprints']['sastCheck/v1'] for r in d['runs'][0]['results'] if r['ruleId']=='sast.js.code-eval' and r['locations'][0]['physicalLocation']['region']['startLine']==9][0])")
check "fingerprint survives a line move"              "$FP2" "$FP1"
git checkout -q -- src/app.js

# clean PR passes
git checkout -q -b clean main~1 && echo "y = 2" >> src/util.py && git commit -qam clean
set +e; python3 "$HERE/scripts/sast.py" --mode diff --base main~1 --only opengrep,ruff,gitleaks >/dev/null; code=$?; set -e
check "clean PR passes"                                "$code" "0"

exit $fail
