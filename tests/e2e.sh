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
q() { python3 -I -c "import json,sys;d=json.load(open('$F'));print($1)"; }
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

# review fixes: multi-line match whose changed line is inside it; non-ASCII path; staged secret (local run)
git checkout -q -b more main
cat > ami.tf <<'TF'
data "aws_ami" "app" {
  most_recent = false
  filter {
    name   = "name"
    values = ["app-*"]
  }
}
TF
git add -A && git commit -qm ami
sed -i 's/most_recent = false/most_recent = true/' ami.tf
mkdir -p "src/évil" && printf "app.get('/x', (req, res) => { eval(req.query.c); });\n" > "src/évil/h.js"
git add -A && git commit -qm "range + path"
echo 'K2 = "AKIAIOSFODNN7ABCDEFG"' > staged.py && git add staged.py
set +e; python3 "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only opengrep,gitleaks >/dev/null; set -e
check "multi-line match blocks when an inner line changed" "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='sast.terraform.aws-ami-no-owner')")" "1"
check "file under a non-ASCII path is scanned"            "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='sast.js.code-eval' and 'vil/h.js' in f['path'])")" "1"
check "staged (uncommitted) secret is caught"             "$(q "sum(1 for f in d['findings'] if f['kind']=='secret' and f['path']=='staged.py')")" "1"
git reset -q --hard && git checkout -q main

# round-3 review fixes: "++" added line, string-literal ignore, Ruff multi-line range, untracked path with a space
git checkout -q -b r3 main
printf 'let counter = 0;\n\n\n\n\n\n\nmodule.exports = {};\n' > src/c.js
printf 'import subprocess\nsubprocess.run(\n    ["ls"],\n    shell=False,\n)\n' > src/run.py
git add -A && git commit -qm r3base
sed -i '1a ++counter;' src/c.js
printf "app.get('/z', (req, res) => { eval(req.query.z); });\n" >> src/c.js
sed -i 's/shell=False/shell=True/' src/run.py
printf 'note = "sast-ignore[ruff.S307]: not a comment"\neval(input())\n' > src/s.py
git add -A && git commit -qm r3
printf "app.get('/u', (req, res) => { eval(req.query.u); });\n" > "src/new module.js"
set +e; python3 "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only opengrep,ruff >/dev/null; set -e
check "eval in a later hunk after a '++' line blocks"     "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='sast.js.code-eval' and f['path']=='src/c.js')")" "1"
check "sast-ignore inside a string does not suppress"     "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='ruff.S307' and f['path']=='src/s.py')")" "1"
check "Ruff multi-line finding counts as new"             "$(q "[f['in_diff'] for f in d['findings'] if f['rule']=='ruff.S602' and f['path']=='src/run.py']")" "[True]"
check "untracked file with a space in its name is scanned" "$(q "sum(1 for f in d['findings'] if f['path']=='src/new module.js')")" "1"
rm -f "src/new module.js"

# round-4: non-ASCII before a multi-line call; a symlink replaced by a real file (git type change "T")
git checkout -q -b r4 main
python3 -c 'open("src/u.py", "w", encoding="utf-8").write("import subprocess\n\u00e9 = subprocess.run(\n    [\"ls\"],\n    shell=False,\n)\n")'
ln -s util.py src/link.py
git add -A src && git commit -qm r4base
sed -i 's/shell=False/shell=True/' src/u.py
rm src/link.py && printf 'import pickle\npickle.loads(open(0, "rb").read())\n' > src/link.py
git add -A src && git commit -qm r4
set +e; python3 "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null; set -e
check "multi-line call after non-ASCII text counts as new" "$(q "[f['in_diff'] for f in d['findings'] if f['rule']=='ruff.S602' and f['path']=='src/u.py']")" "[True]"
check "symlink replaced by a file is scanned"             "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/link.py')")" "1"
git checkout -q r3

# round-4 security: .gitattributes cannot hide a change; a planted json.py/pip.py cannot hijack Python
git checkout -q -b r4s main
printf 'def f(s):\n    return s\n' > src/h.py && git add src/h.py && git commit -qm h
printf '*.py -diff\n' > .gitattributes
printf 'def f(s):\n    return eval(s)\n' > src/h.py
printf 'raise SystemExit("hijacked")\n' > json.py && cp json.py pip.py
git add .gitattributes src/h.py && git commit -qm hide
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null; set -e
check "-diff in .gitattributes cannot hide a change"       "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/h.py')")" "1"
check "planted json.py does not hijack the scanner (-I)"   "$(python3 -I -c "import json,sys;print(json.load(open(sys.argv[1]))['verdict'])" sast-results/findings.json)" "fail"
rm -f json.py pip.py; git checkout -q r3

# settings come from the base branch: a PR cannot switch off its own blocking or allow-list its own secret
git checkout -q -b cfg main
printf '[policy]\nblock_on = []\n[tools]\nopengrep = false\nruff = false\ngitleaks = false\n' > .sast-check.toml
printf '[extend]\nuseDefault = true\n[allowlist]\npaths = [".*"]\n' > .gitleaks.toml
printf "app.get('/k', (req, res) => { eval(req.query.k); });\n" > src/k.js
echo 'K3 = "AKIAIOSFODNN7ABCDEFG"' > src/k.py
git add .sast-check.toml .gitleaks.toml src/k.js src/k.py && git commit -qm cfg
G=$(git log -1 --format=%H); for f in src/k.py; do echo "$G:$f:aws-access-token:1" >> .gitleaksignore; done
git add .gitleaksignore && git commit -qm ignore
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~2 --only opengrep,gitleaks >/dev/null; set -e
check "PR's .sast-check.toml cannot turn off blocking"   "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/k.js')")" "1"
check "PR's .gitleaks.toml/.gitleaksignore cannot hide a secret" "$(q "sum(f['blocking'] for f in d['findings'] if f['kind']=='secret' and f['path']=='src/k.py')")" "1"
check "PR's .gitleaksignore is put back after the scan" "$(test -f .gitleaksignore && git status --porcelain .gitleaksignore | wc -l)" "0"
check "report says the settings change applies after merge" "$(grep -c 'take effect after merge' sast-results/report.md)" "1"
if command -v zizmor >/dev/null; then
  mkdir -p .github/workflows
  printf 'rules:\n  template-injection:\n    disable: true\n' > zizmor.yml
  printf 'on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n' > .github/workflows/x.yml
  git add zizmor.yml .github/workflows/x.yml && git commit -qm zcfg
  set +e; env -u GH_TOKEN -u GITHUB_TOKEN python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~3 --only zizmor >/dev/null; set -e
  check "PR's zizmor.yml cannot switch audits off"        "$(q "int(any(f['rule']=='zizmor.template-injection' for f in d['findings']))")" "1"
fi
git checkout -q r3

# an unreadable base fails closed with a report (no crash)
rm -rf sast-results
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base 0000000000000000000000000000000000000bad --only ruff >/dev/null 2>&1; code=$?; set -e
check "unreadable base: exit 2 (error), not a crash"      "$code" "2"
check "unreadable base: settings error is reported"       "$(q "[r['status'] for r in d['runs'] if r['name']=='settings']")" "['error']"

# a PR file named like an option must not hijack the scanner's arguments
printf 'x\n' > ./--exclude && printf "app.get('/v', (req, res) => { eval(req.query.v); });\n" > vuln.js && printf 'x\n' > zzzz
git add -- ./--exclude vuln.js zzzz && git commit -qm dash
set +e; python3 "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only opengrep >/dev/null; set -e
check "file named '--exclude' cannot hide another file"   "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='vuln.js')")" "1"
git checkout -q main

# clean PR passes
git checkout -q -b clean main~1 && echo "y = 2" >> src/util.py && git commit -qam clean
set +e; python3 "$HERE/scripts/sast.py" --mode diff --base main~1 --only opengrep,ruff,gitleaks >/dev/null; code=$?; set -e
check "clean PR passes"                                "$code" "0"

exit $fail
