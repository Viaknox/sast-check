#!/usr/bin/env bash
# End-to-end test: builds a throwaway repo with a "PR" and checks the gate's decisions.
# Needs on PATH: opengrep or semgrep, ruff, gitleaks. zizmor/osv-scanner optional.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
for t in ${E2E_REQUIRE:-}; do   # optional scanners whose checks must run (CI sets this)
  command -v "$t" >/dev/null || { echo "FAIL - $t required by E2E_REQUIRE but not installed"; exit 1; }
done
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
# run the gate; its exit code lands in $code. Exit 2 (a scanner errored) fails the test: an erroring
# scanner reports no findings, which would make every "expect 0 findings" check pass for the wrong reason.
gate() {
  set +e; env -u GH_TOKEN -u GITHUB_TOKEN python3 -I "$HERE/scripts/sast.py" "$@" >/dev/null 2>&1; code=$?; set -e
  if [ "$code" = 2 ]; then echo "FAIL - gate errored: $* :: $(q "[r for r in d['runs'] if r['status']=='error']")"; fail=1; fi
}

check "exit code is 1 (blocking findings)"            "$code" "1"
check "new eval blocks"                               "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='sast.js.code-eval' and f['line']==6)")" "1"
check "pre-existing eval does not block"              "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='sast.js.code-eval' and f['line']==3)")" "0"
check "inline sast-ignore with reason suppresses"     "$(q "sum(1 for f in d['findings'] if f['suppressed'] and f['line']==10)")" "1"
check "report lists the suppression and its reason"   "$(grep -c 'sast.js.code-eval.*inline: reviewed sandbox endpoint' sast-results/report.md)" "1"
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
gate --mode full --only opengrep
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
gate --mode diff --base HEAD~1 --only opengrep,gitleaks
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
gate --mode diff --base HEAD~1 --only opengrep,ruff
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
gate --mode diff --base HEAD~1 --only ruff
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
gate --mode diff --base HEAD~1 --only ruff
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
gate --mode diff --base HEAD~2 --only opengrep,gitleaks
check "PR's .sast-check.toml cannot turn off blocking"   "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/k.js')")" "1"
check "PR's .gitleaks.toml/.gitleaksignore cannot hide a secret" "$(q "sum(f['blocking'] for f in d['findings'] if f['kind']=='secret' and f['path']=='src/k.py')")" "1"
check "PR's .gitleaksignore is put back after the scan" "$(test -f .gitleaksignore && git status --porcelain .gitleaksignore | wc -l)" "0"
check "report says the settings change applies after merge" "$(grep -c 'take effect after merge' sast-results/report.md)" "1"
if command -v zizmor >/dev/null; then
  mkdir -p .github/workflows
  printf 'rules:\n  template-injection:\n    disable: true\n' > zizmor.yml
  printf 'on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n' > .github/workflows/x.yml
  git add zizmor.yml .github/workflows/x.yml && git commit -qm zcfg
  gate --mode diff --base HEAD~3 --only zizmor
  check "PR's zizmor.yml cannot switch audits off"        "$(q "int(any(f['rule']=='zizmor.template-injection' for f in d['findings']))")" "1"
fi
git checkout -q r3

# an unreadable base fails closed with a report (no crash)
rm -rf sast-results
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base 0000000000000000000000000000000000000bad --only ruff >/dev/null 2>&1; code=$?; set -e
check "unreadable base: exit 2 (error), not a crash"      "$code" "2"
check "unreadable base: settings error is reported"       "$(q "[r['status'] for r in d['runs'] if r['name']=='settings']")" "['error']"

# a "-- x" line replaced by "++ y" looks like a file header in the diff; it must not derail later hunks
git checkout -q -b hdr main
printf -- '-- old\n\n\n\n\n\n\n\nmodule.exports = {};\n' > src/hd.js && git add src/hd.js && git commit -qm hd
sed -i 's/^-- old$/++ new/' src/hd.js
printf "app.get('/h', (req, res) => { eval(req.query.h); });\n" >> src/hd.js
git commit -qam hd2
gate --mode diff --base HEAD~1 --only opengrep
check "pseudo '---/+++' lines inside a hunk are not headers" "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/hd.js')")" "1"
git checkout -q r3

# notebooks and .pyw files are Python too; a notebook finding maps to the right file line
git checkout -q -b nb main
python3 -I -c '
import json
cell = lambda src: {"cell_type": "code", "execution_count": None, "id": "c", "metadata": {}, "outputs": [], "source": src}
nb = {"cells": [{"cell_type": "markdown", "id": "m", "metadata": {}, "source": ["# t"]},
                cell(["x = 1\n", "y = 2"])], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
open("src/n.ipynb", "w").write(json.dumps(nb, indent=1, sort_keys=True) + "\n")'
git add src/n.ipynb && git commit -qm nb
sed -i 's/"y = 2"/"eval(input())"/' src/n.ipynb
printf 'eval(input())\n' > src/w.pyw
git add src/n.ipynb src/w.pyw && git commit -qm nb2
gate --mode diff --base HEAD~1 --only ruff
check "notebook finding blocks on the changed line"      "$(q "[(f['blocking'], open('src/n.ipynb').read().split(chr(10))[f['line']-1].strip()) for f in d['findings'] if f['path']=='src/n.ipynb' and f['rule']=='ruff.S307']")" "[(True, '\"eval(input())\"')]"
check ".pyw files are scanned"                            "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/w.pyw')")" "1"
git checkout -q r3

# full scope with a base still scans the PR's history: a secret added then deleted is caught
git checkout -q -b hist main
echo 'K5 = "AKIAIOSFODNN7ABCDEFG"' > src/h5.py && git add src/h5.py && git commit -qm add
git rm -q src/h5.py && git commit -qm del
gate --mode full --base HEAD~2 --only gitleaks
check "full scope: secret added then deleted is caught"   "$(q "int(any(f['kind']=='secret' and f['path']=='src/h5.py' for f in d['findings']))")" "1"
# full scope honors excludes for workflows
mkdir -p .github/workflows && printf '[paths]\nexclude = [".github/workflows/skip.yml"]\n' > .sast-check.toml
printf 'on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n' > .github/workflows/skip.yml
git add .sast-check.toml .github/workflows/skip.yml && git commit -qm skip
if command -v zizmor >/dev/null; then
  gate --mode full --only zizmor
  check "full scope: excluded workflow is not scanned"    "$(q "sum(1 for f in d['findings'] if f['path']=='.github/workflows/skip.yml')")" "0"
fi
# a PR's osv-scanner.toml cannot hide a vulnerable dependency
if command -v osv-scanner >/dev/null; then
  printf 'requests==2.19.0\n' > requirements.txt
  printf '[[PackageOverrides]]\nname = "requests"\nignore = true\n' > osv-scanner.toml
  git add requirements.txt osv-scanner.toml && git commit -qm osv
  gate --mode diff --base HEAD~1 --only osv
  check "PR's osv-scanner.toml cannot hide a vulnerable dep" "$(q "int(sum(1 for f in d['findings'] if f['kind']=='dependency') > 0)")" "1"
fi
git checkout -q r3

# full scope: a PR's ignore files (.semgrepignore, .opengrepignore, .gitignore) cannot hide committed code
git checkout -q -b ign main
mkdir -p src/ig .github/workflows
printf "app.get('/i', (req, res) => { eval(req.query.i); });\n" > src/ig/v.js
printf 'def f(s):\n    return eval(s)\n' > src/ig/v.py
printf 'src/ig/\n' > .semgrepignore && cp .semgrepignore .opengrepignore && printf 'src/ig/\n' > .gitignore
git add -f src/ig/v.js src/ig/v.py .semgrepignore .opengrepignore .gitignore && git commit -qm ign
printf 'on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n' > .github/workflows/new.yml
gate --mode full --only opengrep,ruff,zizmor
check "full: committed findings block (exit 1)"         "$code" "1"
check "full: .semgrepignore cannot hide committed code"   "$(q "sum(1 for f in d['findings'] if f['path']=='src/ig/v.js')")" "1"
check "full: .gitignore cannot hide committed Python"     "$(q "int(any(f['path']=='src/ig/v.py' and f['rule']=='ruff.S307' for f in d['findings']))")" "1"
if command -v zizmor >/dev/null; then
  check "full (local): untracked workflow is scanned"     "$(q "int(any(f['path']=='.github/workflows/new.yml' for f in d['findings']))")" "1"
fi
rm -f .github/workflows/new.yml; git checkout -q r3

# a pure rename into a scanned file type is scanned (no hunk in the diff)
git checkout -q -b ren main
printf 'eval(input())\n' > src/payload.txt && git add src/payload.txt && git commit -qm txt
git mv src/payload.txt src/payload.py && git commit -qm ren
gate --mode diff --base HEAD~1 --only ruff
check "pure rename into .py is scanned"                   "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/payload.py')")" "1"
git checkout -q r3

# native "ignore this line" comments never hide a finding (only sast-ignore with a reason does)
git checkout -q -b noqa main
printf 'import pickle\ndef f(b):\n    return pickle.loads(b)  # noqa: S301\n' > src/nq.py
printf "app.get('/n', (req, res) => { eval(req.query.n); }); // nosemgrep\n" > src/ns.js
echo 'K4 = "AKIAIOSFODNN7ABCDEFG" # gitleaks:allow' > src/ga.py
printf '<div>{{{ user.bio }}}</div>\n' > src/t.hbs
printf '<template><div v-html="post.body"></div></template>\n' > src/t.vue
git add src/nq.py src/ns.js src/ga.py src/t.hbs src/t.vue && git commit -qm noqa
gate --mode diff --base HEAD~1 --only opengrep,ruff,gitleaks
check "# noqa cannot hide a Ruff finding"                 "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/nq.py')")" "1"
check "// nosemgrep cannot hide an Opengrep finding"      "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/ns.js')")" "1"
check "gitleaks:allow cannot hide a secret"               "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/ga.py')")" "1"
check "template files (.hbs, .vue) are scanned"           "$(q "len({f['path'] for f in d['findings'] if f['path'] in ('src/t.hbs','src/t.vue')})")" "2"
if command -v zizmor >/dev/null; then
  mkdir -p .github/workflows
  printf 'on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}" # zizmor: ignore[template-injection]\n' > .github/workflows/z.yml
  git add .github/workflows/z.yml && git commit -qm zig
  gate --mode diff --base HEAD~1 --only zizmor
  check "# zizmor: ignore cannot hide a workflow finding" "$(q "int(any(f['rule']=='zizmor.template-injection' for f in d['findings']))")" "1"
fi
git checkout -q r3

# a PR file named like an option must not hijack the scanner's arguments
printf 'x\n' > ./--exclude && printf "app.get('/v', (req, res) => { eval(req.query.v); });\n" > vuln.js && printf 'x\n' > zzzz
git add -- ./--exclude vuln.js zzzz && git commit -qm dash
gate --mode diff --base HEAD~1 --only opengrep
check "file named '--exclude' cannot hide another file"   "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='vuln.js')")" "1"
git checkout -q main

# round-5: a deletion alone can create a finding; a '#' inside a string is not a comment; typo'd block_on
git checkout -q -b r5 main
printf 'data "aws_ami" "base" {\n  most_recent = true\n  owners      = ["amazon"]\n  filter {\n    name   = "name"\n    values = ["al2023-*"]\n  }\n}\n' > del.tf
git add del.tf && git commit -qm delbase
sed -i '/owners/d' del.tf
printf 'note = "# sast-ignore[ruff.S307]: data, not a comment"\neval(input())\n' > src/hs.py
printf 'x = "it'"'"'s"  # sast-ignore[ruff.S307]: reviewed, quote before the comment\neval(x)\n' > src/hq.py
git add del.tf src/hs.py src/hq.py && git commit -qm r5
gate --mode diff --base HEAD~1 --only opengrep,ruff
check "deleting a protective line blocks"                 "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='sast.terraform.aws-ami-no-owner' and f['path']=='del.tf')")" "1"
check "'# sast-ignore' inside a string does not suppress" "$(q "sum(f['blocking'] for f in d['findings'] if f['rule']=='ruff.S307' and f['path']=='src/hs.py')")" "1"
check "real comment after a quoted string suppresses"     "$(q "[bool(f['suppressed']) for f in d['findings'] if f['rule']=='ruff.S307' and f['path']=='src/hq.py']")" "[True]"
printf '[policy]\nblock_on = ["criticial"]\n' > .sast-check.toml && git add .sast-check.toml && git commit -qm typo
printf 'eval(input())\n' > src/ty.py && git add src/ty.py && git commit -qm ty
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
check "typo in base block_on fails closed (exit 2)"       "$code" "2"
check "typo in base block_on is reported"                 "$(q "int(any(r['name']=='settings' and 'block_on' in r['detail'] for r in d['runs']))")" "1"
# Trivy (optional): a PR's .trivyignore / trivy.yaml / inline trivy:ignore cannot hide a finding; ranges hold
if command -v trivy >/dev/null; then
  git checkout -q -b tv main
  printf 'resource "aws_security_group_rule" "r" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["10.0.0.0/8"]\n  security_group_id = "sg-1"\n}\n' > sg.tf
  git add sg.tf && git commit -qm sgbase
  sed -i 's#10.0.0.0/8#0.0.0.0/0#' sg.tf && sed -i '1i #trivy:ignore:AWS-0124' sg.tf
  printf 'AWS-0107\n' > .trivyignore && printf 'misconfiguration:\n  scanners: [dockerfile]\n' > trivy.yaml
  git add sg.tf .trivyignore trivy.yaml && git commit -qm tv
  gate --mode diff --base HEAD~1 --only trivy
  check "trivy: PR's .trivyignore/trivy.yaml cannot hide"  "$(q "int(any(f['rule']=='trivy.AWS-0107' for f in d['findings']))")" "1"
  check "trivy: inline trivy:ignore cannot hide"           "$(q "int(any(f['rule']=='trivy.AWS-0124' for f in d['findings']))")" "1"
  check "trivy: inner-line change inside a resource is new" "$(q "[f['in_diff'] for f in d['findings'] if f['rule']=='trivy.AWS-0124']")" "[True]"
  git checkout -q main
  # Terraform vars named in the base trivy.yaml are scan inputs: the PR's value is the one scanned
  git checkout -q -b tvv main
  printf 'variable "cidr" {\n  type = string\n}\nresource "aws_security_group_rule" "r" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = [var.cidr]\n  security_group_id = "sg-1"\n}\n' > vsg.tf
  printf 'cidr = "10.0.0.0/8"\n' > prod.tfvars && printf 'misconfiguration:\n  terraform:\n    vars: [prod.tfvars]\n' > trivy.yaml
  git add vsg.tf prod.tfvars trivy.yaml && git commit -qm tvvbase
  printf 'cidr = "0.0.0.0/0"\n' > prod.tfvars && git commit -qam tvv
  gate --mode diff --base HEAD~1 --only trivy
  check "trivy: a changed tfvars value is scanned as new"  "$(q "[f['in_diff'] for f in d['findings'] if f['rule']=='trivy.AWS-0107' and f['path']=='vsg.tf']")" "[True]"
  git checkout -q main
  # ...also when the vars move the same violation from one resource to another in the same file
  git checkout -q -b tvm main
  rule() { printf 'resource "aws_security_group_rule" "%s" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = [var.%s]\n  security_group_id = "sg-1"\n}\n' "$1" "$1"; }
  { printf 'variable "a" {\n  type = string\n}\nvariable "b" {\n  type = string\n}\n'; rule a; rule b; } > two.tf
  printf 'a = "0.0.0.0/0"\nb = "10.0.0.0/8"\n' > prod.tfvars && printf 'misconfiguration:\n  terraform:\n    vars: [prod.tfvars]\n' > trivy.yaml
  git add two.tf prod.tfvars trivy.yaml && git commit -qm tvmbase
  printf 'a = "10.0.0.0/8"\nb = "0.0.0.0/0"\n' > prod.tfvars && git commit -qam tvm
  gate --mode diff --base HEAD~1 --only trivy
  check "trivy: a vars change moving a finding is new"     "$(q "[(f['line'] > 14, f['in_diff']) for f in d['findings'] if f['rule']=='trivy.AWS-0107' and f['path']=='two.tf']")" "[(True, True)]"
  git checkout -q main
  # ...and when the PR deletes the vars file whose safe value masked an unsafe default
  git checkout -q -b tvd main
  printf 'variable "cidr" {\n  default = "0.0.0.0/0"\n}\nresource "aws_security_group_rule" "r" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = [var.cidr]\n  security_group_id = "sg-1"\n}\n' > dsg.tf
  printf 'cidr = "10.0.0.0/8"\n' > prod.tfvars && printf 'misconfiguration:\n  terraform:\n    vars: [prod.tfvars]\n' > trivy.yaml
  git add dsg.tf prod.tfvars trivy.yaml && git commit -qm tvdbase
  git rm -q prod.tfvars && git commit -qm tvd
  gate --mode diff --base HEAD~1 --only trivy
  check "trivy: deleting a masking tfvars file is new"     "$(q "[f['in_diff'] for f in d['findings'] if f['rule']=='trivy.AWS-0107' and f['path']=='dsg.tf']")" "[True]"
  git checkout -q main
  git checkout -q -b tvp main
  printf 'cidr = "10.0.0.0/8"\n' > p.tfvars && git add p.tfvars && git commit -qm pvars
  printf 'misconfiguration:\n  terraform:\n    vars: [p.tfvars]\n' > trivy.yaml && git add trivy.yaml && git commit -qm ptrivy
  set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
  check "proposed trivy.yaml naming an existing file is valid" "$code" "0"
  git checkout -q main
fi
git checkout -q main

# round-6: rename+edit into a scanned type; bare CR inside a changed line; new symlink; notebook multi-line
# call; changed SBOM
git checkout -q -b r6 main
printf 'eval(input())\n\n\n\nz = 1\n' > src/p6.txt
printf 'x = 1\ny = 2\nz = 3\neval(input())\n' > src/target.txt
python3 -I -c '
import json
cell = lambda src: {"cell_type": "code", "execution_count": None, "id": "c", "metadata": {}, "outputs": [], "source": src}
nb = {"cells": [cell(["import subprocess\n", "subprocess.run(\n", "    [\"ls\"],\n", "    shell=False,\n", ")\n"])],
      "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
open("src/m.ipynb", "w").write(json.dumps(nb, indent=1, sort_keys=True) + "\n")'
git add src/p6.txt src/target.txt src/m.ipynb && git commit -qm r6base
git mv src/p6.txt src/p6.py && sed -i 's/z = 1/z = 2/' src/p6.py
ln -s target.txt src/link6.py
sed -i 's/shell=False/shell=True/' src/m.ipynb
git add -A src && git commit -qm r6
gate --mode diff --base HEAD~1 --only ruff
check "rename+edit into .py: old line 1 is new"          "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/p6.py')")" "1"
check "new symlink: finding keeps the link's path"       "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/link6.py')")" "1"
check "notebook multi-line call counts as new"           "$(q "[f['in_diff'] for f in d['findings'] if f['rule']=='ruff.S602' and f['path']=='src/m.ipynb']")" "[True]"
# a bare CR inside a changed line must not desync the diff reader (later hunks of the same file)
printf '// a\r-- c\n' > src/cr.js && for i in $(seq 1 12); do echo "const v$i = $i;" >> src/cr.js; done
git add src/cr.js && git commit -qm crbase
python3 -I -c '
s = open("src/cr.js", newline="").read().replace("a\r-- c", "a\r-- d")
s = s.replace("const v12 = 12;", "app.get(\"/cr\", (req, res) => { eval(req.query.cr); });")
open("src/cr.js", "w", newline="").write(s)'
git add src/cr.js && git commit -qm cr
gate --mode diff --base HEAD~1 --only opengrep
check "bare CR in a changed line: later hunk still read"  "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/cr.js')")" "1"
if command -v osv-scanner >/dev/null; then
  printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"requests","version":"2.19.0","purl":"pkg:pypi/requests@2.19.0"}]}\n' > bom.json
  git add bom.json && git commit -qm sbom
  gate --mode diff --base HEAD~1 --only osv
  check "changed SBOM (bom.json) is scanned"             "$(q "int(any(f['kind']=='dependency' and f['path']=='bom.json' for f in d['findings']))")" "1"
fi
git checkout -q main

# round-7: CR in a renamed file's name; a renamed secret; alternate requirements file; gitleaks extend path
git checkout -q -b r7 main
mkdir -p vendor && echo 'K7 = "AKIAIOSFODNN7ABCDEFG"' > vendor/key.py
printf 'eval(input())\n' > src/inert.txt
git add vendor/key.py src/inert.txt && git commit -qm r7base
git mv src/inert.txt "$(printf 'src/evil\r.py')" && git mv vendor/key.py src/key.py && git commit -qm r7
gate --mode diff --base HEAD~1 --only ruff,gitleaks
check "rename to a name with a CR is scanned"             "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/evil'+chr(13)+'.py')")" "1"
check "pure rename brings a secret into scope: blocks"    "$(q "sum(f['blocking'] for f in d['findings'] if f['kind']=='secret' and f['path']=='src/key.py')")" "1"
if command -v osv-scanner >/dev/null; then
  printf 'requests==2.19.0\n' > requirements-dev.txt && git add requirements-dev.txt && git commit -qm reqdev
  gate --mode diff --base HEAD~1 --only osv
  check "changed requirements-dev.txt is scanned"         "$(q "int(any(f['kind']=='dependency' and f['path']=='requirements-dev.txt' for f in d['findings']))")" "1"
fi
printf '[extend]\npath = "extra-gitleaks.toml"\n' > .gitleaks.toml && printf '[extend]\nuseDefault = true\n' > extra-gitleaks.toml
git add .gitleaks.toml extra-gitleaks.toml && git commit -qm extbase
printf '[extend]\nuseDefault = true\n[allowlist]\npaths = [".*"]\n' > extra-gitleaks.toml
echo 'K8 = "AKIAIOSFODNN7ABCDEFG"' > src/k8.py && git add extra-gitleaks.toml src/k8.py && git commit -qm ext
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only gitleaks >/dev/null 2>&1; code=$?; set -e
check "base gitleaks [extend] path fails closed (exit 2)" "$code" "2"
check "...and says why"                                   "$(q "int(any(r['name']=='gitleaks' and 'extend' in r['detail'] for r in d['runs']))")" "1"
git checkout -q main

# round-8: zizmor .yaml config names, Dependabot config, multi-line ranges, unparseable workflow;
# Trivy config files referenced from the base trivy.yaml
if command -v zizmor >/dev/null; then
  git checkout -q -b r8 main
  mkdir -p .github/workflows
  printf 'rules:\n  forbidden-uses:\n    config:\n      deny: ["evil-org/*"]\n' > .github/zizmor.yaml
  printf 'on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    container:\n      image: foo@sha256:0000000000000000000000000000000000000000000000000000000000000000\n      credentials:\n        username: u\n        password: ${{ secrets.P }}\n    steps:\n      - run: echo\n' > .github/workflows/co.yml
  git add .github/zizmor.yaml .github/workflows/co.yml && git commit -qm r8base
  printf 'on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: evil-org/x@08eba0b27e820071cde6df949e0beb9ba4906955\n' > .github/workflows/ev.yml
  sed -i 's/password: .*/password: hunter2/' .github/workflows/co.yml
  printf 'version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n    schedule: {interval: weekly}\n    insecure-external-code-execution: allow\n' > .github/dependabot.yml
  git add .github/workflows/ev.yml .github/workflows/co.yml .github/dependabot.yml && git commit -qm r8
  gate --mode diff --base HEAD~1 --only zizmor
  check "base .github/zizmor.yaml is honored"             "$(q "int(any(f['rule']=='zizmor.forbidden-uses' for f in d['findings']))")" "1"
  check "changed dependabot.yml is audited"               "$(q "int(any(f['rule']=='zizmor.dependabot-execution' for f in d['findings']))")" "1"
  check "zizmor multi-line finding counts as new"         "$(q "[f['in_diff'] for f in d['findings'] if f['rule']=='zizmor.hardcoded-container-credentials']")" "[True]"
  printf 'on: [no_such_event]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n' > .github/workflows/bad.yml
  git add .github/workflows/bad.yml && git commit -qm bad
  set +e; env -u GH_TOKEN -u GITHUB_TOKEN python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only zizmor >/dev/null 2>&1; code=$?; set -e
  check "workflow zizmor cannot parse fails closed"       "$code" "2"
  git checkout -q main
fi
if command -v trivy >/dev/null; then
  git checkout -q -b r8t main
  printf 'variable "cidr" {\n  default = "10.0.0.0/8"\n}\nresource "aws_security_group_rule" "r" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = [var.cidr]\n  security_group_id = "sg-1"\n}\n' > sgv.tf
  printf 'cidr = "0.0.0.0/0"\n' > prod.tfvars && printf 'misconfiguration:\n  terraform:\n    vars:\n      - prod.tfvars\n' > trivy.yaml
  ln -s /etc/hostname abs.lnk   # a base symlink leaving the tree must not break the base snapshot
  git add sgv.tf prod.tfvars trivy.yaml abs.lnk && git commit -qm tvbase
  printf 'cidr = "10.0.0.0/8"\n' > prod.tfvars && git add prod.tfvars && git commit -qm tvpr
  gate --mode diff --base HEAD~1 --only trivy
  check "trivy: the PR's tfvars value is scanned (now safe)" "$(q "int(any(f['rule']=='trivy.AWS-0107' for f in d['findings']))")" "0"
  git checkout -q main
fi

# round-9: a new symlink to a secret file; `-diff` cannot hide a secret from history; zizmor span ending at col 0
git checkout -q -b r9 main
mkdir -p vendor && echo 'K9 = "AKIAIOSFODNN7ABCDEFG"' > vendor/key9.py && git add vendor/key9.py && git commit -qm r9base
ln -s ../vendor/key9.py src/key9.py && printf '*.py -diff\n' > .gitattributes && echo 'K10 = "AKIAIOSFODNN7ABCDEFH"' > src/k10.py
git add src/key9.py .gitattributes src/k10.py && git commit -qm r9
gate --mode diff --base HEAD~1 --only gitleaks
check "new symlink to a secret file blocks (link path)"   "$(q "sum(f['blocking'] for f in d['findings'] if f['kind']=='secret' and f['path']=='src/key9.py')")" "1"
check "-diff in .gitattributes cannot hide a secret"      "$(q "sum(f['blocking'] for f in d['findings'] if f['kind']=='secret' and f['path']=='src/k10.py')")" "1"
check "zizmor span ending at column 0 excludes that row" "$(python3 -I -c "import sys; sys.path.insert(0, sys.argv[1]); import sast
print(sast.zizmor_end_line({'start_point': {'row': 2, 'column': 2}, 'end_point': {'row': 6, 'column': 0}}),
      sast.zizmor_end_line({'start_point': {'row': 2, 'column': 2}, 'end_point': {'row': 5, 'column': 17}}))" "$HERE/scripts")" "6 6"
git checkout -q main

# round-10: a symlinked directory brings in its files (code and secrets), named through the link
git checkout -q -b r10 main
mkdir -p vendor/pkg && printf 'def f(s):\n    return eval(s)\n' > vendor/pkg/vuln.py && echo 'K11 = "AKIAIOSFODNN7ABCDEFG"' > vendor/pkg/k.py
git add vendor/pkg && git commit -qm r10base
ln -s ../vendor/pkg src/pkg && git add src/pkg && git commit -qm r10
gate --mode diff --base HEAD~1 --only ruff,gitleaks
check "symlinked dir: its code is scanned via the link"   "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/pkg/vuln.py')")" "1"
check "symlinked dir: its secrets are scanned via the link" "$(q "sum(f['blocking'] for f in d['findings'] if f['kind']=='secret' and f['path']=='src/pkg/k.py')")" "1"
git checkout -q main

# round-11: findings created without touching the flagged line are caught by comparing with the base;
# a symlink brings excluded IaC into Trivy; identical old findings stay pre-existing
git checkout -q -b r11 main
cat > src/san.js <<'JS'
app.get('/calc', (req, res) => {
  let expr = req.query.expr;
  expr = Number(expr);
  const a = 1;
  const b = 2;
  res.send(String(eval(expr)));
});
JS
cat > src/two.js <<'JS'
app.get('/t1', (req, res) => {
  let v = req.query.a;
  res.send(String(eval(v)));
});
app.get('/t2', (req, res) => {
  let v = req.query.a;
  v = Number(v);
  const pad = 1;
  res.send(String(eval(v)));
});
JS
git add src/san.js src/two.js && git commit -qm r11base
sed -i '/expr = Number(expr);/d' src/san.js                                         # sanitizer deleted far from sink
sed -i '/v = Number(v);/d' src/two.js     # same sink text as an existing finding: only the count shows it is new
git add src/san.js src/two.js && git commit -qm r11
gate --mode diff --base HEAD~1 --only opengrep
check "deleting a distant sanitizer blocks (base compare)" "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/san.js')")" "1"
check "identical sink text: only the newly exposed one blocks" "$(q "[f['line'] for f in d['findings'] if f['path']=='src/two.js' and f['blocking']]")" "[8]"
printf 'const pad = 3;\n' >> src/san.js && git commit -qam r11b
gate --mode diff --base HEAD~1 --only opengrep
check "unrelated edit: old finding stays pre-existing"     "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/san.js')")" "0"
git checkout -q main
# a base comparison that cannot run raises (main() then records an error: the check fails closed)
check "base comparison failure raises"                     "$(python3 -I -c "import sys; sys.path.insert(0, sys.argv[1]); import sast, pathlib
c = sast.Ctx(repo=pathlib.Path('.').resolve(), cfg=sast.load_config(None), mode='diff', base='no-such-ref', changed_files=['src/util.py'])
try:
    sast.baseline_new(c, [], ['ruff']); print('no')
except RuntimeError:
    print('raised')" "$HERE/scripts")" "raised"
if command -v trivy >/dev/null; then
  git checkout -q -b r11t main
  mkdir -p vendor && printf 'resource "aws_security_group_rule" "r" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["0.0.0.0/0"]\n  security_group_id = "sg-1"\n}\n' > vendor/payload.tf
  git add vendor/payload.tf && git commit -qm tlbase
  ln -s vendor/payload.tf main.tf && git add main.tf && git commit -qm tl
  gate --mode diff --base HEAD~1 --only trivy
  check "trivy: symlink to excluded IaC is scanned as the link" "$(q "int(any(f['rule']=='trivy.AWS-0107' and f['path']=='main.tf' for f in d['findings']))")" "1"
  git checkout -q main
fi

# gitleaks: a textconv filter that makes `git log` fail cannot turn the history scan into "no leaks"
git checkout -q -b r11g main
printf '*.cfg diff=broken\n' > .gitattributes && git config diff.broken.textconv false
git add .gitattributes && git commit -qm tcbase
echo 'K12 = "AKIAIOSFODNN7ABCDEFG"' > src/k12.cfg && git add src/k12.cfg && git commit -qm tc
gate --mode diff --base HEAD~1 --only gitleaks
check "failing textconv cannot hide a secret"              "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/k12.cfg')")" "1"
git config --unset diff.broken.textconv; git checkout -q main

# round-12: nested links; identical sinks trading places; oversized file; invalid proposed settings;
# deletions inside zizmor / Trivy findings
git checkout -q -b r12 main
mkdir -p vendor/npkg && printf 'eval(input())\n' > vendor/npkg/payload.txt
ln -s payload.txt vendor/npkg/vuln.py && ln -s ../vendor/npkg src/npkg
cat > src/swap.js <<'JS'
app.get('/a', (req, res) => {
  let v = req.query.v;
  res.send(String(eval(v)));
});
app.get('/b', (req, res) => {
  let v = req.query.v;
  v = Number(v);
  const p1 = 1;
  const p2 = 2;
  const p3 = 3;
  res.send(String(eval(v)));
});
JS
git add vendor/npkg src/npkg src/swap.js && git commit -qm r12base
# route a gets the sanitizer, route b loses it: one finding before, one after, same sink text
cat > src/swap.js <<'JS'
app.get('/a', (req, res) => {
  let v = req.query.v;
  v = Number(v);
  res.send(String(eval(v)));
});
app.get('/b', (req, res) => {
  let v = req.query.v;
  const p1 = 1;
  const p2 = 2;
  const p3 = 3;
  res.send(String(eval(v)));
});
JS
python3 -I -c 'open("src/big.js", "w").write("// " + "x" * 1100000 + "\napp.get(\"/big\", (req, res) => { eval(req.query.b); });\n")'
git add src/swap.js src/big.js && git commit -qm r12
gate --mode diff --base HEAD~1 --only opengrep
check "identical sinks trading places: the new one blocks" "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/swap.js')")" "1"
gate --mode full --only opengrep   # a directory scan applies Opengrep's size cutoff (explicit targets do not)
check "full scan: file over 1 MB is still scanned"         "$(q "int(any(f['path']=='src/big.js' for f in d['findings']))")" "1"
git checkout -q -b r12n main
mkdir -p vendor/npkg && printf 'eval(input())\n' > vendor/npkg/payload.txt && ln -s payload.txt vendor/npkg/vuln.py
git add vendor/npkg && git commit -qm nbase
ln -s ../vendor/npkg src/npkg && git add src/npkg && git commit -qm nlink
gate --mode diff --base HEAD~1 --only ruff
check "link inside a linked dir is followed"               "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/npkg/vuln.py')")" "1"
printf '[policy]\nblock_on = ["hgih"]\n' > .sast-check.toml && git add .sast-check.toml && git commit -qm badcfg
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
check "invalid proposed settings fail the PR (exit 2)"     "$code" "2"
git checkout -q main
if command -v zizmor >/dev/null; then
  git checkout -q -b r12z main && mkdir -p .github/workflows
  printf 'on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955 # v4.3.0\n        with:\n          persist-credentials: false\n      - run: echo\n' > .github/workflows/del.yml
  git add .github/workflows/del.yml && git commit -qm zdbase
  sed -i '/with:/d; /persist-credentials/d' .github/workflows/del.yml && git commit -qam zd
  gate --mode diff --base HEAD~1 --only zizmor
  check "zizmor: deleting persist-credentials counts as new" "$(q "[f['in_diff'] for f in d['findings'] if f['rule']=='zizmor.artipacked']")" "[True]"
  git checkout -q main
fi
if command -v trivy >/dev/null; then
  git checkout -q -b r12t main
  printf 'resource "aws_security_group_rule" "r" {\n  type              = "ingress"\n  description       = "ssh from office"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["10.0.0.0/8"]\n  security_group_id = "sg-1"\n}\n' > sgd.tf
  git add sgd.tf && git commit -qm tdbase
  sed -i '/description/d' sgd.tf && git commit -qam td
  gate --mode diff --base HEAD~1 --only trivy
  check "trivy: deleting a line inside a resource counts"  "$(q "[f['in_diff'] for f in d['findings'] if f['rule']=='trivy.AWS-0124']")" "[True]"
  git checkout -q main
fi

# round-13: identical sinks with identical context; logical aliases; changed target of an old link;
# symlinked settings; unreadable changed lockfile; CDN URL in docs
git checkout -q -b r13 main
cat > src/ctx.js <<'JS'
app.get('/a', (req, res) => {
  let v = req.query.v;
  const p1 = 1;
  const p2 = 2;
  const p3 = 3;
  res.send(String(eval(v)));
});
app.get('/b', (req, res) => {
  let v = req.query.v;
  v = Number(v);
  const p1 = 1;
  const p2 = 2;
  const p3 = 3;
  res.send(String(eval(v)));
});
JS
mkdir -p vendor/root vendor/payload && printf 'eval(input())\n' > vendor/payload/vuln.py
ln -s ../payload vendor/root/node_modules && ln -s ../payload vendor/root/src
printf 'x = 1\n' > vendor/payload6.txt && ln -s ../vendor/payload6.txt src/vuln6.py
git add src/ctx.js vendor src/vuln6.py && git commit -qm r13base
cat > src/ctx.js <<'JS'
app.get('/a', (req, res) => {
  let v = req.query.v;
  v = Number(v);
  const p1 = 1;
  const p2 = 2;
  const p3 = 3;
  res.send(String(eval(v)));
});
app.get('/b', (req, res) => {
  let v = req.query.v;
  const p1 = 1;
  const p2 = 2;
  const p3 = 3;
  res.send(String(eval(v)));
});
JS
ln -s vendor/root app
printf 'eval(input())\n' > vendor/payload6.txt
printf 'See [the incident](https://polyfill.io/) for background.\n' > NOTES.md
git add src/ctx.js app vendor/payload6.txt NOTES.md && git commit -qm r13
gate --mode diff --base HEAD~1 --only opengrep,ruff
check "identical sinks, identical context: exposed one blocks" "$(q "[f['line'] for f in d['findings'] if f['path']=='src/ctx.js' and f['blocking']]")" "[14]"
check "an excluded alias cannot hide another alias"       "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='app/src/vuln.py')")" "1"
check "old link whose target changed is rescanned"        "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/vuln6.py')")" "1"
check "a CDN URL in Markdown is not a finding"            "$(q "sum(1 for f in d['findings'] if f['path']=='NOTES.md')")" "0"
printf '[policy]\nblock_on = ["critical"]\n' > cfg.toml && ln -sf cfg.toml .sast-check.toml && git add cfg.toml .sast-check.toml && git commit -qm cfglink
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
check "symlinked .sast-check.toml in a PR fails (exit 2)" "$code" "2"
check "...and the error names .sast-check.toml"           "$(q "any(r['name']=='settings' and r['status']=='error' and '.sast-check.toml' in r['detail'] for r in d['runs'])")" "True"
git checkout -q main
if command -v osv-scanner >/dev/null; then
  git checkout -q -b r13o main
  printf 'requests==2.31.0\n' > requirements.txt && git add requirements.txt && git commit -qm obase
  printf '{"lockfileVersion": 3, "packages": {\n' > package-lock.json && git add package-lock.json && git commit -qm obad
  set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only osv >/dev/null 2>&1; code=$?; set -e
  check "unreadable changed lockfile fails (exit 2)"      "$code" "2"
  check "...and the error names package-lock.json"        "$(q "any(r['name']=='osv' and r['status']=='error' and 'package-lock.json' in r['detail'] for r in d['runs'])")" "True"
  git checkout -q main
fi

# Opengrep refuses symlink targets: a linked JS file is scanned (as the link), not a scanner error
git checkout -q -b r13j main
mkdir -p vendor && printf "app.get('/l', (req, res) => { eval(req.query.l); });\n" > vendor/evil.js && git add vendor/evil.js && git commit -qm jbase
ln -s ../vendor/evil.js src/evil-link.js && git add src/evil-link.js && git commit -qm jlink
gate --mode diff --base HEAD~1 --only opengrep
check "symlinked JS file is scanned by Opengrep"          "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src/evil-link.js')")" "1"
git checkout -q main

# full scope: gitleaks also scans in-repo aliases (gitleaks dir . does not follow links)
git checkout -q -b r14 main
mkdir -p vendor && echo 'K14 = "AKIAIOSFODNN7ABCDEFG"' > vendor/key14.py && ln -s ../vendor/key14.py src/key14.py
git add vendor/key14.py src/key14.py && git commit -qm r14
gate --mode full --base HEAD~1 --only gitleaks
check "full: a link to an excluded secret file blocks"    "$(q "sum(f['blocking'] for f in d['findings'] if f['kind']=='secret' and f['path']=='src/key14.py')")" "1"
git checkout -q main

# r15: proposed settings are checked by the parser that will read them (once merged, a broken one fails every PR)
git checkout -q -b r15s main
printf '[tools]\nopengrepp = true\n' > .sast-check.toml && git add .sast-check.toml && git commit -qm badkey
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
check "unknown key in proposed .sast-check.toml fails"    "$code" "2"
check "...and the error names the key"                    "$(q "any(r['name']=='settings' and 'opengrepp' in r['detail'] for r in d['runs'])")" "True"
git checkout -q main
if command -v zizmor >/dev/null; then
  git checkout -q -b r15z main
  mkdir -p .github && printf 'rules:\n  bogus: [\n' > .github/zizmor.yml && git add .github/zizmor.yml && git commit -qm badz
  set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
  check "malformed proposed zizmor.yml fails"             "$code" "2"
  check "...and the error names zizmor.yml"               "$(q "any(r['name']=='settings' and 'zizmor.yml' in r['detail'] for r in d['runs'])")" "True"
  git checkout -q main
fi
if command -v osv-scanner >/dev/null; then
  git checkout -q -b r15o main
  printf 'IgnoredVulnz = 1\n' > osv-scanner.toml && git add osv-scanner.toml && git commit -qm bado
  set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
  check "invalid proposed osv-scanner.toml fails"         "$code" "2"
  git checkout -q main
  # OSV's own inventory format is a dependency input like a lockfile
  git checkout -q -b r15c main
  printf '{"results":[{"source":{"path":"/x","type":"lockfile"},"packages":[{"package":{"name":"lodash","version":"4.17.15","ecosystem":"npm"}}]}]}\n' > osv-scanner-custom.json
  git add osv-scanner-custom.json && git commit -qm custom
  gate --mode diff --base HEAD~1 --only osv
  check "osv-scanner-custom.json in a PR is scanned"      "$(q "int(any(f['path']=='osv-scanner-custom.json' and f['in_diff'] for f in d['findings']))")" "1"
  git checkout -q main
fi

# r15b: settings errors fail even when the base allows scanner errors; settings must be UTF-8
git checkout -q -b r15e main
printf '[policy]\nfail_on_tool_error = false\n' > .sast-check.toml && git add .sast-check.toml && git commit -qm lax
printf '[policy]\nfail_on_tool_error = false\n[tools]\nopengrepp = true\n' > .sast-check.toml && git commit -qam badkey2
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
check "settings error fails despite fail_on_tool_error=false" "$code" "2"
printf '# \xff\n[policy]\nfail_on_tool_error = false\n' > .sast-check.toml && git commit -qam nonutf8
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~2 --only ruff >/dev/null 2>&1; code=$?; set -e
check "non-UTF-8 proposed .sast-check.toml fails"        "$code" "2"
git checkout -q main
if command -v osv-scanner >/dev/null; then
  # a changed lockfile reached only through a directory link keeps its explicit-scan findings
  git checkout -q -b r15l main
  mkdir -p vendor/pkg15l src && printf '{"name":"x","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x","dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}}}\n' > vendor/pkg15l/package-lock.json
  ln -s ../vendor/pkg15l src/pkg15l && git add vendor/pkg15l src/pkg15l && git commit -qm lbase
  sed -i 's/4.17.21/4.17.15/' vendor/pkg15l/package-lock.json && git commit -qam lvuln
  gate --mode diff --base HEAD~1 --only osv
  check "lockfile behind a directory link is reported"     "$(q "int(any(f['path']=='src/pkg15l/package-lock.json' and f['in_diff'] for f in d['findings']))")" "1"
  git checkout -q main
fi

# r17: "**/*_test.py" also matches a root-level test file (only the "**/" prefix is optional)
git checkout -q -b r17 main
printf 'def test_x():\n    assert 1 + 1 == 2\n' > root_test.py && git add root_test.py && git commit -qm r17
gate --mode diff --base HEAD~1 --only ruff
check "root-level *_test.py is treated as a test"        "$(q "sum(1 for f in d['findings'] if f['path']=='root_test.py' and f['rule']=='ruff.S101')")" "0"
git checkout -q main

# r16: full scope also gives zizmor and OSV the files behind directory aliases
git checkout -q -b r16 main
mkdir -p vendor/act16 vendor/pkg16
printf 'name: a\ndescription: a\nruns:\n  using: composite\n  steps:\n    - run: echo "${{ github.event.issue.title }}"\n      shell: bash\n' > vendor/act16/action.yml
printf '{"name":"x","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x","dependencies":{"lodash":"4.17.15"}},"node_modules/lodash":{"version":"4.17.15","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"}}}\n' > vendor/pkg16/package-lock.json
ln -s vendor/act16 act16 && ln -s vendor/pkg16 pkg16 && git add vendor/act16 vendor/pkg16 act16 pkg16 && git commit -qm r16
if command -v zizmor >/dev/null; then
  gate --mode full --only zizmor
  check "full: zizmor audits an action behind a link"     "$(q "int(any(f['path']=='act16/action.yml' for f in d['findings']))")" "1"
fi
if command -v osv-scanner >/dev/null; then
  gate --mode full --only osv
  check "full: OSV scans a lockfile behind a link"        "$(q "int(any(f['path']=='pkg16/package-lock.json' for f in d['findings']))")" "1"
fi
git checkout -q main

# r15: full scope scans code behind a directory alias of an excluded path (once, under the link's name)
git checkout -q -b r15f main
mkdir -p vendor/pkg15 && printf 'eval(input())\n' > vendor/pkg15/vuln.py && ln -s vendor/pkg15 src15
git add vendor/pkg15 src15 && git commit -qm r15f
gate --mode full --only ruff
check "full: code behind a directory alias blocks once"  "$(q "sum(f['blocking'] for f in d['findings'] if f['path']=='src15/vuln.py')")" "1"
git checkout -q main

# r15: two identical blocks swap which one is sanitized; the aligner may pair the old sink with the new one
git checkout -q -b r15d main
blk() { printf "app.use((req, res) => {\n  let v = req.query.v;\n  %s\n  const p1 = 1;\n  const p2 = 2;\n  const p3 = 3;\n  res.send(String(eval(v)));\n});\n" "$1"; }
{ blk 'const pad = 0;'; blk 'v = Number(v);'; } > src/dup.js && git add src/dup.js && git commit -qm dupbase
{ blk 'v = Number(v);'; blk 'const pad = 0;'; } > src/dup.js && git commit -qam dupswap   # difflib pairs old sink 7 with new sink 15
gate --mode diff --base HEAD~1 --only opengrep
check "identical blocks swapped: the exposed sink blocks" "$(q "[f['line'] for f in d['findings'] if f['path']=='src/dup.js' and f['blocking']]")" "[15]"
git checkout -q main

# r15: changes the scanners cannot see are named in the report
git checkout -q -b r15b main
printf 'version https://git-lfs.github.com/spec/v1\noid sha256:%064d\nsize 12\n' 0 > src/big.dat
git update-index --add --cacheinfo "160000,$(git rev-parse HEAD),libsub"
git add src/big.dat && git commit -qm blind
gate --mode diff --base HEAD~1 --only ruff
check "report names a changed LFS pointer"               "$(grep -c 'Git LFS file `src/big.dat`' sast-results/report.md)" "1"
check "report names a changed submodule"                 "$(grep -c 'submodule `libsub`' sast-results/report.md)" "1"
git checkout -q main

# r18: a '#' or '//' inside a JS regex or template literal is not a comment, so it cannot suppress
git checkout -q -b r18 main
cat > src/rx.js <<'JS'
app.get('/rx', (req, res) => {
  const re = /# sast-ignore[sast.js.code-eval]: harmless/;
  res.send(String(eval(req.query.a)));
  const t = `// sast-ignore[sast.js.code-eval]: template data`;
  res.send(String(eval(req.query.b)));
});
JS
git add src/rx.js && git commit -qm r18
gate --mode diff --base HEAD~1 --only opengrep
check "marker inside a JS regex/template does not suppress" "$(q "sorted(f['line'] for f in d['findings'] if f['path']=='src/rx.js' and f['blocking'])")" "[3, 5]"
git checkout -q main

# r18: a third identical sink (2 copies -> 3) counts as new
git checkout -q -b r18d main
printf 'app.get("/a", (req, res) => { eval(req.query.v); });\napp.get("/b", (req, res) => { eval(req.query.v); });\n' > src/three.js
git add src/three.js && git commit -qm base3
printf 'app.get("/c", (req, res) => { eval(req.query.v); });\n' >> src/three.js && git commit -qam add3
gate --mode diff --base HEAD~1 --only opengrep
check "2 -> 3 identical sinks: the change blocks"        "$(q "int(any(f['path']=='src/three.js' and f['blocking'] for f in d['findings']))")" "1"
git checkout -q main

# r18: an unknown --only scanner and a settings error both fail without running any scanner
set +e; python3 -I "$HERE/scripts/sast.py" --mode full --only opengrp >/dev/null 2>&1; code=$?; set -e
check "--only with an unknown scanner exits 2"           "$code" "2"
git checkout -q -b r18s main
printf '[tools]\nopengrepp = true\n' > .sast-check.toml && git add .sast-check.toml && git commit -qm badbase
echo 'x = 2' >> src/util.py && git commit -qam next
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 >/dev/null 2>&1; code=$?; set -e
check "invalid base settings: exit 2"                     "$code" "2"
check "...and no scanner ran"                             "$(q "[r['name'] for r in d['runs'] if r['status']=='ran']")" "[]"
git checkout -q main
if command -v trivy >/dev/null; then
  git checkout -q -b r18t main
  printf 'misconfiguration: [\n' > trivy.yaml && git add trivy.yaml && git commit -qm badtrivy
  set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
  check "malformed proposed trivy.yaml fails"             "$code" "2"
  git checkout -q main
fi
if command -v zizmor >/dev/null && [ -n "${E2E_NETWORK:-}" ]; then
  # zizmor online audits failing (bad token) must fail the gate, not silently drop known-vulnerable-actions
  git checkout -q -b r18z main
  mkdir -p .github/workflows && printf 'on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with: {persist-credentials: false}\n' > .github/workflows/z.yml
  git add .github/workflows/z.yml && git commit -qm z
  set +e; GH_TOKEN=invalid-token python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only zizmor >/dev/null 2>&1; code=$?; set -e
  check "zizmor online failure fails the gate"            "$code" "2"
  check "...and names the lost online audits"             "$(q "any(r['name']=='zizmor-online' and r['status']=='error' for r in d['runs'])")" "True"
  git checkout -q main
fi

# r19: settings paths must be regular files even when the content compares equal
git checkout -q -b r19s main
printf '[policy]\nblock_on = ["critical"]\n' > .sast-check.toml && cp .sast-check.toml same.toml && git add .sast-check.toml same.toml && git commit -qm sbase
rm .sast-check.toml && ln -s same.toml .sast-check.toml && git add .sast-check.toml && git commit -qm slink
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
check "settings symlink to an identical file fails"      "$code" "2"
git checkout -q main
git checkout -q -b r19d main
mkdir -p .gitleaks.toml && echo x > .gitleaks.toml/x && git add .gitleaks.toml/x && git commit -qm sdir
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
check "settings path committed as a directory fails"     "$code" "2"
git checkout -q main

# r19: a Python file Ruff cannot parse or read fails closed (it would otherwise not be checked at all)
git checkout -q -b r19r main
printf 'def f(:\n    pass\neval(input())\n' > src/broken.py && git add src/broken.py && git commit -qm broken
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
check "unparsable changed Python file fails closed"      "$code" "2"
printf '# -*- coding: latin-1 -*-\n# caf\xe9\neval(input())\n' > src/broken.py && git commit -qam latin
set +e; python3 -I "$HERE/scripts/sast.py" --mode diff --base HEAD~1 --only ruff >/dev/null 2>&1; code=$?; set -e
check "non-UTF-8 changed Python file fails closed"       "$code" "2"
git checkout -q main

# r19: .mts/.cts and extensionless node/python scripts are scanned
git checkout -q -b r19x main
printf "app.get('/m', (req, res) => { eval(req.query.c); });\n" > src/h.mts
printf '#!/usr/bin/env node\napp.get("/n", (req, res) => { eval(req.query.c); });\n' > src/nodetool
printf '#!/usr/bin/env python3\neval(input())\n' > src/pytool
git add src/h.mts src/nodetool src/pytool && git commit -qm scripts
gate --mode diff --base HEAD~1 --only opengrep,ruff
check ".mts and extensionless scripts are scanned"       "$(q "sorted({f['path'] for f in d['findings'] if f['blocking']})")" "['src/h.mts', 'src/nodetool', 'src/pytool']"
git checkout -q main

# r19: links leaving the repo are never read; excluded paths and such links are named in the report
git checkout -q -b r19l main
ln -s /etc/hostname src/host.py && mkdir -p vendor && printf 'eval(input())\n' > vendor/hidden.py
git add src/host.py vendor/hidden.py && git commit -qm outlink
gate --mode diff --base HEAD~1 --only ruff
check "link leaving the repo is named, not read"         "$(grep -c 'symlink `src/host.py` (points outside the repository)' sast-results/report.md)" "1"
check "changed file in an excluded path is named"         "$(grep -c 'vendor/hidden.py' sast-results/report.md)" "1"
git checkout -q main

# r19: PR-controlled file names cannot break out of the report's code span into a link
git checkout -q -b r19m main
f='src/x`[click](evil.example)`.py'; printf 'eval(input())\n' > "$f" && git add "$f" && git commit -qm mdname
gate --mode diff --base HEAD~1 --only ruff
check "file name stays inside one code span"             "$(grep -cF "\`src/x'[click](evil.example)'.py:1\`" sast-results/report.md)" "1"
git checkout -q main

# clean PR passes
git checkout -q -b clean main~1 && echo "y = 2" >> src/util.py && git commit -qam clean
gate --mode diff --base main~1 --only opengrep,ruff,gitleaks
check "clean PR passes"                                "$code" "0"

exit $fail
