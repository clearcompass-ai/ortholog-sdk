cd /Users/anil/workspace/ortholog-sdk

echo "=== lifecycle/provision.go ==="
cat lifecycle/provision.go

echo "=== lifecycle/scope_governance.go ==="
cat lifecycle/scope_governance.go

echo "=== did/resolver.go ==="
cat did/resolver.go

echo "=== verifier/contest_override.go ==="
cat verifier/contest_override.go

echo "=== existing manifest package? ==="
find . -type d \( -name "manifest" -o -name "manifests" -o -name "domain" \) -not -path "./.git/*" -not -path "./.wave1-backup*"

echo "=== spec / decisions / design docs in repo ==="
find . -name "*.md" -not -path "./.git/*" -not -path "./.wave1-backup*" -not -path "./node_modules/*" 2>/dev/null