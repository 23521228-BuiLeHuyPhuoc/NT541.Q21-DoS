"""Signature-based detector — đọc CSV của TV1 + parse safe."""
import csv
import ast
import operator

ALLOWED_OPS = {
    ast.Lt: operator.lt, ast.Gt: operator.gt,
    ast.LtE: operator.le, ast.GtE: operator.ge,
    ast.Eq: operator.eq, ast.NotEq: operator.ne,
    ast.And: all, ast.Or: any
}

def safe_eval(rule_str, ctx):
    if not rule_str or rule_str.strip() == "":
        return False
        
    # Tự động sửa lỗi cú pháp: đổi ' AND ' thành ' and ', ' OR ' thành ' or '
    clean_rule = rule_str.replace(' AND ', ' and ').replace(' OR ', ' or ')
    clean_rule = clean_rule.replace('&&', ' and ').replace('||', ' or ')
    
    try:
        tree = ast.parse(clean_rule.strip(), mode='eval')
    except SyntaxError:
        raise ValueError(f"Sai cú pháp Python: {clean_rule}")

    def _ev(n):
        if isinstance(n, ast.Expression): return _ev(n.body)
        if isinstance(n, ast.BoolOp):
            vals = [_ev(v) for v in n.values]
            return ALLOWED_OPS[type(n.op)](vals)
        if isinstance(n, ast.Compare):
            left = _ev(n.left)
            right = _ev(n.comparators[0])
            return ALLOWED_OPS[type(n.ops[0])](left, right)
        if isinstance(n, ast.Name): return ctx.get(n.id, 0)
        if isinstance(n, ast.Constant): return n.value
        if isinstance(n, ast.Num): return n.n
        raise ValueError(f"Disallowed: {ast.dump(n)}")
    return _ev(tree)

class SignatureMatcher:
    def __init__(self, csv_path='docs/attack_signatures.csv'):
        self.rules = []
        with open(csv_path) as f:
            for row in csv.DictReader(f):
                if row.get('name') == 's08_flashcrowd': continue
                self.rules.append(row)

    def match(self, features):
        hits = []
        for r in self.rules:
            try:
                rule_text = r.get('rule', '')
                if safe_eval(rule_text, features):
                    hits.append({
                        "attack": r.get('name', 'unknown'), 
                        "rule": rule_text,
                        "papers": r.get('papers','')
                    })
            except Exception as e:
                print(f"[sig] eval error {r.get('name')}: {e}")
        return hits