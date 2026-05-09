"""Signature-based detector — đọc CSV của TV1 + parse safe."""
import csv
import ast
import operator

# Chỉ cho phép các phép toán so sánh và logic cơ bản
ALLOWED_OPS = {
    ast.Lt: operator.lt, ast.Gt: operator.gt,
    ast.LtE: operator.le, ast.GtE: operator.ge,
    ast.Eq: operator.eq, ast.NotEq: operator.ne,
    ast.And: all, ast.Or: any
}

def safe_eval(rule_str, ctx):
    tree = ast.parse(rule_str, mode='eval')
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
        if isinstance(n, ast.Num): return n.n  # Hỗ trợ Python bản cũ
        raise ValueError(f"Disallowed: {ast.dump(n)}")
    return _ev(tree)

class SignatureMatcher:
    def __init__(self, csv_path='docs/attack_signatures.csv'):
        self.rules = []
        with open(csv_path) as f:
            for row in csv.DictReader(f):
                # Bỏ qua flashcrowd (vì đây là traffic hợp lệ, không phải tấn công)
                if row['name'] == 's08_flashcrowd': continue
                self.rules.append(row)

    def match(self, features):
        hits = []
        for r in self.rules:
            try:
                # Đưa data vào cây AST để đánh giá
                if safe_eval(r['rule'], features):
                    hits.append({
                        "attack": r['name'], 
                        "rule": r['rule'],
                        "papers": r.get('papers','')
                    })
            except Exception as e:
                print(f"[sig] eval error {r['name']}: {e}")
        return hits