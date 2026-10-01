"""交还撤销（核码后发现物品实际仍在馆内）端到端 + 并发测试（标准库）。

前置：服务已运行在 http://127.0.0.1:8181，数据目录为 /tmp/lfdata。
覆盖：
  - 正常撤销：物品恢复保管中、申请归属与获选状态保持、已核销码永久失效、
    按现有有效期规则签发新码、撤销记录（原核销时间/撤销时间/原因）可追溯；
  - 拒绝情形且不改动数据：非已交还、空原因、伪造 CSRF、物品不存在、
    重复撤销、核销记录不属于当前获选申请、该次登记已撤销；
  - 可见性：工作人员可见撤销记录；访客凭原查询凭证只见本人最新状态与新码，
    不显示撤销原因；
  - 恢复后改判 / 合并 / 核码规则照常（合并时撤销记录随物品归并）；
  - 并发：重复撤销只生效一次；撤销与核码并发时最终状态一致。
"""
import http.cookiejar
import re
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = "http://127.0.0.1:8181"
DB_PATH = "/tmp/lfdata/lostfound.db"
PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def client():
    cj = http.cookiejar.CookieJar()
    return cj, urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def req(op, method, path, form=None):
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    try:
        resp = op.open(r)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def raw(op, method, path, form):
    """不跟随 303，返回 (status, body, location)。"""
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    opener = urllib.request.build_opener(
        NoRedirect, urllib.request.HTTPCookieProcessor(_jar_of(op))
    )
    try:
        resp = opener.open(r)
        return resp.status, resp.read().decode(), resp.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers.get("Location", "")


def raw_cookie(cookie_header, path, form):
    """线程内手工带 Cookie 的无跳转 POST（不共享 CookieJar，线程安全）。"""
    data = urllib.parse.urlencode(form).encode()
    r = urllib.request.Request(BASE + path, data=data, method="POST")
    r.add_header("Cookie", cookie_header)
    try:
        resp = urllib.request.build_opener(NoRedirect).open(r)
        return resp.status, resp.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "")


def _jar_of(op):
    for h in op.handlers:
        if isinstance(h, urllib.request.HTTPCookieProcessor):
            return h.cookiejar
    return http.cookiejar.CookieJar()


def csrf(htmltext):
    m = re.search(r'name="csrf_token" value="([^"]+)"', htmltext)
    return m.group(1) if m else None


def submit_claim(item_id, answer, contact):
    _, v = client()
    st, body = req(v, "POST", f"/items/{item_id}/claims", form={"answer": answer, "contact": contact})
    assert st == 200 and "查询凭证" in body, (st, body[:200])
    return re.search(r'<div class="tokenbox">([^<]+)</div>', body).group(1).strip()


def query(token):
    _, v = client()
    st, body = req(v, "GET", f"/query?token={urllib.parse.quote(token)}")
    assert st == 200
    return body


def make_item(desc, priv="私密特征-用例"):
    st, _, loc = raw(staff, "POST", "/staff/items",
                     form={"csrf_token": SCSRF, "public_description": desc, "private_features": priv})
    assert st == 303, (st, loc)
    return int(loc.rsplit("/", 1)[1])


def claims_of(item_id):
    return dict(db.execute("SELECT id,status FROM claims WHERE item_id=?", (item_id,)).fetchall())


def item_status(item_id):
    return db.execute("SELECT status FROM items WHERE id=?", (item_id,)).fetchone()["status"]


def active_codes(claim_id):
    return db.execute(
        "SELECT * FROM handover_codes WHERE claim_id=? AND consumed_at IS NULL"
        " AND invalidated_at IS NULL", (claim_id,)).fetchall()


jar, staff = client()
_, body = req(staff, "GET", "/staff/login")
req(staff, "POST", "/staff/login", form={"csrf_token": csrf(body), "password": "secret123"})
_, dash = req(staff, "GET", "/staff")
SCSRF = csrf(dash)
cookie_header = "; ".join(f"{c.name}={c.value}" for c in jar)

db = sqlite3.connect(DB_PATH)
db.row_factory = sqlite3.Row


def revoke(item_id, reason, csrf_token=SCSRF):
    return raw(staff, "POST", f"/staff/items/{item_id}/revoke-handover",
               form={"csrf_token": csrf_token, "reason": reason})

# ============================================================ 1 正常撤销与追溯
print("== 正常撤销：状态恢复、新码签发、记录可追溯 ==")
i1 = make_item("黑色耳机-用例一", "私密-耳机内侧刻字")
tA = submit_claim(i1, "甲答案-说对刻字", "contact-A")
tB = submit_claim(i1, "乙答案-陪跑", "contact-B")
cA, cB = [r["id"] for r in db.execute(
    "SELECT id FROM claims WHERE item_id=? ORDER BY id", (i1,)).fetchall()]
raw(staff, "POST", f"/staff/claims/{cA}/select", form={"csrf_token": SCSRF})
code1 = re.search(r'codebox">(\d{8})', query(tA)).group(1)
st, _, loc = raw(staff, "POST", "/staff/verify", form={"csrf_token": SCSRF, "code": code1})
check("核码交还成功", st == 303 and loc == f"/staff/items/{i1}", f"{st} {loc}")
check("物品已交还", item_status(i1) == "returned")
_, v = client()
st, body = req(v, "GET", "/")
check("已交还物品不在公开列表", "黑色耳机-用例一" not in body)

st, body = req(staff, "GET", f"/staff/items/{i1}")
check("已交还物品页提供撤销表单",
      f"/staff/items/{i1}/revoke-handover" in body and "撤销交还登记" in body)

st, _, loc = revoke(i1, "核码后发现物品仍在馆内")
check("撤销成功并跳回物品页", st == 303 and loc == f"/staff/items/{i1}", f"{st} {loc}")
st, body = req(staff, "GET", loc)
check("撤销完成提示", "已撤销" in body)

check("物品恢复保管中", item_status(i1) == "kept")
rows = claims_of(i1)
check("申请归属与获选状态保持", rows[cA] == "selected" and rows[cB] == "rejected", str(rows))
consumed = db.execute(
    "SELECT * FROM handover_codes WHERE claim_id=? AND consumed_at IS NOT NULL",
    (cA,)).fetchall()
check("已核销码保持已核销（永久失效）", len(consumed) == 1, str(len(consumed)))
rev = db.execute("SELECT * FROM handover_revocations WHERE item_id=?", (i1,)).fetchall()
check("撤销记录已保存并关联本次核销码",
      len(rev) == 1 and rev[0]["claim_id"] == cA and rev[0]["code_id"] == consumed[0]["id"],
      str([dict(r) for r in rev]))
check("撤销记录含原核销时间快照",
      rev and rev[0]["consumed_at"] == consumed[0]["consumed_at"])
check("撤销记录含原因与撤销时间",
      rev and rev[0]["reason"] == "核码后发现物品仍在馆内" and rev[0]["created_at"] is not None)

act = active_codes(cA)
check("撤销后为获选人签发恰一枚新码", len(act) == 1, str(len(act)))
check("新码按现有有效期规则签发", act and act[0]["expires_at"] > act[0]["issued_at"])
qA = query(tA)
m = re.search(r'codebox">(\d{8})', qA)
check("获选人凭原查询凭证看到新码", bool(m) and m.group(1) != code1)
code2 = m.group(1) if m else ""
check("获选人查询页不显示撤销原因", "核码后发现物品仍在馆内" not in qA and "撤销" not in qA)
qB = query(tB)
check("其他申请人看不到新码与撤销原因", code2 not in qB and "撤销" not in qB)

st, body = req(staff, "GET", f"/staff/items/{i1}")
check("工作人员物品页展示撤销记录（含原因与原核销/撤销时间）",
      "交还撤销记录" in body and "核码后发现物品仍在馆内" in body
      and "原核销时间" in body and "撤销时间" in body)
st, body = req(staff, "GET", f"/staff/claims/{cA}")
check("工作人员在获选申请页可见新码", code2 in body)
_, v = client()
st, body = req(v, "GET", "/")
check("撤销后物品重回公开列表", "黑色耳机-用例一" in body)
st, body = req(v, "GET", f"/items/{i1}")
check("访客物品页不显示撤销原因", "核码后发现物品仍在馆内" not in body and "撤销" not in body)
st, _ = req(v, "POST", f"/staff/items/{i1}/revoke-handover",
            form={"csrf_token": "x", "reason": "x"})
check("访客不能调用撤销接口(403)", st == 403)

st, body = req(staff, "POST", "/staff/verify", form={"csrf_token": SCSRF, "code": code1})
check("已核销旧码核销被拒（永久失效）", "已使用" in body, body[:120])
check("物品未因旧码尝试改变状态", item_status(i1) == "kept")

print("== 再次交还可再次撤销（多周期） ==")
st, _, loc = raw(staff, "POST", "/staff/verify", form={"csrf_token": SCSRF, "code": code2})
check("新码可正常核销", st == 303 and item_status(i1) == "returned", f"{st} {loc}")
st, _, _ = revoke(i1, "第二次撤销")
check("第二次撤销成功", item_status(i1) == "kept")
check("撤销记录累计两条",
      db.execute("SELECT COUNT(*) AS n FROM handover_revocations WHERE item_id=?",
                 (i1,)).fetchone()["n"] == 2)
check("第二次撤销后再签发一枚新码", len(active_codes(cA)) == 1)

# ============================================================ 2 拒绝情形
print("== 拒绝情形：不改动任何数据 ==")
i2 = make_item("白色水杯-拒绝用例", "私密-杯底划痕")
tC = submit_claim(i2, "丙答案", "contact-C")
tD = submit_claim(i2, "丁答案", "contact-D")
cC, cD = [r["id"] for r in db.execute(
    "SELECT id FROM claims WHERE item_id=? ORDER BY id", (i2,)).fetchall()]
raw(staff, "POST", f"/staff/claims/{cC}/select", form={"csrf_token": SCSRF})
codeC = re.search(r'codebox">(\d{8})', query(tC)).group(1)

st, _, loc = revoke(i2, "物品还没交还")
check("保管中物品撤销被拒并跳回", st == 303 and loc == f"/staff/items/{i2}")
st, body = req(staff, "GET", f"/staff/items/{i2}")
check("非已交还拒绝提示", "仅已交还" in body)
check("保管中物品页不提供撤销表单", "revoke-handover" not in body)
check("拒绝后物品状态与交还码不变",
      item_status(i2) == "kept" and len(active_codes(cC)) == 1
      and db.execute("SELECT COUNT(*) AS n FROM handover_revocations WHERE item_id=?",
                     (i2,)).fetchone()["n"] == 0)

st, _, loc = revoke(i2, "   ")
check("空原因被拒并跳回", st == 303 and loc == f"/staff/items/{i2}")
st, body = req(staff, "GET", f"/staff/items/{i2}")
check("空原因提示", "撤销原因不能为空" in body)

st, _, _ = revoke(i2, "x", csrf_token="bad")
check("伪造 CSRF 被拒(400)", st == 400)

st, _, _ = raw(staff, "POST", "/staff/items/99999999/revoke-handover",
               form={"csrf_token": SCSRF, "reason": "幽灵物品"})
check("物品不存在(404)", st == 404)

i3 = make_item("已撤下物品-拒绝用例", "p")
raw(staff, "POST", f"/staff/items/{i3}/remove", form={"csrf_token": SCSRF})
st, _, _ = revoke(i3, "撤下后撤销")
st, body = req(staff, "GET", f"/staff/items/{i3}")
check("已撤下物品撤销被拒", "仅已交还" in body)
check("已撤下物品页不提供撤销表单", "revoke-handover" not in body)

print("== 重复撤销与记录不匹配 ==")
raw(staff, "POST", "/staff/verify", form={"csrf_token": SCSRF, "code": codeC})
check("物品2已交还", item_status(i2) == "returned")
st, _, _ = revoke(i2, "第一次撤销")
check("第一次撤销成功", item_status(i2) == "kept")
n_codes = db.execute("SELECT COUNT(*) AS n FROM handover_codes WHERE claim_id=?",
                     (cC,)).fetchone()["n"]
st, _, _ = revoke(i2, "重复撤销")
st, body = req(staff, "GET", f"/staff/items/{i2}")
check("重复撤销被拒（物品已非已交还）", "仅已交还" in body)
check("重复撤销不改动数据",
      db.execute("SELECT COUNT(*) AS n FROM handover_revocations WHERE item_id=?",
                 (i2,)).fetchone()["n"] == 1
      and db.execute("SELECT COUNT(*) AS n FROM handover_codes WHERE claim_id=?",
                     (cC,)).fetchone()["n"] == n_codes)

# 核销记录不属于当前获选申请：直接把已核销码改挂到另一份申请（构造记录不匹配）
i4 = make_item("背包-记录不匹配", "p")
tE = submit_claim(i4, "戊答案", "contact-E")
tF = submit_claim(i4, "己答案", "contact-F")
cE, cF = [r["id"] for r in db.execute(
    "SELECT id FROM claims WHERE item_id=? ORDER BY id", (i4,)).fetchall()]
raw(staff, "POST", f"/staff/claims/{cE}/select", form={"csrf_token": SCSRF})
codeE = re.search(r'codebox">(\d{8})', query(tE)).group(1)
raw(staff, "POST", "/staff/verify", form={"csrf_token": SCSRF, "code": codeE})
check("物品4已交还", item_status(i4) == "returned")
db.execute("UPDATE handover_codes SET claim_id=? WHERE claim_id=? AND consumed_at IS NOT NULL",
           (cF, cE))
db.commit()
st, _, _ = revoke(i4, "记录不匹配")
st, body = req(staff, "GET", f"/staff/items/{i4}")
check("核销记录不属于当前获选申请时被拒", "核销记录" in body)
check("不匹配拒绝后状态不变", item_status(i4) == "returned")

# 该次登记已有撤销记录：拒绝重复撤销（把码挂回并预置一条撤销记录）
db.execute("UPDATE handover_codes SET claim_id=? WHERE claim_id=? AND consumed_at IS NOT NULL",
           (cE, cF))
row = db.execute("SELECT id, consumed_at FROM handover_codes"
                 " WHERE claim_id=? AND consumed_at IS NOT NULL", (cE,)).fetchone()
db.execute(
    "INSERT INTO handover_revocations (item_id, claim_id, code_id, consumed_at, reason, created_at)"
    " VALUES (?, ?, ?, ?, ?, ?)",
    (i4, cE, row["id"], row["consumed_at"], "预置撤销记录", row["consumed_at"]))
db.commit()
st, _, _ = revoke(i4, "重复撤销已撤销的登记")
st, body = req(staff, "GET", f"/staff/items/{i4}")
check("该次登记已撤销时拒绝重复撤销", "已被撤销" in body)
check("已撤销拒绝后状态不变", item_status(i4) == "returned"
      and db.execute("SELECT COUNT(*) AS n FROM handover_revocations WHERE item_id=?",
                     (i4,)).fetchone()["n"] == 1)

# ============================================================ 3 并发：重复撤销只生效一次
print("== 并发：两个撤销请求只生效一次 ==")
i5 = make_item("灰色手套-并发用例", "p")
tG = submit_claim(i5, "庚答案", "contact-G")
cG = db.execute("SELECT id FROM claims WHERE item_id=?", (i5,)).fetchone()["id"]
raw(staff, "POST", f"/staff/claims/{cG}/select", form={"csrf_token": SCSRF})
codeG = re.search(r'codebox">(\d{8})', query(tG)).group(1)
raw(staff, "POST", "/staff/verify", form={"csrf_token": SCSRF, "code": codeG})
check("物品5已交还", item_status(i5) == "returned")
barrier = threading.Barrier(2)


def revoke_hit():
    barrier.wait()
    return raw_cookie(cookie_header, f"/staff/items/{i5}/revoke-handover",
                      {"csrf_token": SCSRF, "reason": "并发撤销"})


with ThreadPoolExecutor(max_workers=2) as ex:
    r1, r2 = [f.result() for f in [ex.submit(revoke_hit), ex.submit(revoke_hit)]]
check("并发撤销后物品保管中", item_status(i5) == "kept", f"{r1} {r2}")
check("并发撤销只产生一条撤销记录",
      db.execute("SELECT COUNT(*) AS n FROM handover_revocations WHERE item_id=?",
                 (i5,)).fetchone()["n"] == 1)
check("并发撤销只签发一枚新码", len(active_codes(cG)) == 1)
check("已核销码仍恰一枚",
      db.execute("SELECT COUNT(*) AS n FROM handover_codes"
                 " WHERE claim_id=? AND consumed_at IS NOT NULL", (cG,)).fetchone()["n"] == 1)

# ============================================================ 4 并发：撤销 × 核码
print("== 并发：撤销与核码交错时最终状态一致 ==")
codeG2 = re.search(r'codebox">(\d{8})', query(tG)).group(1)
barrier2 = threading.Barrier(2)


def revoke2():
    barrier2.wait()
    return raw_cookie(cookie_header, f"/staff/items/{i5}/revoke-handover",
                      {"csrf_token": SCSRF, "reason": "与核码并发"})


def consume2():
    barrier2.wait()
    return raw_cookie(cookie_header, "/staff/verify", {"csrf_token": SCSRF, "code": codeG2})


with ThreadPoolExecutor(max_workers=2) as ex:
    fr = ex.submit(revoke2)
    fc = ex.submit(consume2)
    rr, rc = fr.result(), fc.result()
n_rev = db.execute("SELECT COUNT(*) AS n FROM handover_revocations WHERE item_id=?",
                   (i5,)).fetchone()["n"]
n_consumed = db.execute("SELECT COUNT(*) AS n FROM handover_codes"
                        " WHERE claim_id=? AND consumed_at IS NOT NULL", (cG,)).fetchone()["n"]
n_active = len(active_codes(cG))
st5 = item_status(i5)
# 两种合法交错：
#  A) 核码先提交 -> 物品 returned；撤销随后看到 returned 且新核销未撤销 -> 再次生效：
#     最终 kept、2 条撤销、2 枚已核销、1 枚活跃新码；
#  B) 撤销先被判拒（物品 kept 不满足条件）-> 核码生效：
#     最终 returned、1 条撤销、2 枚已核销、0 枚活跃码。
if st5 == "kept":
    check("交错A：核码后撤销再次生效，状态一致",
          n_rev == 2 and n_consumed == 2 and n_active == 1,
          f"{rr} {rc} rev={n_rev} consumed={n_consumed} active={n_active}")
else:
    check("交错B：撤销被拒、核码生效，状态一致",
          st5 == "returned" and n_rev == 1 and n_consumed == 2 and n_active == 0,
          f"{rr} {rc} rev={n_rev} consumed={n_consumed} active={n_active} status={st5}")

# ============================================================ 5 恢复后规则照常
print("== 恢复后改判 / 合并 / 核码规则照常 ==")
i6 = make_item("折叠雨伞-恢复规则", "p")
tH = submit_claim(i6, "辛答案", "contact-H")
tI = submit_claim(i6, "壬答案", "contact-I")
cH, cI = [r["id"] for r in db.execute(
    "SELECT id FROM claims WHERE item_id=? ORDER BY id", (i6,)).fetchall()]
raw(staff, "POST", f"/staff/claims/{cH}/select", form={"csrf_token": SCSRF})
codeH = re.search(r'codebox">(\d{8})', query(tH)).group(1)
raw(staff, "POST", "/staff/verify", form={"csrf_token": SCSRF, "code": codeH})
check("物品6已交还", item_status(i6) == "returned")
st, _, _ = revoke(i6, "恢复后规则验证")
check("撤销后物品恢复保管中", item_status(i6) == "kept")

st, _, loc = raw(staff, "POST", f"/staff/claims/{cH}/rejudge",
                 form={"csrf_token": SCSRF, "to_claim_id": cI, "reason": "撤销后改判"})
check("撤销恢复后可正常改判", st == 303 and loc == f"/staff/claims/{cI}", f"{st} {loc}")
check("改判后获选转移", claims_of(i6)[cI] == "selected")
codeI = re.search(r'codebox">(\d{8})', query(tI)).group(1)

i7 = make_item("折叠雨伞-保留条", "p")
st, _, loc = raw(staff, "POST", f"/staff/items/{i7}/merge",
                 form={"csrf_token": SCSRF, "merged_item_id": i6, "reason": "同物合并"})
check("撤销恢复后物品可参与合并", st == 303 and item_status(i6) == "merged", f"{st} {loc}")
check("撤销记录随合并归到保留物品",
      db.execute("SELECT COUNT(*) AS n FROM handover_revocations WHERE item_id=?",
                 (i7,)).fetchone()["n"] == 1
      and db.execute("SELECT COUNT(*) AS n FROM handover_revocations WHERE item_id=?",
                     (i6,)).fetchone()["n"] == 0)
st, body = req(staff, "GET", f"/staff/items/{i7}")
check("保留物品页展示归并的撤销记录", "交还撤销记录" in body and "恢复后规则验证" in body)
check("合并后获选人原交还码保留", codeI in query(tI))
st, _, loc = raw(staff, "POST", "/staff/verify", form={"csrf_token": SCSRF, "code": codeI})
check("合并后核码照常完成交还", st == 303 and item_status(i7) == "returned", f"{st} {loc}")

print(f"\n结果：{PASS} 通过, {FAIL} 失败")
raise SystemExit(1 if FAIL else 0)
