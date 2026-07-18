/**
 * Worker خاص بمنصة نقاط شحن Free Fire
 * المسارات:
 *   POST /api/register        { ff_id, pin }            -> إنشاء حساب جديد
 *   POST /api/login           { ff_id, pin }             -> تسجيل الدخول + إرجاع session token
 *   GET  /api/me               (Authorization: Bearer)   -> بيانات المستخدم ورصيده
 *   GET  /api/postback/:network  (?transaction_id&payout&points&ff_id) -> إشعار شبكة CPA عند اكتمال عرض
 *   POST /api/redeem          { diamonds }  (Authorization: Bearer) -> طلب استبدال نقاط بجواهر
 *   GET  /api/redemptions      (admin, Authorization: Bearer ADMIN_SECRET) -> قائمة الطلبات المعلّقة
 */

const POINTS_PER_DIAMOND = 1; // معدل التحويل: 1 نقطة = 1 جوهرة
const CLAIM_THRESHOLD_POINTS = 100; // الحد الأدنى من النقاط قبل السماح بالمطالبة
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // أسبوع

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function cors(resp) {
  resp.headers.set("Access-Control-Allow-Origin", "*");
  resp.headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  resp.headers.set("Access-Control-Allow-Headers", "Content-Type,Authorization");
  return resp;
}

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hashPin(ff_id, pin, salt) {
  return sha256(`${salt}:${ff_id}:${pin}`);
}

function makeToken() {
  return crypto.randomUUID().replace(/-/g, "");
}

async function getUserFromAuth(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const row = await env.DB.prepare(
    "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > datetime('now')"
  )
    .bind(token)
    .first();
  return row || null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));

    try {
      // ---------- تسجيل حساب جديد ----------
      if (path === "/api/register" && request.method === "POST") {
        const { ff_id, pin } = await request.json();
        if (!ff_id || !/^\d{4}$/.test(pin || "")) {
          return cors(json({ error: "ff_id مطلوب، و pin يجب أن يكون 4 أرقام" }, 400));
        }
        const existing = await env.DB.prepare("SELECT id FROM users WHERE ff_id = ?").bind(ff_id).first();
        if (existing) return cors(json({ error: "هذا المعرف مسجل مسبقاً" }, 409));

        const salt = crypto.randomUUID();
        const pin_hash = `${salt}:${await hashPin(ff_id, pin, salt)}`;
        await env.DB.prepare("INSERT INTO users (ff_id, pin_hash) VALUES (?, ?)").bind(ff_id, pin_hash).run();
        return cors(json({ ok: true }));
      }

      // ---------- تسجيل الدخول ----------
      if (path === "/api/login" && request.method === "POST") {
        const { ff_id, pin } = await request.json();
        const user = await env.DB.prepare("SELECT * FROM users WHERE ff_id = ?").bind(ff_id).first();
        if (!user || user.status === "banned") return cors(json({ error: "بيانات الدخول غير صحيحة" }, 401));

        const [salt, storedHash] = user.pin_hash.split(":");
        const attemptHash = await hashPin(ff_id, pin, salt);
        if (attemptHash !== storedHash) return cors(json({ error: "بيانات الدخول غير صحيحة" }, 401));

        const token = makeToken();
        await env.DB.prepare(
          "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+' || ? || ' seconds'))"
        )
          .bind(token, user.id, SESSION_TTL_SECONDS)
          .run();
        await env.DB.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").bind(user.id).run();

        return cors(json({ token, points: user.points }));
      }

      // ---------- بيانات المستخدم الحالي ----------
      if (path === "/api/me" && request.method === "GET") {
        const user = await getUserFromAuth(request, env);
        if (!user) return cors(json({ error: "غير مصرح" }, 401));
        return cors(json({ ff_id: user.ff_id, points: user.points, status: user.status }));
      }

      // ---------- postback من شبكة CPA عند اكتمال عرض ----------
      // مثال رابط تضبطه في إعدادات CPAlead:
      // https://your-worker.dev/api/postback/cpalead?ff_id={subid}&transaction_id={transaction_id}&payout={payout}
      if (path.startsWith("/api/postback/") && request.method === "GET") {
        const network = path.split("/").pop();
        const ff_id = url.searchParams.get("ff_id");
        const transaction_id = url.searchParams.get("transaction_id");
        const payout = parseFloat(url.searchParams.get("payout") || "0");

        if (!ff_id || !transaction_id) return cors(json({ error: "بيانات ناقصة" }, 400));

        const user = await env.DB.prepare("SELECT * FROM users WHERE ff_id = ?").bind(ff_id).first();
        if (!user) return cors(json({ error: "مستخدم غير موجود" }, 404));

        // نسبة تحويل من الدولار إلى نقاط - عدّلها حسب هامش ربحك المحسوب
        const USD_TO_POINTS = 50; // كل 1$ = 50 نقطة → أي 2$ = 100 نقطة
        const points_awarded = Math.floor(payout * USD_TO_POINTS);

        try {
          await env.DB.prepare(
            "INSERT INTO offer_completions (user_id, network, transaction_id, payout_usd, points_awarded) VALUES (?, ?, ?, ?, ?)"
          )
            .bind(user.id, network, transaction_id, payout, points_awarded)
            .run();
        } catch (e) {
          // transaction_id مكرر -> يمنع الاحتيال بإعادة إرسال نفس postback
          return cors(json({ error: "تم تسجيل هذه المعاملة مسبقاً" }, 409));
        }

        await env.DB.prepare("UPDATE users SET points = points + ? WHERE id = ?").bind(points_awarded, user.id).run();
        return cors(json({ ok: true, points_awarded }));
      }

      // ---------- مطالبة بالجواهر: تظهر فقط عند بلوغ الحد الأدنى ----------
      // يحوّل كامل الرصيد المتاح (بما يقبل القسمة على معدل التحويل) إلى طلب شحن معلّق
      if (path === "/api/redeem" && request.method === "POST") {
        const user = await getUserFromAuth(request, env);
        if (!user) return cors(json({ error: "غير مصرح" }, 401));

        if (user.points < CLAIM_THRESHOLD_POINTS) {
          return cors(json({ error: `تحتاج ${CLAIM_THRESHOLD_POINTS} نقطة على الأقل للمطالبة` }, 400));
        }

        const diamonds = Math.floor(user.points / POINTS_PER_DIAMOND);
        const points_cost = diamonds * POINTS_PER_DIAMOND; // يترك الباقي (fraction) في رصيد المستخدم

        // خصم ذري (atomic): ينجح فقط إذا كان الرصيد كافياً فعلياً وقت التنفيذ.
        // هذا يمنع نجاح أكثر من طلب استبدال متزامن (مثلاً عند الضغط على الزر عدة مرات بسرعة).
        const updateResult = await env.DB.prepare(
          "UPDATE users SET points = points - ? WHERE id = ? AND points >= ?"
        ).bind(points_cost, user.id, points_cost).run();

        if (!updateResult.meta || updateResult.meta.changes === 0) {
          return cors(json({ error: "تم تنفيذ طلب آخر بالفعل على نفس الرصيد، حدّث الصفحة وحاول مجدداً" }, 409));
        }

        await env.DB.prepare(
          "INSERT INTO redemptions (user_id, diamonds, points_cost) VALUES (?, ?, ?)"
        ).bind(user.id, diamonds, points_cost).run();

        return cors(json({ ok: true, diamonds, remaining_points: user.points - points_cost }));
      }

      // ---------- لوحة الأدمن: عرض طلبات الاستبدال المعلّقة ----------
      if (path === "/api/redemptions" && request.method === "GET") {
        const adminSecret = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
        if (adminSecret !== env.ADMIN_SECRET) return cors(json({ error: "غير مصرح" }, 401));

        const { results } = await env.DB.prepare(
          `SELECT r.id, u.ff_id, r.diamonds, r.points_cost, r.status, r.created_at
           FROM redemptions r JOIN users u ON u.id = r.user_id
           WHERE r.status = 'pending' ORDER BY r.created_at ASC`
        ).all();
        // r.id متاح هنا ليُستخدم في POST /api/redemptions/:id/complete من لوحة الأدمن
        return cors(json({ redemptions: results }));
      }

      // ---------- تعليم طلب استبدال كمكتمل بعد الشحن اليدوي ----------
      if (path.match(/^\/api\/redemptions\/\d+\/complete$/) && request.method === "POST") {
        const adminSecret = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
        if (adminSecret !== env.ADMIN_SECRET) return cors(json({ error: "غير مصرح" }, 401));

        const id = path.split("/")[3];
        await env.DB.prepare(
          "UPDATE redemptions SET status = 'completed', processed_at = datetime('now') WHERE id = ?"
        )
          .bind(id)
          .run();
        return cors(json({ ok: true }));
      }

      return cors(json({ error: "المسار غير موجود" }, 404));
    } catch (err) {
      return cors(json({ error: "خطأ في الخادم", details: String(err) }, 500));
    }
  },
};
