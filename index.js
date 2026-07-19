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

// ============ تطبيق MD5 (مطلوب لتوقيع postback الخاص بـ offerwall.me) ============
// Cloudflare Workers لا يدعم MD5 عبر Web Crypto القياسي (يدعم SHA فقط)، لذا هذا تطبيق JS بحت موثوق (نمط Myers، Public Domain).
function md5(str) {
  function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
  function cmn(q, a, b, x, s, t) {
    a = add32(add32(a, q), add32(x, t));
    return add32((a << s) | (a >>> (32 - s)), b);
  }
  function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
  function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
  function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
  function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }

  function md5cycle(x, k) {
    let a = x[0], b = x[1], c = x[2], d = x[3];
    a = ff(a, b, c, d, k[0], 7, -680876936); d = ff(d, a, b, c, k[1], 12, -389564586);
    c = ff(c, d, a, b, k[2], 17, 606105819); b = ff(b, c, d, a, k[3], 22, -1044525330);
    a = ff(a, b, c, d, k[4], 7, -176418897); d = ff(d, a, b, c, k[5], 12, 1200080426);
    c = ff(c, d, a, b, k[6], 17, -1473231341); b = ff(b, c, d, a, k[7], 22, -45705983);
    a = ff(a, b, c, d, k[8], 7, 1770035416); d = ff(d, a, b, c, k[9], 12, -1958414417);
    c = ff(c, d, a, b, k[10], 17, -42063); b = ff(b, c, d, a, k[11], 22, -1990404162);
    a = ff(a, b, c, d, k[12], 7, 1804603682); d = ff(d, a, b, c, k[13], 12, -40341101);
    c = ff(c, d, a, b, k[14], 17, -1502002290); b = ff(b, c, d, a, k[15], 22, 1236535329);
    a = gg(a, b, c, d, k[1], 5, -165796510); d = gg(d, a, b, c, k[6], 9, -1069501632);
    c = gg(c, d, a, b, k[11], 14, 643717713); b = gg(b, c, d, a, k[0], 20, -373897302);
    a = gg(a, b, c, d, k[5], 5, -701558691); d = gg(d, a, b, c, k[10], 9, 38016083);
    c = gg(c, d, a, b, k[15], 14, -660478335); b = gg(b, c, d, a, k[4], 20, -405537848);
    a = gg(a, b, c, d, k[9], 5, 568446438); d = gg(d, a, b, c, k[14], 9, -1019803690);
    c = gg(c, d, a, b, k[3], 14, -187363961); b = gg(b, c, d, a, k[8], 20, 1163531501);
    a = gg(a, b, c, d, k[13], 5, -1444681467); d = gg(d, a, b, c, k[2], 9, -51403784);
    c = gg(c, d, a, b, k[7], 14, 1735328473); b = gg(b, c, d, a, k[12], 20, -1926607734);
    a = hh(a, b, c, d, k[5], 4, -378558); d = hh(d, a, b, c, k[8], 11, -2022574463);
    c = hh(c, d, a, b, k[11], 16, 1839030562); b = hh(b, c, d, a, k[14], 23, -35309556);
    a = hh(a, b, c, d, k[1], 4, -1530992060); d = hh(d, a, b, c, k[4], 11, 1272893353);
    c = hh(c, d, a, b, k[7], 16, -155497632); b = hh(b, c, d, a, k[10], 23, -1094730640);
    a = hh(a, b, c, d, k[13], 4, 681279174); d = hh(d, a, b, c, k[0], 11, -358537222);
    c = hh(c, d, a, b, k[3], 16, -722521979); b = hh(b, c, d, a, k[6], 23, 76029189);
    a = hh(a, b, c, d, k[9], 4, -640364487); d = hh(d, a, b, c, k[12], 11, -421815835);
    c = hh(c, d, a, b, k[15], 16, 530742520); b = hh(b, c, d, a, k[2], 23, -995338651);
    a = ii(a, b, c, d, k[0], 6, -198630844); d = ii(d, a, b, c, k[7], 10, 1126891415);
    c = ii(c, d, a, b, k[14], 15, -1416354905); b = ii(b, c, d, a, k[5], 21, -57434055);
    a = ii(a, b, c, d, k[12], 6, 1700485571); d = ii(d, a, b, c, k[3], 10, -1894986606);
    c = ii(c, d, a, b, k[10], 15, -1051523); b = ii(b, c, d, a, k[1], 21, -2054922799);
    a = ii(a, b, c, d, k[8], 6, 1873313359); d = ii(d, a, b, c, k[15], 10, -30611744);
    c = ii(c, d, a, b, k[6], 15, -1560198380); b = ii(b, c, d, a, k[13], 21, 1309151649);
    a = ii(a, b, c, d, k[4], 6, -145523070); d = ii(d, a, b, c, k[11], 10, -1120210379);
    c = ii(c, d, a, b, k[2], 15, 718787259); b = ii(b, c, d, a, k[9], 21, -343485551);
    x[0] = add32(a, x[0]); x[1] = add32(b, x[1]); x[2] = add32(c, x[2]); x[3] = add32(d, x[3]);
  }

  function md5blk(s) {
    const blks = [];
    for (let i = 0; i < 64; i += 4) {
      blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24);
    }
    return blks;
  }

  function md51(s) {
    const n = s.length;
    const state = [1732584193, -271733879, -1732584194, 271733878];
    let i;
    for (i = 64; i <= s.length; i += 64) md5cycle(state, md5blk(s.substring(i - 64, i)));
    s = s.substring(i - 64);
    const tail = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    for (i = 0; i < s.length; i++) tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
    tail[i >> 2] |= 0x80 << ((i % 4) << 3);
    if (i > 55) {
      md5cycle(state, tail);
      for (i = 0; i < 16; i++) tail[i] = 0;
    }
    tail[14] = n * 8;
    md5cycle(state, tail);
    return state;
  }

  const hexChr = "0123456789abcdef".split("");
  function rhex(n) {
    let s = "";
    for (let j = 0; j < 4; j++) s += hexChr[(n >> (j * 8 + 4)) & 0x0F] + hexChr[(n >> (j * 8)) & 0x0F];
    return s;
  }

  const utf8 = unescape(encodeURIComponent(str));
  return md51(utf8).map(rhex).join("");
}

// يستخرج بيانات الـ postback سواء وصلت كـ query params أو POST body (form/json)
async function getPostbackParams(request, url) {
  const params = {};
  for (const [k, v] of url.searchParams) params[k] = v;
  if (request.method === "POST") {
    const ct = request.headers.get("content-type") || "";
    try {
      if (ct.includes("application/json")) {
        const body = await request.json();
        Object.assign(params, body);
      } else {
        const text = await request.text();
        const usp = new URLSearchParams(text);
        for (const [k, v] of usp) params[k] = v;
      }
    } catch (e) {
      // تجاهل، نعتمد فقط على query params لو فشل تحليل الجسم
    }
  }
  return params;
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

      // ---------- postback مخصص لشبكة offerwall.me ----------
      // رابط تضبطه بلوحة offerwall.me بالضبط بدون أي باراميترات إضافية:
      // https://your-worker.dev/api/postback/offerwallme
      // الشبكة نفسها ترسل كل البيانات (subId, transId, reward, payout, status, signature...) بجسم الطلب
      if (path === "/api/postback/offerwallme" && (request.method === "GET" || request.method === "POST")) {
        const p = await getPostbackParams(request, url);
        const { subId, transId, reward, payout, status, signature } = p;

        if (!subId || !transId || reward === undefined || !signature) {
          return new Response("ERROR: missing parameters", { status: 400 });
        }

        // التحقق من التوقيع: MD5(subId + "." + transId + "." + reward + "." + السر الخاص بك)
        const expectedSignature = md5(`${subId}.${transId}.${reward}.${env.OFFERWALLME_SECRET || ""}`);
        if (expectedSignature !== signature) {
          return new Response("ERROR: Signature doesn't match", { status: 403 });
        }

        const user = await env.DB.prepare("SELECT * FROM users WHERE ff_id = ?").bind(subId).first();
        if (!user) return new Response("ERROR: user not found", { status: 404 });

        // status = "2" يعني استرجاع (chargeback) بسبب احتيال أو خطأ من المعلن -> نخصم بدل ما نضيف
        const isChargeback = String(status) === "2";
        const rewardAmount = Math.round(parseFloat(reward)) || 0;
        const delta = isChargeback ? -rewardAmount : rewardAmount;

        try {
          await env.DB.prepare(
            "INSERT INTO offer_completions (user_id, network, transaction_id, payout_usd, points_awarded) VALUES (?, ?, ?, ?, ?)"
          )
            .bind(user.id, "offerwallme", transId, parseFloat(payout || "0"), delta)
            .run();
        } catch (e) {
          // transId مكرر -> تم تسجيله مسبقاً، لا تضف نقاط مرة ثانية لكن أكّد الاستلام
          return new Response("ok");
        }

        await env.DB.prepare("UPDATE users SET points = points + ? WHERE id = ?").bind(delta, user.id).run();
        return new Response("ok"); // مهم: يجب أن يكون الرد بالضبط "ok" وليس JSON
      }

      // ---------- postback عام لبقية الشبكات (CPAlead وغيرها) ----------
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
      // يحوّل الرصيد إلى أقرب مضاعف صحيح للحد الأدنى (100، 200، 300...) فقط
      // مثال: لو الرصيد 140 نقطة، يُستبدل 100 فقط ويبقى 40 بالحساب لمرة قادمة
      if (path === "/api/redeem" && request.method === "POST") {
        const user = await getUserFromAuth(request, env);
        if (!user) return cors(json({ error: "غير مصرح" }, 401));

        if (user.points < CLAIM_THRESHOLD_POINTS) {
          return cors(json({ error: `تحتاج ${CLAIM_THRESHOLD_POINTS} نقطة على الأقل للمطالبة` }, 400));
        }

        // عدد "الوحدات" الكاملة من الحد الأدنى المتاحة بالرصيد الحالي
        const redeemableUnits = Math.floor(user.points / CLAIM_THRESHOLD_POINTS);
        const points_cost = redeemableUnits * CLAIM_THRESHOLD_POINTS; // دائماً مضاعف لـ 100
        const diamonds = points_cost / POINTS_PER_DIAMOND;

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
