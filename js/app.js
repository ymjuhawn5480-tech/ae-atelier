const app = document.getElementById("app");
const nav = document.getElementById("siteNav");
const toggle = document.getElementById("navToggle");

const state = {
  user: null,
  portfolios: [],
  activeId: null,
  ready: false,
};

toggle.addEventListener("click", () => nav.classList.toggle("open"));
nav.addEventListener("click", (e) => {
  if (e.target.matches("[data-link]") || e.target.id === "logoutBtn") nav.classList.remove("open");
});

const DB_KEY = "ae-atelier-accounts";
const SESSION_KEY = "ae-atelier-session";

function loadDb() {
  try {
    const db = JSON.parse(localStorage.getItem(DB_KEY) || "");
    if (!db || !Array.isArray(db.users) || !Array.isArray(db.portfolios)) throw new Error("empty");
    return db;
  } catch {
    return { users: [], portfolios: [] };
  }
}

function saveDb(db) {
  try {
    localStorage.setItem(DB_KEY, JSON.stringify(db));
  } catch {
    throw new Error("저장 공간이 부족합니다. 이미지 용량을 줄이거나 포트폴리오를 삭제하세요.");
  }
}

function currentLocalUser(db) {
  const id = localStorage.getItem(SESSION_KEY);
  return db.users.find((u) => u.id === id) || null;
}

function publicUser(user) {
  return user ? { id: user.id, name: user.name, email: user.email } : null;
}

function sessionView(db, user) {
  return {
    user: publicUser(user),
    portfolios: user
      ? db.portfolios
          .filter((p) => p.userId === user.id)
          .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)))
      : [],
    activeId: user?.activePortfolioId || null,
  };
}

function bytesToB64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

async function digestPassword(password, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 120000, hash: "SHA-256" },
    key,
    256
  );
  return bytesToB64(new Uint8Array(bits));
}

async function localApi(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const body = options.body || {};
  const db = loadDb();
  let user = currentLocalUser(db);

  if (path === "/api/auth/signup" && method === "POST") {
    const name = String(body.name || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (name.length < 2) throw new Error("이름을 2자 이상 입력하세요.");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("올바른 이메일을 입력하세요.");
    if (password.length < 8) throw new Error("비밀번호는 8자 이상이어야 합니다.");
    if (db.users.some((u) => u.email === email)) throw new Error("이미 가입된 이메일입니다.");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const created = {
      id: crypto.randomUUID(),
      name,
      email,
      salt: bytesToB64(salt),
      passwordHash: await digestPassword(password, salt),
      activePortfolioId: null,
    };
    db.users.push(created);
    saveDb(db);
    localStorage.setItem(SESSION_KEY, created.id);
    return sessionView(db, created);
  }

  if (path === "/api/auth/login" && method === "POST") {
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const found = db.users.find((u) => u.email === email);
    let ok = false;
    if (found) {
      const salt = Uint8Array.from(atob(found.salt), (c) => c.charCodeAt(0));
      ok = (await digestPassword(password, salt)) === found.passwordHash;
    }
    if (!ok) throw new Error("이메일 또는 비밀번호가 올바르지 않습니다.");
    localStorage.setItem(SESSION_KEY, found.id);
    return sessionView(db, found);
  }

  if (path === "/api/auth/logout" && method === "POST") {
    localStorage.removeItem(SESSION_KEY);
    return { ok: true };
  }

  if (path === "/api/auth/me" && method === "GET") {
    if (!user) throw new Error("로그인이 필요합니다.");
    return sessionView(db, user);
  }

  if (!user) throw new Error("로그인이 필요합니다.");

  if (path === "/api/portfolios" && method === "POST") {
    if (!String(body.name || "").trim() || !String(body.school || "").trim()) {
      throw new Error("이름과 학교를 입력하세요.");
    }
    if (body.cover && String(body.cover).length > 2_500_000) {
      throw new Error("이미지가 너무 큽니다. 더 작은 파일을 선택하세요.");
    }
    const item = {
      id: crypto.randomUUID(),
      userId: user.id,
      name: String(body.name || "").trim(),
      school: String(body.school || "").trim(),
      year: String(body.year || "3"),
      yearLabel: String(body.yearLabel || ""),
      gpa: String(body.gpa || ""),
      goal: String(body.goal || "").trim(),
      bio: String(body.bio || "").trim(),
      skills: Array.isArray(body.skills) ? body.skills : [],
      interests: Array.isArray(body.interests) ? body.interests : [],
      projectTitle: String(body.projectTitle || "").trim(),
      projectDesc: String(body.projectDesc || "").trim(),
      cover: String(body.cover || ""),
      updatedAt: new Date().toISOString(),
    };
    db.portfolios.unshift(item);
    user.activePortfolioId = item.id;
    saveDb(db);
    return sessionView(db, user);
  }

  const activeMatch = path.match(/^\/api\/portfolios\/([^/]+)\/active$/);
  if (activeMatch && method === "POST") {
    const item = db.portfolios.find((p) => p.id === activeMatch[1] && p.userId === user.id);
    if (!item) throw new Error("포트폴리오를 찾을 수 없습니다.");
    user.activePortfolioId = item.id;
    saveDb(db);
    return sessionView(db, user);
  }

  const idMatch = path.match(/^\/api\/portfolios\/([^/]+)$/);
  if (idMatch && method === "PUT") {
    const item = db.portfolios.find((p) => p.id === idMatch[1] && p.userId === user.id);
    if (!item) throw new Error("포트폴리오를 찾을 수 없습니다.");
    if (body.cover && String(body.cover).length > 2_500_000) {
      throw new Error("이미지가 너무 큽니다. 더 작은 파일을 선택하세요.");
    }
    Object.assign(item, {
      name: String(body.name || item.name).trim(),
      school: String(body.school || item.school).trim(),
      year: String(body.year || item.year),
      yearLabel: String(body.yearLabel || item.yearLabel),
      gpa: String(body.gpa ?? item.gpa),
      goal: String(body.goal ?? item.goal).trim(),
      bio: String(body.bio ?? item.bio).trim(),
      skills: Array.isArray(body.skills) ? body.skills : item.skills,
      interests: Array.isArray(body.interests) ? body.interests : item.interests,
      projectTitle: String(body.projectTitle ?? item.projectTitle).trim(),
      projectDesc: String(body.projectDesc ?? item.projectDesc).trim(),
      cover: body.cover === undefined ? item.cover : String(body.cover || ""),
      updatedAt: new Date().toISOString(),
    });
    saveDb(db);
    return sessionView(db, user);
  }

  if (idMatch && method === "DELETE") {
    const idx = db.portfolios.findIndex((p) => p.id === idMatch[1] && p.userId === user.id);
    if (idx === -1) throw new Error("포트폴리오를 찾을 수 없습니다.");
    db.portfolios.splice(idx, 1);
    if (user.activePortfolioId === idMatch[1]) {
      user.activePortfolioId = db.portfolios.find((p) => p.userId === user.id)?.id || null;
    }
    saveDb(db);
    return sessionView(db, user);
  }

  throw new Error("요청에 실패했습니다.");
}

async function api(path, options = {}) {
  try {
    const res = await fetch(path, {
      credentials: "include",
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      method: options.method || "GET",
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const type = res.headers.get("content-type") || "";
    if (!type.includes("application/json")) throw new Error("static-host");
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || "요청에 실패했습니다.");
      err.fromServer = true;
      throw err;
    }
    return data;
  } catch (err) {
    if (err.fromServer) throw err;
    return localApi(path, options);
  }
}

function applySession(data) {
  if ("user" in data) state.user = data.user;
  if ("portfolios" in data) state.portfolios = data.portfolios || [];
  if ("activeId" in data) state.activeId = data.activeId || null;
}

function loadPortfolios() {
  return state.portfolios;
}

function getActive() {
  return state.portfolios.find((p) => p.id === state.activeId) || state.portfolios[0] || null;
}

function escapeHtml(str = "") {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function currentRoute() {
  const hash = location.hash.replace("#", "") || "home";
  const [page, extra] = hash.split("/");
  return { page, extra };
}

function matchScore(item, profile) {
  if (!profile) return { score: 40, reasons: ["기본 추천"] };
  const reasons = [];
  let score = 35;
  if (item.years.includes(profile.year)) {
    score += 20;
    reasons.push("학년 적합");
  }
  const gpa = Number(profile.gpa || 0);
  if (gpa >= item.minGpa) {
    score += 15;
    reasons.push("성적 기준 충족");
  } else if (item.minGpa > 0) {
    score -= 10;
  }
  const tags = new Set([...(profile.skills || []), ...(profile.interests || [])]);
  const overlap = item.tags.filter((t) => tags.has(t));
  score += overlap.length * 10;
  if (overlap.length) reasons.push(overlap.join(", ") + " 관심사 일치");
  if (profile.goal && item.tags.some((t) => profile.goal.includes(t))) {
    score += 8;
    reasons.push("목표 진로와 연결");
  }
  return { score: Math.max(0, Math.min(99, score)), reasons: reasons.length ? reasons : ["탐색 추천"] };
}

function ranked(type, profile) {
  return RECOMMENDATIONS.filter((r) => !type || r.type === type)
    .map((item) => ({ item, ...matchScore(item, profile) }))
    .sort((a, b) => b.score - a.score);
}

function requireLogin(nextHash) {
  location.hash = `#login/${encodeURIComponent(nextHash || "home")}`;
}

function buildNav() {
  const { page } = currentRoute();
  const links = [
    ["home", "홈"],
    ["recommend", "진로 추천"],
    ["scholarships", "장학금"],
    ["contests", "대회"],
    ["careers", "자격·진로"],
  ];
  const auth = state.user
    ? `<span class="nav-user">${escapeHtml(state.user.name)}</span>
       <a href="#portfolio" data-link class="nav-cta ${page === "portfolio" ? "active" : ""}">내 포트폴리오</a>
       <button class="linkish" id="logoutBtn" type="button">로그아웃</button>`
    : `<a href="#login" data-link class="${page === "login" ? "active" : ""}">로그인</a>
       <a href="#signup" data-link class="nav-cta ${page === "signup" ? "active" : ""}">회원가입</a>`;
  nav.innerHTML =
    links
      .map(
        ([href, label]) =>
          `<a href="#${href}" data-link class="${page === href ? "active" : ""}">${label}</a>`
      )
      .join("") + auth;
  const logout = document.getElementById("logoutBtn");
  if (logout) {
    logout.addEventListener("click", async () => {
      await api("/api/auth/logout", { method: "POST" }).catch(() => {});
      applySession({ user: null, portfolios: [], activeId: null });
      location.hash = "#home";
      render();
    });
  }
}

function layout(html) {
  app.innerHTML = html;
  buildNav();
  window.scrollTo({ top: 0, behavior: "instant" });
}

function recCards(list) {
  if (!list.length) return `<div class="empty">조건에 맞는 추천이 없습니다.</div>`;
  return `<div class="grid cols-3">${list
    .map(
      ({ item, score, reasons }) => `
      <article class="rec-card">
        <span class="tag">${TYPE_LABEL[item.type]}</span>
        <h3>${escapeHtml(item.title)}</h3>
        <div class="meta">
          <span>${escapeHtml(item.org)}</span>
          <span>마감 ${escapeHtml(item.deadline)}</span>
        </div>
        <p>${escapeHtml(item.summary)}</p>
        <p class="match">추천도 ${score}% · ${escapeHtml(reasons.join(" · "))}</p>
        <a class="btn ghost" href="${item.link}" ${item.link.startsWith("#") ? "data-link" : 'target="_blank" rel="noreferrer"'}>자세히</a>
      </article>`
    )
    .join("")}</div>`;
}

function homeView() {
  const profile = getActive();
  const top = ranked(null, profile).slice(0, 6);
  layout(`
    <section class="hero">
      <div>
        <p class="kicker">Architecture Engineering Studio</p>
        <h1>작품을 남기고<br />길을 고르다</h1>
        <p class="lede">건축공학과 학생 누구나 가입해 자신의 포트폴리오를 저장하고, 학년·관심사·성적에 맞는 장학금, 대회, 인턴, 자격을 추천받을 수 있습니다.</p>
        <div class="hero-actions">
          ${
            state.user
              ? `<a class="btn" href="#portfolio/new" data-link>포트폴리오 만들기</a>
                 <a class="btn ghost" href="#recommend" data-link>맞춤 진로 추천</a>`
              : `<a class="btn" href="#signup" data-link>회원가입</a>
                 <a class="btn ghost" href="#login" data-link>로그인</a>`
          }
        </div>
      </div>
      <div class="hero-panel">
        <div class="hero-stat">
          <b>${state.user ? loadPortfolios().length : "회원"}</b>
          ${state.user ? "내 저장된 포트폴리오" : "계정으로 시작하는 작업실"}
          <div class="muted">${
            state.user
              ? profile
                ? escapeHtml(profile.name) + " 기준 추천 중"
                : "프로필을 만들면 추천이 정교해집니다"
              : "로그인하면 나만의 추천과 작품 보관함이 열립니다"
          }</div>
        </div>
      </div>
    </section>
    <section class="section">
      <div class="section-head">
        <div>
          <p class="kicker">Main menu</p>
          <h2>건축공학 진로 허브</h2>
        </div>
      </div>
      <div class="grid cols-4">
        <a class="menu-card" href="#scholarships" data-link>
          <span>01</span>
          <div><h3>장학금</h3><p class="muted">학회·기업·공공 장학 정보를 성적과 학년에 맞춰 정리했습니다.</p></div>
        </a>
        <a class="menu-card" href="#contests" data-link>
          <span>02</span>
          <div><h3>대회</h3><p class="muted">설계, BIM, 구조, 친환경, CM 공모전으로 포트폴리오를 채우세요.</p></div>
        </a>
        <a class="menu-card" href="#careers" data-link>
          <span>03</span>
          <div><h3>자격·진로</h3><p class="muted">건축기사부터 시공, 구조, CM, 대학원 로드맵까지.</p></div>
        </a>
        <a class="menu-card" href="${state.user ? "#portfolio" : "#signup"}" data-link>
          <span>04</span>
          <div><h3>포트폴리오</h3><p class="muted">계정에 프로젝트, 역량, 목표를 저장하고 언제든 수정하세요.</p></div>
        </a>
      </div>
    </section>
    <section class="section">
      <div class="section-head">
        <div>
          <p class="kicker">For you</p>
          <h2>지금 추천하는 기회</h2>
        </div>
        <a class="btn ghost" href="#recommend" data-link>전체 보기</a>
      </div>
      ${recCards(top)}
    </section>
  `);
}

function recommendView(type) {
  const profile = getActive();
  const titles = {
    recommend: ["맞춤 추천", "저장한 포트폴리오를 기준으로 장학금, 대회, 인턴, 자격을 정렬합니다."],
    scholarships: ["장학금", "건축공학 전공생이 실제 지원하는 공공·학회·기업 장학 프로그램입니다."],
    contests: ["대회·공모전", "작품성과 실무 역량을 동시에 보여주는 공모전을 모았습니다."],
    careers: ["자격증·진로", "기사 자격과 시공, 구조, CM, 연구 트랙을 한눈에 비교하세요."],
  };
  const key = type || "recommend";
  const filterType =
    key === "scholarships" ? "scholarship" : key === "contests" ? "contest" : key === "careers" ? null : null;
  const list =
    key === "careers"
      ? ranked(null, profile).filter((x) => ["license", "career", "intern"].includes(x.item.type))
      : ranked(filterType, profile);
  const [title, desc] = titles[key];

  layout(`
    <section class="page-hero">
      <p class="kicker">${profile ? escapeHtml(profile.name) + " 님 기준" : state.user ? "계정 카탈로그" : "전체 카탈로그"}</p>
      <h1>${title}</h1>
      <p class="lede">${desc}</p>
      ${
        profile
          ? `<p class="notice">${escapeHtml(profile.yearLabel || profile.year)} · 관심 ${escapeHtml(
              (profile.interests || []).join(", ") || "미설정"
            )} · 평균 ${escapeHtml(profile.gpa || "-")}</p>`
          : state.user
            ? `<p class="notice">포트폴리오를 저장하면 학년과 관심사에 맞춰 추천도가 계산됩니다. <a href="#portfolio/new" data-link>지금 만들기</a></p>`
            : `<p class="notice">회원가입 후 포트폴리오를 남기면 개인 맞춤 추천이 열립니다. <a href="#signup" data-link>가입하기</a></p>`
      }
    </section>
    <section class="section">
      <div class="filters" id="typeFilters">
        ${
          key === "recommend"
            ? ["all", "scholarship", "contest", "intern", "license", "career"]
                .map(
                  (t) =>
                    `<button class="chip ${t === "all" ? "active" : ""}" data-filter="${t}">${
                      t === "all" ? "전체" : TYPE_LABEL[t]
                    }</button>`
                )
                .join("")
            : ""
        }
      </div>
      <div id="recTarget">${recCards(list)}</div>
    </section>
  `);

  if (key === "recommend") {
    const target = document.getElementById("recTarget");
    document.getElementById("typeFilters").addEventListener("click", (e) => {
      const btn = e.target.closest("[data-filter]");
      if (!btn) return;
      document.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      const f = btn.dataset.filter;
      const next = f === "all" ? ranked(null, profile) : ranked(f, profile);
      target.innerHTML = recCards(next);
    });
  }
}

function defaultForm(existing) {
  return (
    existing || {
      id: "",
      name: state.user?.name || "",
      school: "",
      year: "3",
      gpa: "",
      goal: "",
      bio: "",
      skills: [],
      interests: [],
      projectTitle: "",
      projectDesc: "",
      cover: "",
    }
  );
}

const YEAR_OPTIONS = [
  ["1", "1학년"],
  ["2", "2학년"],
  ["3", "3학년"],
  ["4", "4학년"],
  ["grad", "대학원"],
];

function authView(mode) {
  const isSignup = mode === "signup";
  layout(`
    <section class="auth-wrap">
      <form class="auth-card" id="authForm">
        <p class="kicker">${isSignup ? "Create account" : "Welcome back"}</p>
        <h1>${isSignup ? "회원가입" : "로그인"}</h1>
        <p class="muted">${isSignup ? "계정을 만들면 포트폴리오와 추천이 회원님만의 공간에 저장됩니다." : "가입한 이메일로 내 작업실에 들어오세요."}</p>
        ${
          isSignup
            ? `<label for="authName">이름</label>
               <input id="authName" name="name" required minlength="2" placeholder="김건축" />`
            : ""
        }
        <label for="authEmail">이메일</label>
        <input id="authEmail" name="email" type="email" required placeholder="you@university.ac.kr" />
        <label for="authPassword">비밀번호</label>
        <input id="authPassword" name="password" type="password" required minlength="8" placeholder="8자 이상" />
        <p class="form-error" id="authError"></p>
        <div class="hero-actions">
          <button class="btn" type="submit">${isSignup ? "가입하고 시작하기" : "로그인"}</button>
          <a class="btn ghost" href="#${isSignup ? "login" : "signup"}" data-link>${isSignup ? "이미 계정이 있어요" : "회원가입"}</a>
        </div>
      </form>
    </section>
  `);

  document.getElementById("authForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = document.getElementById("authError");
    err.textContent = "";
    const fd = new FormData(e.target);
    const body = {
      email: fd.get("email"),
      password: fd.get("password"),
    };
    if (isSignup) body.name = fd.get("name");
    try {
      const data = await api(isSignup ? "/api/auth/signup" : "/api/auth/login", {
        method: "POST",
        body,
      });
      applySession(data);
      const next = decodeURIComponent(currentRoute().extra || "home");
      location.hash = `#${next === "login" || next === "signup" ? "home" : next}`;
      render();
    } catch (ex) {
      err.textContent = ex.message;
    }
  });
}

function portfolioListView() {
  const list = loadPortfolios();
  const active = getActive();
  layout(`
    <section class="page-hero">
      <p class="kicker">${escapeHtml(state.user.name)} archive</p>
      <h1>내 포트폴리오</h1>
      <p class="lede">이 계정에만 보이는 보관함입니다. 선택한 프로필이 메인 메뉴 추천의 기준이 됩니다.</p>
      <div class="hero-actions">
        <a class="btn" href="#portfolio/new" data-link>새 포트폴리오</a>
      </div>
    </section>
    <section class="section">
      ${
        list.length
          ? `<div class="port-list">${list
              .map(
                (p) => `
            <article class="port-card">
              <div class="port-thumb" style="background-image:url('${p.cover || "https://images.unsplash.com/photo-1503387762-592deb58ef4e?auto=format&fit=crop&w=400&q=80"}')"></div>
              <div>
                <h3 class="serif" style="margin:0 0 6px;font-size:26px;">${escapeHtml(p.name)}</h3>
                <p class="muted">${escapeHtml(p.school)} · ${escapeHtml(p.yearLabel || p.year)} · ${escapeHtml(
                  p.projectTitle || "프로젝트 미입력"
                )}</p>
                ${active && active.id === p.id ? `<span class="tag">추천 기준</span>` : ""}
              </div>
              <div class="actions">
                <button class="btn ghost" data-use="${p.id}">이 프로필 사용</button>
                <a class="btn ghost" href="#portfolio/edit/${p.id}" data-link>수정</a>
                <button class="btn danger" data-del="${p.id}">삭제</button>
              </div>
            </article>`
              )
              .join("")}</div>`
          : `<div class="empty">아직 저장된 포트폴리오가 없습니다. 첫 작품을 남겨보세요.</div>`
      }
    </section>
  `);

  app.querySelectorAll("[data-use]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      try {
        applySession(await api(`/api/portfolios/${btn.dataset.use}/active`, { method: "POST" }));
        render();
      } catch (ex) {
        alert(ex.message);
      }
    })
  );
  app.querySelectorAll("[data-del]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      if (!confirm("이 포트폴리오를 삭제할까요?")) return;
      try {
        applySession(await api(`/api/portfolios/${btn.dataset.del}`, { method: "DELETE" }));
        render();
      } catch (ex) {
        alert(ex.message);
      }
    })
  );
}

function portfolioFormView(existing) {
  const data = defaultForm(existing);
  const editing = Boolean(existing);
  layout(`
    <section class="page-hero">
      <p class="kicker">${editing ? "Edit" : "New"} portfolio</p>
      <h1>${editing ? "포트폴리오 수정" : "포트폴리오 제작"}</h1>
      <p class="lede">기본 정보와 대표 프로젝트를 남기면 진로 추천이 개인화됩니다. 내용은 ${escapeHtml(
        state.user.email
      )} 계정에 저장됩니다.</p>
    </section>
    <section class="section">
      <form class="form-grid" id="portForm">
        <div class="form-card">
          <h2>프로필</h2>
          <div class="row">
            <div>
              <label for="name">이름</label>
              <input id="name" name="name" required value="${escapeHtml(data.name)}" placeholder="홍길동" />
            </div>
            <div>
              <label for="school">학교 / 전공</label>
              <input id="school" name="school" required value="${escapeHtml(data.school)}" placeholder="○○대학교 건축공학과" />
            </div>
          </div>
          <div class="row">
            <div>
              <label for="year">학년</label>
              <select id="year" name="year">
                ${YEAR_OPTIONS.map(
                  ([v, l]) => `<option value="${v}" ${data.year === v ? "selected" : ""}>${l}</option>`
                ).join("")}
              </select>
            </div>
            <div>
              <label for="gpa">평균 학점</label>
              <input id="gpa" name="gpa" type="number" min="0" max="4.5" step="0.01" value="${escapeHtml(
                data.gpa
              )}" placeholder="3.70" />
            </div>
          </div>
          <label for="goal">목표 진로</label>
          <input id="goal" name="goal" value="${escapeHtml(data.goal)}" placeholder="예: 시공관리, 구조설계, 건축사" />
          <label for="bio">소개</label>
          <textarea id="bio" name="bio" placeholder="관심 분야, 스튜디오 경험, 앞으로 하고 싶은 일">${escapeHtml(
            data.bio
          )}</textarea>
          <label>역량</label>
          <div class="skill-picks" id="skillPicks">
            ${SKILLS.map(
              (s) => `<button type="button" data-skill="${s}" class="${(data.skills || []).includes(s) ? "on" : ""}">${s}</button>`
            ).join("")}
          </div>
          <label>관심 분야</label>
          <div class="skill-picks" id="interestPicks">
            ${INTERESTS.map(
              (s) =>
                `<button type="button" data-interest="${s}" class="${(data.interests || []).includes(s) ? "on" : ""}">${s}</button>`
            ).join("")}
          </div>
        </div>
        <div class="form-card">
          <h2>대표 프로젝트</h2>
          <div class="preview-cover" id="coverPreview" style="background-image:url('${data.cover || ""}')"></div>
          <label for="cover">커버 이미지</label>
          <input id="cover" name="cover" type="file" accept="image/*" />
          <label for="projectTitle">프로젝트 제목</label>
          <input id="projectTitle" name="projectTitle" value="${escapeHtml(data.projectTitle)}" placeholder="철골조 복합시설 구조·시공 계획" />
          <label for="projectDesc">프로젝트 설명</label>
          <textarea id="projectDesc" name="projectDesc" placeholder="역할, 사용 도구, 해결한 문제, 성과">${escapeHtml(
            data.projectDesc
          )}</textarea>
          <p class="form-error" id="portError"></p>
          <div class="hero-actions">
            <button class="btn" type="submit">${editing ? "변경 저장" : "포트폴리오 저장"}</button>
            <a class="btn ghost" href="#portfolio" data-link>목록으로</a>
          </div>
        </div>
      </form>
    </section>
  `);

  let cover = data.cover || "";
  const preview = document.getElementById("coverPreview");
  document.getElementById("cover").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 1_800_000) {
      document.getElementById("portError").textContent = "이미지는 1.8MB 이하로 올려 주세요.";
      e.target.value = "";
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      cover = reader.result;
      preview.style.backgroundImage = `url('${cover}')`;
    };
    reader.readAsDataURL(file);
  });

  document.getElementById("skillPicks").addEventListener("click", (e) => {
    const btn = e.target.closest("button");
    if (btn) btn.classList.toggle("on");
  });
  document.getElementById("interestPicks").addEventListener("click", (e) => {
    const btn = e.target.closest("button");
    if (btn) btn.classList.toggle("on");
  });

  document.getElementById("portForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = document.getElementById("portError");
    err.textContent = "";
    const fd = new FormData(e.target);
    const year = fd.get("year");
    const payload = {
      name: fd.get("name").trim(),
      school: fd.get("school").trim(),
      year,
      yearLabel: YEAR_OPTIONS.find((y) => y[0] === year)?.[1] || year,
      gpa: fd.get("gpa"),
      goal: fd.get("goal").trim(),
      bio: fd.get("bio").trim(),
      skills: [...document.querySelectorAll("#skillPicks .on")].map((b) => b.dataset.skill),
      interests: [...document.querySelectorAll("#interestPicks .on")].map((b) => b.dataset.interest),
      projectTitle: fd.get("projectTitle").trim(),
      projectDesc: fd.get("projectDesc").trim(),
      cover,
    };
    try {
      const saved = existing
        ? await api(`/api/portfolios/${existing.id}`, { method: "PUT", body: payload })
        : await api("/api/portfolios", { method: "POST", body: payload });
      applySession(saved);
      location.hash = "#portfolio";
    } catch (ex) {
      err.textContent = ex.message;
    }
  });
}

function render() {
  if (!state.ready) return;
  const { page, extra } = currentRoute();
  if (page === "login") return authView("login");
  if (page === "signup") return authView("signup");
  if (page === "home") return homeView();
  if (page === "recommend") return recommendView("recommend");
  if (page === "scholarships") return recommendView("scholarships");
  if (page === "contests") return recommendView("contests");
  if (page === "careers") return recommendView("careers");
  if (page === "portfolio") {
    if (!state.user) return requireLogin(location.hash.replace("#", "") || "portfolio");
    if (extra === "new") return portfolioFormView(null);
    if (extra && extra.startsWith("edit")) {
      const id = location.hash.split("/")[2];
      const found = loadPortfolios().find((p) => p.id === id);
      return found ? portfolioFormView(found) : portfolioListView();
    }
    return portfolioListView();
  }
  homeView();
}

async function boot() {
  try {
    applySession(await api("/api/auth/me"));
  } catch {
    applySession({ user: null, portfolios: [], activeId: null });
  }
  state.ready = true;
  window.addEventListener("hashchange", render);
  render();
}

boot();
