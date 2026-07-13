// ============================================================
// geomdan-ceu  supabase.js  (A방식: Supabase Auth + RLS)
//
//  * 로그인: 이메일 + 비밀번호 (Supabase Auth)
//  * 세션: sessionStorage (창 닫으면 로그아웃) + refresh_token 자동 갱신
//  * 정지 계정 차단: user_metadata.is_active === false 면 로그인 거부
//  * 데이터: ceu_data (owner_id = 내 Auth UUID, RLS로 본인만)
//  * 계정관리(관리자): admin-users Edge Function
//      list / create / delete / update_password / set_active
// ============================================================

const SUPABASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_SUPABASE_URL) ||
  'https://vdubgrxwijydwfabwpnk.supabase.co';

const SUPABASE_ANON =
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_SUPABASE_ANON_KEY) ||
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZkdWJncnh3aWp5ZHdmYWJ3cG5rIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODE2MDk1ODgsImV4cCI6MjA5NzE4NTU4OH0.nqNO3vany3M6fzmG5BG6QVdvi8BW2UbhTDhxNnwvA88';

const REST = `${SUPABASE_URL}/rest/v1`;
const AUTH = `${SUPABASE_URL}/auth/v1`;
const FUNCTIONS = `${SUPABASE_URL}/functions/v1`;

const SESSION_KEY = 'ceu-session';

// ---- 세션 저장/복원 (sessionStorage) ----
function saveSession(s) {
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(s)); } catch {}
}
function readSession() {
  try { const r = sessionStorage.getItem(SESSION_KEY); return r ? JSON.parse(r) : null; } catch { return null; }
}
function clearSession() {
  try { sessionStorage.removeItem(SESSION_KEY); } catch {}
}

export function currentUser() {
  const s = readSession();
  if (!s || !s.user) return null;
  return {
    id: s.user.id,
    email: s.user.email,
    name: s.user.user_metadata?.display_name || (s.user.email ? s.user.email.split('@')[0] : ''),
    role: s.user.user_metadata?.role || 'therapist',
    is_active: s.user.user_metadata?.is_active !== false,
    myCerts: s.user.user_metadata?.my_certs || null, // 보유자격은 데이터에도 있지만 편의상 캐시
  };
}

function accessToken() {
  const s = readSession();
  return s?.access_token || null;
}

// ---- refresh_token 으로 세션 갱신 ----
async function refreshSession() {
  const s = readSession();
  if (!s?.refresh_token) return null;
  const r = await fetch(`${AUTH}/token?grant_type=refresh_token`, {
    method: 'POST',
    headers: { apikey: SUPABASE_ANON, 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: s.refresh_token }),
  });
  if (!r.ok) { clearSession(); return null; }
  const data = await r.json();
  const ns = { access_token: data.access_token, refresh_token: data.refresh_token, user: data.user };
  saveSession(ns);
  return ns;
}

// 앱 시작 시 호출: 저장된 세션 복원(만료 시 refresh)
export async function restoreSession() {
  const s = readSession();
  if (!s) return null;
  // access_token 유효성 간단 확인 (getUser)
  const r = await fetch(`${AUTH}/user`, {
    headers: { apikey: SUPABASE_ANON, Authorization: `Bearer ${s.access_token}` },
  });
  if (r.ok) {
    const user = await r.json();
    saveSession({ ...s, user });
    return currentUser();
  }
  // 만료 → refresh 시도
  const ns = await refreshSession();
  return ns ? currentUser() : null;
}

// ---- 로그인 ----
export async function login(email, password) {
  const r = await fetch(`${AUTH}/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: SUPABASE_ANON, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await r.json();
  if (!r.ok) {
    return { error: '이메일 또는 비밀번호가 올바르지 않습니다.' };
  }
  // 정지 계정 차단
  if (data.user?.user_metadata?.is_active === false) {
    return { error: '정지된 계정입니다. 관리자에게 문의하세요.' };
  }
  saveSession({ access_token: data.access_token, refresh_token: data.refresh_token, user: data.user });
  return { user: currentUser() };
}

// ---- 로그아웃 ----
export async function logout() {
  const t = accessToken();
  try {
    if (t) await fetch(`${AUTH}/logout`, { method: 'POST', headers: { apikey: SUPABASE_ANON, Authorization: `Bearer ${t}` } });
  } catch {}
  clearSession();
}

// ---- 내 보유자격을 Auth metadata에도 저장(로그인 화면 캐시용, 선택) ----
export async function updateMyCerts(certs) {
  const t = accessToken();
  if (!t) return;
  try {
    await fetch(`${AUTH}/user`, {
      method: 'PUT',
      headers: { apikey: SUPABASE_ANON, Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: { my_certs: certs } }),
    });
    const s = readSession();
    if (s?.user) { s.user.user_metadata = { ...(s.user.user_metadata || {}), my_certs: certs }; saveSession(s); }
  } catch {}
}

// ============================================================
// 데이터 (ceu_data) — 본인 행만 (RLS)
// ============================================================
async function authedFetch(url, opts = {}) {
  let t = accessToken();
  const doFetch = (tok) => fetch(url, {
    ...opts,
    headers: { apikey: SUPABASE_ANON, Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  let r = await doFetch(t);
  if (r.status === 401) {
    const ns = await refreshSession();
    if (ns) r = await doFetch(ns.access_token);
  }
  return r;
}

// 내 데이터 읽기 → data(JSON) 반환, 없으면 null
export async function loadMyData() {
  const me = currentUser();
  if (!me) return null;
  const r = await authedFetch(`${REST}/ceu_data?owner_id=eq.${me.id}&select=data`, { method: 'GET' });
  if (!r.ok) return null;
  const rows = await r.json();
  return rows.length ? rows[0].data : null;
}

// 내 데이터 저장 (upsert)
export async function saveMyData(data) {
  const me = currentUser();
  if (!me) return { error: '로그인이 필요합니다.' };
  const r = await authedFetch(`${REST}/ceu_data`, {
    method: 'POST',
    headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify({ owner_id: me.id, data }),
  });
  if (!r.ok) {
    const t = await r.text();
    return { error: '저장 실패: ' + t };
  }
  return { ok: true };
}

// ============================================================
// 관리자: admin-users Edge Function
// ============================================================
async function callAdmin(action, payload = {}) {
  const t = accessToken();
  if (!t) return { error: '로그인이 필요합니다.' };
  const r = await fetch(`${FUNCTIONS}/admin-users`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, ...payload }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) return { error: data.error || '요청 실패' };
  return data;
}

export async function adminListUsers() {
  const res = await callAdmin('list');
  return res.error ? { error: res.error } : { users: res.users || [] };
}
export async function adminCreateUser(email, password, displayName) {
  return callAdmin('create', { email, password, display_name: displayName || email.split('@')[0] });
}
export async function adminDeleteUser(userId) {
  return callAdmin('delete', { user_id: userId });
}
export async function adminUpdatePassword(userId, password) {
  return callAdmin('update_password', { user_id: userId, password });
}
export async function adminSetActive(userId, isActive) {
  return callAdmin('set_active', { user_id: userId, is_active: isActive });
}

export function supabaseConfigured() {
  return !!SUPABASE_URL && !!SUPABASE_ANON;
}

// ============================================================
// 이수증 사진 (Storage: ceu-receipts, 비공개, 본인 폴더만)
// ============================================================
const BUCKET = "ceu-receipts";

// base64(data 부분) → 업로드. 성공 시 저장 경로(path) 반환
export async function uploadReceipt(base64, mediaType) {
  const me = currentUser();
  if (!me) return { error: "로그인이 필요합니다." };
  const t = accessToken();
  if (!t) return { error: "로그인이 필요합니다." };
  try {
    // base64 → 바이너리(Blob)
    const bin = atob(base64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const ext = (mediaType && mediaType.includes("png")) ? "png" : "jpg";
    const path = `${me.id}/${Date.now()}_${Math.random().toString(36).slice(2, 8)}.${ext}`;
    const r = await fetch(`${SUPABASE_URL}/storage/v1/object/${BUCKET}/${path}`, {
      method: "POST",
      headers: { apikey: SUPABASE_ANON, Authorization: `Bearer ${t}`, "Content-Type": mediaType || "image/jpeg" },
      body: bytes,
    });
    if (!r.ok) { const e = await r.text(); return { error: "사진 저장 실패: " + e }; }
    return { path };
  } catch (e) {
    return { error: "사진 처리 오류: " + e.message };
  }
}

// 저장 경로 → 열람용 임시 서명 URL (비공개 버킷)
export async function getReceiptUrl(path, expiresSec = 3600) {
  if (!path) return { error: "경로 없음" };
  const t = accessToken();
  if (!t) return { error: "로그인이 필요합니다." };
  try {
    const r = await fetch(`${SUPABASE_URL}/storage/v1/object/sign/${BUCKET}/${path}`, {
      method: "POST",
      headers: { apikey: SUPABASE_ANON, Authorization: `Bearer ${t}`, "Content-Type": "application/json" },
      body: JSON.stringify({ expiresIn: expiresSec }),
    });
    if (!r.ok) { const e = await r.text(); return { error: "URL 생성 실패: " + e }; }
    const data = await r.json();
    return { url: `${SUPABASE_URL}/storage/v1${data.signedURL}` };
  } catch (e) {
    return { error: "URL 오류: " + e.message };
  }
}

export async function deleteReceipt(path) {
  if (!path) return { ok: true };
  const t = accessToken();
  if (!t) return { error: "로그인이 필요합니다." };
  try {
    const r = await fetch(`${SUPABASE_URL}/storage/v1/object/${BUCKET}/${path}`, {
      method: "DELETE",
      headers: { apikey: SUPABASE_ANON, Authorization: `Bearer ${t}` },
    });
    if (!r.ok) { const e = await r.text(); return { error: "삭제 실패: " + e }; }
    return { ok: true };
  } catch (e) {
    return { error: "삭제 오류: " + e.message };
  }
}
