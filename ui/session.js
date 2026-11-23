/* goauth session store, shared by the sign-in page and the OAuth callback
 * page. Sessions are kept in localStorage under "authorization-storage" as
 *   {sessions: [...], current_session, redirectUrl}
 * exactly as the callback page has always written them. A zustand-persist
 * snapshot ({state: {...}, version}) is also accepted when reading. */
(function () {
  'use strict';
  var KEY = 'authorization-storage';

  function read() {
    try {
      var parsed = JSON.parse(localStorage.getItem(KEY) || 'null');
      var s = parsed && typeof parsed === 'object' && parsed.state && typeof parsed.state === 'object' ? parsed.state : parsed;
      if (s && Array.isArray(s.sessions)) return s;
    } catch (_) {}
    return { sessions: [], current_session: '', redirectUrl: '' };
  }

  function write(snapshot) {
    try {
      localStorage.setItem(KEY, JSON.stringify(snapshot));
    } catch (_) {}
    return snapshot;
  }

  function sessionId(user, id) {
    if (id) return id;
    if (user && user.id) return user.id;
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return 'session-' + Date.now();
  }

  /* persist stores a successful sign-in and makes it the current session. */
  function persist(data) {
    var s = read();
    var user = data.user || {};
    var tokens = data.tokens || {};
    var id = sessionId(user, data.session_id);
    s.sessions = s.sessions.filter(function (x) { return x.session_id !== id; });
    s.sessions.push({
      session_id: id,
      user: Object.assign({ id: user.id }, user),
      tokens: { access_token: tokens.access_token || '', refresh_token: tokens.refresh_token || '' },
      trusted: Boolean(data.trusted)
    });
    s.current_session = id;
    s.redirectUrl = s.redirectUrl || '';
    return write(s);
  }

  /* setRedirect remembers where to go after an OAuth round-trip. Same-origin
   * paths and absolute http(s) URLs are stored (the sign-in page only puts
   * TrustedRedirectOrigins / AuthURL targets into data-redirect). */
  function setRedirect(path) {
    if (typeof path !== 'string') return;
    path = path.trim();
    if (!path) return;
    if (path.charAt(0) === '/') {
      if (path.charAt(1) === '/' || path.charAt(1) === '\\') return;
    } else {
      try {
        var u = new URL(path);
        if ((u.protocol !== 'http:' && u.protocol !== 'https:') || u.username || u.password) return;
        path = u.href;
      } catch (_) {
        return;
      }
    }
    var s = read();
    s.redirectUrl = path;
    write(s);
  }

  window.GoAuthSession = { read: read, persist: persist, setRedirect: setRedirect };
})();
