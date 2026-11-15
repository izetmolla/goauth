/* goauth pages (sign-in, register, forgot password, one-time code, verify
 * email). Every page works without this script: forms post normally and the
 * server answers with the next step. This adds inline errors, instant step
 * changes, loading states, segmented code boxes, password reveal and
 * strength hints, resend countdowns and "last used" memory. */
(function () {
  'use strict';

  var card = document.getElementById('ga-card');
  if (!card) return;

  var LAST_KEY = 'goauth:last-provider';
  var redirect = card.getAttribute('data-redirect') || '/';
  var errorBox = document.getElementById('ga-error');
  var errorText = document.getElementById('ga-error-text');
  var noticeBox = document.getElementById('ga-notice');
  var noticeText = document.getElementById('ga-notice-text');
  var session = window.GoAuthSession;

  function save(key, value) { try { localStorage.setItem(key, value); } catch (_) {} }
  function load(key) { try { return localStorage.getItem(key); } catch (_) { return null; } }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function visible(el) { return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length); }

  /* --- Messages ------------------------------------------------------------ */

  function showError(message, field, form) {
    noticeBox.hidden = true;
    errorText.textContent = message || 'Something went wrong. Please try again.';
    errorBox.hidden = false;
    errorBox.classList.remove('is-shake');
    void errorBox.offsetWidth; // restart the animation
    errorBox.classList.add('is-shake');
    if (form && field) {
      var input = form.querySelector('[name="' + CSS.escape(field) + '"]');
      if (input) {
        input.setAttribute('aria-invalid', 'true');
        var otp = input.closest('.ga-otp');
        if (otp) otp.setAttribute('aria-invalid', 'true');
        if (field === 'code') { input.value = ''; input.dispatchEvent(new Event('input')); }
        input.focus();
      }
    }
  }
  function showNotice(message) {
    if (!message) return;
    errorBox.hidden = true;
    noticeText.textContent = message;
    noticeBox.hidden = false;
  }
  function clearMessages() {
    errorBox.hidden = true;
    noticeBox.hidden = true;
    $all('[aria-invalid="true"]').forEach(function (el) { el.removeAttribute('aria-invalid'); });
  }

  /* --- Steps ---------------------------------------------------------------- */

  function setEmail(email) {
    if (!email) return;
    $all('[data-ga-email]').forEach(function (el) { el.textContent = email; });
    $all('input[name="email"]').forEach(function (el) { el.value = email; });
  }

  function setStep(step, opts) {
    opts = opts || {};
    card.setAttribute('data-step', step);
    card.classList.remove('is-stepping');
    void card.offsetWidth;
    card.classList.add('is-stepping');
    try {
      var url = new URL(location.href);
      url.searchParams.set('step', step);
      ['error', 'token'].forEach(function (k) { url.searchParams.delete(k); });
      if (opts.email) url.searchParams.set('email', opts.email);
      history.replaceState(null, '', url);
    } catch (_) {}
    if (step === 'code' || step === 'sent') startCountdown(opts.resendAfter);
    var first = $all('[data-for~="' + step + '"] input:not([type=hidden])').filter(visible)[0];
    if (first) first.focus({ preventScroll: true });
  }

  $all('[data-step-link]').forEach(function (link) {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      clearMessages();
      setStep(link.getAttribute('data-step-link'));
    });
  });

  // Carry the typed email to "Forgot password?" and "Email me a code".
  $all('a[data-carry-email]').forEach(function (link) {
    link.addEventListener('click', function () {
      var input = document.querySelector('input[type=email]');
      if (input && input.value.trim()) {
        var url = new URL(link.href);
        url.searchParams.set('email', input.value.trim());
        link.href = url.toString();
      }
    });
  });

  /* --- Resend countdown ------------------------------------------------------- */

  var timer;
  function startCountdown(seconds) {
    var buttons = $all('button[data-resend]');
    if (!buttons.length) return;
    var left = seconds == null ? parseInt(card.getAttribute('data-resend-after') || '0', 10) : seconds;
    clearInterval(timer);
    function tick() {
      buttons.forEach(function (b) {
        b.disabled = left > 0;
        b.textContent = left > 0 ? 'Resend in ' + left + 's' : 'Resend email';
      });
      if (left-- <= 0) clearInterval(timer);
    }
    tick();
    timer = setInterval(tick, 1000);
  }

  /* --- Password reveal and strength ----------------------------------------- */

  $all('.ga-reveal').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = btn.parentElement.querySelector('input');
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.setAttribute('aria-pressed', String(show));
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      input.focus();
    });
  });

  var checks = {
    length: function (v) { return v.length >= 8; },
    number: function (v) { return /\d/.test(v); },
    mixed: function (v) { return (/[a-z]/.test(v) && /[A-Z]/.test(v)) || /[^A-Za-z0-9]/.test(v); }
  };
  $all('.ga-rules').forEach(function (rules) {
    var input = rules.parentElement.querySelector('input[autocomplete="new-password"]');
    if (!input) { rules.hidden = true; return; }
    input.addEventListener('input', function () {
      $all('li', rules).forEach(function (li) {
        li.classList.toggle('is-met', checks[li.getAttribute('data-rule')](input.value));
      });
    });
  });

  document.addEventListener('input', function (e) {
    if (e.target.getAttribute && e.target.getAttribute('aria-invalid') === 'true') {
      e.target.removeAttribute('aria-invalid');
      var otp = e.target.closest('.ga-otp');
      if (otp) otp.removeAttribute('aria-invalid');
    }
  });

  /* --- Segmented code boxes ---------------------------------------------------- */

  $all('input.ga-code').forEach(function (input) {
    var length = parseInt(input.getAttribute('data-length') || '6', 10);
    var wrap = document.createElement('div');
    wrap.className = 'ga-otp';
    input.parentNode.insertBefore(wrap, input);
    var boxes = [];
    for (var i = 0; i < length; i++) {
      var box = document.createElement('span');
      box.className = 'ga-otp-box';
      box.setAttribute('aria-hidden', 'true');
      wrap.appendChild(box);
      boxes.push(box);
    }
    wrap.appendChild(input); // the real input sits on top, invisible, and receives typing and paste
    function render() {
      var v = input.value.replace(/[\s-]/g, '').toUpperCase().slice(0, length);
      if (input.value !== v) input.value = v;
      var focused = document.activeElement === input;
      boxes.forEach(function (b, i) {
        b.textContent = v[i] || '';
        b.classList.toggle('is-filled', !!v[i]);
        b.classList.toggle('is-active', focused && i === Math.min(v.length, length - 1));
      });
      return v;
    }
    input.addEventListener('input', function () {
      var v = render();
      if (v) errorBox.hidden = true; // a fresh attempt replaces the old error
      if (v.length === length && input.form) {
        if (input.form.requestSubmit) input.form.requestSubmit(); else input.form.dispatchEvent(new Event('submit', { cancelable: true }));
      }
    });
    input.addEventListener('focus', render);
    input.addEventListener('blur', render);
    input.addEventListener('keyup', render);
    render();
  });

  /* --- OAuth buttons ---------------------------------------------------------- */

  var last = load(LAST_KEY);
  $all('.ga-provider').forEach(function (btn) {
    var id = btn.getAttribute('data-provider');
    if (id && id === last) {
      btn.classList.add('is-last');
      btn.querySelector('.ga-badge').hidden = false;
    }
    btn.addEventListener('click', function () {
      save(LAST_KEY, id);
      if (session) session.setRedirect(redirect);
      btn.classList.add('is-loading');
      btn.setAttribute('aria-busy', 'true');
    });
  });
  // The back button restores pages from cache: drop stale spinners.
  window.addEventListener('pageshow', function () {
    $all('.is-loading').forEach(function (el) {
      el.classList.remove('is-loading');
      el.removeAttribute('aria-busy');
    });
  });

  /* --- Forms -------------------------------------------------------------------- */

  function firstEmpty(form) {
    return $all('input[required]', form).filter(function (i) { return !i.value.trim(); })[0] || null;
  }

  function busy(button, on) {
    if (!button) return;
    button.classList.toggle('is-loading', on);
    if (on) button.setAttribute('aria-busy', 'true'); else button.removeAttribute('aria-busy');
  }

  $all('form.ga-form').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      clearMessages();
      var empty = firstEmpty(form);
      if (empty) {
        var label = form.querySelector('label[for="' + empty.id + '"]');
        showError((label ? label.textContent : 'This field') + ' is required.', empty.name, form);
        return;
      }
      var button = form.querySelector('.ga-submit') || form.querySelector('button[data-resend]');
      busy(button, true);

      fetch(form.action, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(new FormData(form))
      })
        .then(function (res) {
          return res.json().catch(function () { return {}; }).then(function (data) { return { ok: res.ok, data: data }; });
        })
        .then(function (r) {
          var d = r.data;
          if (!r.ok) {
            busy(button, false);
            showError(d.message, d.field, form);
            return;
          }
          if (d.type === 'sign_in') {
            var provider = form.getAttribute('data-provider');
            if (provider) save(LAST_KEY, provider);
            if (session) session.persist(d);
            var label = button && button.querySelector('.ga-submit-label');
            if (label) label.textContent = 'Redirecting…';
            location.replace(d.redirect_url || redirect);
            return;
          }
          busy(button, false);
          if (d.type === 'step') {
            setEmail(d.email);
            if (d.step === 'done') {
              var done = document.getElementById('ga-done-text');
              if (done && d.message) done.textContent = d.message;
              setStep('done', { email: d.email });
              return;
            }
            var resent = form.classList.contains('ga-resend');
            setStep(d.step, { email: d.email, resendAfter: d.resend_after });
            // The "sent" panel already explains itself; only confirm resends.
            showNotice(resent ? 'We sent you a new email.' : (d.step === 'sent' ? '' : d.message));
          }
        })
        .catch(function () {
          busy(button, false);
          showError('Network error. Check your connection and try again.');
        });
    });
  });

  /* --- Initial state ------------------------------------------------------------- */

  // A link token has done its job once the page has it in a hidden field:
  // take it out of the address bar and history.
  try {
    var url = new URL(location.href);
    if (url.searchParams.has('token')) {
      url.searchParams.delete('token');
      history.replaceState(null, '', url);
    }
  } catch (_) {}

  var step = card.getAttribute('data-step');
  if (step === 'code' || step === 'sent') startCountdown();
  var first = $all('[data-for~="' + step + '"] input:not([type=hidden]), .ga-form:not([data-for]) input:not([type=hidden])').filter(visible)[0];
  if (first && !first.value) first.focus({ preventScroll: true });
})();
