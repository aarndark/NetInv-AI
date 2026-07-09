/* П.11 (v1.6.5): действия над уязвимостями — «скрыть» и «копировать»
 * (принять в работу). Работает через делегирование событий, поэтому
 * корректно обрабатывает и содержимое, подгруженное в модальное окно
 * (история/текущее сканирование), и обычные страницы отчёта. */
(function () {
  'use strict';

  // Собрать снимок полей уязвимости из data-атрибутов контейнера действий.
  function collectFields(box) {
    return {
      vkey: box.getAttribute('data-vkey') || '',
      ip: box.getAttribute('data-ip') || '',
      port: box.getAttribute('data-port') || '',
      title: box.getAttribute('data-title') || '',
      cve_id: box.getAttribute('data-cve-id') || '',
      cvss: box.getAttribute('data-cvss') || '',
      severity: box.getAttribute('data-severity') || '',
      detail: box.getAttribute('data-detail') || '',
      recommendation: box.getAttribute('data-recommendation') || '',
      tool: box.getAttribute('data-tool') || '',
      url: box.getAttribute('data-url') || '',
      log_run_id: box.getAttribute('data-run-id') || ''
    };
  }

  // Сформировать текст для буфера обмена по уязвимости.
  function clipboardText(f) {
    var lines = [];
    lines.push('Уязвимость: ' + f.title);
    if (f.severity) { lines.push('Критичность: ' + f.severity); }
    lines.push('IP: ' + f.ip + (f.port ? (':' + f.port) : ''));
    if (f.cve_id) { lines.push('CVE: ' + f.cve_id + (f.cvss ? (' (CVSS ' + f.cvss + ')') : '')); }
    if (f.tool) { lines.push('Инструмент: ' + f.tool); }
    if (f.url) { lines.push('URL: ' + f.url); }
    if (f.detail) { lines.push('Описание: ' + f.detail); }
    if (f.recommendation) { lines.push('Рекомендация: ' + f.recommendation); }
    return lines.join('\n');
  }

  // Скопировать текст в буфер обмена (с фолбэком для старых браузеров).
  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(function () {
        fallbackCopy(text);
      });
    }
    fallbackCopy(text);
    return Promise.resolve();
  }

  function fallbackCopy(text) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    } catch (e) { /* игнорируем */ }
  }

  // Отправить POST-запрос на сервер с состоянием уязвимости.
  function postState(targetId, action, fields) {
    var data = new URLSearchParams();
    Object.keys(fields).forEach(function (k) { data.append(k, fields[k]); });
    return fetch('/vuln/' + targetId + '/' + action, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: data.toString()
    }).then(function (r) { return r.json(); });
  }

  // Кратко подсветить кнопку статусом.
  function flash(btn, ok, msg) {
    var old = btn.textContent;
    btn.textContent = ok ? ('✓ ' + msg) : ('✗ ' + msg);
    btn.classList.add(ok ? 'vuln-btn-ok' : 'vuln-btn-err');
    setTimeout(function () {
      btn.textContent = old;
      btn.classList.remove('vuln-btn-ok', 'vuln-btn-err');
    }, 1600);
  }

  // Делегирование кликов по всему документу.
  document.addEventListener('click', function (ev) {
    var btn = ev.target.closest(
      '.vuln-copy, .vuln-hide, .vuln-unhide');
    if (!btn) { return; }
    var box = btn.closest('.vuln-actions');
    if (!box) { return; }
    var targetId = box.getAttribute('data-target-id');
    if (!targetId) { return; }
    var fields = collectFields(box);

    if (btn.classList.contains('vuln-copy')) {
      // Принять в работу: копируем в буфер + accepted на сервере.
      copyToClipboard(clipboardText(fields));
      postState(targetId, 'accept', fields).then(function (j) {
        flash(btn, j.ok, j.ok ? 'В работе' : (j.message || 'Ошибка'));
      }).catch(function () { flash(btn, false, 'Ошибка'); });
    } else if (btn.classList.contains('vuln-hide')) {
      postState(targetId, 'hide', fields).then(function (j) {
        flash(btn, j.ok, j.ok ? 'Скрыта' : (j.message || 'Ошибка'));
        // Скрытую уязвимость убираем из вида (если не режим «показать скрытые»).
        var item = box.closest('.vuln-item');
        if (j.ok && item && !document.body.classList.contains('show-hidden-vulns')) {
          item.style.transition = 'opacity .3s';
          item.style.opacity = '0.35';
        }
      }).catch(function () { flash(btn, false, 'Ошибка'); });
    } else if (btn.classList.contains('vuln-unhide')) {
      postState(targetId, 'clear', fields).then(function (j) {
        flash(btn, j.ok, j.ok ? 'Возвращена' : (j.message || 'Ошибка'));
      }).catch(function () { flash(btn, false, 'Ошибка'); });
    }
  });
})();
