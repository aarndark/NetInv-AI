/*
 * table-resize.js — настройка ширины колонок перетягиванием (требование 2).
 *
 * Для каждой таблицы с классом .tbl.report:
 *   - в каждый <th> добавляется маркер-«ручка» (.col-resizer) справа;
 *   - перетягивание ручки мышью меняет ширину колонки;
 *   - ширины сохраняются в localStorage по ключу таблицы и восстанавливаются
 *     при следующей загрузке страницы.
 *
 * Без внешних библиотек. Горизонтальная прокрутка остаётся доступной:
 * таблица имеет table-layout:fixed и min-width, контейнер .table-scroll
 * всегда показывает горизонтальный скроллбар (см. style.css).
 */
(function () {
  "use strict";

  var MIN_WIDTH = 60;       // минимальная ширина колонки, px
  var STORE_PREFIX = "netinv.colw."; // префикс ключа в localStorage

  // Ключ хранения ширин для конкретной таблицы. Если у таблицы есть
  // data-table-key — используем его (стабильнее), иначе порядковый номер.
  function tableKey(table, idx) {
    var k = table.getAttribute("data-table-key");
    return STORE_PREFIX + (k || ("t" + idx));
  }

  function loadWidths(key) {
    try {
      var raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : {};
    } catch (e) {
      return {};
    }
  }

  function saveWidths(key, widths) {
    try {
      localStorage.setItem(key, JSON.stringify(widths));
    } catch (e) {
      /* localStorage может быть недоступен — тихо игнорируем */
    }
  }

  function applyWidths(headers, widths) {
    headers.forEach(function (th, i) {
      var w = widths[i];
      if (w && w >= MIN_WIDTH) {
        th.style.width = w + "px";
      }
    });
  }

  function initTable(table, idx) {
    var headRow = table.querySelector("thead tr");
    if (!headRow) return;
    var headers = Array.prototype.slice.call(headRow.children);
    var key = tableKey(table, idx);
    var widths = loadWidths(key);

    // Восстанавливаем сохранённые ширины.
    applyWidths(headers, widths);

    headers.forEach(function (th, colIndex) {
      // Не добавляем ручку в последнюю колонку (тянуть её некуда полезно).
      if (colIndex === headers.length - 1) return;

      var resizer = document.createElement("span");
      resizer.className = "col-resizer";
      resizer.title = "Потяните, чтобы изменить ширину колонки";
      th.appendChild(resizer);

      var startX = 0;
      var startW = 0;

      function onDown(ev) {
        ev.preventDefault();
        ev.stopPropagation();
        startX = ev.clientX;
        startW = th.getBoundingClientRect().width;
        resizer.classList.add("dragging");
        table.classList.add("resizing");
        document.addEventListener("mousemove", onMove);
        document.addEventListener("mouseup", onUp);
      }

      function onMove(ev) {
        var delta = ev.clientX - startX;
        var newW = Math.max(MIN_WIDTH, Math.round(startW + delta));
        th.style.width = newW + "px";
      }

      function onUp() {
        resizer.classList.remove("dragging");
        table.classList.remove("resizing");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        // Сохраняем итоговую ширину этой колонки.
        widths[colIndex] = Math.round(th.getBoundingClientRect().width);
        saveWidths(key, widths);
      }

      resizer.addEventListener("mousedown", onDown);
      // Двойной клик по ручке — сброс ширины этой колонки.
      resizer.addEventListener("dblclick", function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        th.style.width = "";
        delete widths[colIndex];
        saveWidths(key, widths);
      });
    });
  }

  // Инициализация всех таблиц отчёта (в т.ч. подгруженных позже —
  // вызывается повторно через window.netinvInitResizable).
  function initAll(root) {
    var scope = root || document;
    var tables = scope.querySelectorAll("table.tbl.report");
    Array.prototype.forEach.call(tables, function (table, idx) {
      if (table.__resizableInit) return; // не инициализируем дважды
      table.__resizableInit = true;
      initTable(table, idx);
    });
  }

  // Экспортируем для повторного вызова при AJAX-подгрузке (требование 3).
  window.netinvInitResizable = initAll;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { initAll(); });
  } else {
    initAll();
  }
})();
