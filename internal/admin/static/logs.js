// ログの画面: /api/logs を定期的に読み込み、新しいログを表に追加する。
// 外部のライブラリは使わない（CA は外部と遮断した環境に置く前提のため）。
(function () {
  "use strict";
  var tbody = document.querySelector("#log-table tbody");
  var level = document.getElementById("log-level");
  var query = document.getElementById("log-q");
  var follow = document.getElementById("log-follow");
  var lastSeq = 0;
  var maxRows = 2000;
  var timer = null;

  function cell(text, cls) {
    var td = document.createElement("td");
    if (cls) td.className = cls;
    td.textContent = text; // textContent なので、ログの内容が HTML として解釈されることはない
    return td;
  }

  function render(entries) {
    entries.forEach(function (e) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(e.time, "time"));
      tr.appendChild(cell(e.level, "lvl-" + e.level));
      tr.appendChild(cell(e.msg));
      var attrs = document.createElement("td");
      (e.attrs || []).forEach(function (a) {
        var span = document.createElement("span");
        span.className = "attr";
        var k = document.createElement("span");
        k.className = "k";
        k.textContent = a.key + "=";
        span.appendChild(k);
        span.appendChild(document.createTextNode(a.value));
        attrs.appendChild(span);
      });
      tr.appendChild(attrs);
      tbody.insertBefore(tr, tbody.firstChild); // 新しいものを上に
      lastSeq = e.seq;
    });
    while (tbody.rows.length > maxRows) tbody.deleteRow(tbody.rows.length - 1);
  }

  function load() {
    var params = new URLSearchParams({ after: String(lastSeq), level: level.value, q: query.value });
    fetch("/api/logs?" + params.toString(), { credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (data) { render(data.entries || []); })
      .catch(function () { /* 一時的な失敗は次の読み込みで回復する */ });
  }

  function reset() {
    lastSeq = 0;
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    load();
  }

  function schedule() {
    if (timer) clearInterval(timer);
    timer = follow.checked ? setInterval(load, 3000) : null;
  }

  level.addEventListener("change", reset);
  query.addEventListener("input", function () { clearTimeout(query._t); query._t = setTimeout(reset, 300); });
  follow.addEventListener("change", schedule);
  document.getElementById("log-filter").addEventListener("submit", function (ev) { ev.preventDefault(); reset(); });
  reset();
  schedule();
})();
