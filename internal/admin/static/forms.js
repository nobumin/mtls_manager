// 変更の操作のフォームで、送信の前に確認のダイアログを出す（サーバ側でも「確認」のチェックを必須にしている）。
"use strict";
document.addEventListener("submit", function (ev) {
  var f = ev.target;
  var msg = f.getAttribute && f.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) {
    ev.preventDefault();
  }
});
