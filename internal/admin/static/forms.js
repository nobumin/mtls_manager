// 変更の操作のフォームで、送信の前に確認のダイアログを出す（サーバ側でも「確認」のチェックを必須にしている）。
"use strict";
document.addEventListener("submit", function (ev) {
  var f = ev.target;
  var msg = f.getAttribute && f.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) {
    ev.preventDefault();
  }
});

// 指紋の入力欄（data-nopaste）では、貼り付けとドロップを受け付けない。
// 照合のときに読み上げを聞いて入力させるため（照合を省いて、取り込んだファイルの値を貼り付けないように）。
document.addEventListener("paste", function (ev) {
  if (ev.target && ev.target.hasAttribute && ev.target.hasAttribute("data-nopaste")) {
    ev.preventDefault();
  }
});
document.addEventListener("drop", function (ev) {
  if (ev.target && ev.target.hasAttribute && ev.target.hasAttribute("data-nopaste")) {
    ev.preventDefault();
  }
});
