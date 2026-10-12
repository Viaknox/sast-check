function t1() {
  // ruleid: sast.js.jquery-xss
  $(location.hash);
}
function t2() {
  const q = new URLSearchParams(location.search).get("q");
  // ruleid: sast.js.jquery-xss
  $("#result").html("Results for " + q);
}
function t3() {
  const who = new URLSearchParams(window.location.search).get("who");
  // ruleid: sast.js.jquery-xss
  $(".banner").append("<h2>" + who + "</h2>");
}
function t5() {
  window.addEventListener("message", function (e) {
    // ruleid: sast.js.jquery-xss
    $("#panel").after(e.data.markup);
  });
}
function t6() {
  // ruleid: sast.js.jquery-xss
  jQuery("#t").replaceWith(document.referrer);
}

function ok1() {
  const q = new URLSearchParams(location.search).get("q");
  // ok: sast.js.jquery-xss
  $("#result").text("Results for " + q);
}
function ok2() {
  // ok: sast.js.jquery-xss
  $("#result").html("<em>nothing yet</em>");
}
function ok3() {
  const q = new URLSearchParams(location.search).get("q");
  // ok: sast.js.jquery-xss
  $("#result").html(DOMPurify.sanitize(q));
}
function ok4() {
  // ok: sast.js.jquery-xss
  $(document).ready(function () { init(); });
}
function ok5(items) {
  // ok: sast.js.jquery-xss
  $("#list").append("<li>" + items.length + "</li>");
}
function ok7() {
  const sel = new URLSearchParams(location.search).get("target");
  // ok: sast.js.jquery-xss
  $("<li>item</li>").appendTo(sel);
}
function bad10() {
  // ruleid: sast.js.jquery-xss
  $("#x").html(DOMPurify.sanitize(location.hash) + location.search);
}
function ok9() {
  const q = new URLSearchParams(location.search).get("q");
  // ok: sast.js.jquery-xss
  $("#x").html(DOMPurify.sanitize(q) + "<hr>");
}
