function t4() {
  const u = new URLSearchParams(location.search).get("u");
  // ruleid: sast.js.jquery-url-xss
  $("a.next").attr("href", u);
}
function ok6() {
  const id = new URLSearchParams(location.search).get("id");
  // ok: sast.js.jquery-url-xss
  $("a.next").attr("href", "/item/" + encodeURIComponent(id));
}
function bad9() {
  const u = location.hash.slice(1);
  // ruleid: sast.js.jquery-url-xss
  $("a").attr("href", DOMPurify.sanitize(u));
}
function ok8() {
  const u = location.hash.slice(1);
  // ok: sast.js.jquery-url-xss
  $("a").attr("href", sanitizeUrl(u));
}
function bad8() {
  const u = new URLSearchParams(location.search).get("u");
  // ruleid: sast.js.jquery-url-xss
  $("a.next").attr("href", encodeURI(u));
}
function bad11() {
  const s = new URLSearchParams(location.search).get("s");
  // ruleid: sast.js.jquery-url-xss
  $("img.avatar").attr("src", s);
}
function bad12() {
  const u = location.hash.slice(1);
  // ruleid: sast.js.jquery-url-xss
  $("a").attr("href", sanitizeUrl(u) + location.search);
}
function ok9() {
  // ok: sast.js.jquery-url-xss
  $("a.home").attr("href", "/home");
}
function ok10() {
  const t = new URLSearchParams(location.search).get("t");
  // ok: sast.js.jquery-url-xss
  $("a.home").attr("title", t);
}
