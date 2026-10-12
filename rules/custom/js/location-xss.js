function t1() {
  const next = new URLSearchParams(location.search).get("next");
  // ruleid: sast.js.location-xss
  window.location = next;
}
function t2() {
  // ruleid: sast.js.location-xss
  location.href = location.hash.slice(1);
}
function t3() {
  const params = new URLSearchParams(window.location.search);
  const target = params.get("redirect");
  // ruleid: sast.js.location-xss
  location.assign(target);
}
function t4() {
  window.addEventListener("message", (e) => {
    // ruleid: sast.js.location-xss
    window.open(e.data.url);
  });
}
function t5() {
  const r = new URLSearchParams(location.search).get("r");
  // ruleid: sast.js.location-xss
  window.location.replace(r);
}
function t6() {
  const next = new URLSearchParams(location.search).get("next");
  // ruleid: sast.js.location-xss
  location.href = encodeURI(next);
}

function ok1() {
  // ok: sast.js.location-xss
  window.location = "/dashboard";
}
function ok2() {
  const next = new URLSearchParams(location.search).get("next");
  if (isSafeUrl(next)) {
    // ok: sast.js.location-xss
    location.href = next;
  }
}
function ok3() {
  const next = new URLSearchParams(location.search).get("next");
  // ok: sast.js.location-xss
  location.assign(sanitizeUrl(next));
}
function ok4() {
  const id = new URLSearchParams(location.search).get("id");
  // ok: sast.js.location-xss
  location.href = "/items/" + encodeURIComponent(id);
}
function ok5(item) {
  // ok: sast.js.location-xss
  window.open(item.url, "_blank");
}
