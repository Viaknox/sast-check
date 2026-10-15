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
function bad6() {
  // ruleid: sast.js.location-xss
  location.href = "javascript:" + location.hash.slice(1);
}
function bad7() {
  const v = new URLSearchParams(location.search).get("v");
  // ruleid: sast.js.location-xss
  window.open("javascript:" + v);
}
function ok6() {
  const q = new URLSearchParams(location.search).get("q");
  // ok: sast.js.location-xss
  window.open("https://example.com/search?q=" + q);
}
function bad8() {
  const host = new URLSearchParams(location.search).get("h");
  // ruleid: sast.js.location-xss
  location.href = "//" + host;
}
function ok5(item) {
  // ok: sast.js.location-xss
  window.open(item.url, "_blank");
}
function bad9() {
  const next = new URLSearchParams(location.search).get("next");
  isSafeUrl(next);
  // ruleid: sast.js.location-xss
  location.href = next;
}
function bad10() {
  const next = new URLSearchParams(location.search).get("next");
  if (isSafeUrl(next)) {
    location.href = "/ok";
  }
  // ruleid: sast.js.location-xss
  location.href = next;
}
function ok7() {
  const next = new URLSearchParams(location.search).get("next");
  if (!isSafeRedirect(next)) {
    return;
  }
  // ok: sast.js.location-xss
  location.href = next;
}
function ok8() {
  const next = new URLSearchParams(location.search).get("next");
  if (isSafeRedirect(next)) {
    // ok: sast.js.location-xss
    window.location.assign(next);
  }
}

// a local variable, parameter or prop called location is not the browser location
function l1(location) {
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.href = v;
}
const l2 = function (location) {
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.assign(v);
};
const l3 = (location) => {
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.replace(v);
};
function l4() {
  const location = getPlace();
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location = v;
}
function l5(props) {
  const { location } = props;
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.href = v;
}
function L6({ location }) {
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.href = v;
}
const l7 = ({ id, location }) => {
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.href = v;
};
// the same names as the source: location.search / location.hash of a local object
function s1(location) {
  // ok: sast.js.location-xss
  window.location.href = location.search;
}
const s2 = function (location) {
  // ok: sast.js.location-xss
  window.location.href = location.hash;
};
const s3 = (location) => {
  // ok: sast.js.location-xss
  window.location.href = location.search;
};
function s4() {
  const location = getPlace();
  // ok: sast.js.location-xss
  window.location.href = location.search;
}
function s5(props) {
  const { location } = props;
  // ok: sast.js.location-xss
  window.location.href = location.hash;
}
function S6({ location }) {
  // ok: sast.js.location-xss
  window.location.href = location.search;
}
const s7 = ({ location }) => {
  // ok: sast.js.location-xss
  window.location.href = location.search;
};
// the browser location is still checked when another function has a parameter with that name
function m1(location) {
  return location;
}
function m2() {
  const v = new URLSearchParams(window.location.search).get("v");
  // ruleid: sast.js.location-xss
  location = v;
}
function m3() {
  const v = new URLSearchParams(window.location.search).get("v");
  // ruleid: sast.js.location-xss
  location.replace(v);
}
function m4(location) {
  const v = new URLSearchParams(window.location.search).get("v");
  // ruleid: sast.js.location-xss
  window.location.href = v;
}
function m7() {
  const v = new URLSearchParams(window.location.search).get("v");
  location.assign(
    // ruleid: sast.js.location-xss
    v
  );
}
function m6() {
  // ruleid: sast.js.location-xss
  window.location.href = location.search;
}
function m5(location) {
  // ruleid: sast.js.location-xss
  window.location.href = window.location.search;
}
// var inside a function is local; function-scoped declarations shadow the browser location
function f1() {
  var location = getPlace();
  // ok: sast.js.location-xss
  window.location.href = location.search;
}
const f2 = function () {
  var location = getPlace();
  // ok: sast.js.location-xss
  window.location.href = location.hash;
};
const f3 = () => {
  var location = getPlace();
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.href = v;
};
function f4(props) {
  var { location } = props;
  // ok: sast.js.location-xss
  window.location.href = location.search;
}
// lexical declarations are local wherever they sit in the block
function g1() {
  init();
  const location = getPlace();
  // ok: sast.js.location-xss
  window.location.href = location.search;
}
function g2() {
  init();
  let location = getPlace();
  // ok: sast.js.location-xss
  window.location.href = location.hash;
}
function g3(props) {
  init();
  const { location } = props;
  // ok: sast.js.location-xss
  window.location.href = location.search;
}
function g4(props) {
  init();
  let { location } = props;
  // ok: sast.js.location-xss
  window.location.href = location.search;
}
function g5() {
  init();
  const location = getPlace();
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.href = v;
}
function g6() {
  init();
  let location = getPlace();
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.href = v;
}
function g7(props) {
  init();
  const { location } = props;
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.href = v;
}
function g8(props) {
  init();
  let { location } = props;
  const v = new URLSearchParams(window.location.search).get("v");
  // ok: sast.js.location-xss
  location.href = v;
}
// let and const are lexical, so even at the top level they are not window.location
{
  let location = getPlace();
  // ok: sast.js.location-xss
  window.location.href = location.search;
}
// a top-level var in a classic script does not shadow window.location
var location = window.location;
// ruleid: sast.js.location-xss
location.href = location.hash.slice(1);
