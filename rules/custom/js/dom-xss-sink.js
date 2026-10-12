function t1() {
  // ruleid: sast.js.dom-xss-sink
  document.getElementById("out").innerHTML = location.hash;
}
function t2() {
  const params = new URLSearchParams(window.location.search);
  const name = params.get("name");
  // ruleid: sast.js.dom-xss-sink
  document.querySelector("#greet").innerHTML = "<b>" + name + "</b>";
}
function t3() {
  // ruleid: sast.js.dom-xss-sink
  document.write(document.referrer);
}
function t4() {
  window.addEventListener("message", function (e) {
    // ruleid: sast.js.dom-xss-sink
    box.insertAdjacentHTML("beforeend", e.data);
  });
}
function t5() {
  // ruleid: sast.js.dom-xss-sink
  el.outerHTML = window.name;
}

function ok1() {
  // ok: sast.js.dom-xss-sink
  document.getElementById("out").innerHTML = "<p>static</p>";
}
function ok2() {
  const q = new URLSearchParams(location.search).get("q");
  // ok: sast.js.dom-xss-sink
  document.getElementById("out").textContent = q;
}
function ok3() {
  const q = new URLSearchParams(location.search).get("q");
  // ok: sast.js.dom-xss-sink
  document.getElementById("out").innerHTML = DOMPurify.sanitize(q);
}
async function ok4() {
  const res = await fetch("/api/profile");
  const data = await res.json();
  // ok: sast.js.dom-xss-sink
  document.getElementById("bio").innerHTML = data.bio;
}
function ok5(items) {
  // ok: sast.js.dom-xss-sink
  list.innerHTML = items.map((i) => "<li>" + i.id + "</li>").join("");
}
