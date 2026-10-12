import DOMPurify from "dompurify";
import sanitizeHtml from "sanitize-html";

export function A({ html }) {
  // ruleid: sast.js.react-dangerous-html
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function B({ post }) {
  // ruleid: sast.js.react-dangerous-html
  return <article className="post" dangerouslySetInnerHTML={{ __html: post.body }} />;
}

export function C({ name }) {
  // ruleid: sast.js.react-dangerous-html
  return <p dangerouslySetInnerHTML={{ __html: "<b>" + name + "</b>" }}></p>;
}

export function D({ md }) {
  // ruleid: sast.js.react-dangerous-html
  return <section dangerouslySetInnerHTML={{ __html: renderMarkdown(md) }} />;
}

export function E({ name }) {
  // ruleid: sast.js.react-dangerous-html
  return <p dangerouslySetInnerHTML={{ __html: `<b>${name}</b>` }} />;
}

export function Ok1() {
  // ok: sast.js.react-dangerous-html
  return <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />;
}

export function Ok2({ html }) {
  // ok: sast.js.react-dangerous-html
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export function Ok3({ html }) {
  // ok: sast.js.react-dangerous-html
  return <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(html) }} />;
}

export function Ok4({ html }) {
  // ok: sast.js.react-dangerous-html
  return <div>{html}</div>;
}

export function Ok5() {
  // ok: sast.js.react-dangerous-html
  return <style dangerouslySetInnerHTML={{ __html: `body { margin: 0 }` }} />;
}
