import { Component } from "@angular/core";
import { DomSanitizer } from "@angular/platform-browser";

@Component({ selector: "app-x", template: "" })
export class XComponent {
  constructor(private sanitizer: DomSanitizer) {}

  a(url: string) {
    // ruleid: sast.js.angular-bypass-trust
    return this.sanitizer.bypassSecurityTrustUrl(url);
  }
  b(html: string) {
    // ruleid: sast.js.angular-bypass-trust
    return this.sanitizer.bypassSecurityTrustHtml(html);
  }
  c(id: string) {
    // ruleid: sast.js.angular-bypass-trust
    return this.sanitizer.bypassSecurityTrustResourceUrl("https://host/embed/" + id);
  }
  d(css: string) {
    // ruleid: sast.js.angular-bypass-trust
    return this.sanitizer.bypassSecurityTrustStyle(`background: url(${css})`);
  }

  ok1() {
    // ok: sast.js.angular-bypass-trust
    return this.sanitizer.bypassSecurityTrustHtml("<b>static</b>");
  }
  ok2() {
    // ok: sast.js.angular-bypass-trust
    return this.sanitizer.bypassSecurityTrustResourceUrl("https://www.youtube.com/embed/abc");
  }
  ok3(v: string) {
    // ok: sast.js.angular-bypass-trust
    return this.sanitizer.sanitize(1, v);
  }
  ok4(v: string) {
    // ok: sast.js.angular-bypass-trust
    return this.other.trustedValue(v);
  }
  ok5() {
    // ok: sast.js.angular-bypass-trust
    return this.sanitizer.bypassSecurityTrustStyle("color: red");
  }
}
