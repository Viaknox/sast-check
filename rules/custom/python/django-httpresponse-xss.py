from django.http import HttpResponse
from django.utils.html import escape, format_html


def bad_direct(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET.get("name"))


def bad_fstring(request):
    name = request.GET["name"]
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(f"<h1>Hello {name}</h1>")


def bad_percent_format(request):
    q = request.POST.get("q", "")
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse("<p>You searched for %s</p>" % q)


def bad_dot_format(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse("<b>{}</b>".format(request.COOKIES.get("theme")))


def ok_escaped(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(escape(request.GET.get("name")))


def ok_format_html(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(format_html("<b>{}</b>", request.GET.get("name")))


def ok_constant(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse("<h1>Welcome</h1>")


def ok_plain_text(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET.get("name"), content_type="text/plain")


def bad_strip_tags(request):
    name = strip_tags(request.GET.get("name"))
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(f"<p>{name}</p>")


def ok_int_cast(request):
    page = int(request.GET.get("page", 1))
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(f"Page {page}")


def bad_bad_request(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponseBadRequest(request.GET.get('q'))


def bad_not_found(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponseNotFound(f"<p>{request.GET.get('p')}</p>")


def bad_mark_safe(request):
    # ruleid: sast.python.django-httpresponse-xss
    return render(request, "page.html", {"h": mark_safe(request.GET.get('h'))})


def bad_prefixed_forbidden(request):
    # ruleid: sast.python.django-httpresponse-xss
    return django.http.HttpResponseForbidden(request.POST.get('why'))


def ok_bad_request_constant(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponseBadRequest("invalid input")


def ok_not_found_escaped(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponseNotFound(escape(request.GET.get('p')))


def ok_mark_safe_escaped(request):
    # ok: sast.python.django-httpresponse-xss
    return mark_safe(escape(request.GET.get('h')))


# item 4: only a constant format string makes format_html safe
GREETING_FMT = "<i>{}</i>"


def bad_format_html_tainted_format(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(format_html(request.GET["html"], "x"))


def bad_format_html_tainted_format_var(request):
    fmt = request.POST.get("fmt", "")
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(format_html(fmt, "x"))


def bad_format_html_fstring_format(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(format_html(f"<b>{request.GET['a']}</b>", "x"))


def bad_format_html_percent_format(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(format_html("<b>%s</b>" % request.GET["a"], "x"))


def ok_qualified_format_html_literal(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(django.utils.html.format_html("<b>{}</b>", request.GET["a"]))


def ok_format_html_constant_var(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(format_html(GREETING_FMT, request.GET.get("n")))


# item 17: the view's request parameter may have any name
def bad_renamed_param(req):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(req.GET["x"])


def bad_renamed_post_extra_args(r, slug=None):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse("<p>%s</p>" % r.POST.get("x"))


async def bad_renamed_async(req):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(req.GET["x"])


class BadRenamedMethod(View):
    def get(self, req):
        # ruleid: sast.python.django-httpresponse-xss
        return HttpResponse(req.COOKIES.get("c"))


@require_POST
def bad_decorated_body(r):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(r.body)


@csrf_exempt
@require_http_methods(["POST"])
def bad_stacked_decorators_headers(r):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(r.headers.get("X-Name"))


def ok_renamed_escaped(req):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(escape(req.GET["x"]))


def ok_undecorated_body_attribute(resp):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(resp.body)


@lru_cache
def ok_other_decorator_body(resp):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(resp.body)


@require_POST
def ok_decorated_other_attribute(r):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(r.method)


def ok_get_attribute_on_local_object():
    cfg = load_settings()
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(cfg.GET)


def bad_wrapper_with_constant_arg(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(build_page(GREETING_FMT, request.GET["n"]))


def bad_template_defined_but_unused(request):
    tpl = Template("<p>{{ q }}</p>")
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["q"])


def bad_template_source_fstring(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(Template(f"<p>{request.GET['t']}</p>").render(Context({})))


# item 22: autoescaping template rendering and non-HTML content types are safe
def ok_template_render_inline(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(Template("<p>{{ q }}</p>").render(Context({"q": request.GET.get("q")})))


def ok_template_render_variable(request):
    tpl = Template("<p>{{ q }}</p>")
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(tpl.render(Context({"q": request.GET["q"]})))


def bad_template_source_is_request_data(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(Template(request.GET["t"]).render(Context({})))


def ok_plain_text_charset_fstring(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(f"hi {request.GET['n']}", content_type="text/plain; charset=utf-8")


def ok_plain_text_charset_percent(request, enc):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["n"], content_type="text/plain; charset=%s" % enc)


def ok_plain_text_charset_format(request, enc):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["n"], content_type="text/plain; charset={}".format(enc))


def ok_subclass_plain_text_charset(request, enc):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponseBadRequest(request.GET["n"], content_type=f"text/plain; charset={enc}")


def bad_jsonp_content_type(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["cb"], content_type="application/jsonp")


def bad_plain_prefix_content_type(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["x"], content_type="text/plainish")


def bad_plain_replaced_to_html(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["x"], content_type="text/plain".replace("plain", "html"))


def bad_plain_concatenated(request, extra):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["x"], content_type="text/plain" + extra)


def bad_json_charset_replaced(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["x"], content_type="application/json; charset=utf-8".replace("application/json", "text/html"))


def bad_subclass_plain_replaced_to_html(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponseBadRequest(request.GET["x"], content_type="text/plain".replace("plain", "html"))


def bad_subclass_json_concatenated(request, extra):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponseNotFound(request.GET["x"], content_type="application/json" + extra)


def bad_percent_before_parameter(request, kind):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["x"], content_type="text/%s" % kind)


def bad_plain_replaced_multiline(request):
    return HttpResponse(
        # ruleid: sast.python.django-httpresponse-xss
        request.GET["x"],
        content_type="text/plain".replace("plain", "html"),
    )


def bad_subclass_plain_replaced_multiline(request):
    return HttpResponseBadRequest(
        # ruleid: sast.python.django-httpresponse-xss
        request.GET["x"],
        content_type="text/plain".replace("plain", "html"),
    )


def bad_subclass_jsonp_content_type(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponseBadRequest(request.GET["cb"], content_type="application/jsonp")


def ok_json_charset(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["x"], content_type="application/json; charset=utf-8")


def ok_json_exact(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["x"], content_type='application/json')


def ok_subclass_json_charset(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponseNotFound(request.GET["x"], content_type="application/json; charset=utf-8")


def ok_subclass_plain_exact(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponseForbidden(request.GET["x"], content_type="text/plain")


def bad_html_content_type(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(request.GET["x"], content_type="text/html; charset=utf-8")


def bad_subclass_html_content_type(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponseNotFound(request.GET["x"], content_type="text/html")


# a helper that receives the request in another position: only the request.* sources reach it
def bad_helper_get(user, request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse("<p>" + request.GET["q"] + "</p>")


def bad_helper_post(user, request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(request.POST["comment"])


def bad_helper_cookies(user, request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse("hi " + request.COOKIES["name"])


# a literal template only sanitizes when it keeps Django's autoescaping
def bad_template_autoescape_off(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(Template("{% autoescape off %}{{ q }}{% endautoescape %}").render(Context({"q": request.GET["q"]})))


def bad_template_safe_filter(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(Template("<p>{{ q|safe }}</p>").render(Context({"q": request.GET["q"]})))


def bad_template_safe_filter_spaced(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(Template("<p>{{ q | safe }}</p>").render(Context({"q": request.GET["q"]})))


def bad_template_safeseq_filter(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(Template("{{ items|safeseq|join:',' }}").render(Context({"items": request.GET.getlist("i")})))


def bad_template_multiline_autoescape_off(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(Template("""<div>
{% autoescape off %}
{{ q }}
{% endautoescape %}
</div>""").render(Context({"q": request.GET["q"]})))


def bad_template_variable_autoescape_off(request):
    tpl = Template("{% autoescape off %}{{ q }}{% endautoescape %}")
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(tpl.render(Context({"q": request.GET["q"]})))


def bad_template_variable_safe_filter(request):
    tpl = Template("<p>{{ q|safe }}</p>")
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(tpl.render(Context({"q": request.GET["q"]})))


def bad_template_context_autoescape_false(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(Template("<p>{{ q }}</p>").render(Context({"q": request.GET["q"]}, autoescape=False)))


def bad_template_variable_context_autoescape_false(request):
    tpl = Template("<p>{{ q }}</p>")
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(tpl.render(Context({"q": request.GET["q"]}, autoescape=False)))


def bad_template_context_autoescape_positional(request):
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(Template("<p>{{ q }}</p>").render(Context({"q": request.GET["q"]}, False)))


def bad_template_variable_context_autoescape_positional(request):
    tpl = Template("<p>{{ q }}</p>")
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(tpl.render(Context({"q": request.GET["q"]}, False)))


def ok_template_escape_filters(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(Template("<p>{{ q|escape }} {{ q|force_escape }} {{ q|upper }}</p>").render(Context({"q": request.GET["q"]})))


def ok_template_autoescape_on(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(Template("{% autoescape on %}{{ q }}{% endautoescape %}").render(Context({"q": request.GET["q"]})))


def ok_template_context_autoescape_true(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(Template("<p>{{ q }}</p>").render(Context({"q": request.GET["q"]}, autoescape=True)))


# a constant format string, bound once to a literal (PR #11 review 3)
ROW = "<p>{}</p>"
ROW_B = "<p>{} {}</p>"
FROM_REQUEST = ""


def ok_format_html_module_constant(request):
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(format_html(ROW, request.GET["name"]))


def ok_format_html_local_constant(request):
    row = "<li>{}</li>"
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(format_html(row, request.GET["name"]))


def ok_format_html_qualified_local_constant(request):
    row = "<li>{}</li>"
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(django.utils.html.format_html(row, request.GET["name"]))


def bad_format_html_local_from_request(request):
    row = request.GET["fmt"]
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(format_html(row, "x"))


def bad_format_html_local_fstring(request):
    row = f"<p>{request.GET['a']}</p>{{}}"
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(format_html(row, "x"))


def bad_format_html_local_percent(request):
    row = "<p>%s</p>{}" % request.GET["a"]
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(format_html(row, "x"))


def bad_format_html_reassigned_local(request):
    row = "<p>{}</p>"
    row = request.GET["fmt"]
    # ruleid: sast.python.django-httpresponse-xss
    return HttpResponse(format_html(row, "x"))
