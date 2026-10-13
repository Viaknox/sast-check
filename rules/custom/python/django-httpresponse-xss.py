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
