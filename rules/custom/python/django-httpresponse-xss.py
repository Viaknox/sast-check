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


def ok_int_cast(request):
    page = int(request.GET.get("page", 1))
    # ok: sast.python.django-httpresponse-xss
    return HttpResponse(f"Page {page}")
