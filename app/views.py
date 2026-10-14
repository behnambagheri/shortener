import json
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from django.conf import settings
from django.db import IntegrityError, transaction
from django.http import FileResponse, Http404, HttpResponseRedirect
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .domains import destination
from .serializers import CreateSerializer
from .models import Url


def page(request, data=None, status=200):
    manifest = settings.BASE_DIR / "public/manifest.json"
    assets = json.loads(manifest.read_text()) if manifest.exists() else {}
    return render(request, "index.html", {**assets, "page_data": data or {}}, status=status)


class CreateAPIView(APIView):
    def get(self, request):
        return page(request)

    def post(self, request):
        serializer = CreateSerializer(data=request.data)
        if not serializer.is_valid():
            field, messages = next(iter(serializer.errors.items()))
            data = {"error": str(messages[0]), "field": field}
            return Response(data, status=400) if request.path == "/api/links" or "application/json" in request.headers.get("Accept", "") else page(request, data, 400)
        values = serializer.validated_data
        name = values.get("shortened") or secrets.token_urlsafe(6)
        if Url.objects.filter(shortened=name).exists():
            data = {"error": "That short name is already taken. Choose another.", "field": "shortened"}
            return Response(data, status=409) if request.path == "/api/links" else page(request, data, 409)
        try:
            with transaction.atomic():
                link = Url.objects.create(original=values["original"], shortened=name)
        except IntegrityError:
            data = {"error": "That short name is already taken. Choose another.", "field": "shortened"}
            return Response(data, status=409) if request.path == "/api/links" else page(request, data, 409)
        result = {"original": link.original, "shortened": name, "short_url": settings.SHORTENER_URL + "/" + name}
        return Response(result, status=201) if request.path == "/api/links" or "application/json" in request.headers.get("Accept", "") else page(request, {"result": result})


class ConfigAPIView(APIView):
    def get(self, request):
        return Response({"approved_domains": settings.APPROVED_DOMAINS, "include_subdomains": True, "short_origin": settings.SHORTENER_URL})


class RedirectAPIView(APIView):
    def get(self, request, url):
        link = Url.objects.filter(shortened=url).last()
        if not link:
            return Response({"error": "Short link not found."}, status=404)
        try:
            target = destination(link.original, settings.APPROVED_DOMAINS, [urlsplit(settings.SHORTENER_URL).hostname])
        except ValueError as error:
            return Response({"error": str(error)}, status=403)
        response = HttpResponseRedirect(target)
        response["Cache-Control"] = "no-store"
        response["Referrer-Policy"] = "no-referrer"
        return response


def asset(request, name):
    if not re.fullmatch(r"(?:app-[a-f0-9]{12}\.(?:css|js)|font-[a-f0-9]{12}\.woff2)", name):
        raise Http404
    file = settings.BASE_DIR / "public/assets" / name
    if not file.is_file():
        raise Http404
    response = FileResponse(file.open("rb"))
    response["Cache-Control"] = "public, max-age=31536000, immutable"
    return response
