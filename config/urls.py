from django.urls import path
from app.views import CreateAPIView, ConfigAPIView, RedirectAPIView, asset

urlpatterns = [
    path("", CreateAPIView.as_view()),
    path("api/links", CreateAPIView.as_view()),
    path("api/config", ConfigAPIView.as_view()),
    path("assets/<str:name>", asset),
    path("<slug:url>", RedirectAPIView.as_view()),
]
