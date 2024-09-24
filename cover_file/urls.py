from django.urls import path
from .views import CoverUploadView, EmbedView

urlpatterns = [
    path("covers/", CoverUploadView.as_view(), name="cover-upload"),
    path("embed/", EmbedView.as_view(), name="embed"),
]
