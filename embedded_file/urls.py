from django.urls import path

from embedded_file.views import EmbeddedUploadView

urlpatterns = [
    path("extract/", EmbeddedUploadView.as_view(), name="embedded-upload"),
]
