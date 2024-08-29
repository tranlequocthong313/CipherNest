from django.urls import path
from .views import CoverUploadView

urlpatterns = [
    path("covers/", CoverUploadView.as_view(), name="cover-upload"),
]
