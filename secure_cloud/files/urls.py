from django.urls import path
from files import views

app_name = "files"

urlpatterns = [
    path('<username>/', views.view_files, name="view_files"),

    path('<username>/download/<filename>/', views.download_file, name="file_download"),

    path('<username>/upload/', views.upload_file, name="upload"),
]
