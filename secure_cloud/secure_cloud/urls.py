"""secure_cloud URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from . import views

app_name = "secure_cloud"

urlpatterns = [
    path('', views.landing_page, name="landing_page"),

    path('files/', views.view_files, name="view_files"),

    path('files/download/<filename>/', views.download_file, name="file_download"),

    path('files/upload/', views.upload_file, name="upload"),

    path('files/symkey/', views.generate_symmetric_key, name="symkey"),

    path('admin/', admin.site.urls)
]
