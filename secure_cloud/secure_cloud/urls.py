from django.urls import path
from secure_cloud import views

app_name = "secure_cloud"

urlpatterns = [
    path('', views.landing_page, name="landing_page"),

    path('owner/initialise/', views.initialise, name="initialise"),

    path('owner/', views.owner_landing_page, name="owner_landing"),

    path('owner/grant/<guest_name>/', views.grant_access, name="grant_access"),

    path('owner/revoke/<guest_name>/', views.revoke_access, name="revoke_access"),

    path('guest/login/', views.guest_login, name="guest_login"),

    path('guest/request/', views.request_access, name="request_access"),

    path('files/<username>/', views.view_files, name="view_files"),

    path('files/<username>/download/<filename>/', views.download_file, name="file_download"),

    path('files/<username>/upload/', views.upload_file, name="upload"),
]
