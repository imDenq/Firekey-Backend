# myproject/urls.py
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from django.contrib import admin

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('accounts.urls')),
    path('api/', include('credentials.urls')),
    path('api/', include('security.urls')),
    path('api/import-export/', include('importexport.urls')),
    path('notifications/', include('notifications.urls')),
]

# Pour servir les fichiers uploadés en mode dev
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
