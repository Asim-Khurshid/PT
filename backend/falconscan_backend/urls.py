from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.views import TokenObtainPairView
from apps.accounts.serializers import CustomTokenObtainPairSerializer

# Create custom view with our serializer
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

# Health check and root endpoint
def health_check(request):
    return JsonResponse({
        'status': 'ok',
        'message': 'FalconScan API is running',
        'version': '1.0.0'
    })

urlpatterns = [
    path('', health_check, name='health_check'),
    path('health/', health_check, name='health_check_alt'),
    path('admin/', admin.site.urls),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/accounts/', include('apps.accounts.urls')),
    path('api/scans/', include('apps.scans.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
