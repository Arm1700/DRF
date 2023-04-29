from django.contrib import admin
from django.urls import path, include, re_path

from rest_framework import permissions
from rest_framework import routers

from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="API",
        default_version='v1',
        description="API documentation",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@snippets.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=False,
    permission_classes=[permissions.AllowAny],
)

router = routers.DefaultRouter()
admin.autodiscover()

urlpatterns = [
    path('', include(router.urls)),
    path('admin/', admin.site.urls),
    path('home_page/', include('shop.urls')),
    path('accounts/', include('accounts.urls')),
    re_path('swagger(?P<format>\.json|\.yaml)', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    re_path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
