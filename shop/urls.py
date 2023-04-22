from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('posts/', views.PostListGetView.as_view(), name='post-list-get'),
    path('posts/create/', views.PostListCreateView.as_view(), name='post-list-create'),
    path('posts/<int:pk>/', views.PostDetailView.as_view(), name='post-detail'),
    path('posts/<int:pk>/get/', views.PostGetOnePostView.as_view(), name='post-detail'),
    path('posts/image/delete/<int:pk>/', views.PostImageDeleteView.as_view(), name='post-image-delete'),
    path('posts/<int:pk>/like/', views.PostLikeView.as_view(), name='post-like'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
