from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('users/<int:pk>', views.GetUserOneView.as_view(), name='user-detail'),
    path('users/search/', views.UserSearchView.as_view(), name='user-search'),
    path('user/<int:pk>/delete/', views.DeleteUserView.as_view(), name='delete_user'),
    path('user/update/', views.UserUpdateView.as_view(), name='update'),
    path('update_user/<int:pk>/admin/', views.UpdateUserAdminStatusView.as_view(), name='update_user_admin_status'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('create/', views.CreateUserView.as_view(), name='create_user'),
    path('change_password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset_password'),
    path('reset-password/done/', auth_views.PasswordResetDoneView.as_view(template_name='accounts/reset_password_done.html'), name='password_reset_done'),
    path('reset-password/confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='accounts/reset_password_confirm.html'), name='password_reset_confirm'),
    path('reset-password/complete/', auth_views.PasswordResetCompleteView.as_view(template_name='accounts/reset_password_complete.html'), name='password_reset_complete'),
    path('friend-requests/', views.FriendRequestListCreateAPIView.as_view()),
    path('friend-requests/my-friends/', views.FriendListAPIView.as_view()),
    path('friend-requests/<int:pk>/', views.FriendRequestUpdateAPIView.as_view()),
    path('friend-requests/create/', views.FriendRequestCreateAPIView.as_view()),
    path('api/token/refresh/', views.RefreshTokenView.as_view(), name='token_refresh'),
    path('api/token/verify/', views.VerifyTokenView.as_view(), name='token_verify'),
]
