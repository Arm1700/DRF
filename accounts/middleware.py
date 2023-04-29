# from datetime import timedelta, timezone
# from rest_framework_simplejwt.tokens import RefreshToken
#
#
# class TokenRefreshMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response
#
#     def __call__(self, request):
#         response = self.get_response(request)
#         if response.status_code == 401 and 'access_token' in response.data:
#             token = RefreshToken(response.data['refresh_token'])
#             if token.access_token:
#                 response.data['access_token'] = str(token.access_token)
#         return response
#
#
# class TokenExpirationMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response
#
#     def __call__(self, request):
#         if request.user.is_authenticated:
#             access_token = request.user.access_token
#             if access_token and access_token.expires_at < timezone.now():
#                 token = RefreshToken(request.user.refresh_token)
#                 access_token.delete()
#                 access_token = token.access_token
#                 access_token.expires_at = timezone.now() + timedelta(minutes=5)
#                 access_token.save()
#                 request.user.access_token = access_token
#         response = self.get_response(request)
#         return response
