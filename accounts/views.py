from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.utils.encoding import force_bytes
from django.contrib.auth import authenticate, logout
from django.utils.http import urlsafe_base64_encode
from django.shortcuts import get_object_or_404
from django.core.mail import EmailMessage
from django.db.models import Q
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from django.http import Http404
from django.db import IntegrityError

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from rest_framework import generics, status, permissions

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from . import serializers
from . import models


Get_response_schema = {
    status.HTTP_200_OK: openapi.Response('OK')
}

Add_response_schema = {
    status.HTTP_201_CREATED: openapi.Response('Posted'),
    status.HTTP_400_BAD_REQUEST: openapi.Response('Not Valid')
}

Edit_response_schema = {
    status.HTTP_201_CREATED: openapi.Response('Edited'),
    status.HTTP_400_BAD_REQUEST: openapi.Response('Not Valid'),
    status.HTTP_401_UNAUTHORIZED: openapi.Response('Unauthorized')
}

Delete_response_schema = {
    status.HTTP_204_NO_CONTENT: openapi.Response('Deleted'),
    status.HTTP_401_UNAUTHORIZED: openapi.Response('Unauthorized')
}


class UserSearchView(APIView):
    permission_classes = [permissions.AllowAny]
    # authentication_classes = [JWTAuthentication]
    parser_classes = [MultiPartParser, FormParser]
    serializer_class = serializers.UserSerializer
    queryset = models.User.objects.all()

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='page',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_INTEGER,
                description='Page number',
                required=True,
                default='1',
            ),
            openapi.Parameter(
                'Search',
                openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                description='Search query string',
            ),
        ],
        operation_description='Search users by username or ID',
        responses={
            200: 'Successful search operation',
            400: 'Bad request',
            500: 'Server error',
        }
    )
    def get(self, request):
        search_query = self.request.query_params.get('Search')
        user_id = models.User.objects.all().order_by('-id')

        if search_query:
            user_id = user_id.filter(Q(username__icontains=search_query))

        paginator = Paginator(user_id, 2)
        page_number = request.GET.get('page', 1)

        try:
            page_obj = paginator.page(page_number)
        except (PageNotAnInteger, EmptyPage):
            page_number = 1
            page_obj = paginator.page(page_number)

        if request.user.is_authenticated:
            serializer = serializers.UserSerializer(page_obj, many=True, context={'request': request})
        else:
            serializer = serializers.UserSerializer(page_obj, many=True, context={'request': request})
        return Response(serializer.data, headers={
            'X-Total-Count': paginator.count,
            'X-Total-Pages': paginator.num_pages,
            'X-Page-Number': page_obj.number,
        })


class UserListCreateView(APIView):
    authentication_classes = [JWTAuthentication]
    parser_classes = [MultiPartParser, FormParser]

    def get_object(self, pk):
        try:
            user = models.User.objects.get(pk=pk)
            self.check_object_permissions(self.request, user)
            return user
        except models.User.DoesNotExist:
            raise Http404

    @swagger_auto_schema(responses=Get_response_schema)
    def get(self, request, pk):
        if request.user.is_staff:
            user = self.get_object(pk)
            serializer = serializers.UserSerializer(user, context={'request': request})
            return Response(serializer.data)
        else:
            return Response(status=status.HTTP_403_FORBIDDEN)


class ResetPasswordView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    parser_classes = [MultiPartParser, FormParser]
    serializer_class = serializers.ResetPasswordSerializer

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'email',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='email',
                required=True,
                default='example@example.com',
            ),
        ],
        operation_description='Send an email with instructions to reset a user\'s password.',
        responses={
            200: 'Password reset instructions sent',
            400: 'Bad request',
            500: 'Server error',
        }
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        try:
            user = models.User.objects.get(email=email)
        except models.User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        password_reset_url = request.build_absolute_uri(
            reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token}))
        subject = 'Password reset instructions'
        from_email = settings.EMAIL_HOST_USER
        to_email = email

        context = {
            'password_reset_url': password_reset_url,
        }

        message = render_to_string('accounts/reset_password_email.html', context)

        email = EmailMessage(
            subject,
            message,
            from_email,
            [to_email],
        )
        email.content_subtype = 'html'
        email.send()

        return Response({'message': 'Password reset instructions sent', 'password_reset_url': password_reset_url},
                        status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    authentication_classes = [JWTAuthentication]
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'old_password',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='old_password',
                required=True,
                default='Example_password1',
            ),
            openapi.Parameter(
                'new_password',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='new_password',
                required=True,
                default='Example_password2',
            ),
            openapi.Parameter(
                'new_password2',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='new_password2',
                required=True,
                default='Example_password2',
            ),
        ],
        responses={
            200: openapi.Response("Password has been changed successfully."),
            400: openapi.Response("Invalid old password."),
        },
        operation_description="Change password",
        operation_summary="Change password",
    )
    def put(self, request):
        serializer = serializers.ChangePasswordSerializer(data=request.data)
        if request.user.is_authenticated:
            if serializer.is_valid():
                old_password = serializer.validated_data['old_password']
                new_password = serializer.validated_data['new_password']
                new_password2 = serializer.validated_data['new_password2']
                user = request.user
                if user.check_password(old_password):
                    if new_password == new_password2:
                        if old_password != new_password:
                            user.set_password(new_password)
                            user.save()
                            return Response({'detail': 'Password has been changed successfully.'},
                                            status=status.HTTP_200_OK)
                        else:
                            return Response({'error': 'New password cannot be the same as the old password.'},
                                            status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response({'error': 'New passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({'error': 'Invalid old password.'}, status=status.HTTP_400_BAD_REQUEST)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class DeleteUserView(APIView):
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(responses=Delete_response_schema)
    def delete(self, request, pk):
        if request.user.is_authenticated:
            try:
                user = models.User.objects.get(id=pk)
            except models.User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

            if request.user.is_superuser or request.user == user:
                user.delete()
                return Response(status=status.HTTP_204_NO_CONTENT)
            else:
                return Response({'error': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class UserUpdateView(APIView):
    authentication_classes = [JWTAuthentication]
    parser_classes = [MultiPartParser, FormParser]
    serializer_class = serializers.UserSerializer

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'username',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='username',
                required=False,
                default='example',
            ),
            openapi.Parameter(
                'last_name',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='last_name',
                required=False,
                default='example',
            ),
            openapi.Parameter(
                'first_name',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='first_name',
                required=False,
                default='example',
            ),
            openapi.Parameter(
                'profile_pic',
                openapi.IN_FORM,
                type=openapi.TYPE_FILE,
                required=False,
                description='Image file to upload',
            ),
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                type=openapi.TYPE_INTEGER,
                required=False,
                description='User ID to update',
            ),
        ],
        responses={
            200: serializers.UserSerializer(),
            400: openapi.Response("Invalid data."),
            401: openapi.Response("Authentication credentials were not provided."),
            404: openapi.Response("Object not found."),
        })
    def put(self, request):
        if request.user.is_authenticated:
            if self.request.query_params.get('id'):
                pk = int(self.request.query_params.get('id'))
            else:
                pk = None
            if pk == request.user.id:
                my_object = models.User.objects.get(id=pk)
            elif not pk:
                my_object = request.user
            elif request.user.pk != pk and not request.user.is_superuser:
                return Response({'message': 'You do not have permission to update this profile.'},
                                status=status.HTTP_403_FORBIDDEN)
            else:
                try:
                    my_object = models.User.objects.get(id=pk)
                except models.User.DoesNotExist:
                    return Response({'error': 'User not found.'}, status=404)
            serializer = serializers.UserSerializer(my_object, data=request.data, partial=True, context={'request': request})

            if serializer.is_valid():
                try:
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                except IntegrityError as e:
                    if 'unique constraint' in str(e).lower():
                        return Response({'message': 'Username already exists.'}, status=status.HTTP_400_BAD_REQUEST)
                    return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class UpdateUserAdminStatusView(APIView):
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        responses=Edit_response_schema,
    )
    def post(self, request, pk):
        if request.user.is_staff:
            request.data.get('user_id')
            if not pk:
                return Response({'error': 'User ID not provided.'}, status=400)

            try:
                user = models.User.objects.get(id=pk)
            except models.User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=404)

            user.is_admin = True
            user.is_staff = True
            user.is_superuser = True
            user.save()

            return Response({'success': f'{user.username} has been granted admin privileges.'})
        else:
            return Response(status=status.HTTP_403_FORBIDDEN)


class CreateUserView(APIView):
    permission_classes = [permissions.AllowAny]
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'email',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='email',
                required=True,
                default='example@example.com',

            ),
            openapi.Parameter(
                'username',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='username',
                required=True,
                default='example',

            ),
            openapi.Parameter(
                'password',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='password',
                required=True,
                default='Example_password1',

            ),
            openapi.Parameter(
                'password_confirmation',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='password_confirmation',
                required=True,
                default='Example_password1',

            ),
            openapi.Parameter(
                'first_name',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='first_name',
                required=True,
                default='example',

            ),
            openapi.Parameter(
                'last_name',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='last_name',
                required=True,
                default='example',

            ),
        ],
        responses={
            200: openapi.Response("Create successful."),
            401: openapi.Response("Invalid credentials."),
        },
        operation_description="User create",
        operation_summary="User create",
    )
    def post(self, request):
        serializer = serializers.UserSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            try:
                serializer.save(created_date=timezone.now())
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except IntegrityError as e:
                if 'unique constraint' in str(e).lower():
                    return Response({'message': 'Username or email already exists.'},
                                    status=status.HTTP_400_BAD_REQUEST)
                return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'email',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='email',
                required=True,
                default='example@example.com',
            ),
            openapi.Parameter(
                'password',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='password',
                required=True,
                default='Example_password1',
            ),
        ],
        responses={
            200: openapi.Response("Login successful."),
            401: openapi.Response("Invalid credentials."),
        },
        operation_description="User login",
        operation_summary="User login",
    )
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, email=email, password=password)
        if user is not None:
            # login(request, user)
            refresh = RefreshToken.for_user(user)
            return Response({
                'detail': 'Login successful.',
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    # permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        responses={
            200: openapi.Response("Logout successful."),
            401: openapi.Response("Authentication credentials were not provided."),
        },
        operation_description="Logout",
        operation_summary="Logout",
    )
    def post(self, request):
        if request.user.is_authenticated:
            logout(request)
            return Response({'detail': 'Logout successful.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class FriendListAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    serializer_class = serializers.UserSerializer

    @swagger_auto_schema(
        responses={
            200: 'Success',
            401: 'Unauthorized',
            500: 'Server error',
        }
    )
    def get(self, request):
        if request.user.is_authenticated:
            user_id = request.user.id
            friends = models.User.objects.filter(
                Q(friendship_initiated__to_user_id=user_id) | Q(friendship_received__from_user_id=user_id),
                ~Q(id=user_id)
            ).distinct()
            serializer = self.serializer_class(friends, many=True, context={'request': request})
            return Response(serializer.data)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class FriendRequestListCreateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    serializer_class = serializers.FriendRequestAcceptedSerializer

    @swagger_auto_schema(
        responses={
            200: 'Success',
            401: 'Unauthorized',
            500: 'Server error',
        }
    )
    def get(self, request):
        if request.user.is_authenticated:
            to_user_id = request.query_params.get('to_user', None)
            if to_user_id is None:
                friend_requests = models.FriendRequest.objects.all()
            else:
                friend_requests = models.FriendRequest.objects.filter(to_user_id=to_user_id)
            serializer = self.serializer_class(friend_requests, many=True)
            return Response(serializer.data)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class FriendRequestCreateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    serializer_class = serializers.FriendRequestSerializer

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='from_user',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_INTEGER,
                description='ID of the user sending the friend request',
                required=True
            ),
            openapi.Parameter(
                name='to_user',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_INTEGER,
                description='ID of the user receiving the friend request',
                required=True
            ),
            openapi.Parameter(
                name='message',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                description='Message to be included with the friend request',
                required=False,
                default='Hi my friend!!!',
            ),
        ],
        operation_description='Create a friend request between two users',
        responses={
            201: 'Friend request created successfully',
            400: 'Bad request',
            401: 'Unauthorized',
            500: 'Server error',
        }
    )
    def post(self, request):
        if request.user.is_authenticated:
            from_user_id = request.query_params.get('from_user')
            to_user_id = request.query_params.get('to_user')

            if from_user_id is None or to_user_id is None:
                raise serializers.ValidationError('Both from_user and to_user query parameters must be provided')

            from_user_id = int(from_user_id)
            to_user_id = int(to_user_id)

            if from_user_id != request.user.id:
                raise PermissionDenied('You cannot create a friend request on behalf of another user.')

            if from_user_id == to_user_id:
                raise ValidationError('You cannot send a friend request to yourself')

            if models.Friendship.objects.filter(
                    Q(from_user_id=from_user_id, to_user_id=to_user_id) | Q(to_user_id=to_user_id, from_user_id=from_user_id)).exists():
                raise ValidationError('These users are already friends')

            if models.FriendRequest.objects.filter(from_user_id=from_user_id, to_user_id=to_user_id).exists():
                raise ValidationError('A friend request already exists between these users')

            serializer = self.serializer_class(
                data={'from_user': from_user_id, 'to_user': to_user_id, 'message': request.query_params.get('message', '')})
            serializer.is_valid(raise_exception=True)
            serializer.save(from_user_id=from_user_id)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class FriendRequestUpdateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    serializer_class = serializers.FriendRequestSerializer

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='accepted',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_BOOLEAN,
                description='Indicates whether the friend request has been accepted or not',
                required=True,
            )
        ],
        responses={
            200: 'Friend request updated successfully',
            400: 'Bad request',
            401: 'Unauthorized',
            500: 'Server error',
        }
    )
    def put(self, request, pk):
        if request.user.is_authenticated:
            friend_request = get_object_or_404(models.FriendRequest, pk=pk)
            accepted = request.query_params.get('accepted', '').lower() in ['true', '1']
            if friend_request.to_user != request.user:
                raise PermissionDenied("You are not allowed to update this friend request.")

            if accepted:
                friendship1 = models.Friendship.objects.create(
                    from_user=friend_request.from_user,
                    to_user=friend_request.to_user,
                )
                friendship1.save()

                friendship2 = models.Friendship.objects.create(
                    from_user=friend_request.to_user,
                    to_user=friend_request.from_user,
                )
                friendship2.save()

            friend_request.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
