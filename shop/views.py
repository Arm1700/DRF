from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Post, PostImage
from .serializers import PostSerializer, PostImageSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.shortcuts import get_object_or_404, get_list_or_404
from django.db.models import Q
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.http import Http404
import os
from django.contrib.sessions.backends.base import SessionBase

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


class PostListGetView(APIView):
    # permission_classes = [IsAuthenticated]
    # authentication_classes = [JWTAuthentication]
    parser_classes = [MultiPartParser, FormParser]
    serializer_class = PostSerializer
    queryset = Post.objects.all()

    @swagger_auto_schema(
        responses=Get_response_schema,
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
        ]
    )
    def get(self, request):
        search_query = self.request.query_params.get('Search')
        posts = Post.objects.all().order_by('-created_at')

        if search_query:
            posts = posts.filter(Q(description__icontains=search_query))

        paginator = Paginator(posts, 2)
        page_number = request.GET.get('page', 1)

        try:
            page_obj = paginator.page(page_number)
        except (PageNotAnInteger, EmptyPage):
            page_number = 1
            page_obj = paginator.page(page_number)

        serializer = PostSerializer(page_obj, many=True)
        return Response(serializer.data, headers={
            'X-Total-Count': paginator.count,
            'X-Total-Pages': paginator.num_pages,
            'X-Page-Number': page_obj.number,
        })


class PostListCreateView(APIView):
    authentication_classes = [JWTAuthentication]
    parser_classes = [MultiPartParser, FormParser]
    serializer_class = PostSerializer

    MAX_IMAGES = 5

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'description',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description='add',
                required=False,
            ),
            openapi.Parameter(
                'uploaded_images',
                openapi.IN_FORM,
                type=openapi.TYPE_ARRAY,
                items=openapi.Items(type=openapi.TYPE_FILE, required=True),
                required=True,
                description='Image file to upload (max. 5)',
                max_items=5,
            ),
        ],
        responses={
            status.HTTP_201_CREATED: PostSerializer(),
            status.HTTP_400_BAD_REQUEST: "Invalid data",
            status.HTTP_401_UNAUTHORIZED: "Authentication credentials were not provided",
        },
    )
    def post(self, request):
        if request.user.is_authenticated:
            uploaded_images = request.FILES.getlist('uploaded_images')
            num_uploaded_images = len(uploaded_images)
            if num_uploaded_images > self.MAX_IMAGES:
                return Response(
                    {'detail': 'You have reached the maximum number of images allowed.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = PostSerializer(data=request.data)
            if serializer.is_valid():
                image_file = request.FILES.get('posts')
                if image_file:
                    filename = os.path.join('posts', image_file.name)
                    with open(filename, 'wb') as f:
                        for chunk in image_file.chunks():
                            f.write(chunk)
                    serializer.save(user=request.user, image=filename)
                else:
                    serializer.save(user=request.user)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class PostGetOnePostView(APIView):
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def get_object(self, pk):
        try:
            post = Post.objects.get(pk=pk)
            self.check_object_permissions(self.request, post)
            return post
        except Post.DoesNotExist:
            raise Http404

    @swagger_auto_schema(responses=Get_response_schema)
    def get(self, request, pk):
        post = self.get_object(pk)
        serializer = PostSerializer(post)
        return Response(serializer.data)


class PostDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    parser_classes = [MultiPartParser, FormParser]

    def get_object(self, pk):
        try:
            post = Post.objects.get(pk=pk)
            self.check_object_permissions(self.request, post)
            return post
        except Post.DoesNotExist:
            raise Http404

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'description',
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                required=False,
                description='add',
                allow_empty_value=True,
            ),
            openapi.Parameter(
                'image_id',
                openapi.IN_FORM,
                type=openapi.TYPE_INTEGER,
                required=False,
                description='Image ID to update',
            ),
            openapi.Parameter(
                'images',
                openapi.IN_FORM,
                type=openapi.TYPE_FILE,
                required=False,
                description='Image file to upload',
            ),
        ],
        responses={
            status.HTTP_200_OK: PostSerializer(),
            status.HTTP_400_BAD_REQUEST: "Invalid data",
            status.HTTP_401_UNAUTHORIZED: "Authentication credentials were not provided",
            status.HTTP_404_NOT_FOUND: "Post not found",
        },
    )
    def put(self, request, pk):
        if request.user.is_authenticated:
            post = self.get_object(pk)
            if post.user != request.user:
                return Response(status=status.HTTP_401_UNAUTHORIZED)

            if post.images.count() > 5:
                return Response({'error': 'Maximum number of images for this post has been reached'},
                                status=status.HTTP_400_BAD_REQUEST)

            serializer = PostSerializer(post, data=request.data, partial=True)
            if serializer.is_valid():
                post_data = serializer.validated_data
                post.description = post_data.get('description', post.description)
                post.save()

                image_id = request.data.get('image_id')
                image = request.FILES.get('images')

                if not image_id and image:
                    if post.images.count() >= 5:
                        return Response({'error': 'Maximum number of images for this post has been reached'},
                                        status=status.HTTP_400_BAD_REQUEST)

                    post_image = PostImage.objects.create(image_post=post, image=image)
                    serializer = PostSerializer(post)
                    return Response(serializer.data)

                elif image_id and image:
                    try:
                        post_image = post.images.get(id=image_id)
                        post_image.image = image
                        post_image.save()
                    except PostImage.DoesNotExist:
                        return Response({'error': f'Image with ID {image_id} does not exist for this post'},
                                        status=status.HTTP_404_NOT_FOUND)

                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

    @swagger_auto_schema(responses=Delete_response_schema)
    def delete(self, request, pk):
        if request.user.is_authenticated:
            post = self.get_object(pk)
            if request.user == post.user or request.user.is_staff:
                post.delete()
                return Response(status=status.HTTP_204_NO_CONTENT)
            else:
                return Response(status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class PostImageDeleteView(APIView):
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'image_id',
                openapi.IN_QUERY,
                type=openapi.TYPE_INTEGER,
                required=True,
                description='Image ID to delete',
            ),
        ],
        responses={
            status.HTTP_204_NO_CONTENT: "Image deleted",
            status.HTTP_400_BAD_REQUEST: "Invalid data",
            status.HTTP_401_UNAUTHORIZED: "Authentication credentials were not provided",
            status.HTTP_404_NOT_FOUND: "Post or image not found",
            status.HTTP_409_CONFLICT: "Cannot delete last image",
        },
    )
    def delete(self, request, pk):
        if request.user.is_authenticated:
            post = get_object_or_404(Post, pk=pk)
            image_id = request.query_params.get('image_id')
            try:
                image_id = int(image_id)
            except (TypeError, ValueError):
                return Response({'error': 'Invalid image ID'}, status=status.HTTP_400_BAD_REQUEST)

            if post.user != request.user:
                return Response(status=status.HTTP_401_UNAUTHORIZED)

            if post.images.count() == 1:
                return Response({'error': 'Cannot delete last image'}, status=status.HTTP_403_FORBIDDEN)

            try:
                post_image = post.images.get(id=image_id)
                post_image.delete()
            except PostImage.DoesNotExist:
                return Response({'error': f'Image with ID {image_id} does not exist for this post'},
                                status=status.HTTP_404_NOT_FOUND)

            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class PostLikeView(APIView):
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(responses=Get_response_schema)
    def get(self, request, pk):
        if request.user.is_authenticated:
            post = get_object_or_404(Post, pk=pk)
            liked = post.like_post(request.user)
            if liked:
                return Response({'status': 'liked'})
            else:
                return Response({'status': 'unliked'})
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


