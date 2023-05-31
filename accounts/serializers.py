from . import models
from rest_framework import serializers
from django.urls import reverse
from shop import serializers as shop_serializers
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.core import validators
from django.db.models import Q


class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        validators=[
            validators.RegexValidator(
                regex=r'^[\w.@+-]+$',
                message='Username must not contain spaces or special characters',
            ),
            validators.MinLengthValidator(
                limit_value=3,
                message='Username must be at least 3 characters long',
            ),
        ]
    )
    first_name = serializers.CharField(
        validators=[
            validators.RegexValidator(
                regex=r'^[\w.@+-]+$',
                message='first_name must not contain spaces or special characters',
            ),
            validators.MinLengthValidator(
                limit_value=1,
                message='first_name must be at least 1 characters long',
            ),
        ]
    )
    last_name = serializers.CharField(
        validators=[
            validators.RegexValidator(
                regex=r'^[\w.@+-]+$',
                message='last_name must not contain spaces or special characters',
            ),
            validators.MinLengthValidator(
                limit_value=1,
                message='last_name must be at least 1 characters long',
            ),
        ]
    )
    password = serializers.CharField(write_only=True, validators=[
        validators.RegexValidator(
            regex=r'^\S+$',
            message='Password must not contain spaces'
        ),
        validators.RegexValidator(
            regex=r'[A-Z]',
            message='Password must contain at least one uppercase letter'
        ),
        validators.MinLengthValidator(
            limit_value=8,
            message='Password must be at least 8 characters long'
        ),
    ])
    password_confirmation = serializers.CharField(write_only=True)
    posts = serializers.SerializerMethodField()
    profile_pic = serializers.ImageField(max_length=None, allow_empty_file=False, use_url=True, required=False,
                                         read_only=False)

    is_friend = serializers.SerializerMethodField()

    class Meta:
        model = models.User
        fields = ("id", 'email', 'username', 'password', 'password_confirmation', 'first_name', 'last_name', 'is_friend', 'profile_pic', 'posts')

    def create(self, validated_data):
        password = validated_data.pop('password')
        password_confirmation = validated_data.pop('password_confirmation')

        if password != password_confirmation:
            raise serializers.ValidationError('Passwords do not match')

        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))

        validated_data.pop('created_date', None)
        user = models.User.objects.create_user(**validated_data, password=password)
        return user

    def get_is_friend(self, obj, user_id=None):
        if not self.context['request'].user.is_authenticated:
            return "not friend"
        else:
            user = self.context['request'].user
            try:
                # Check if a friendship exists between the current user and the user being serialized
                friendship = models.Friendship.objects.filter(
                    Q(from_user=user, to_user=obj) | Q(from_user=obj, to_user=user)
                )
                if friendship.exists():
                    return "friend"
                else:
                    return "not friend"
            except models.Friendship.DoesNotExist:
                return "not friend"

    @staticmethod
    def get_posts(obj):
        posts = obj.posts.all()
        return shop_serializers.PostSerializer(posts, many=True).data


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context['request']
        uidb64 = data['uidb64']
        token = data['token']
        data['password_reset_url'] = request.build_absolute_uri(reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token}))
        return data


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=20, write_only=True, required=True)
    new_password = serializers.CharField(max_length=20, write_only=True, required=True, validators=[
        validators.RegexValidator(
            regex=r'^\S+$',
            message='Password must not contain spaces'
        ),
        validators.RegexValidator(
            regex=r'[A-Z]',
            message='Password must contain at least one uppercase letter'
        ),
        validators.MinLengthValidator(
            limit_value=8,
            message='Password must be at least 8 characters long'
        ),
    ])
    new_password2 = serializers.CharField(max_length=20, write_only=True, required=True, validators=[
        validators.RegexValidator(
            regex=r'^\S+$',
            message='Password must not contain spaces'
        ),
        validators.RegexValidator(
            regex=r'[A-Z]',
            message='Password must contain at least one uppercase letter'
        ),
        validators.MinLengthValidator(
            limit_value=8,
            message='Password must be at least 8 characters long'
        ),
    ])

    def validate_new_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))

        return value


class FriendRequestSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.FriendRequest
        fields = ('id', 'from_user', 'to_user',  'message', 'created_at')


class FriendRequestAcceptedSerializer(serializers.ModelSerializer):
    accepted = serializers.SerializerMethodField()
    from_user_username = serializers.CharField(source='from_user.username')

    class Meta:
        model = models.FriendRequest
        fields = ('id', 'from_user', 'to_user', 'from_user_username', 'message', 'created_at', 'accepted')

    def get_accepted(self, obj):
        return obj.accepted

class FriendshipSerializer(serializers.ModelSerializer):
    to_user_username = serializers.CharField(source='to_user.username')
    accepted = serializers.SerializerMethodField()

    class Meta:
        model = models.Friendship
        fields = ('id', 'from_user', 'to_user', 'to_user_username', 'created_at', 'accepted')

    def get_accepted(self, obj):
        try:
            return obj.to_user.friend_requests_received.get(from_user=obj.from_user).accepted
        except models.FriendRequest.DoesNotExist:
            return False
