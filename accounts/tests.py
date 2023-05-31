from django.test import TestCase, Client
from rest_framework.test import APITestCase
from rest_framework.test import APIClient
from rest_framework.reverse import reverse
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken

User = get_user_model()


class UserSearchViewTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user1 = User.objects.create(username='test_user1', email='test_user1@test.com', password='testpass')
        self.user2 = User.objects.create(username='test_user2', email='test_user2@test.com', password='testpass')
        self.user3 = User.objects.create(username='another_user', email='another_user@test.com', password='testpass')

    def test_user_search(self):
        response = self.client.get('/accounts/users/search/?Search=test_user')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
        self.assertEqual(response.data[1]['username'], self.user1.username)
        self.assertEqual(response.data[0]['username'], self.user2.username)
        self.assertEqual(response['X-Total-Count'], '2')
        self.assertEqual(response['X-Total-Pages'], '1')
        self.assertEqual(response['X-Page-Number'], '1')

    def test_user_search_pagination(self):
        response = self.client.get('/accounts/users/search/?Search=test_user&page=2')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
        self.assertEqual(response['X-Page-Number'], '1')
        self.assertEqual(response['X-Total-Count'], '2')
        self.assertEqual(response['X-Total-Pages'], '1')


class GetUserOneViewTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='test_user',
            email='test_user@test.com',
            first_name='testpass',
            last_name='testpass',
            password='testpass'
        )
        self.url = reverse('user-detail', args=[self.user.id])
        self.token = AccessToken.for_user(self.user)

    def test_get_user_as_staff(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url, HTTP_AUTHORIZATION=f'Bearer {self.token}')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], self.user.username)
        self.assertEqual(response.data['email'], self.user.email)

    def test_get_user_as_non_staff(self):
        non_staff_user = User.objects.create_user(
            username='non_staff_user',
            email='non_staff_user@test.com',
            first_name='testpass',
            last_name='testpass',
            password='testpass'
        )
        self.client.force_authenticate(user=non_staff_user)
        response = self.client.get(self.url, HTTP_AUTHORIZATION=f'Bearer {self.token}')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
