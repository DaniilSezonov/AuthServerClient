"""
UserSocialAuth (or another your class name) is a abstract layer that responsible for creating user entity in your data layer.
This example is demonstration of my realisation the layer for my Django project.
"""

# from ...models.user_profile import UserProfile
# from ...models.user_social import UserSocial, PROVIDER_CODES
from ..oauth2 import Oauth2


class UserSocialAuth:
    """
    Обработка социальных сетей при авторизации
    """

    oauth: Oauth2
    provider_name: str or None = None

    @staticmethod
    def get_redirect_uri(scheme, http_host, provider):
        try:
            """
                urls.py 
                url(r'^(?P<provider>(VK|FB|GOOGLE))/$', UserSocialAuthView.as_view(), name='login_social_auth')
            """
            url = reverse('user:login_social_auth', args=[provider])
        except NoReverseMatch:
            raise Exception(message='Unknown Social', code='unknown_social')
        return f"{scheme}://{http_host}{url}"

    @transaction.atomic()
    def get_or_create_user(self, provider_name, provider_user_id, profile_data: dict):
        provider_type = PROVIDER_CODES[provider_name]
        try:
            user_social = UserSocial.objects.get(provider=provider_type, provider_id=provider_user_id)
            user = user_social.user
        except UserSocial.DoesNotExist:
            user, user_social, user_profile = self.create_user(
                provider_type=provider_type,
                provider_user_id=provider_user_id,
                **profile_data
            )
        return user

    @transaction.atomic()
    def create_user(self, provider_type, provider_user_id, **profile_data):
        user = User.objects.create(
            email=uuid.uuid4(),
            password=uuid.uuid4(),
            is_using_email=False,
            is_active=True
        )
        user_social = UserSocial.objects.create(
            user=user,
            provider=provider_type,
            provider_id=provider_user_id
        )

        user_profile = UserProfile.objects.create(
            user=user,
            **profile_data
        )
        user_profile.save()
        user_social.save()
        return user, user_social, user_profile

    def auth(self, code, redirect_uri, credentials: dict):
        auth_server_user = self.oauth.auth(code, redirect_uri, credentials)
        user_profile_data = self.convert_remote_profile_to_local(auth_server_user)
        auth_server_user_id = auth_server_user.get('id') or auth_server_user.get('sub')
        user = self.get_or_create_user(self.provider_name, auth_server_user_id, user_profile_data)
        return user

    @staticmethod
    def convert_remote_profile_to_local(user_profile: dict):
        raise NotImplementedError()

    def get_configuration(self):
        return self.oauth.get_configuration()

    def get_user_profile(self, exchange_code_response: dict):
        raise NotImplementedError()
