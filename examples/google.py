from ..oauth2 import Oauth2, RemoteUserProfile
from .local_db_layer import UserSocialAuth


static_configuration = {
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
}

class GoogleAuth(UserSocialAuth):
    auth_server_domain_name: str = "accounts.google.com"
    provider_name: str = "GOOGLE"

    def __init__(self):
        self.oauth = GoogleOAuth(**{
            'auth_server_domain_name': self.auth_server_domain_name
        })

        self.oauth.load_configuration(static_configuration)

    @staticmethod
    def convert_remote_profile_to_local(user_profile: RemoteUserProfile):
        return {
            'first_name': user_profile.get('given_name'),
            'last_name': user_profile.get('family_name'),
        }

    def get_user_profile(self, exchange_code_response: dict):
        return self.oauth.get_user_profile(exchange_code_response)


class GoogleOAuth(Oauth2):
    def get_user_profile(self, exchange_code_response)->RemoteUserProfile:
        """
        :param exchange_code_response: response from auth server token api "exchange code for token"
        :return: json response like a dict with such keys are: id, name, given_name, family_name, picture and locale.
        """
        access_token = exchange_code_response.get('access_token')
        url = "https://www.googleapis.com/userinfo/v2/me"
        response = requests.get(url, headers={
            "Authorization": f'Bearer {access_token}',
        })
        json = response.json()
        if response.status_code != 200:
            error = (
                f'Google integration error on getting user info'
                f'Invalid response from server.\n'
                f'Response: {json} with status {response.status_code}'
            )
            logger = logging.getLogger("error")
            logger.log(error)
            raise YouGidException(message=error, code="login_google_user_info")
        return json


class GoogleOpenidAuth(UserSocialAuth):
    provider_name: str = "GOOGLE"
    auth_server_domain_name: str = "accounts.google.com"

    def __init__(self):
        self.oauth = OpenID(**{
            'auth_server_domain_name': self.auth_server_domain_name,
            'audience': GOOGLE_CLIENT_ID
        })

        self.oauth.load_configuration()

    @staticmethod
    def convert_remote_profile_to_local(user_profile: OpenidJWTModel):
        sex = SEX_NOT_SPECIFIED
        gender = user_profile.get('gender')

        if gender == "male":
            sex = SEX_MALE
        elif gender == "female":
            sex = SEX_FEMALE

        return {
            'first_name': user_profile.get('given_name'),
            'last_name': user_profile.get('family_name'),
            'sex': sex,
            'birthday': user_profile.get('birthdate')
        }

    def get_user_profile(self, token):
        return self.oauth.get_user_profile({'id_token': token})

"""
Using
"""

@list_route(["POST"], permission_classes=[IsAnonymous])
def login_google(self, request):
    jwt = request.data.get('id_token')
    if not jwt:
        raise ValidationError(
            code="jwt",
            detail="Необходимо предоставить jwt токен"
        )
    provider = GoogleOpenidAuth()
    user_profile = provider.get_user_profile(jwt)
    converted_user_data = provider.convert_remote_profile_to_local(user_profile)
    user = provider.get_or_create_user(
        provider.provider_name,
        user_profile.get('sub'),
        converted_user_data
    )
    serializer_context = {**self.get_serializer_context(), 'token_required': True}
    serializer = ProfileSerializer(instance=user.profile, context=serializer_context)
    return Response(data=serializer.data)

@list_route(methods=['POST'], permission_classes=[IsAnonymous])
def login_facebook(self, request):
    access_token = request.data.get("access_token")
    if not access_token:
        raise ValidationError(
            code="access_token_fb",
            detail="необходимо предоставить access_token"
        )
    provider = GoogleOAuth()
    try:
        remote_user_data = provider.get_user_profile({'access_token': access_token})
    except YouGidException:
        raise ValidationError(
            code="access_token",
            detail="Не верный токен доступ"
        )
    converted_user_data = provider.convert_remote_profile_to_local(remote_user_data)
    user = provider.get_or_create_user(
        provider.provider_name,
        remote_user_data.get('id'),
        converted_user_data
    )
    serializer_context = {**self.get_serializer_context(), 'token_required': True}
    serializer = ProfileSerializer(instance=user.profile, context=serializer_context)
    return Response(data=serializer.data)
