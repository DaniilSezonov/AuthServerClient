import jwt
import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from oauth2 import Oauth2, ResponseObject, RemoteUserProfile, OAuthDiscoveryError


class OpenID(Oauth2):
    state_token: str or None = None
    well_know_path_part: str = ".well-known"  # it is path in url to .well-know https://tools.ietf.org/html/rfc5785
    openid_conf_path_part = "openid-configuration"  # it is path in url to openid configuration
    auth_server_domain_name: str or None = None

    _configuration: dict or None = None  # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    was_load_openid_conf: bool = False

    audience: str or None = None

    jwk_cert: dict or None = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.openid_conf_path_part = kwargs.get("openid_conf_path_part") or self.openid_conf_path_part
        self.state_token = kwargs.get('state_token')
        self.jwk_cert = kwargs.get('jwk_cert')
        self.audience = kwargs.get('audience')

    @staticmethod
    def get_jwt_header(token):
        """
        :param token: the token is a jwt (that has name id_token in google notation)
        :return: dict with key alg (algorithm), kid (key id), typ (token type(JWT always))
        """
        return jwt.get_unverified_header(token)

    @staticmethod
    def jwk_to_rsa(jwk):
        """
        Decoding jwk format to public rsa key carried out by next steps:
        (jwk['e'] (RSA exponent) and jwk['n'] (RSA modulus) -> decode from base64url to binary -> encode binary to DEC (десятичная))
        :param jwk: JSON Web Key https://tools.ietf.org/html/rfc7517
        :return: RSA public key as instance of cryptography.hazmat.backends.openssl.rsa._RSAPublicKey
        """
        e = jwk.get('e')  # exponent
        assert e, "jwk must contains the exponent value by key 'e'"

        n = jwk.get('n')  # modulus
        assert n, "jwk must contains the modulus value by key 'n'"

        base64_url_exp = jwt.api_jws.base64url_decode(e)
        base64_url_modulus = jwt.api_jws.base64url_decode(n)

        dec64_url_exp = int(base64_url_exp.hex(), base=16)
        dec64_url_modulus = int(base64_url_modulus.hex(), base=16)

        return RSAPublicNumbers(e=dec64_url_exp, n=dec64_url_modulus).public_key(default_backend())

    def get_user_info_by_jwt(self, token, with_verify=True, **options)-> dict:
        """
        :param token: jwt
        :param with_verify: verify that response is not compromised
        :param options: if verify is True we need to pass JWK value for verification
        :return:
        """
        user_info = {}

        jwk = options.get("jwk")

        jwt_decode_options = {}
        audience = options.get('audience')
        if audience:
            jwt_decode_options['audience'] = audience
        elif self.audience:
            jwt_decode_options['audience'] = self.audience

        rsa_key = self.jwk_to_rsa(jwk)

        if with_verify:
            user_info = jwt.decode(token, key=rsa_key, **jwt_decode_options)
        else:
            user_info = jwt.decode(token, verify=False)

        return user_info

    def is_state_token_valid(self, state):
        # todo
        return self.state_token == state

    def get_user_profile(self, exchange_code_response: ResponseObject) -> RemoteUserProfile:
        id_token = exchange_code_response.get('id_token')
        assert id_token, "Wrong openid response from auth server. " \
                         "response must contains id_token (with JWT data) field"
        options = {
            'jwk': self.get_jwk_for_jwt(id_token)
        }
        return self.get_user_info_by_jwt(id_token, **options)

    def load_configuration(self, configuration: dict = None):
        if configuration is None:
            configuration = self.get_oauth_conf_by_discovery_doc()

        self._configuration = configuration
        self.was_load_openid_conf = True

    def get_oauth_conf_by_discovery_doc(self):
        discovery_path = f'https://{self.auth_server_domain_name}/{self.well_know_path_part}/{self.openid_conf_path_part}'
        response = requests.get(url=discovery_path)

        if response.status_code != 200:
            raise OAuthDiscoveryError()

        configuration = response.json()
        return configuration

    def get_jwk_for_jwt(self, token):
        if self.jwk_cert is None:
            jwt_header = self.get_jwt_header(token)
            self.load_jwk_by_remote(jwt_header.get('kid'))
        return self.jwk_cert

    def load_jwk_by_remote(self, kid: str):
        """
        :param kid: remote key id
        :return: jwk
        """
        assert kid, "You cant load jwk if key id (kid) is not set"
        configuration = self.get_configuration()
        jwks_uri = configuration.get('jwks_uri')
        certs_response = requests.get(url=jwks_uri).json()
        for key in certs_response['keys']:
            if key['kid'] == kid:
                self.load_jwk(key)
                break

    def load_jwk(self, jwk):
        self.jwk_cert = jwk
