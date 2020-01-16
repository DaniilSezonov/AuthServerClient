import logging

import requests


RemoteUserProfile = dict
ResponseObject = dict


class ExchangeCodeForTokenError(Exception):
    def __init__(self, status_code):
        super().__init__(self, "Oauth integration error on exchanging code for token. Response status code is {status_code}.")


class OAuthDiscoveryError(Exception):
    def __init__(self):
        super().__init__(self, "Loading configuration from discovery api of auth server Failed")


class OAuthConfigurationError(Exception):
    def __init__(self):
        super().__init__(self, "OAuth configuration is not set.")


class Oauth2:
    #  it is path in url to .well-know
    #  https://tools.ietf.org/id/draft-ietf-oauth-discovery-08.html#ASConfigurationRequest
    well_know_path_part: str = ".well-known"
    oauth_conf_path_part = "oauth-authorization-server"  # it is path in url to openid configuration
    auth_server_domain_name: str or None = None

    #  https://tools.ietf.org/id/draft-ietf-oauth-discovery-09.html#ASConfigurationResponse
    _configuration: dict or None = None
    was_load_oauth_conf: bool = False

    _provider_name: str or None = None
    _access_token: str = ""

    client_id: str or None = None
    client_secret: str or None = None

    def __init__(self, *args, **kwargs):
        self.well_know_path_part = kwargs.get('well_know_path_part') or self.well_know_path_part
        self.oauth_conf_path_part = kwargs.get('oauth_conf_path_part') or self.oauth_conf_path_part
        self.auth_server_domain_name = kwargs.get('auth_server_domain_name')

    def auth(self, code, redirect_uri, credentials: dict, *args, **kwargs):
        """

        :param code: code that return auth server after redirect
        :param redirect_uri:
        :param args:
        :param credentials: credentials that contains client_id and client_secret
        :param kwargs:
        :return:
        """
        response = self.exchange_code_for_token(
            code=code,
            redirect_uri=redirect_uri,
            credentials=credentials
        )
        return self.get_user_profile(response)

    def get_user_profile(self, exchange_code_response: ResponseObject)->RemoteUserProfile:
        """
        :param exchange_code_response: response from auth server token api "exchange code for token"
        :return: json response like a dict with such keys are: id, name, given_name, family_name, picture and locale.
        """
        raise NotImplementedError()

    def exchange_code_for_token(self, code, redirect_uri, credentials: dict)->ResponseObject:
        configuration = self.get_configuration()

        response = requests.post(configuration.get("token_endpoint"), data={
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
            **credentials
        })
        json = response.json()

        if response.status_code != 200:
            error = (
                f'Oauth integration error on exchanging code for token'
                f'Invalid response from server.\n'
                f'Response: {json} with status {response.status_code}'
            )
            logger = logging.getLogger("error")
            logger.error(error)
            raise ExchangeCodeForTokenError(response.status_code)
        return json

    def get_access_token(self):
        assert self._access_token, "At first you must call auth() " \
                                   "for getting access token from " \
                                   "authenticated server."
        return self._access_token

    def get_oauth_conf_by_discovery_doc(self):
        discovery_path = f'https://{self.auth_server_domain_name}/{self.well_know_path_part}/{self.oauth_conf_path_part}'
        response = requests.get(url=discovery_path)

        if response.status_code != 200:
            raise OAuthDiscoveryError()

        configuration = response.json()
        return configuration

    def load_configuration(self, configuration: dict = None):
        if configuration is None:
            configuration = self.get_oauth_conf_by_discovery_doc()

        self._configuration = configuration
        self.was_load_oauth_conf = True

    def get_configuration(self):
        if self._configuration is None:
            try:
                self.load_configuration()
            except OAuthDiscoveryError:
                raise OAuthConfigurationError()
        return self._configuration
