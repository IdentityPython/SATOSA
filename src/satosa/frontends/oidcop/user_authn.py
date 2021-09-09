from oidcop.user_authn.user import UserAuthnMethod


class SatosaAuthnMethod(UserAuthnMethod):
    """
    Dummy approach to get SATOSA working with oidcop as it is
    """

    def __call__(self, **kwargs):
        """
        Display user interaction.

        :param args:
        :param kwargs:
        :return:
        """
        # raise NotImplementedError

    def verify(self, *args, **kwargs):
        """
        Callback to verify user input
        :return: username of the authenticated user
        """
        # raise NotImplementedError
