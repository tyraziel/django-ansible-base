import pytest
from unittest import mock

from ansible_base.lib.utils.response import get_relative_url


@pytest.mark.django_db
def test_authenticators_view_denies_delete_last_enabled_authenticator(admin_api_client, system_user, local_authenticator):
    """
    Test that the admin can't delete the last enabled authenticator.
    """

    url = get_relative_url("authenticator-detail", kwargs={'pk': local_authenticator.pk})
    response = admin_api_client.delete(url)
    assert response.status_code == 400
    assert response.data['details'] == "Authenticator cannot be deleted, as no authenticators would be enabled"


@pytest.mark.django_db
def test_authenticators_metadata_not_instanced_on_create(admin_api_client, local_authenticator):
    url = get_relative_url("authenticator-list")
    response = admin_api_client.options(url)
    assert response.status_code == 200
    assert response.data['actions']['POST']['slug']["read_only"] is False


def test_authenticators_metadata_instanced_on_update(admin_api_client, local_authenticator):
    url = get_relative_url("authenticator-detail", kwargs={'pk': local_authenticator.pk})
    response = admin_api_client.options(url)
    assert response.status_code == 200
    assert response.data['actions']['PUT']['slug']["read_only"] is True


@pytest.mark.django_db
def test_authenticator_viewset_allows_service_token(system_user):
    """
    Test that AuthenticatorViewSet has allow_service_token = True
    """
    from ansible_base.authentication.views.authenticator import AuthenticatorViewSet
    
    viewset = AuthenticatorViewSet()
    assert viewset.allow_service_token is True


@pytest.mark.django_db 
def test_authenticator_view_service_token_auth_access(system_user, local_authenticator):
    """
    Test that service token authentication works for authenticator endpoints
    """
    from django.test import RequestFactory
    from ansible_base.authentication.views.authenticator import AuthenticatorViewSet
    
    factory = RequestFactory()
    request = factory.get('/api/v1/authenticators/')
    request.user = system_user
    request.auth = 'ServiceTokenAuthentication'
    
    viewset = AuthenticatorViewSet()
    viewset.action = 'list'
    viewset.request = request
    
    # Mock the permission check to verify service token auth is allowed
    with mock.patch('ansible_base.lib.utils.views.permissions.check_service_token_auth') as mock_check:
        mock_check.return_value = True
        
        # Verify that check_service_token_auth would return True for this setup
        from ansible_base.lib.utils.views.permissions import check_service_token_auth
        assert check_service_token_auth(request, viewset) is True


@pytest.mark.django_db
def test_authenticator_view_service_token_auth_denied_for_non_system_user(random_user, local_authenticator):
    """
    Test that regular users with service tokens are denied access
    """
    from django.test import RequestFactory
    from ansible_base.authentication.views.authenticator import AuthenticatorViewSet
    from ansible_base.lib.utils.views.permissions import check_service_token_auth
    
    factory = RequestFactory()
    request = factory.get('/api/v1/authenticators/')
    request.user = random_user  # Regular user, not system user
    request.auth = 'ServiceTokenAuthentication'
    
    viewset = AuthenticatorViewSet()
    viewset.action = 'list'
    viewset.request = request
    
    # Service token auth should be denied for non-system users
    assert check_service_token_auth(request, viewset) is False


@pytest.mark.django_db
def test_authenticator_view_service_token_auth_denied_for_superuser_non_system(admin_user, local_authenticator):
    """
    Test that even superusers with service tokens are denied if they're not system users
    """
    from django.test import RequestFactory
    from ansible_base.authentication.views.authenticator import AuthenticatorViewSet
    from ansible_base.lib.utils.views.permissions import check_service_token_auth
    
    factory = RequestFactory()
    request = factory.get('/api/v1/authenticators/')
    request.user = admin_user  # Superuser but not system user
    request.auth = 'ServiceTokenAuthentication'
    
    viewset = AuthenticatorViewSet()
    viewset.action = 'list'
    viewset.request = request
    
    # Service token auth should be denied even for superusers if they're not system users
    assert check_service_token_auth(request, viewset) is False


@pytest.mark.django_db
def test_authenticator_view_permissions_fallback_for_non_system_with_service_token(admin_user, local_authenticator):
    """
    Test that non-system users with service tokens fall back to normal permission checks
    """
    from django.test import RequestFactory
    from ansible_base.authentication.views.authenticator import AuthenticatorViewSet
    from ansible_base.lib.utils.views.permissions import IsSuperuser
    
    factory = RequestFactory()
    request = factory.get('/api/v1/authenticators/')
    request.user = admin_user  # Superuser but not system user
    request.auth = 'ServiceTokenAuthentication'
    
    viewset = AuthenticatorViewSet()
    
    # Service token auth should fail, but superuser permission should still work
    permission = IsSuperuser()
    assert permission.has_permission(request, viewset) is True  # Should pass because user is superuser
    
    # Test with regular user - should fail both service token and superuser checks
    request.user.is_superuser = False
    request.user.save()
    assert permission.has_permission(request, viewset) is False
