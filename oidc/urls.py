from django.urls import path
from .views import AuthorizeView, TokenView, UserInfoView, ProtectedTestView, RevocationView, IntrospectionView, LogoutView

urlpatterns = [
    path('authorize/', AuthorizeView.as_view(), name='authorize'),
    path('token/', TokenView.as_view(), name='token'),
    path('userinfo/', UserInfoView.as_view(), name='userinfo'),
    path('test-auth/', ProtectedTestView.as_view(), name='test-auth'),
    path('revoke/', RevocationView.as_view(), name='revoke'),
    path('introspect/', IntrospectionView.as_view(), name='introspect'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
