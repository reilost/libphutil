<?php

/**
 * Authentication adapter for SSO OAuth2.
 */
final class PhutilSSOAuthAdapter extends PhutilOAuthAuthAdapter {

  public function getAdapterType() {
    return 'sso';
  }

  public function getAdapterDomain() {
    return 'sso.ricebook.net';

  }

  public function getAccountID() {
    return $this->getOAuthAccountData('id');
  }

  public function getAccountEmail() {
    return $this->getOAuthAccountData('email');
  }

  public function getAccountName() {
    return $this->getOAuthAccountData('login');
  }

  public function getAccountImageURI() {
    return $this->getOAuthAccountData('avatar_url');
  }

  public function getAccountURI() {
    $name = $this->getAccountName();
    if (strlen($name)) {
      return 'https://sso.ricebook.net';
    }
    return null;
  }

  public function getScope() {
    return 'email';
  }

  public function getExtraAuthenticateParameters() {
    return array(
      'response_type' => 'code',
    );
  }

  public function getExtraTokenParameters() {
    return array(
      'grant_type' => 'authorization_code',
    );
  }

  public function getAccountRealName() {
    return $this->getOAuthAccountData('name');
  }

  protected function getAuthenticateBaseURI() {
    return 'https://sso.ricebook.net/login/oauth/authorize';
  }

  protected function getAuthorizeTokenURI() {
    return 'https://sso.ricebook.net/login/oauth/authorize';
  }



  protected function getTokenBaseURI() {
    return 'https://sso.ricebook.net/oauth/token';
  }

  protected function loadOAuthAccountData() {
    $uri = new PhutilURI('https://sso.ricebook.net/oauth/api/me');
    $uri->setQueryParam('access_token', $this->getAccessToken());

    $future = new HTTPSFuture($uri);

    list($body) = $future->resolvex();

    try{
      return phutil_json_decode($body);
    } catch (PhutilJSONParserException $ex) {
      throw new PhutilProxyException(
        pht('Expected valid JSON response from sso account data request.'),
        $ex);
    }
  }

}