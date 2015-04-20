mod_oauth2
==========

A Zotonic module that provides OAuth2 authentication. 


Usage
-----

### Authorization code grant

To use the [authorization code grant](https://tools.ietf.org/html/rfc6749#section-4.1),
redirect users to `/oauth2/dialog` with a `redirect_uri` and `client_id` in
the query string, e.g., `/oauth2/dialog?client_id=1&redirect_uri=http://your-domain.com/path`.
After users have logged in, they will be redirected to the `redirect_uri`, with
their access token in the query string.

### Client credentials grant

To use the [client credentials grant](https://tools.ietf.org/html/rfc6749#section-4.4),
POST to `/oauth2/token` with:

Name          | Description            | Type
------------- | ---------------------- | ------
client_id     | Your client app id     | string
client_secret | Your client app secret | string

### Sending authenticated requests

After retrieving an access token, authenticate your requests with that token
by setting the Authorization header:

```http
GET /some/url
Authorization: Bearer your-token
```
