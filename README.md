# Discourse SSO for AD

Single Sign On (aka SSO, aka Integrated Login) for Discourse with Active Directory.

You can use this app to let your users login using their Windows accounts without them having to enter their password.

Thanks to [paully21](https://gist.github.com/paully21/9232979) for the SSO code.

## Deploy

You can either deploy with Visual Studio or simply copy all files to your IIS server (e.g. to /DiscSso).

Make sure that /DiscSso is an application in IIS Manager (*convert to application*) and that Windows Authentication is enabled (*in IIS/Authentication*).

## Configuration

### Prepare Admin

You should create an admin user so you can log in after enabling SSO. Set the username to your AD accountname (without a domain).

### Edit your web.config

appSettings:

- Secret: enter your secret, must match the value from discourse in "sso_secret"
- Allow: define the Active Directory groups you wish to give access in the format DOMAIN\GROUPNAME (separated by a comma)
- DiscourseUrl: the URL for your discourse server.

### Update Discourse

In Admin go to the login section:

- sso_url: the URL pointing to the login page in this app, e.g. http://YOURSERVER/discsso/login
- sso_secret: your secret, same as in appSettings
- enable_sso: must be enabled
- login required: should be enabled to automatically log in your intranet users
- allow new registrations: should be disabled (if you are only using sso)

## Troubleshooting

If you lock yourself out you can disable sso again:

```
./launcher enter app
rails c
irb > SiteSetting.enable_sso = false
irb > exit
exit
```

Also see https://meta.discourse.org/t/official-single-sign-on-for-discourse/13045

