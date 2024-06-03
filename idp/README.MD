# IdP

## How to run
Start by installing the dependencies:
```bash
pip3 install -r requirements.txt
```

Since this is not in production, set the following env variable:
```bash
export AUTHLIB_INSECURE_TRANSPORT=true
```

Finally, start the server:
```bash
python3 idp.py
```

Notice if you wish to create the IdP clients from the config files, you need to run it like so:
```bash
python3 idp.py LOAD_CLIENTS
```
If the application is running in `debug` mode, the clients will be loaded twice but with different ids.


## Development shortcuts

Create a user:
```bash
curl <client_id>:<client_secret> -XPOST http://127.0.0.1:5000/register --header "Content-Type: application/json" --data '{"email":"<client_email>", "client_id": "<client_id>", "role": "<role>"}'
```

Then, if the email feature is enabled an email is sent to the specified email with the link to finish the registration. You can go to the database and check the `registration_code` and finish the registration in the browser by going to:
```
http://127.0.0.1:5000/register?id=<registration_code>
```

To get the authorization code use the following in the browser:
```
http://127.0.0.1:5000/oauth/authorize?response_type=code&client_id=${client_id}&scope=profile
```

To get the access token (a JWT) use:
```bash
curl -u <client_id>:<client_secret> -XPOST http://127.0.0.1:5000/oauth/token -F grant_type=authorization_code -F scope=profile -F code=<authorization_code>
```


## Setup clients
...


## Notes
The base implementation of this IdP was based on the [reference implementation](https://github.com/authlib/example-oauth2-server) provided by [Authlib](https://authlib.org/).