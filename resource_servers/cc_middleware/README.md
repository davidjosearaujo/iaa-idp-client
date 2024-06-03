# Portuguese Citizen Card Middleware

Small API that runs locally on the user machines that makes a bridge between the IdP and the CC.
Its only functionality is to sign a given string. A access token is needs also to be provided 
in order to check if the request is valid and it is just a relay from the IdP. This access token is a JWT
with the id of the user and signed by the IdP with just one minute of lifetime.
