# Flexible, Risk Aware Authentication System - Bank Use-Case
> Authors: Diogo Matos (dftm@ua.pt), David Araújo (davidaraujo@ua.pt)


## How to run

### Simple setup and interaction flow

To launch all the applications, from the root of the project, run the following commands:
```bash
export CLIENT_EMAIL="<your-client-email>"
export OFFICER_EMAIL="<your-officer-email>"
export MANAGER_EMAIL="<your-manager-email>"
./run.sh
```

Note that the three emails **MUST be different from each other**! They are unique keys in the IdP database. These emails are used for three dummy users created automatically on start up.

This starts the IdP and all the services and resource servers.

### Step-by-step
This section explains in detail the process of launching manually the various services. For a _almost_ fully automated setup, see section _[Simple setup and interaction flow](#simple-setup-and-interaction-flow)_.

### 1. Create a docker network

Create a new docker network named `iaa_network`, for the different applications to communicate with each other.
```bash
docker network create iaa_network
```

### 2. Start and register to the IdP

First, add the `client.json` to the `/idp` directory. And set `CLIENT_EMAIL`, `OFFICER_EMAIL` and `MANAGER_EMAIL` in `/idp/environment_variables`. These are the emails of the dummy clients and they must be unique, those are going to be used to send the registration link and the email OTP.

Go to `/idp`. Then start the IdP:
```bash
xhost +
docker compose up
```

The `xhost +` allows the container to use the host display to show its internal browser where credentials need to be introduced in Google's IdP. This is needed to have access to Gmail API to send emails from the IdP.

This will open a browser window where you'll be asked to login with you're Google account, and authorize the application to send an email in your name.

### 3. Start the services

Next go to the `/services` and execute:
```bash
docker compose up
```

Finally, start the resource servers, by changing the directory to `/resource_servers` and execute:
```bash
docker compose up
```

The citizen card middleware is the only service that needs to be executed outside docker due to its dependencies. For this authentication method to work, the user needs the [Autenticação.Gov plugin](https://autenticacao.gov.pt/fa/ajuda/autenticacaogovpt.aspx) and [Auntenticação Gov for desktop](https://www.autenticacao.gov.pt/cc-aplicacao), a smart card reader and this `cc_middleware` API running. Change directory to `/resource_servers/cc_middleware/` and then run:
```bash
python3 -m flask run --host=127.0.0.1 --port 6004
```

Also, when the IdP first starts up, three default users are generated but not set up because the authentication methods information cannot be static. Three URLs are printed to the `stdout` (one for each dummy client) and can be introduced in the browser to finish the authentication setup. If the emails set in `/idp/environment_variables` are valid, an email was sent with the respective link. 
