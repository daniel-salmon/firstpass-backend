# firstpass-backend

Provides a FastAPI server for storing and retrieving secrets with JWT
authentication.  Secrets can be stored as arbitrary bytes in a database,
allowing you to use any encryption scheme you want.

For a detailed explanation of the endpoints exposed by the server along with
documentation on requests and responses, please see the autogenerated client at
[firstpass-client](https://github.com/daniel-salmon/firstpass-client). That
repo is generated using an OpenAPI client generator run with GitHub Actions on
each successful merge into the `main` branch of this repo.

# Table of Contents

- [Usage](#usage)
- [Design](#design)
- [Deploying to Heroku](#deploying-to-heroku)

## Usage <a name="usage"></a>

The server is written using FastAPI. By default it uses a Postgres database for
storage. To run everything, it's easiest to use the provided Docker compose
file:

```sh
$ docker compose up --build
```
On subsequent runs, the `--build` flag can be omitted, unless you've made
changes that need pulled into the image.

## Design <a name="design"></a>

The overall design of the server is that it should possess zero knowledge about
whatever data gets stored for each user. To that end, each user in the backend
possess's a single `blob` of data which is just a Postgres `bytea` byte string.
The client is responsible for encrypting data -- with whatever mechanism most
appropriate -- and submitting that to the server.

User's must have a unique `username`. The password is stored using the SHA512
hash of the user's password plus randomly generated salt. User authentication
is handled using JWT.

## Deploying to Heroku <a name="deploying-to-heroku"></a>

The project was written with the intention of deploying this server on Heroku
(although very little is custom tailored to Heroku -- perhaps the main thing is
the way the Docker `CMD` is written in shell form style).  The best
documentation for that will be Heroku docs, since what is written here will
inevitably out of date. However, as of this writing the process is:

Build the image and push to Heroku's container registry:

```sh
$ heroku container:push web
```
Then release:
```sh
$ heroku container:release web
```
You will have to manage other addons yourself, e.g., Postgres and Sentry.
