# flask_restful
RESTFul API in Flask With JSON Web Token Authentication and Flask-SQLAlchemy

Exposes a User and a TODO rest API where user can login and get a JSON web token using pyJWT. This web token can then be used in the authorization header of subsequent requests for that particular user. Without the web token user cannot perform any of the actions and the json web-token auto expires after a specific time delta. As an alternate the web token auto-expiration time can be prolonged to a timedelta of 24hrs so that users can access and perform actions on the REST API without the need to re authenticate from time to  time.

Actions supported by the User and TODO API's are create-user, see all users, get one user at a time, check the todo list of a user, promote a user to admin, demote a user, create todo's, delete to-do's, mark todo's as complete etc.
For performing any of the above mentioned requests, user first needs to login to get a web-token and then the same token should be used in the authorization header of subsequent requests to perform any of the supported actions.
