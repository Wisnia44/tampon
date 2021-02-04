# TAMP-on
### Anti-spam web app for Gmail Accounts. 

In order to use **full funcionality** of the app you have to configure settings in Google Developers Console! <br/>
Currently it's using settings which **do not allow** accessing your messages by third parties.

**Using instruction:**
1. Clone this repository;
2. Install necessary dependecies with `pip install -r requirements.txt`;
3. Migrate created migrations with `python tampon/manage.py migrate`;
4. Run the app with `python tampon/manage.py runserver`;
5. The app is accessible at *http://127.0.0.1:8000/*.


**Configuring settings in Google Developers Console:**
1. Visit *console.developers.google.com* and log in;
2. Create new project;
3. Click the button *Enable APIs and services*, look for *Gmail* app and enable it;
4. Create OAuth consent screen. Name the app. Provide user support email and  developer's email. Add */auth/userinfo.email* and *openid* scopes. Add test users by giving their emails. 
5. Create OAuth2.0 Client. Add *http://localhost:8080/* and *http://127.0.0.1:8000/oauth/complete/google-oauth2/* to *Authorised redirect URIs*.
6. From just created OAuth2.0 client copy *Client ID* to *tampon/settings.py* line 153 as a value of `SOCIAL_AUTH_GOOGLE_OAUTH2_KEY`.
7. From just created OAuth2.0 client copy *Client secret* to *tampon/settings.py* line 154 as a value of `SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET`.
8. From just created OAuth2.0 client download JSON containg all the data, rename it as *Credentials.json* and replace the existing file in tampon directory.
9. Start the app, all the funcionalities are ready to use by test users you've just defined.
