## Secure notepad implemented with Flask backend and Jupyter Notebook frontend.

The app allows securely creation/editing of text documents on the Server from the Client.

The notepad uses the Serpent algorithm to encrypt transmitted data via HTTP.

For the initial Serpent secret key exchange it uses the RSA algorithm.

Much thanks to @ypldan for the Client-Server part of the application.