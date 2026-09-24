<div align="center">
    <img src="raw.githubusercontent.com/scherepi/guactegrations/main/.github/header.png" alt="guactegrations - a Go package to integrate with Hack Club's ecosystem">
</div>

guactegrations is a Go package that provides anything you might need to connect to Hack Club's ecosystem. it's currently compatible with Hackatime and Hack Club Auth, designed to be as plug-and-play as possible. 

# Notes
Guactegrations is in active development and doesn't yet support all the API endpoints for HCA and Hackatime. I should make it very clear that **guactegrations is not for building Hackatime/Wakatime clients** and does not support those endpoints. This library is for external apps that want to retrieve data from Hackatime on behalf of a user through OAuth.There is an endpoint (`/api/v1/authenticated/api_keys`) that allows an OAuth app to retrieve a user's personal API keys, but it is purposefully not being supported. I may build a separate Go library for programs that want to serve as a proper Hackatime client.