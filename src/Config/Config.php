<?php
return [
  'base_oauth_url' => env('ImapOauth2_BASE_URL', 'https://id-staging.ebomb.edu.vn'),
  'client_id' => env('ImapOauth2_CLIENT_ID','api2'),
  'client_secret'=> env('ImapOauth2_CLIENT_SECRET','secret2'),
  'jwt_public_key'=> env('ImapOauth2_JWT_PUBLIC_KEY', ''),
  'api_gateway_url' => env('API_GATEWAY_URL', '')
  // other options...
];